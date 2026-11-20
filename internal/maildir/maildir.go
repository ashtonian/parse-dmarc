// Package maildir reads DMARC report mail from a local Maildir, for hosts that
// already receive the reports on the filesystem they run the parser on.
package maildir

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dmarcguardhq/parse-dmarc/internal/config"
	"github.com/dmarcguardhq/parse-dmarc/internal/intake"
	"github.com/emersion/go-message/mail"
	"github.com/rs/zerolog"
)

// Client reads the messages a MTA has delivered into a Maildir. It is an
// intake.Source.
type Client struct {
	config *config.MaildirConfig
	log    *zerolog.Logger
}

// NewClient creates a new Maildir client. It fails fast when the process
// cannot read the configured path: an unreadable Maildir would otherwise look
// like an empty one on every cycle.
func NewClient(cfg *config.MaildirConfig, log *zerolog.Logger) (*Client, error) {
	if _, err := os.ReadDir(cfg.Path); err != nil {
		return nil, fmt.Errorf("maildir %s: %w", cfg.Path, err)
	}
	return &Client{config: cfg, log: log}, nil
}

// Name names the source in logs and metrics.
func (c *Client) Name() string { return "maildir" }

// Cycle reads every message in new/ and settles each as it is handled: a
// stored message moves to cur/, which is how a Maildir marks a message as
// read; one no report could be read from moves to the deadletter mailbox,
// where the operator sees what the parser dropped; one to retry stays in
// new/ for the next cycle.
func (c *Client) Cycle(ctx context.Context, handle intake.Handler) error {
	newDir := filepath.Join(c.config.Path, "new")
	entries, err := os.ReadDir(newDir)
	if err != nil {
		return fmt.Errorf("read maildir %s: %w", newDir, err)
	}

	var errs []error
	for _, entry := range entries {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		path := filepath.Join(newDir, name)
		if info, err := entry.Info(); err == nil && info.Size() > intake.MaxMessageSize {
			c.log.Warn().Str("file", name).Int64("size", info.Size()).Msg("message is too large to be a report; it is moved to the deadletter mailbox")
			if err := c.moveTo(c.deadletterDir(), name); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			// A message mid-delivery (tmp/ -> new/) or removed by a human
			// happens in a Maildir; skip it and look again next cycle.
			c.log.Warn().Err(err).Str("file", name).Msg("skipping maildir message")
			continue
		}

		msg := intake.Message{Key: name}
		msg.Subject, msg.From, msg.Date, msg.MessageID = c.headers(data)
		msg.Attachments = intake.CollectAttachments(c.log, bytes.NewReader(data))

		outcome := intake.OutcomeInvalid
		if len(msg.Attachments) == 0 {
			c.log.Warn().
				Str("file", name).
				Str("message_id", msg.MessageID).
				Str("from", msg.From).
				Str("subject", msg.Subject).
				Msg("no report attachment in message; it is moved to the deadletter mailbox")
		} else {
			outcome = handle(ctx, msg)
		}

		switch outcome {
		case intake.OutcomeStored:
			err = c.moveTo(filepath.Join(c.config.Path, "cur"), name)
		case intake.OutcomeInvalid:
			err = c.moveTo(c.deadletterDir(), name)
		default:
			err = nil
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Client) deadletterDir() string {
	return filepath.Join(c.config.Path, c.config.DeadletterMailbox)
}

// moveTo renames a message out of new/ into dir.
func (c *Client) moveTo(dir, name string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create maildir directory %s: %w", dir, err)
	}
	src := filepath.Join(c.config.Path, "new", name)
	dst := filepath.Join(dir, infoName(name))
	if err := os.Rename(src, dst); err != nil {
		if os.IsNotExist(err) {
			c.log.Debug().Str("file", name).Msg("maildir message already moved")
			return nil
		}
		return fmt.Errorf("move maildir message %s to %s: %w", name, dir, err)
	}
	return nil
}

// infoName is the new/ file name with the `:2,S` info suffix a message carries
// once it has been moved out of new/. An existing info block is replaced,
// never stacked.
func infoName(name string) string {
	if i := strings.Index(name, ":2,"); i >= 0 {
		name = name[:i]
	}
	return name + ":2,S"
}

// headers reads the fields the run log quotes, and the Message-ID that finds
// the message again in the MTA log.
func (c *Client) headers(data []byte) (subject, from string, date time.Time, messageID string) {
	mr, err := mail.CreateReader(bytes.NewReader(data))
	if err != nil {
		c.log.Warn().Err(err).Msg("failed to create mail reader")
		return
	}
	defer func() { _ = mr.Close() }()

	subject = mr.Header.Get("Subject")
	messageID = mr.Header.Get("Message-ID")
	if addrs, err := mr.Header.AddressList("From"); err == nil && len(addrs) > 0 {
		from = addrs[0].Address
	}
	if d, err := mr.Header.Date(); err == nil {
		date = d
	}
	return subject, from, date, messageID
}
