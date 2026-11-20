// Package jmapintake reads report mail from one mailbox over JMAP. It never
// changes the mailbox: its progress is kept in the ledger, so the token it
// runs with can be, and by default must be, read-only.
package jmapintake

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/dmarcguardhq/parse-dmarc/internal/config"
	"github.com/dmarcguardhq/parse-dmarc/internal/intake"
	"github.com/dmarcguardhq/parse-dmarc/internal/jmap"
)

// ErrTokenCanWrite is returned when the read-only requirement is on and the
// server says the token may change the mail account.
var ErrTokenCanWrite = errors.New("the JMAP token can change the mailbox; issue a read-only token or set JMAP_REQUIRE_READ_ONLY=false")

// batchSize bounds how many messages are listed per Email/get, and so how
// many are in flight between two ledger writes.
const batchSize = 50

// Source is an intake.Source reading one JMAP mailbox.
type Source struct {
	client *jmap.Client
	cfg    *config.JMAPConfig
	ledger intake.Ledger
	log    *zerolog.Logger
}

// New returns a source for the configured mailbox. Options are passed to the
// JMAP client; tests use them to reach a local server.
func New(cfg *config.JMAPConfig, ledger intake.Ledger, log *zerolog.Logger, opts ...jmap.Option) (*Source, error) {
	if ledger == nil {
		return nil, errors.New("the JMAP intake needs a ledger to keep its progress")
	}
	opts = append([]jmap.Option{
		jmap.WithTimeout(time.Duration(cfg.TimeoutSeconds) * time.Second),
		jmap.WithMaxBlobBytes(intake.MaxMessageSize),
	}, opts...)
	client, err := jmap.NewClient(cfg.SessionURL, cfg.Token, opts...)
	if err != nil {
		return nil, err
	}
	return &Source{client: client, cfg: cfg, ledger: ledger, log: log}, nil
}

// Name names the source in logs and metrics.
func (s *Source) Name() string { return "jmap" }

// Cycle reads every message of the mailbox the ledger has not recorded,
// oldest first, hands each to handle and records stored and invalid ones.
// A message to retry is not recorded and is read again next cycle.
func (s *Source) Cycle(ctx context.Context, handle intake.Handler) error {
	// The session is fetched every cycle: the server may move its API and
	// download URLs, and revoking the token or widening it shows up here.
	sess, err := s.client.Session(ctx)
	if err != nil {
		return err
	}
	accountID, acct, err := sess.MailAccount()
	if err != nil {
		return err
	}
	if s.cfg.RequireReadOnly && !acct.IsReadOnly {
		return ErrTokenCanWrite
	}

	boxes, err := s.client.Mailboxes(ctx, sess, accountID)
	if err != nil {
		return err
	}
	box, err := jmap.ResolveMailbox(boxes, s.cfg.Mailbox)
	if err != nil {
		return err
	}
	ids, err := s.client.QueryEmailIDs(ctx, sess, accountID, box.ID)
	if err != nil {
		return err
	}

	// Mailbox ids survive renames, so the ledger keeps its place when the
	// folder is renamed or JMAP_MAILBOX is given by id.
	source := "jmap://" + accountID + "/" + box.ID
	done, err := s.ledger.ProcessedKeys(ctx, source, ids)
	if err != nil {
		return err
	}
	fresh := make([]string, 0, len(ids))
	for _, id := range ids {
		if !done[id] {
			fresh = append(fresh, id)
		}
	}
	if len(fresh) == 0 {
		s.log.Info().Str("mailbox", s.cfg.Mailbox).Msg("no new messages found")
		return nil
	}
	s.log.Info().Int("count", len(fresh)).Str("mailbox", s.cfg.Mailbox).Bool("read_only", acct.IsReadOnly).Msg("found new messages")

	for start := 0; start < len(fresh); start += batchSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		emails, _, err := s.client.GetEmails(ctx, sess, accountID, fresh[start:min(start+batchSize, len(fresh))])
		if err != nil {
			return err
		}
		for _, email := range emails {
			if err := ctx.Err(); err != nil {
				return err
			}
			outcome, err := s.process(ctx, sess, accountID, email, handle)
			if err != nil {
				return err
			}
			if outcome == intake.OutcomeRetry {
				continue
			}
			if err := s.ledger.MarkProcessed(ctx, source, email.ID, outcome.String(), messageID(email)); err != nil {
				return err
			}
		}
	}
	return nil
}

// process downloads one message and hands it to handle. An error means the
// mailbox itself could not be read, and ends the cycle.
func (s *Source) process(ctx context.Context, sess *jmap.Session, accountID string, email jmap.Email, handle intake.Handler) (intake.Outcome, error) {
	if email.Size > intake.MaxMessageSize {
		s.log.Warn().Str("email_id", email.ID).Str("message_id", messageID(email)).Int64("size", email.Size).
			Msg("message is too large to be a report; it is marked processed without being read")
		return intake.OutcomeInvalid, nil
	}

	raw, err := s.client.DownloadBlob(ctx, sess, accountID, email.BlobID, "message.eml", "message/rfc822")
	if errors.Is(err, jmap.ErrBlobTooLarge) {
		s.log.Warn().Str("email_id", email.ID).Msg("message is too large to be a report; it is marked processed without being read")
		return intake.OutcomeInvalid, nil
	}
	if err != nil {
		return 0, err
	}

	msg := intake.Message{
		Key:         email.ID,
		MessageID:   messageID(email),
		Subject:     email.Subject,
		Date:        email.ReceivedAt,
		Attachments: intake.CollectAttachments(s.log, bytes.NewReader(raw)),
	}
	if len(email.From) > 0 {
		msg.From = email.From[0].Email
	}
	if len(msg.Attachments) == 0 {
		s.log.Warn().
			Str("email_id", email.ID).
			Str("message_id", msg.MessageID).
			Str("from", msg.From).
			Str("subject", msg.Subject).
			Msg("no report attachment in message; it is marked processed all the same")
		return intake.OutcomeInvalid, nil
	}
	return handle(ctx, msg), nil
}

// messageID renders the Message-ID header as the other intakes report it.
func messageID(e jmap.Email) string {
	if len(e.MessageID) == 0 {
		return ""
	}
	return fmt.Sprintf("<%s>", strings.Trim(e.MessageID[0], "<>"))
}
