// Package imap reads report mail from one IMAP mailbox.
package imap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/dmarcguardhq/parse-dmarc/internal/config"
	"github.com/dmarcguardhq/parse-dmarc/internal/intake"
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/rs/zerolog"
)

// ConnectionRecorder observes connection attempts; *metrics.Metrics is one.
type ConnectionRecorder interface {
	RecordIMAPConnection(success bool, duration time.Duration)
}

// Client reads report mail from the configured mailbox. It is an
// intake.Source.
type Client struct {
	config   *config.IMAPConfig
	client   *client.Client
	log      *zerolog.Logger
	recorder ConnectionRecorder
}

// NewClient creates a new IMAP client. recorder may be nil.
func NewClient(cfg *config.IMAPConfig, log *zerolog.Logger, recorder ConnectionRecorder) *Client {
	return &Client{config: cfg, log: log, recorder: recorder}
}

// Name names the source in logs and metrics.
func (c *Client) Name() string { return "imap" }

// tlsConfig builds the TLS settings used for both implicit TLS and STARTTLS.
func (c *Client) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName:         c.config.Host,
		InsecureSkipVerify: c.config.TLSSkipVerify, // #nosec G402 -- opt-in, for internal IMAP servers
		MinVersion:         tls.VersionTLS12,
	}

	if c.config.TLSCAFile == "" {
		return cfg, nil
	}

	pem, err := os.ReadFile(c.config.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("read IMAP CA file %s: %w", c.config.TLSCAFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in IMAP CA file %s", c.config.TLSCAFile)
	}
	cfg.RootCAs = pool

	return cfg, nil
}

// dial opens the connection: implicit TLS, plaintext upgraded via STARTTLS, or
// plaintext. StartTLS wins over UseTLS since UseTLS defaults to true.
func (c *Client) dial(addr string, tlsCfg *tls.Config) (*client.Client, error) {
	if c.config.UseTLS && !c.config.StartTLS {
		return client.DialTLS(addr, tlsCfg)
	}

	imapClient, err := client.Dial(addr)
	if err != nil || !c.config.StartTLS {
		return imapClient, err
	}

	if err := imapClient.StartTLS(tlsCfg); err != nil {
		_ = imapClient.Logout()
		return nil, fmt.Errorf("starttls: %w", err)
	}

	return imapClient, nil
}

// connect dials and logs in, recording the attempt.
func (c *Client) connect() error {
	start := time.Now()
	err := c.dialAndLogin()
	if c.recorder != nil {
		c.recorder.RecordIMAPConnection(err == nil, time.Since(start))
	}
	return err
}

func (c *Client) dialAndLogin() error {
	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
	c.log.Debug().Str("addr", addr).Msg("connecting")

	tlsCfg, err := c.tlsConfig()
	if err != nil {
		return err
	}

	imapClient, err := c.dial(addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}

	c.client = imapClient
	c.log.Info().Str("addr", addr).Msg("connected")

	// Login
	if err := c.client.Login(c.config.Username, c.config.Password); err != nil {
		_ = c.client.Logout()
		return fmt.Errorf("log in as %s: %w", c.config.Username, err)
	}

	c.log.Info().Str("username", c.config.Username).Msg("logged in")
	return nil
}

// disconnect logs out, or closes the connection when the session is gone.
func (c *Client) disconnect() {
	if c.client == nil {
		return
	}
	if err := c.client.Logout(); err != nil {
		_ = c.client.Terminate()
	}
	c.client = nil
}

// batchSize bounds how many messages one fetch command returns, and so how
// many bodies are held in memory at once.
const batchSize = 50

// Cycle reads the unseen messages of the mailbox, hands each to handle and
// settles it by its outcome: stored and invalid messages are marked seen
// and moved to the processed mailbox as configured; a message to retry is
// left exactly as it was. Bodies are fetched with BODY.PEEK, so reading a
// message never marks it seen by itself.
func (c *Client) Cycle(ctx context.Context, handle intake.Handler) error {
	if err := c.connect(); err != nil {
		return err
	}
	defer c.disconnect()

	// go-imap v1 takes no context: closing the connection is what ends a
	// command in flight when the cycle is cancelled.
	stop := context.AfterFunc(ctx, func() { _ = c.client.Terminate() })
	defer stop()

	mbox, err := c.client.Select(c.config.Mailbox, false)
	if err != nil {
		return fmt.Errorf("select mailbox %s: %w", c.config.Mailbox, err)
	}

	criteria := imap.NewSearchCriteria()
	criteria.WithoutFlags = []string{imap.SeenFlag}
	uids, err := c.client.UidSearch(criteria)
	if err != nil {
		return fmt.Errorf("search mailbox %s: %w", c.config.Mailbox, err)
	}
	if len(uids) == 0 {
		c.log.Info().Str("mailbox", c.config.Mailbox).Msg("no new messages found")
		return nil
	}
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	c.log.Info().Int("count", len(uids)).Str("mailbox", c.config.Mailbox).Msg("found new messages")

	var errs []error
	for start := 0; start < len(uids); start += batchSize {
		if ctx.Err() != nil {
			break
		}
		batch := uids[start:min(start+batchSize, len(uids))]
		done, err := c.processBatch(ctx, mbox.UidValidity, batch, handle)
		if err != nil {
			errs = append(errs, err)
			break
		}
		if err := c.settle(done); err != nil {
			errs = append(errs, err)
		}
	}
	if err := ctx.Err(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// processBatch fetches a batch of messages and hands each to handle. It
// returns the UIDs that are done with: stored or invalid.
func (c *Client) processBatch(ctx context.Context, uidValidity uint32, uids []uint32, handle intake.Handler) ([]uint32, error) {
	envelopes, err := c.fetchEnvelopes(uids)
	if err != nil {
		return nil, err
	}

	var done, wanted []uint32
	for _, uid := range uids {
		env, ok := envelopes[uid]
		if !ok {
			// Expunged by another client since the search.
			continue
		}
		if env.size > intake.MaxMessageSize {
			c.log.Warn().
				Uint32("uid", uid).
				Str("message_id", env.messageID).
				Uint32("size", env.size).
				Msg("message is too large to be a report; it is marked processed without being read")
			done = append(done, uid)
			continue
		}
		wanted = append(wanted, uid)
	}

	bodies, err := c.fetchBodies(wanted)
	if err != nil {
		return nil, err
	}

	for _, uid := range wanted {
		env := envelopes[uid]
		body, ok := bodies[uid]
		if !ok {
			c.log.Warn().Uint32("uid", uid).Msg("server didn't return message body")
			continue
		}
		msg := intake.Message{
			Key:         fmt.Sprintf("%d:%d", uidValidity, uid),
			MessageID:   env.messageID,
			From:        env.from,
			Subject:     env.subject,
			Date:        env.date,
			Attachments: intake.CollectAttachments(c.log, bytes.NewReader(body)),
		}

		outcome := intake.OutcomeInvalid
		if len(msg.Attachments) == 0 {
			// The only trace that a sender's report went unrecognized:
			// message_id finds it again anywhere.
			c.log.Warn().
				Str("message_id", msg.MessageID).
				Uint32("uid", uid).
				Str("mailbox", c.config.Mailbox).
				Str("from", msg.From).
				Str("subject", msg.Subject).
				Time("date", msg.Date).
				Msg("no report attachment in message; it is marked processed all the same")
		} else {
			outcome = handle(ctx, msg)
		}

		if outcome != intake.OutcomeRetry {
			done = append(done, uid)
		}
	}
	return done, nil
}

type envelope struct {
	messageID, from, subject string
	date                     time.Time
	size                     uint32
}

func (c *Client) fetchEnvelopes(uids []uint32) (map[uint32]envelope, error) {
	out := make(map[uint32]envelope, len(uids))
	err := c.uidFetch(uids, []imap.FetchItem{imap.FetchUid, imap.FetchEnvelope, imap.FetchRFC822Size}, func(msg *imap.Message) {
		e := envelope{size: msg.Size}
		if msg.Envelope != nil {
			e.messageID = msg.Envelope.MessageId
			e.subject = msg.Envelope.Subject
			e.date = msg.Envelope.Date
			if len(msg.Envelope.From) > 0 {
				e.from = msg.Envelope.From[0].Address()
			}
		}
		out[msg.Uid] = e
	})
	if err != nil {
		return nil, fmt.Errorf("fetch envelopes: %w", err)
	}
	return out, nil
}

func (c *Client) fetchBodies(uids []uint32) (map[uint32][]byte, error) {
	out := make(map[uint32][]byte, len(uids))
	if len(uids) == 0 {
		return out, nil
	}
	section := &imap.BodySectionName{Peek: true}
	err := c.uidFetch(uids, []imap.FetchItem{imap.FetchUid, section.FetchItem()}, func(msg *imap.Message) {
		r := msg.GetBody(section)
		if r == nil {
			return
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r); err != nil {
			c.log.Warn().Err(err).Uint32("uid", msg.Uid).Msg("reading message body")
			return
		}
		out[msg.Uid] = buf.Bytes()
	})
	if err != nil {
		return nil, fmt.Errorf("fetch bodies: %w", err)
	}
	return out, nil
}

// uidFetch runs UID FETCH and calls fn for each message as it arrives.
func (c *Client) uidFetch(uids []uint32, items []imap.FetchItem, fn func(*imap.Message)) error {
	seqSet := new(imap.SeqSet)
	seqSet.AddNum(uids...)

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)
	go func() {
		done <- c.client.UidFetch(seqSet, items, messages)
	}()
	for msg := range messages {
		fn(msg)
	}
	return <-done
}

// settle marks the given messages seen and moves them to the processed
// mailbox, as configured, addressing them by UID so a concurrent expunge by
// another client cannot shift the command onto other messages.
func (c *Client) settle(uids []uint32) error {
	if len(uids) == 0 {
		return nil
	}
	seqSet := new(imap.SeqSet)
	seqSet.AddNum(uids...)

	if c.config.MarkAsSeen {
		item := imap.FormatFlagsOp(imap.AddFlags, true)
		if err := c.client.UidStore(seqSet, item, []interface{}{imap.SeenFlag}, nil); err != nil {
			return fmt.Errorf("mark %d messages seen: %w", len(uids), err)
		}
		c.log.Info().Int("count", len(uids)).Msg("marked messages as seen")
	}

	if dest := c.config.ProcessedMailbox; dest != "" {
		// Ensure the destination exists; an error here usually means it
		// already does, and the move reports any real problem.
		if err := c.client.Create(dest); err != nil {
			c.log.Debug().Err(err).Str("mailbox", dest).Msg("create mailbox (may already exist)")
		}
		// MOVE (RFC 6851) where the server has it; otherwise go-imap falls
		// back to UID COPY, UID STORE \Deleted and EXPUNGE.
		if err := c.client.UidMove(seqSet, dest); err != nil {
			return fmt.Errorf("move %d messages to %s: %w", len(uids), dest, err)
		}
		c.log.Info().Int("count", len(uids)).Str("mailbox", dest).Msg("moved messages to processed mailbox")
	}
	return nil
}
