// Package imap reads report mail from one IMAP mailbox.
package imap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
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
	ledger   intake.Ledger
}

// Option configures a Client.
type Option func(*Client)

// WithConnectionRecorder observes every connection attempt.
func WithConnectionRecorder(r ConnectionRecorder) Option {
	return func(c *Client) { c.recorder = r }
}

// WithLedger keeps the progress of a read-only mailbox; IMAP_READ_ONLY
// requires it.
func WithLedger(l intake.Ledger) Option {
	return func(c *Client) { c.ledger = l }
}

// ErrReadOnlyNeedsLedger is returned for a read-only client without a ledger.
var ErrReadOnlyNeedsLedger = errors.New("a read-only IMAP intake needs a ledger to keep its progress")

// NewClient creates a new IMAP client.
func NewClient(cfg *config.IMAPConfig, log *zerolog.Logger, opts ...Option) (*Client, error) {
	c := &Client{config: cfg, log: log}
	for _, opt := range opts {
		opt(c)
	}
	if cfg.ReadOnly && c.ledger == nil {
		return nil, ErrReadOnlyNeedsLedger
	}
	return c, nil
}

// ledgerSource names the mailbox in the ledger: the account and the
// mailbox, never the password.
func (c *Client) ledgerSource() string {
	return fmt.Sprintf("imap://%s@%s:%d/%s", c.config.Username, c.config.Host, c.config.Port, c.config.Mailbox)
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

// DefaultTimeout bounds the connection and each command when
// IMAP_TIMEOUT_SECONDS is unset.
const DefaultTimeout = 60 * time.Second

func (c *Client) timeout() time.Duration {
	if c.config.TimeoutSeconds > 0 {
		return time.Duration(c.config.TimeoutSeconds) * time.Second
	}
	return DefaultTimeout
}

// dial opens the connection: implicit TLS, plaintext upgraded via STARTTLS, or
// plaintext. StartTLS wins over UseTLS since UseTLS defaults to true. The
// timeout bounds the TCP connect and greeting, and then every command, so
// a server that stops answering ends the cycle instead of hanging it.
func (c *Client) dial(addr string, tlsCfg *tls.Config) (*client.Client, error) {
	dialer := &net.Dialer{Timeout: c.timeout()}

	var (
		imapClient *client.Client
		err        error
	)
	if c.config.UseTLS && !c.config.StartTLS {
		imapClient, err = client.DialWithDialerTLS(dialer, addr, tlsCfg)
	} else {
		imapClient, err = client.DialWithDialer(dialer, addr)
	}
	if err != nil {
		return nil, err
	}
	imapClient.Timeout = c.timeout()

	if c.config.StartTLS {
		if err := imapClient.StartTLS(tlsCfg); err != nil {
			_ = imapClient.Logout()
			return nil, fmt.Errorf("starttls: %w", err)
		}
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

// Cycle reads the new messages of the mailbox, hands each to handle and
// settles it by its outcome.
//
// By default the new messages are the unseen ones: stored and invalid
// messages are marked seen and moved to the processed mailbox as
// configured. A read-only client opens the mailbox with EXAMINE, takes every
// message the ledger has not recorded, and records stored and invalid ones
// there instead. Either way a message to retry is left exactly as it was,
// and bodies are fetched with BODY.PEEK, so reading a message never marks
// it seen by itself.
func (c *Client) Cycle(ctx context.Context, handle intake.Handler) error {
	if err := c.connect(); err != nil {
		return err
	}
	defer c.disconnect()

	// go-imap v1 takes no context: closing the connection is what ends a
	// command in flight when the cycle is cancelled.
	stop := context.AfterFunc(ctx, func() { _ = c.client.Terminate() })
	defer stop()

	mbox, err := c.client.Select(c.config.Mailbox, c.config.ReadOnly)
	if err != nil {
		return fmt.Errorf("select mailbox %s: %w", c.config.Mailbox, err)
	}

	uids, err := c.newUIDs(ctx, mbox.UidValidity)
	if err != nil {
		return err
	}
	if len(uids) == 0 {
		c.log.Info().Str("mailbox", c.config.Mailbox).Msg("no new messages found")
		return nil
	}
	c.log.Info().Int("count", len(uids)).Str("mailbox", c.config.Mailbox).Bool("read_only", c.config.ReadOnly).Msg("found new messages")

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
		if err := c.settle(ctx, done); err != nil {
			errs = append(errs, err)
		}
	}
	if err := ctx.Err(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// newUIDs returns the UIDs to read this cycle, in ascending order.
func (c *Client) newUIDs(ctx context.Context, uidValidity uint32) ([]uint32, error) {
	criteria := imap.NewSearchCriteria()
	if !c.config.ReadOnly {
		criteria.WithoutFlags = []string{imap.SeenFlag}
	}
	uids, err := c.client.UidSearch(criteria)
	if err != nil {
		return nil, fmt.Errorf("search mailbox %s: %w", c.config.Mailbox, err)
	}
	sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
	if !c.config.ReadOnly {
		return uids, nil
	}

	keys := make([]string, len(uids))
	for i, uid := range uids {
		keys[i] = messageKey(uidValidity, uid)
	}
	done, err := c.ledger.ProcessedKeys(ctx, c.ledgerSource(), keys)
	if err != nil {
		return nil, err
	}
	fresh := uids[:0]
	for i, uid := range uids {
		if !done[keys[i]] {
			fresh = append(fresh, uid)
		}
	}
	return fresh, nil
}

// messageKey identifies a message for as long as the mailbox keeps its
// UIDVALIDITY; a new UIDVALIDITY makes every message new again, and the
// store recognises the reports it already has.
func messageKey(uidValidity, uid uint32) string {
	return fmt.Sprintf("%d:%d", uidValidity, uid)
}

// settled is a message the cycle is done with.
type settled struct {
	uid       uint32
	key       string
	messageID string
	outcome   intake.Outcome
}

// processBatch fetches a batch of messages and hands each to handle. It
// returns the messages that are done with: stored or invalid.
func (c *Client) processBatch(ctx context.Context, uidValidity uint32, uids []uint32, handle intake.Handler) ([]settled, error) {
	envelopes, err := c.fetchEnvelopes(uids)
	if err != nil {
		return nil, err
	}

	var done []settled
	var wanted []uint32
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
			done = append(done, settled{uid: uid, key: messageKey(uidValidity, uid), messageID: env.messageID, outcome: intake.OutcomeInvalid})
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
			Key:         messageKey(uidValidity, uid),
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
			done = append(done, settled{uid: uid, key: msg.Key, messageID: msg.MessageID, outcome: outcome})
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

// settle records the messages a read-only client is done with in the
// ledger; otherwise it marks them seen and moves them to the processed
// mailbox, as configured, addressing them by UID so a concurrent expunge by
// another client cannot shift the command onto other messages.
func (c *Client) settle(ctx context.Context, done []settled) error {
	if len(done) == 0 {
		return nil
	}
	if c.config.ReadOnly {
		for _, m := range done {
			if err := c.ledger.MarkProcessed(ctx, c.ledgerSource(), m.key, m.outcome.String(), m.messageID); err != nil {
				return err
			}
		}
		return nil
	}

	seqSet := new(imap.SeqSet)
	for _, m := range done {
		seqSet.AddNum(m.uid)
	}

	if c.config.MarkAsSeen {
		item := imap.FormatFlagsOp(imap.AddFlags, true)
		if err := c.client.UidStore(seqSet, item, []interface{}{imap.SeenFlag}, nil); err != nil {
			return fmt.Errorf("mark %d messages seen: %w", len(done), err)
		}
		c.log.Info().Int("count", len(done)).Msg("marked messages as seen")
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
			return fmt.Errorf("move %d messages to %s: %w", len(done), dest, err)
		}
		c.log.Info().Int("count", len(done)).Str("mailbox", dest).Msg("moved messages to processed mailbox")
	}
	return nil
}
