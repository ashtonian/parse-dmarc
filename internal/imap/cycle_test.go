package imap

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap/backend/memory"
	"github.com/emersion/go-imap/server"
	"github.com/rs/zerolog"

	"github.com/dmarcguardhq/parse-dmarc/internal/config"
	"github.com/dmarcguardhq/parse-dmarc/internal/intake"
)

const cycleReportXML = `<?xml version="1.0"?><feedback><report_metadata><report_id>1</report_id></report_metadata></feedback>`

func reportMail(subject string) string {
	return "From: noreply-dmarc-support@google.com\r\n" +
		"Subject: " + subject + "\r\n" +
		"Message-ID: <" + subject + "@google.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nReport attached.\r\n" +
		"--b\r\nContent-Type: application/xml\r\n" +
		"Content-Disposition: attachment; filename=\"google.com!example.com!1!2.xml\"\r\n\r\n" +
		cycleReportXML + "\r\n--b--\r\n"
}

const chatterMail = "From: someone@example.com\r\nSubject: chatter\r\nMessage-ID: <chatter@example.com>\r\n\r\nno report here\r\n"

// testServer runs go-imap's in-memory server with the given messages, all
// unseen, in INBOX. The backend already holds one seen message.
func testServer(t *testing.T, mails ...string) (*config.IMAPConfig, backend.User) {
	t.Helper()
	be := memory.New()
	user, err := be.Login(nil, "username", "password")
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := user.GetMailbox("INBOX")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range mails {
		if err := inbox.CreateMessage(nil, time.Unix(1700000000, 0), bytes.NewBufferString(m)); err != nil {
			t.Fatal(err)
		}
	}

	srv := server.New(movingBackend{be})
	srv.AllowInsecureAuth = true
	srv.ErrorLog = discardLogger{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return &config.IMAPConfig{
		Host: host, Port: p, Username: "username", Password: "password",
		Mailbox: "INBOX", UseTLS: false, MarkAsSeen: true,
	}, user
}

// movingBackend adds MOVE to the memory backend, which the go-imap server
// advertises but the memory backend does not implement.
type movingBackend struct{ *memory.Backend }

func (b movingBackend) Login(info *imap.ConnInfo, username, password string) (backend.User, error) {
	u, err := b.Backend.Login(info, username, password)
	if err != nil {
		return nil, err
	}
	return movingUser{u}, nil
}

type movingUser struct{ backend.User }

func (u movingUser) GetMailbox(name string) (backend.Mailbox, error) {
	m, err := u.User.GetMailbox(name)
	if err != nil {
		return nil, err
	}
	return movingMailbox{m}, nil
}

type movingMailbox struct{ backend.Mailbox }

func (m movingMailbox) MoveMessages(uid bool, seqset *imap.SeqSet, dest string) error {
	if err := m.CopyMessages(uid, seqset, dest); err != nil {
		return err
	}
	if err := m.UpdateMessagesFlags(uid, seqset, imap.AddFlags, []string{imap.DeletedFlag}); err != nil {
		return err
	}
	return m.Expunge()
}

type discardLogger struct{}

func (discardLogger) Printf(string, ...interface{}) {}
func (discardLogger) Println(...interface{})        {}

// subjects lists the subjects of a mailbox's messages with the given flag
// state.
func subjects(t *testing.T, user backend.User, mailbox string, seen bool) []string {
	t.Helper()
	mbox, err := user.GetMailbox(mailbox)
	if err != nil {
		t.Fatal(err)
	}
	all := new(imap.SeqSet)
	all.AddRange(1, 0)
	ch := make(chan *imap.Message, 32)
	if err := mbox.ListMessages(false, all, []imap.FetchItem{imap.FetchEnvelope, imap.FetchFlags}, ch); err != nil {
		t.Fatal(err)
	}
	var out []string
	for msg := range ch {
		isSeen := false
		for _, f := range msg.Flags {
			if f == imap.SeenFlag {
				isSeen = true
			}
		}
		if isSeen == seen && msg.Envelope.Subject != "A little message, just for you" {
			out = append(out, msg.Envelope.Subject)
		}
	}
	return out
}

func outcomeBySubject(outcomes map[string]intake.Outcome, handled *[]intake.Message) intake.Handler {
	return func(_ context.Context, msg intake.Message) intake.Outcome {
		*handled = append(*handled, msg)
		return outcomes[msg.Subject]
	}
}

// Stored and invalid messages, and those with no report at all, are marked
// seen; a message to retry is left unseen for the next cycle.
func TestCycleMarksSeenByOutcome(t *testing.T) {
	cfg, user := testServer(t, reportMail("stored"), reportMail("retry"), reportMail("invalid"), chatterMail)
	log := zerolog.Nop()
	c := mustClient(t, cfg, &log)

	var handled []intake.Message
	handle := outcomeBySubject(map[string]intake.Outcome{
		"stored":  intake.OutcomeStored,
		"retry":   intake.OutcomeRetry,
		"invalid": intake.OutcomeInvalid,
	}, &handled)
	if err := c.Cycle(context.Background(), handle); err != nil {
		t.Fatal(err)
	}

	if len(handled) != 3 {
		t.Fatalf("want the 3 messages with a report handled, got %d", len(handled))
	}
	first := handled[0]
	if first.MessageID != "<stored@google.com>" || len(first.Attachments) != 1 || !strings.Contains(first.Key, ":") {
		t.Fatalf("message: %+v", first)
	}

	if got := subjects(t, user, "INBOX", false); len(got) != 1 || got[0] != "retry" {
		t.Fatalf("unseen after the cycle = %v, want only the retry", got)
	}
	if got := subjects(t, user, "INBOX", true); len(got) != 3 {
		t.Fatalf("seen after the cycle = %v, want stored, invalid and chatter", got)
	}

	// Only the retry is read again.
	handled = nil
	if err := c.Cycle(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if len(handled) != 1 || handled[0].Subject != "retry" {
		t.Fatalf("second cycle handled %v, want only the retry", handled)
	}
}

// With a processed mailbox, everything that is done with moves there and the
// retry stays behind.
func TestCycleMovesToProcessedMailbox(t *testing.T) {
	cfg, user := testServer(t, reportMail("stored"), reportMail("retry"), chatterMail)
	cfg.MarkAsSeen = false
	cfg.ProcessedMailbox = "Processed"
	log := zerolog.Nop()
	c := mustClient(t, cfg, &log)

	var handled []intake.Message
	handle := outcomeBySubject(map[string]intake.Outcome{
		"stored": intake.OutcomeStored,
		"retry":  intake.OutcomeRetry,
	}, &handled)
	if err := c.Cycle(context.Background(), handle); err != nil {
		t.Fatal(err)
	}

	if got := subjects(t, user, "INBOX", false); len(got) != 1 || got[0] != "retry" {
		t.Fatalf("INBOX after the cycle = %v, want only the retry", got)
	}
	if got := subjects(t, user, "Processed", false); len(got) != 2 {
		t.Fatalf("Processed after the cycle = %v, want stored and chatter", got)
	}
}

type recorder struct{ ok, failed int }

func (r *recorder) RecordIMAPConnection(success bool, _ time.Duration) {
	if success {
		r.ok++
	} else {
		r.failed++
	}
}

func TestCycleRecordsConnection(t *testing.T) {
	cfg, _ := testServer(t)
	log := zerolog.Nop()
	rec := &recorder{}
	if err := mustClient(t, cfg, &log, WithConnectionRecorder(rec)).Cycle(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	cfg.Password = "wrong"
	if err := mustClient(t, cfg, &log, WithConnectionRecorder(rec)).Cycle(context.Background(), nil); err == nil {
		t.Fatal("want a login error")
	}
	if rec.ok != 1 || rec.failed != 1 {
		t.Fatalf("recorded %d ok, %d failed; want 1 and 1", rec.ok, rec.failed)
	}
}

func mustClient(t *testing.T, cfg *config.IMAPConfig, log *zerolog.Logger, opts ...Option) *Client {
	t.Helper()
	c, err := NewClient(cfg, log, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type memLedger map[string]string

func (l memLedger) ProcessedKeys(_ context.Context, source string, keys []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, k := range keys {
		if _, ok := l[source+"|"+k]; ok {
			out[k] = true
		}
	}
	return out, nil
}

func (l memLedger) MarkProcessed(_ context.Context, source, key, outcome, _ string) error {
	l[source+"|"+key] = outcome
	return nil
}

// A read-only mailbox is opened with EXAMINE and left exactly as it was,
// seen flags included; the ledger alone carries the progress, so a message
// a person already read is still processed.
func TestCycleReadOnlyLeavesMailboxUntouched(t *testing.T) {
	cfg, user := testServer(t, reportMail("stored"), reportMail("retry"), chatterMail)
	cfg.ReadOnly = true
	log := zerolog.Nop()
	ledger := memLedger{}
	c := mustClient(t, cfg, &log, WithLedger(ledger))

	var handled []intake.Message
	handle := outcomeBySubject(map[string]intake.Outcome{
		"stored": intake.OutcomeStored,
		"retry":  intake.OutcomeRetry,
	}, &handled)
	if err := c.Cycle(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	// The backend's own message is seen already and is read all the same.
	if len(handled) != 2 {
		t.Fatalf("handled %d messages, want the 2 with a report", len(handled))
	}
	if got := subjects(t, user, "INBOX", false); len(got) != 3 {
		t.Fatalf("unseen after a read-only cycle = %v, want all 3 untouched", got)
	}
	if len(ledger) != 3 {
		t.Fatalf("ledger = %v, want stored, chatter and the backend's seen message", ledger)
	}

	handled = nil
	if err := c.Cycle(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if len(handled) != 1 || handled[0].Subject != "retry" {
		t.Fatalf("second cycle handled %v, want only the retry", handled)
	}
}

func TestNewClientReadOnlyNeedsLedger(t *testing.T) {
	log := zerolog.Nop()
	if _, err := NewClient(&config.IMAPConfig{ReadOnly: true}, &log); !errors.Is(err, ErrReadOnlyNeedsLedger) {
		t.Fatalf("err = %v, want ErrReadOnlyNeedsLedger", err)
	}
}
