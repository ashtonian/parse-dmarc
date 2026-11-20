package maildir

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dmarcguardhq/parse-dmarc/internal/config"
	"github.com/dmarcguardhq/parse-dmarc/internal/intake"
	"github.com/rs/zerolog"
)

const (
	reportName = "google.com!example.com!1609459200!1609545600.xml"
	reportXML  = `<?xml version="1.0"?><feedback><report_metadata><report_id>1</report_id></report_metadata></feedback>`
)

// reportMessage is a message as the MTA delivers it: a text body plus the
// aggregate report attachment.
func reportMessage() string {
	return "From: noreply-dmarc-support@google.com\r\n" +
		"To: dmarc@example.com\r\n" +
		"Subject: Report Domain: example.com Submitter: google.com\r\n" +
		"Message-ID: <report-1@google.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n" +
		"--b\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\n" +
		"Report attached.\r\n" +
		"--b\r\nContent-Type: application/xml; name=\"" + reportName + "\"\r\n" +
		"Content-Disposition: attachment; filename=\"" + reportName + "\"\r\n\r\n" +
		reportXML + "\r\n--b--\r\n"
}

// newMaildir returns a Maildir skeleton with the given files in new/.
func newMaildir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, "new", name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// Each message is settled by its outcome: stored to cur/, invalid (or with
// no report at all) to the deadletter mailbox, retry left in new/.
func TestCycleSettlesByOutcome(t *testing.T) {
	dir := newMaildir(t, map[string]string{
		"1700000000.report":  reportMessage(),
		"1700000001.chatter": "From: someone@example.com\r\nSubject: no report here\r\n\r\nhello\r\n",
		"1700000002.retry":   reportMessage(),
		"1700000003.invalid": reportMessage(),
	})

	log := zerolog.Nop()
	c, err := NewClient(&config.MaildirConfig{Path: dir, DeadletterMailbox: "DEADLETTER"}, &log)
	if err != nil {
		t.Fatal(err)
	}

	var handled []intake.Message
	outcomes := map[string]intake.Outcome{
		"1700000000.report":  intake.OutcomeStored,
		"1700000002.retry":   intake.OutcomeRetry,
		"1700000003.invalid": intake.OutcomeInvalid,
	}
	handle := func(_ context.Context, msg intake.Message) intake.Outcome {
		handled = append(handled, msg)
		return outcomes[msg.Key]
	}
	if err := c.Cycle(context.Background(), handle); err != nil {
		t.Fatal(err)
	}

	if len(handled) != 3 {
		t.Fatalf("want the 3 messages with a report handled, got %d", len(handled))
	}
	first := handled[0]
	if first.MessageID != "<report-1@google.com>" || len(first.Attachments) != 1 {
		t.Fatalf("message: %+v", first)
	}
	if att := first.Attachments[0]; att.Filename != reportName || string(att.Data) != reportXML {
		t.Fatalf("want the report attachment %q, got %q (%d bytes)", reportName, att.Filename, len(att.Data))
	}

	for _, name := range []string{
		"cur/1700000000.report:2,S",
		"DEADLETTER/1700000001.chatter:2,S",
		"new/1700000002.retry",
		"DEADLETTER/1700000003.invalid:2,S",
	} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(name))); err != nil {
			t.Errorf("want %s: %v", name, err)
		}
	}
	content, err := os.ReadFile(filepath.Join(dir, "cur", "1700000000.report:2,S"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "<feedback>") {
		t.Error("message body changed on the way to cur/")
	}

	// Only the message to retry is read again.
	handled = nil
	if err := c.Cycle(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if len(handled) != 1 || handled[0].Key != "1700000002.retry" {
		t.Fatalf("second cycle handled %d messages, want only the retry", len(handled))
	}
}

// A cancelled cycle stops before the next message and leaves it in new/.
func TestCycleStopsWhenCancelled(t *testing.T) {
	dir := newMaildir(t, map[string]string{"1.report": reportMessage(), "2.report": reportMessage()})
	log := zerolog.Nop()
	c, err := NewClient(&config.MaildirConfig{Path: dir, DeadletterMailbox: "DEADLETTER"}, &log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	handle := func(context.Context, intake.Message) intake.Outcome {
		cancel()
		return intake.OutcomeStored
	}
	if err := c.Cycle(ctx, handle); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	left, err := os.ReadDir(filepath.Join(dir, "new"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 {
		t.Fatalf("want 1 message left in new/, got %d", len(left))
	}
}

// A Maildir the process cannot read looks like an empty one, so NewClient
// fails at startup instead of every cycle silently finding nothing.
func TestNewClientRejectsUnreadablePath(t *testing.T) {
	log := zerolog.Nop()
	if _, err := NewClient(&config.MaildirConfig{Path: filepath.Join(t.TempDir(), "missing")}, &log); err == nil {
		t.Fatal("want an error for a path that does not exist")
	}

	if os.Geteuid() == 0 {
		t.Skip("root reads a 0o000 directory all the same")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := NewClient(&config.MaildirConfig{Path: dir}, &log); err == nil {
		t.Fatal("want an error for a path the process cannot read")
	}
}

func TestCycleWithoutNewDir(t *testing.T) {
	log := zerolog.Nop()
	c, err := NewClient(&config.MaildirConfig{Path: t.TempDir()}, &log)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Cycle(context.Background(), func(context.Context, intake.Message) intake.Outcome { return intake.OutcomeStored }); err == nil {
		t.Fatal("want an error for a directory that is not a Maildir")
	}
}

func TestInfoNameReplacesExistingInfo(t *testing.T) {
	if got := infoName("1700000000.report:2,SR"); got != "1700000000.report:2,S" {
		t.Fatalf("want the info block replaced, got %q", got)
	}
	if got := infoName("1700000000.report"); got != "1700000000.report:2,S" {
		t.Fatalf("want an info block added, got %q", got)
	}
}
