// Package intake is the contract between the mail sources (IMAP, Maildir)
// and the pipeline that stores their reports: a source hands over one
// message at a time and settles it by the outcome the pipeline returns.
package intake

import (
	"context"
	"time"
)

// Attachment is one MIME part that looks like an aggregate report.
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// Message is one report mail.
type Message struct {
	// Key identifies the message within its source: an IMAP UID with its
	// UIDVALIDITY, a Maildir file name.
	Key string
	// MessageID is the RFC 5322 Message-ID, the key that finds the mail
	// again on any server and in the MTA log.
	MessageID   string
	From        string
	Subject     string
	Date        time.Time
	Attachments []Attachment
}

// Outcome is what became of a message, and so what its source does with it.
type Outcome int

const (
	// OutcomeStored: at least one report in the message is in the store,
	// saved now or before. The source marks the message processed.
	OutcomeStored Outcome = iota + 1
	// OutcomeInvalid: no report in the message parses, which reading it
	// again will not change. The source sets it aside (deadletter) or marks
	// it processed, so it is not read on every cycle.
	OutcomeInvalid
	// OutcomeRetry: a report could not be stored for a reason that can
	// pass, such as the database being down or the fetch being cancelled.
	// The source leaves the message as it found it for the next cycle.
	OutcomeRetry
)

func (o Outcome) String() string {
	switch o {
	case OutcomeStored:
		return "stored"
	case OutcomeInvalid:
		return "invalid"
	case OutcomeRetry:
		return "retry"
	default:
		return "unknown"
	}
}

// Handler stores the reports of one message.
type Handler func(ctx context.Context, msg Message) Outcome

// Source reads report mail. Cycle hands every new message to handle and
// settles each by its outcome; it returns an error only when the source as
// a whole could not be read or settled.
type Source interface {
	Name() string
	Cycle(ctx context.Context, handle Handler) error
}

// MaxMessageSize bounds one report mail. Aggregate reports are kilobytes;
// anything this large is not one, and reading it would only cost memory.
const MaxMessageSize = 32 << 20

// Ledger records which messages a source has finished with, for sources
// that may not flag or move mail to mark their progress. *storage.Storage
// is one.
type Ledger interface {
	ProcessedKeys(ctx context.Context, source string, keys []string) (map[string]bool, error)
	MarkProcessed(ctx context.Context, source, key, outcome, messageID string) error
}
