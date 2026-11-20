// Package ingest turns report mail into stored reports: it parses each
// attachment of a message, stores what parses and tells the message's source
// what became of it.
package ingest

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/dmarcguardhq/parse-dmarc/internal/intake"
	"github.com/dmarcguardhq/parse-dmarc/internal/metrics"
	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
)

// Store is where parsed reports go. SaveReport returns false for a report
// that is already stored.
type Store interface {
	SaveReport(ctx context.Context, feedback *parser.Feedback) (bool, error)
}

// Pipeline stores the reports of one message at a time. It is an
// intake.Handler through Handle.
type Pipeline struct {
	store   Store
	metrics *metrics.Metrics
	log     *zerolog.Logger
}

// New returns a pipeline writing to store. m may be nil.
func New(store Store, m *metrics.Metrics, log *zerolog.Logger) *Pipeline {
	return &Pipeline{store: store, metrics: m, log: log}
}

// Handle parses and stores every report attachment of msg. A report that
// does not parse is skipped; one that cannot be stored makes the whole
// message a retry, since reading it again may succeed and the reports it
// did store are recognised as duplicates then.
func (p *Pipeline) Handle(ctx context.Context, msg intake.Message) intake.Outcome {
	p.metrics.MessageFetched()

	stored, retry := 0, false
	for _, att := range msg.Attachments {
		p.metrics.AttachmentSeen()

		feedback, err := parseAttachment(att.Data)
		if err != nil {
			p.log.Warn().Err(err).
				Str("filename", att.Filename).
				Str("message_id", msg.MessageID).
				Str("from", msg.From).
				Msg("failed to parse report")
			p.metrics.ReportParseFailed()
			continue
		}
		p.metrics.ReportParsed()

		saved, err := p.store.SaveReport(ctx, feedback)
		if err != nil {
			p.log.Error().Err(err).
				Str("report_id", feedback.ReportMetadata.ReportID).
				Str("message_id", msg.MessageID).
				Msg("failed to save report")
			p.metrics.ReportStoreFailed()
			retry = true
			continue
		}
		stored++

		event := p.log.Info().
			Str("report_id", feedback.ReportMetadata.ReportID).
			Str("message_id", msg.MessageID).
			Str("org", feedback.ReportMetadata.OrgName).
			Str("domain", feedback.PolicyPublished.Domain)
		if !saved {
			event.Msg("report already stored")
			continue
		}
		p.metrics.ReportStored()
		event.Int("messages", feedback.GetTotalMessages()).Msg("saved report")
	}

	switch {
	case retry || ctx.Err() != nil:
		return intake.OutcomeRetry
	case stored > 0:
		return intake.OutcomeStored
	default:
		return intake.OutcomeInvalid
	}
}

// parseAttachment parses one attachment. A report that crashes the parser
// is a report that does not parse: one hostile attachment must not take the
// fetch loop down with it.
func parseAttachment(data []byte) (feedback *parser.Feedback, err error) {
	defer func() {
		if r := recover(); r != nil {
			feedback, err = nil, fmt.Errorf("parser panic: %v", r)
		}
	}()
	return parser.ParseReport(data)
}
