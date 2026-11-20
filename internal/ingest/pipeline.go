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

// Store is where parsed reports go. Each save returns false for a report
// that is already stored.
type Store interface {
	SaveReport(ctx context.Context, feedback *parser.Feedback) (bool, error)
	SaveTLSReport(ctx context.Context, report *parser.TLSReport) (bool, error)
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

// Handle parses and stores every report attachment of msg, DMARC or TLS-RPT. A report that
// does not parse is skipped; one that cannot be stored makes the whole
// message a retry, since reading it again may succeed and the reports it
// did store are recognised as duplicates then.
func (p *Pipeline) Handle(ctx context.Context, msg intake.Message) intake.Outcome {
	p.metrics.MessageFetched()

	stored, retry := 0, false
	for _, att := range msg.Attachments {
		p.metrics.AttachmentSeen()

		report, err := parseAttachment(att.Data)
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

		saved, err := p.save(ctx, report)
		event := p.log.Info().
			Str("kind", string(report.Kind)).
			Str("message_id", msg.MessageID)
		event = describe(event, report)
		if err != nil {
			p.log.Error().Err(err).
				Str("kind", string(report.Kind)).
				Str("message_id", msg.MessageID).
				Msg("failed to save report")
			p.metrics.ReportStoreFailed()
			retry = true
			continue
		}
		stored++
		if !saved {
			event.Msg("report already stored")
			continue
		}
		p.metrics.ReportStored()
		event.Msg("saved report")
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

func (p *Pipeline) save(ctx context.Context, r *parser.Report) (bool, error) {
	switch r.Kind {
	case parser.KindTLSRPT:
		return p.store.SaveTLSReport(ctx, r.TLSRPT)
	default:
		return p.store.SaveReport(ctx, r.DMARC)
	}
}

// describe adds what identifies a report to a log entry.
func describe(e *zerolog.Event, r *parser.Report) *zerolog.Event {
	switch r.Kind {
	case parser.KindTLSRPT:
		ok, failed := r.TLSRPT.Sessions()
		return e.Str("report_id", r.TLSRPT.ReportID).
			Str("org", r.TLSRPT.OrganizationName).
			Strs("domains", r.TLSRPT.PolicyDomains()).
			Int64("successful_sessions", ok).
			Int64("failed_sessions", failed)
	default:
		return e.Str("report_id", r.DMARC.ReportMetadata.ReportID).
			Str("org", r.DMARC.ReportMetadata.OrgName).
			Str("domain", r.DMARC.PolicyPublished.Domain).
			Int("messages", r.DMARC.GetTotalMessages())
	}
}

// parseAttachment parses one attachment, DMARC or TLS-RPT. A report that
// crashes the parser is a report that does not parse: one hostile attachment
// must not take the fetch loop down with it.
func parseAttachment(data []byte) (report *parser.Report, err error) {
	defer func() {
		if r := recover(); r != nil {
			report, err = nil, fmt.Errorf("parser panic: %v", r)
		}
	}()
	return parser.Parse(data)
}
