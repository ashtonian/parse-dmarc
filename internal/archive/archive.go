// Package archive writes every ingested report to S3-compatible object
// storage: the attachment exactly as received, so reports can be parsed again
// after a parser fix, and the parsed report as JSON for analytics tools.
//
// Keys are Hive-style partitions on the report's begin date in UTC, so
// Athena, Trino and DuckDB can prune by date:
//
//	<prefix>raw/<kind>/year=YYYY/month=MM/day=DD/<org>_<report-id>_<hash>.raw.<ext>
//	<prefix>parsed/<kind>/year=YYYY/month=MM/day=DD/<org>_<report-id>_<hash>.json
//
// Raw and parsed objects live in separate trees because a query engine reads
// every object under a table's location: a table over parsed/dmarc/ must not
// meet gzipped XML. The keys depend only on the report, so writing the same
// report again overwrites its two objects instead of adding copies.
package archive

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Kind is the report format, and the second level of every key.
type Kind string

// Report kinds.
const (
	// KindDMARC is a DMARC aggregate report (RFC 7489).
	KindDMARC Kind = "dmarc"
	// KindTLSRPT is an SMTP TLS report (RFC 8460).
	KindTLSRPT Kind = "tlsrpt"
)

// ErrInvalidReport is returned by Put for a report that lacks what its keys
// or objects are built from. Writing it again cannot succeed.
var ErrInvalidReport = errors.New("invalid report")

// Report is one ingested report.
type Report struct {
	Kind     Kind
	OrgName  string
	ReportID string
	// Domain is the DMARC policy domain or, for TLS-RPT, the sorted
	// comma-joined policy domains. Together with Kind, OrgName and ReportID
	// it identifies the report.
	Domain string
	// Begin is the start of the reporting period; its UTC date picks the
	// partition.
	Begin time.Time

	// Raw is the attachment as received: XML, JSON, gzip or zip.
	Raw []byte
	// RawFilename is the attachment's file name; its extension is kept on
	// the raw object.
	RawFilename string
	// RawContentType is the attachment's declared media type. Empty or
	// unparsable, the type is sniffed from Raw.
	RawContentType string

	// Parsed is the parsed report, stored as JSON.
	Parsed any
}

func (r Report) validate() error {
	switch {
	case r.Kind != KindDMARC && r.Kind != KindTLSRPT:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidReport, r.Kind)
	case r.Begin.IsZero():
		return fmt.Errorf("%w: %s report %q has no begin time", ErrInvalidReport, r.Kind, r.ReportID)
	case len(r.Raw) == 0:
		return fmt.Errorf("%w: %s report %q has no raw attachment", ErrInvalidReport, r.Kind, r.ReportID)
	case r.Parsed == nil:
		return fmt.Errorf("%w: %s report %q has no parsed form", ErrInvalidReport, r.Kind, r.ReportID)
	}
	return nil
}

// Keys are the object keys one report was written to.
type Keys struct {
	Raw    string
	Parsed string
}

// Archiver stores reports.
type Archiver interface {
	Put(ctx context.Context, r Report) (Keys, error)
}

var (
	_ Archiver = (*S3)(nil)
	_ Archiver = Nop{}
)

// Nop discards reports: the Archiver to use when archiving is off.
type Nop struct{}

// Put stores nothing and returns empty keys.
func (Nop) Put(context.Context, Report) (Keys, error) {
	return Keys{}, nil
}
