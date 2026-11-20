package ingest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/dmarcguardhq/parse-dmarc/internal/archive"
	"github.com/dmarcguardhq/parse-dmarc/internal/enrich"
	"github.com/dmarcguardhq/parse-dmarc/internal/intake"
	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
)

const goodReport = `<?xml version="1.0"?><feedback><report_metadata><org_name>google.com</org_name>` +
	`<report_id>1</report_id><date_range><begin>1609459200</begin><end>1609545600</end></date_range>` +
	`</report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published>` +
	`<record><row><source_ip>192.0.2.1</source_ip><count>1</count><policy_evaluated><disposition>none</disposition>` +
	`</policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record></feedback>`

type fakeStore struct {
	err   error
	saved map[string]bool
}

func (s *fakeStore) SaveReport(_ context.Context, fb *parser.Feedback) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	if s.saved == nil {
		s.saved = map[string]bool{}
	}
	key := fb.ReportMetadata.OrgName + "/" + fb.ReportMetadata.ReportID
	if s.saved[key] {
		return false, nil
	}
	s.saved[key] = true
	return true, nil
}

func (s *fakeStore) SaveTLSReport(_ context.Context, r *parser.TLSReport) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	if s.saved == nil {
		s.saved = map[string]bool{}
	}
	key := "tls:" + r.OrganizationName + "/" + r.ReportID
	if s.saved[key] {
		return false, nil
	}
	s.saved[key] = true
	return true, nil
}

const tlsReport = `{"organization-name":"Google Inc.","date-range":{"start-datetime":"2026-11-18T00:00:00Z",` +
	`"end-datetime":"2026-11-18T23:59:59Z"},"contact-info":"smtp-tls-reporting@google.com","report-id":"2026-11-18T00:00:00Z_example.com",` +
	`"policies":[{"policy":{"policy-type":"sts","policy-string":["version: STSv1","mode: testing"],"policy-domain":"example.com",` +
	`"mx-host":["mx.example.com"]},"summary":{"total-successful-session-count":12,"total-failure-session-count":0}}]}`

func message(attachments ...string) intake.Message {
	msg := intake.Message{Key: "1", MessageID: "<1@example.com>"}
	for _, a := range attachments {
		msg.Attachments = append(msg.Attachments, intake.Attachment{Filename: "r.xml", Data: []byte(a)})
	}
	return msg
}

func TestHandleOutcomes(t *testing.T) {
	log := zerolog.Nop()
	cases := []struct {
		name  string
		store *fakeStore
		msg   intake.Message
		want  intake.Outcome
	}{
		{"a report that parses is stored", &fakeStore{}, message(goodReport), intake.OutcomeStored},
		{"a TLS-RPT report is stored", &fakeStore{}, message(tlsReport), intake.OutcomeStored},
		{"a TLS-RPT duplicate is stored all the same", &fakeStore{saved: map[string]bool{"tls:Google Inc./2026-11-18T00:00:00Z_example.com": true}}, message(tlsReport), intake.OutcomeStored},
		{"a duplicate is stored all the same", &fakeStore{saved: map[string]bool{"google.com/1": true}}, message(goodReport), intake.OutcomeStored},
		{"one good report among bad ones", &fakeStore{}, message("<garbage", goodReport), intake.OutcomeStored},
		{"nothing parses", &fakeStore{}, message("<garbage", "PK nope"), intake.OutcomeInvalid},
		{"no attachments", &fakeStore{}, message(), intake.OutcomeInvalid},
		{"the store fails", &fakeStore{err: errors.New("database is down")}, message(goodReport), intake.OutcomeRetry},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(tc.store, nil, &log)
			if got := p.Handle(context.Background(), tc.msg); got != tc.want {
				t.Fatalf("outcome = %v, want %v", got, tc.want)
			}
		})
	}
}

// A cancelled fetch leaves its message for the next cycle.
func TestHandleCancelledIsRetry(t *testing.T) {
	log := zerolog.Nop()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := New(&fakeStore{}, nil, &log).Handle(ctx, message(goodReport)); got != intake.OutcomeRetry {
		t.Fatalf("outcome = %v, want retry", got)
	}
}

type fakeEnricher struct{ asked [][]string }

func (f *fakeEnricher) LookupAll(_ context.Context, ips []string, _ int) map[string]enrich.Source {
	f.asked = append(f.asked, ips)
	out := map[string]enrich.Source{}
	for _, ip := range ips {
		out[ip] = enrich.Source{IP: ip, Name: "looked up"}
	}
	return out
}

type fakeSources struct {
	saved   map[string]enrich.Source
	missing []string
}

func (f *fakeSources) SourcesToLookUp(_ context.Context, ips []string, _ time.Time) ([]string, error) {
	var out []string
	for _, ip := range ips {
		if _, ok := f.saved[ip]; !ok {
			out = append(out, ip)
		}
	}
	return out, nil
}

func (f *fakeSources) SourcesMissing(context.Context, int) ([]string, error) { return f.missing, nil }

func (f *fakeSources) SaveSources(_ context.Context, sources []enrich.Source) error {
	for _, s := range sources {
		f.saved[s.IP] = s
	}
	return nil
}

// A new DMARC report has its addresses looked up once; a duplicate, and an
// address already cached, are not looked up again.
func TestHandleEnrichesNewReports(t *testing.T) {
	log := zerolog.Nop()
	e := &fakeEnricher{}
	src := &fakeSources{saved: map[string]enrich.Source{}}
	p := New(&fakeStore{}, nil, &log, WithEnricher(e, src, 24*time.Hour))

	for range 2 {
		if got := p.Handle(context.Background(), message(goodReport)); got != intake.OutcomeStored {
			t.Fatalf("outcome = %v", got)
		}
	}
	if len(e.asked) != 1 || len(e.asked[0]) != 1 || e.asked[0][0] != "192.0.2.1" {
		t.Fatalf("lookups = %v, want one for 192.0.2.1", e.asked)
	}
	if src.saved["192.0.2.1"].Name != "looked up" {
		t.Fatalf("saved = %v", src.saved)
	}

	src.missing = []string{"203.0.113.5"}
	p.EnrichBacklog(context.Background(), 10)
	if _, ok := src.saved["203.0.113.5"]; !ok {
		t.Fatal("backlog address not looked up")
	}
}

type fakeArchive struct {
	err  error
	puts []archive.Report
}

func (a *fakeArchive) Put(_ context.Context, r archive.Report) (archive.Keys, error) {
	if a.err != nil {
		return archive.Keys{}, a.err
	}
	a.puts = append(a.puts, r)
	return archive.Keys{Raw: "raw/x", Parsed: "parsed/x"}, nil
}

// Each report goes to the archive, as received and as parsed, before it is
// stored; a report the archive refuses is not stored and its message is
// retried.
func TestHandleArchivesBeforeStoring(t *testing.T) {
	log := zerolog.Nop()

	a := &fakeArchive{}
	store := &fakeStore{}
	if got := New(store, nil, &log, WithArchive(a)).Handle(context.Background(), message(goodReport, tlsReport)); got != intake.OutcomeStored {
		t.Fatalf("outcome = %v", got)
	}
	if len(a.puts) != 2 {
		t.Fatalf("archived %d reports, want 2", len(a.puts))
	}
	dmarc, tls := a.puts[0], a.puts[1]
	if dmarc.Kind != archive.KindDMARC || dmarc.OrgName != "google.com" || dmarc.Domain != "example.com" || string(dmarc.Raw) != goodReport || dmarc.Parsed == nil {
		t.Errorf("DMARC archive entry: %+v", dmarc)
	}
	if tls.Kind != archive.KindTLSRPT || tls.Domain != "example.com" || tls.Begin.IsZero() {
		t.Errorf("TLS-RPT archive entry: %+v", tls)
	}

	refused := &fakeStore{}
	got := New(refused, nil, &log, WithArchive(&fakeArchive{err: errors.New("bucket unreachable")})).Handle(context.Background(), message(goodReport))
	if got != intake.OutcomeRetry {
		t.Fatalf("outcome with the archive down = %v, want retry", got)
	}
	if len(refused.saved) != 0 {
		t.Fatal("a report the archive refused was stored")
	}
}
