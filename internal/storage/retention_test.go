package storage

import (
	"context"
	"testing"
	"time"

	"github.com/dmarcguardhq/parse-dmarc/internal/enrich"
	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
)

func TestPruneBefore(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Storage) {
		ctx := context.Background()
		old := identityReport("google.com", "old", "example.com")
		old.ReportMetadata.DateRange = parser.DateRange{Begin: 1600000000, End: 1600086400}
		old.Records[0].Row.SourceIP = "198.51.100.1"
		recent := identityReport("google.com", "recent", "example.com")
		for _, fb := range []*parser.Feedback{old, recent} {
			if _, err := s.SaveReport(ctx, fb); err != nil {
				t.Fatal(err)
			}
		}
		oldTLS := tlsReport("google.com", "old", 1, 0)
		oldTLS.DateRange.Start = time.Unix(1600000000, 0)
		oldTLS.DateRange.End = time.Unix(1600086400, 0)
		if _, err := s.SaveTLSReport(ctx, oldTLS); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SaveTLSReport(ctx, tlsReport("google.com", "recent", 1, 0)); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveSources(ctx, []enrich.Source{{IP: "198.51.100.1"}, {IP: "192.0.2.1"}}); err != nil {
			t.Fatal(err)
		}

		p, err := s.PruneBefore(ctx, time.Unix(1650000000, 0))
		if err != nil {
			t.Fatal(err)
		}
		if p.DMARCReports != 1 || p.TLSRPTReports != 1 || p.Sources != 1 {
			t.Fatalf("pruned %+v, want one of each", p)
		}

		st, err := s.GetStatistics(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.TotalReports != 1 || st.UniqueSourceIPs != 1 {
			t.Errorf("after prune: %+v", st)
		}
		var records int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM records").Scan(&records); err != nil || records != 1 {
			t.Errorf("records after prune = %d, %v; want the recent report's one record", records, err)
		}
		var failures int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM tlsrpt_policies").Scan(&failures); err != nil || failures != 1 {
			t.Errorf("TLS policies after prune = %d, %v; want 1", failures, err)
		}
	})
}
