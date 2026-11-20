package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
)

// Records are classed when stored, and the class counts reach the
// statistics, the per-domain stats and the top sources.
func TestRecordClasses(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Storage) {
		ctx := context.Background()
		fb := identityReport("google.com", "c1", "example.com")
		fb.ReportMetadata.DateRange.End = 1700086400
		fb.Records = []parser.Record{
			{Row: parser.Row{SourceIP: "192.0.2.1", Count: 5, PolicyEvaluated: parser.PolicyEvaluated{DKIM: "pass", SPF: "fail"}}},
			{
				Row:         parser.Row{SourceIP: "198.51.100.7", Count: 3, PolicyEvaluated: parser.PolicyEvaluated{DKIM: "fail", SPF: "fail"}},
				AuthResults: parser.AuthResults{SPF: []parser.SPFResult{{Domain: "bounces.esp.example", Result: "pass"}}},
			},
			{
				Row: parser.Row{SourceIP: "203.0.113.9", Count: 2, PolicyEvaluated: parser.PolicyEvaluated{DKIM: "fail", SPF: "fail",
					Reason: []parser.Reason{{Type: "mailing_list"}}}},
			},
		}
		if _, err := s.SaveReport(ctx, fb); err != nil {
			t.Fatal(err)
		}

		st, err := s.GetStatistics(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.UnalignedMessages != 3 || st.UnauthenticatedMessages != 2 {
			t.Errorf("statistics: unaligned %d, unauthenticated %d; want 3 and 2", st.UnalignedMessages, st.UnauthenticatedMessages)
		}

		ds, err := s.GetDomainStats(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(ds) != 1 || ds[0].UnalignedMessages != 3 || ds[0].LastReport != 1700086400 ||
			ds[0].LastUnaligned != 1700086400 || ds[0].LastUnauthenticated != 1700086400 {
			t.Errorf("domain stats: %+v", ds)
		}

		top, err := s.GetTopSourceIPs(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		byIP := map[string]TopSourceIP{}
		for _, r := range top {
			byIP[r.SourceIP] = r
		}
		if byIP["198.51.100.7"].Unaligned != 3 || byIP["203.0.113.9"].Unauthenticated != 2 || byIP["192.0.2.1"].Pass != 5 {
			t.Errorf("top sources: %+v", top)
		}
	})
}

// Rows stored before the class column existed are classed by the migration
// from the results they carry.
func TestMigrationClassifiesExistingRecords(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	legacy, err := sql.Open(sqliteDriver, path)
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := loadMigrations(dialectSQLite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, migrations[0].sql); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, `
		INSERT INTO reports (report_id, org_name, domain, date_begin, date_end, created_at, total_messages, compliant_messages, raw_report)
		VALUES ('1', 'google.com', 'example.com', 1, 2, 3, 6, 1, '{}');
		INSERT INTO records (report_id, source_ip, count, dkim_result, spf_result, dkim_domains, spf_domains) VALUES
			(1, '192.0.2.1', 1, 'pass', 'fail', '[{"Domain":"example.com","Result":"pass"}]', '[]'),
			(1, '198.51.100.7', 2, 'fail', 'fail', '[{"Domain":"esp.example","Result":"pass"}]', 'null'),
			(1, '203.0.113.9', 3, 'fail', 'fail', 'null', '[{"Domain":"spoof.example","Result":"softfail"}]');`); err != nil {
		t.Fatal(err)
	}
	_ = legacy.Close()

	s, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	rows, err := s.db.QueryContext(ctx, "SELECT source_ip, auth_class FROM records ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	want := map[string]string{
		"192.0.2.1":    parser.ClassPass,
		"198.51.100.7": parser.ClassUnaligned,
		"203.0.113.9":  parser.ClassUnauthenticated,
	}
	for rows.Next() {
		var ip, class string
		if err := rows.Scan(&ip, &class); err != nil {
			t.Fatal(err)
		}
		if class != want[ip] {
			t.Errorf("%s: class %q, want %q", ip, class, want[ip])
		}
	}
}
