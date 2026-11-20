package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
)

func identityReport(org, reportID, domain string) *parser.Feedback {
	return &parser.Feedback{
		ReportMetadata: parser.ReportMetadata{
			OrgName:   org,
			ReportID:  reportID,
			DateRange: parser.DateRange{Begin: 1700000000, End: 1700086400},
		},
		PolicyPublished: parser.PolicyPublished{Domain: domain, P: "none"},
		Records: []parser.Record{{
			Row: parser.Row{SourceIP: "192.0.2.1", Count: 3, PolicyEvaluated: parser.PolicyEvaluated{
				Disposition: "none", DKIM: "pass", SPF: "pass",
			}},
			Identifiers: parser.Identifiers{HeaderFrom: domain},
		}},
	}
}

// A report ID is only unique within its reporter and policy domain: the same
// ID from another reporter, or for another domain, is a different report.
func TestSaveReportIdentity(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Storage) {
		ctx := context.Background()
		cases := []struct {
			name      string
			report    *parser.Feedback
			wantSaved bool
		}{
			{"first report", identityReport("google.com", "42", "example.com"), true},
			{"same reporter, ID and domain", identityReport("google.com", "42", "example.com"), false},
			{"same ID from another reporter", identityReport("Outlook.com", "42", "example.com"), true},
			{"same ID for another domain", identityReport("google.com", "42", "example.org"), true},
		}
		for _, tc := range cases {
			saved, err := s.SaveReport(ctx, tc.report)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if saved != tc.wantSaved {
				t.Errorf("%s: saved = %v, want %v", tc.name, saved, tc.wantSaved)
			}
		}

		stats, err := s.GetStatistics(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if stats.TotalReports != 3 || stats.TotalMessages != 9 {
			t.Errorf("got %d reports, %d messages; want 3 reports, 9 messages (the duplicate adds no records)",
				stats.TotalReports, stats.TotalMessages)
		}
	})
}

// A database written before migrations existed keeps its reports and records
// and gains the per-reporter identity.
func TestMigrateLegacySQLite(t *testing.T) {
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
		t.Fatalf("create legacy schema: %v", err)
	}
	if _, err := legacy.ExecContext(ctx, `
		INSERT INTO reports (report_id, org_name, domain, date_begin, date_end, created_at, total_messages, compliant_messages, raw_report)
		VALUES ('42', 'google.com', 'example.com', 1, 2, 3, 7, 7, '{}');
		INSERT INTO records (report_id, source_ip, count, disposition, dkim_result, spf_result)
		VALUES (1, '192.0.2.1', 7, 'none', 'pass', 'pass');`); err != nil {
		t.Fatalf("seed legacy rows: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	defer func() { _ = s.Close() }()

	stats, err := s.GetStatistics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalReports != 1 || stats.TotalMessages != 7 || stats.UniqueSourceIPs != 1 {
		t.Fatalf("legacy data after migration: %+v", stats)
	}

	saved, err := s.SaveReport(ctx, identityReport("Outlook.com", "42", "example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !saved {
		t.Error("the same report ID from another reporter was dropped after migration")
	}

	var applied int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != len(migrations) {
		t.Errorf("schema_migrations has %d rows, want %d", applied, len(migrations))
	}
}

// Opening an up-to-date database applies nothing and keeps the data.
func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db.sqlite")
	for i := range 2 {
		s, err := Open(ctx, Options{Path: path})
		if err != nil {
			t.Fatalf("open #%d: %v", i+1, err)
		}
		if i == 0 {
			if _, err := s.SaveReport(ctx, identityReport("google.com", "1", "example.com")); err != nil {
				t.Fatal(err)
			}
		}
		stats, err := s.GetStatistics(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if stats.TotalReports != 1 {
			t.Fatalf("open #%d: %d reports, want 1", i+1, stats.TotalReports)
		}
		_ = s.Close()
	}
}

func TestRebind(t *testing.T) {
	pg := &Storage{dialect: dialectPostgres}
	lite := &Storage{dialect: dialectSQLite}
	const q = "SELECT a FROM t WHERE b = ? AND c IN (?, ?)"
	if got, want := pg.rebind(q), "SELECT a FROM t WHERE b = $1 AND c IN ($2, $3)"; got != want {
		t.Errorf("postgres rebind = %q, want %q", got, want)
	}
	if got := lite.rebind(q); got != q {
		t.Errorf("sqlite rebind changed the query: %q", got)
	}
}

func TestOpenRejectsNonPostgresURL(t *testing.T) {
	_, err := Open(context.Background(), Options{URL: "mysql://localhost/db"})
	if err == nil {
		t.Fatal("want an error for a non-PostgreSQL DATABASE_URL")
	}
}

// Temporary data stays in memory, so the process writes nothing outside the
// database directory.
func TestSQLiteTempStoreIsMemory(t *testing.T) {
	s, err := Open(context.Background(), Options{Path: filepath.Join(t.TempDir(), "db.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	var mode int
	if err := s.db.QueryRowContext(context.Background(), "PRAGMA temp_store").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != 2 {
		t.Fatalf("temp_store = %d, want 2 (MEMORY)", mode)
	}
}
