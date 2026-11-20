package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// testPostgresURLEnv names a PostgreSQL server the storage tests also run
// against, for example postgres://postgres:postgres@localhost:5432/postgres.
// Without it they run on SQLite only.
const testPostgresURLEnv = "PARSE_DMARC_TEST_POSTGRES_URL"

// forEachBackend runs fn against a fresh in-memory SQLite database and, when
// testPostgresURLEnv is set, against a fresh schema on that server.
func forEachBackend(t *testing.T, fn func(t *testing.T, s *Storage)) {
	t.Helper()

	t.Run("sqlite", func(t *testing.T) {
		s, err := Open(context.Background(), Options{Path: ":memory:"})
		if err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		fn(t, s)
	})

	base := os.Getenv(testPostgresURLEnv)
	if base == "" {
		return
	}
	t.Run("postgres", func(t *testing.T) {
		fn(t, openTestPostgres(t, base))
	})
}

// openTestPostgres opens the store in a schema of its own, dropped when the
// test ends, so tests share one server without sharing tables.
func openTestPostgres(t *testing.T, base string) *Storage {
	t.Helper()
	ctx := context.Background()

	admin, err := sql.Open(postgresDriver, base)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	schema := fmt.Sprintf("test_%s_%d", strings.ToLower(sanitizeIdent(t.Name())), time.Now().UnixNano())
	if len(schema) > 63 {
		schema = schema[len(schema)-63:]
		schema = "t" + schema[1:]
	}
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE") })

	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse %s: %v", testPostgresURLEnv, err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	s, err := Open(ctx, Options{URL: u.String()})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sanitizeIdent(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
