package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Options selects and tunes the database. A URL selects PostgreSQL; without
// one, Path names the SQLite file.
type Options struct {
	// URL is a PostgreSQL connection URL (postgres:// or postgresql://).
	URL string
	// Path is the SQLite database file, or ":memory:".
	Path string

	// Pool settings, applied to PostgreSQL only: SQLite always runs on one
	// connection, its single writer.
	MaxOpenConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// Pool defaults for PostgreSQL. One fetch cycle writes at a time; the rest
// serves dashboard, MCP and metrics reads.
const (
	DefaultMaxOpenConns    = 4
	DefaultConnMaxLifetime = 30 * time.Minute
	DefaultConnMaxIdleTime = 5 * time.Minute
)

// ErrInvalidDatabaseURL is returned for a DATABASE_URL that is not a
// PostgreSQL URL.
var ErrInvalidDatabaseURL = errors.New("DATABASE_URL must be a postgres:// or postgresql:// URL")

// dialect is the SQL flavour of the open database. Queries are written once
// with ? placeholders and rebound for PostgreSQL.
type dialect int

const (
	dialectSQLite dialect = iota
	dialectPostgres
)

func (d dialect) String() string {
	if d == dialectPostgres {
		return "postgres"
	}
	return "sqlite"
}

// Storage is the report store.
type Storage struct {
	db      *sql.DB
	dialect dialect
}

// Open connects to the database the options name and applies every pending
// schema migration.
func Open(ctx context.Context, opts Options) (*Storage, error) {
	var (
		s   *Storage
		err error
	)
	if opts.URL != "" {
		s, err = openPostgres(opts)
	} else {
		s, err = openSQLite(opts.Path)
	}
	if err != nil {
		return nil, err
	}

	if err := s.db.PingContext(ctx); err != nil {
		_ = s.db.Close()
		return nil, fmt.Errorf("connect to %s database: %w", s.dialect, err)
	}
	if err := s.migrate(ctx); err != nil {
		_ = s.db.Close()
		return nil, fmt.Errorf("migrate %s schema: %w", s.dialect, err)
	}
	return s, nil
}

func openSQLite(path string) (*Storage, error) {
	if strings.Contains(path, "?") {
		return nil, fmt.Errorf("sqlite database path %q must not contain '?'", path)
	}
	db, err := sql.Open(sqliteDriver, sqliteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite database %s: %w", path, err)
	}
	// One connection: SQLite has a single writer, and an in-memory
	// database exists only on the connection that created it.
	db.SetMaxOpenConns(1)
	return &Storage{db: db, dialect: dialectSQLite}, nil
}

func openPostgres(opts Options) (*Storage, error) {
	if !strings.HasPrefix(opts.URL, "postgres://") && !strings.HasPrefix(opts.URL, "postgresql://") {
		return nil, ErrInvalidDatabaseURL
	}
	db, err := sql.Open(postgresDriver, opts.URL)
	if err != nil {
		return nil, fmt.Errorf("open postgres database: %w", err)
	}
	db.SetMaxOpenConns(positiveOr(opts.MaxOpenConns, DefaultMaxOpenConns))
	db.SetMaxIdleConns(positiveOr(opts.MaxOpenConns, DefaultMaxOpenConns))
	db.SetConnMaxLifetime(positiveDurationOr(opts.ConnMaxLifetime, DefaultConnMaxLifetime))
	db.SetConnMaxIdleTime(positiveDurationOr(opts.ConnMaxIdleTime, DefaultConnMaxIdleTime))
	return &Storage{db: db, dialect: dialectPostgres}, nil
}

func positiveOr(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func positiveDurationOr(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}

// Close closes the database.
func (s *Storage) Close() error {
	return s.db.Close()
}

// Dialect names the database backend: "sqlite" or "postgres".
func (s *Storage) Dialect() string {
	return s.dialect.String()
}

// rebind rewrites ? placeholders as $1, $2, ... for PostgreSQL. Queries in
// this package never carry a literal '?' inside a string.
func (s *Storage) rebind(query string) string {
	if s.dialect != dialectPostgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] != '?' {
			b.WriteByte(query[i])
			continue
		}
		n++
		b.WriteByte('$')
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}

func (s *Storage) exec(ctx context.Context, q execer, query string, args ...any) (sql.Result, error) {
	return q.ExecContext(ctx, s.rebind(query), args...)
}

func (s *Storage) query(ctx context.Context, q execer, query string, args ...any) (*sql.Rows, error) {
	return q.QueryContext(ctx, s.rebind(query), args...)
}

func (s *Storage) queryRow(ctx context.Context, q execer, query string, args ...any) *sql.Row {
	return q.QueryRowContext(ctx, s.rebind(query), args...)
}

// execer is the part of *sql.DB and *sql.Tx the queries use.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}
