//go:build cgo

package storage

import (
	"database/sql"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// sqliteDriver is go-sqlite3 with temp_store set on every connection: the
// driver has no DSN key for it.
const sqliteDriver = "sqlite3_parse_dmarc"

// database/sql drivers register by name, once, at program start.
func init() {
	sql.Register(sqliteDriver, &sqlite3.SQLiteDriver{
		ConnectHook: func(c *sqlite3.SQLiteConn) error {
			_, err := c.Exec("PRAGMA temp_store = MEMORY", nil)
			return err
		},
	})
}

// sqliteDSN enables foreign keys, waits up to 5s on a locked database and
// uses the write-ahead log so dashboard reads do not block a fetch. Temporary
// tables and sort spills stay in memory (see init), so nothing is written
// outside the database's directory and the root filesystem can be read-only.
func sqliteDSN(path string) string {
	return path + "?_foreign_keys=1&_busy_timeout=5000&_journal_mode=WAL"
}
