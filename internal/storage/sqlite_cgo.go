//go:build cgo

package storage

import (
	_ "github.com/mattn/go-sqlite3"
)

const sqliteDriver = "sqlite3"

// sqliteDSN enables foreign keys, waits up to 5s on a locked database and
// uses the write-ahead log so dashboard reads do not block a fetch.
func sqliteDSN(path string) string {
	return path + "?_foreign_keys=1&_busy_timeout=5000&_journal_mode=WAL"
}
