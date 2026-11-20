//go:build !cgo

package storage

import (
	_ "modernc.org/sqlite"
)

const sqliteDriver = "sqlite"

// sqliteDSN enables foreign keys, waits up to 5s on a locked database and
// uses the write-ahead log so dashboard reads do not block a fetch.
func sqliteDSN(path string) string {
	return path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
}
