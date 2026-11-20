package storage

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ledgerChunk bounds the keys of one lookup, below SQLite's and
// PostgreSQL's limits on bound parameters.
const ledgerChunk = 500

// ProcessedKeys returns which of keys the source has already finished with.
func (s *Storage) ProcessedKeys(ctx context.Context, source string, keys []string) (map[string]bool, error) {
	done := make(map[string]bool, len(keys))
	for start := 0; start < len(keys); start += ledgerChunk {
		chunk := keys[start:min(start+ledgerChunk, len(keys))]
		args := make([]any, 0, len(chunk)+1)
		args = append(args, source)
		for _, k := range chunk {
			args = append(args, k)
		}
		rows, err := s.query(ctx, s.db,
			"SELECT message_key FROM processed_messages WHERE source = ? AND message_key IN (?"+
				strings.Repeat(", ?", len(chunk)-1)+")", args...)
		if err != nil {
			return nil, fmt.Errorf("query processed messages of %s: %w", source, err)
		}
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("scan processed message: %w", err)
			}
			done[k] = true
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("query processed messages of %s: %w", source, err)
		}
	}
	return done, nil
}

// MarkProcessed records that the source has finished with a message, and
// how.
func (s *Storage) MarkProcessed(ctx context.Context, source, key, outcome, messageID string) error {
	_, err := s.exec(ctx, s.db, `
		INSERT INTO processed_messages (source, message_key, outcome, message_id, processed_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (source, message_key) DO UPDATE SET
			outcome = excluded.outcome,
			message_id = excluded.message_id,
			processed_at = excluded.processed_at`,
		source, key, outcome, messageID, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("record processed message %s of %s: %w", key, source, err)
	}
	return nil
}
