package storage

import (
	"context"
	"fmt"
	"testing"
)

func TestProcessedMessages(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Storage) {
		ctx := context.Background()
		const src = "imap://dmarc@mail.example.com:993/INBOX"

		keys := make([]string, 0, ledgerChunk+10)
		for i := range ledgerChunk + 10 {
			keys = append(keys, fmt.Sprintf("1:%d", i))
		}
		for _, k := range []string{"1:3", "1:" + fmt.Sprint(ledgerChunk+5)} {
			if err := s.MarkProcessed(ctx, src, k, "stored", "<m@example.com>"); err != nil {
				t.Fatal(err)
			}
		}
		// Recording twice updates the row.
		if err := s.MarkProcessed(ctx, src, "1:3", "invalid", ""); err != nil {
			t.Fatal(err)
		}
		if err := s.MarkProcessed(ctx, "jmap://other/box", "1:4", "stored", ""); err != nil {
			t.Fatal(err)
		}

		done, err := s.ProcessedKeys(ctx, src, keys)
		if err != nil {
			t.Fatal(err)
		}
		if len(done) != 2 || !done["1:3"] || !done["1:"+fmt.Sprint(ledgerChunk+5)] {
			t.Fatalf("processed = %v, want 1:3 and 1:%d only (another source's key does not count)", done, ledgerChunk+5)
		}
	})
}
