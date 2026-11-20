package storage

import (
	"context"
	"fmt"
	"time"
)

// Pruned counts what one prune deleted.
type Pruned struct {
	DMARCReports  int64
	TLSRPTReports int64
	Sources       int64
}

// PruneBefore deletes the reports whose period ended before cutoff, with
// their records, policies and failure details, and the sources no record
// refers to any more. The processed-message ledger is kept: a read-only
// intake would otherwise read the pruned reports in again.
func (s *Storage) PruneBefore(ctx context.Context, cutoff time.Time) (Pruned, error) {
	var p Pruned
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return p, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := s.exec(ctx, tx, "DELETE FROM reports WHERE date_end < ?", cutoff.Unix())
	if err != nil {
		return p, fmt.Errorf("prune DMARC reports: %w", err)
	}
	p.DMARCReports, _ = res.RowsAffected()

	res, err = s.exec(ctx, tx, "DELETE FROM tlsrpt_reports WHERE date_end < ?", cutoff.Unix())
	if err != nil {
		return p, fmt.Errorf("prune TLS-RPT reports: %w", err)
	}
	p.TLSRPTReports, _ = res.RowsAffected()

	if p.DMARCReports > 0 {
		res, err = s.exec(ctx, tx, `
			DELETE FROM sources
			WHERE NOT EXISTS (SELECT 1 FROM records r WHERE r.source_ip = sources.ip)`)
		if err != nil {
			return p, fmt.Errorf("prune sources: %w", err)
		}
		p.Sources, _ = res.RowsAffected()
	}

	if err := tx.Commit(); err != nil {
		return p, fmt.Errorf("commit prune: %w", err)
	}
	return p, nil
}
