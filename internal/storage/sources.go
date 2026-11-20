package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dmarcguardhq/parse-dmarc/internal/enrich"
)

// SourcesToLookUp returns which of ips have no source row, or one looked up
// before staleBefore.
func (s *Storage) SourcesToLookUp(ctx context.Context, ips []string, staleBefore time.Time) ([]string, error) {
	fresh := make(map[string]bool, len(ips))
	for start := 0; start < len(ips); start += ledgerChunk {
		chunk := ips[start:min(start+ledgerChunk, len(ips))]
		args := make([]any, 0, len(chunk)+1)
		args = append(args, staleBefore.Unix())
		for _, ip := range chunk {
			args = append(args, ip)
		}
		rows, err := s.query(ctx, s.db,
			"SELECT ip FROM sources WHERE looked_up_at >= ? AND ip IN (?"+strings.Repeat(", ?", len(chunk)-1)+")", args...)
		if err != nil {
			return nil, fmt.Errorf("query sources: %w", err)
		}
		for rows.Next() {
			var ip string
			if err := rows.Scan(&ip); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("scan source: %w", err)
			}
			fresh[ip] = true
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("query sources: %w", err)
		}
	}

	var out []string
	seen := map[string]bool{}
	for _, ip := range ips {
		if ip != "" && !fresh[ip] && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out, nil
}

// SourcesMissing returns up to limit record addresses that have no source
// row at all, for filling in what was stored before enrichment ran.
func (s *Storage) SourcesMissing(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.query(ctx, s.db, `
		SELECT DISTINCT r.source_ip FROM records r
		LEFT JOIN sources src ON src.ip = r.source_ip
		WHERE src.ip IS NULL AND r.source_ip <> ''
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query addresses without a source: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("scan address: %w", err)
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// SaveSources stores what was found out about each address.
func (s *Storage) SaveSources(ctx context.Context, sources []enrich.Source) error {
	if len(sources) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	for _, src := range sources {
		if _, err := s.exec(ctx, tx, `
			INSERT INTO sources (ip, reverse_dns, reverse_dns_verified, base_domain, name, type,
				country, asn, as_name, as_domain, looked_up_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (ip) DO UPDATE SET
				reverse_dns = excluded.reverse_dns,
				reverse_dns_verified = excluded.reverse_dns_verified,
				base_domain = excluded.base_domain,
				name = excluded.name,
				type = excluded.type,
				country = excluded.country,
				asn = excluded.asn,
				as_name = excluded.as_name,
				as_domain = excluded.as_domain,
				looked_up_at = excluded.looked_up_at`,
			src.IP, src.ReverseDNS, src.ReverseDNSVerified, src.BaseDomain, src.Name, src.Type,
			src.Country, int64(src.ASN), src.ASName, src.ASDomain, now,
		); err != nil {
			return fmt.Errorf("save source %s: %w", src.IP, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sources: %w", err)
	}
	return nil
}
