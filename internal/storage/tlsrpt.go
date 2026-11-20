package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/goccy/go-json"

	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
)

// TLSReportSummary is one TLS-RPT report in a list.
type TLSReportSummary struct {
	ID                 int64    `json:"id"`
	ReportID           string   `json:"report_id"`
	OrgName            string   `json:"org_name"`
	PolicyDomains      []string `json:"policy_domains"`
	DateBegin          int64    `json:"date_begin"`
	DateEnd            int64    `json:"date_end"`
	SuccessfulSessions int64    `json:"successful_sessions"`
	FailedSessions     int64    `json:"failed_sessions"`
	// SuccessRate is null when the report counts no sessions.
	SuccessRate *float64 `json:"success_rate"`
	// Status is the backend's verdict for display: empty, pass or fail. Any
	// failed session is a fail: TLS-RPT reports what a sender could not
	// deliver securely, not a rate to tolerate.
	Status string `json:"status"`
}

func (r *TLSReportSummary) classify() {
	total := r.SuccessfulSessions + r.FailedSessions
	if total == 0 {
		r.Status = "empty"
		return
	}
	rate := float64(r.SuccessfulSessions) / float64(total) * 100
	r.SuccessRate = &rate
	if r.FailedSessions > 0 {
		r.Status = "fail"
		return
	}
	r.Status = "pass"
}

// TLSStatistics summarises every stored TLS-RPT report.
type TLSStatistics struct {
	TotalReports       int                   `json:"total_reports"`
	SuccessfulSessions int64                 `json:"successful_sessions"`
	FailedSessions     int64                 `json:"failed_sessions"`
	SuccessRate        *float64              `json:"success_rate"`
	HasData            bool                  `json:"has_data"`
	Domains            []TLSDomainStats      `json:"domains"`
	FailureTypes       []TLSFailureTypeStats `json:"failure_types"`
}

// TLSDomainStats is the session totals of one policy domain.
type TLSDomainStats struct {
	PolicyDomain       string `json:"policy_domain"`
	SuccessfulSessions int64  `json:"successful_sessions"`
	FailedSessions     int64  `json:"failed_sessions"`
	// LastReport is the end of the newest report covering the domain.
	LastReport int64 `json:"last_report"`
}

// TLSFailureTypeStats is the failed sessions of one result type.
type TLSFailureTypeStats struct {
	ResultType     string `json:"result_type"`
	FailedSessions int64  `json:"failed_sessions"`
}

// SaveTLSReport stores a TLS-RPT report with its policies and failure
// details. It returns false, and stores nothing, when the reporter's report
// ID is already stored.
func (s *Storage) SaveTLSReport(ctx context.Context, r *parser.TLSReport) (bool, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return false, fmt.Errorf("marshal TLS report: %w", err)
	}
	successful, failed := r.Sessions()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var reportID int64
	err = s.queryRow(ctx, tx, `
		INSERT INTO tlsrpt_reports (
			org_name, report_id, contact_info, date_begin, date_end, created_at,
			successful_sessions, failed_sessions, raw_report
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (org_name, report_id) DO NOTHING
		RETURNING id`,
		r.OrganizationName, r.ReportID, r.ContactInfo,
		r.DateRange.Start.Unix(), r.DateRange.End.Unix(), time.Now().Unix(),
		successful, failed, raw,
	).Scan(&reportID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("insert TLS report: %w", err)
	}

	for _, p := range r.Policies {
		policyStrings, err := json.Marshal(p.PolicyStrings)
		if err != nil {
			return false, fmt.Errorf("marshal policy strings: %w", err)
		}
		mxHosts, err := json.Marshal(p.MXHosts)
		if err != nil {
			return false, fmt.Errorf("marshal MX hosts: %w", err)
		}

		var policyID int64
		if err := s.queryRow(ctx, tx, `
			INSERT INTO tlsrpt_policies (
				report_id, policy_type, policy_domain, policy_strings, mx_hosts,
				successful_sessions, failed_sessions
			) VALUES (?, ?, ?, ?, ?, ?, ?)
			RETURNING id`,
			reportID, p.PolicyType, p.PolicyDomain, policyStrings, mxHosts,
			p.SuccessfulSessions, p.FailedSessions,
		).Scan(&policyID); err != nil {
			return false, fmt.Errorf("insert TLS policy %s: %w", p.PolicyDomain, err)
		}

		for _, f := range p.FailureDetails {
			if _, err := s.exec(ctx, tx, `
				INSERT INTO tlsrpt_failures (
					policy_id, result_type, sending_mta_ip, receiving_mx_hostname,
					receiving_mx_helo, receiving_ip, failed_sessions,
					additional_information, failure_reason_code
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				policyID, f.ResultType, f.SendingMTAIP, f.ReceivingMXHostname,
				f.ReceivingMXHelo, f.ReceivingIP, f.FailedSessions,
				f.AdditionalInformation, f.FailureReasonCode,
			); err != nil {
				return false, fmt.Errorf("insert TLS failure detail: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit transaction: %w", err)
	}
	return true, nil
}

// GetTLSReports lists TLS-RPT reports, newest first.
func (s *Storage) GetTLSReports(ctx context.Context, limit, offset int) ([]TLSReportSummary, error) {
	rows, err := s.query(ctx, s.db, `
		SELECT id, report_id, org_name, date_begin, date_end,
		       successful_sessions, failed_sessions
		FROM tlsrpt_reports
		ORDER BY date_begin DESC, id DESC
		LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query TLS reports: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []TLSReportSummary
	index := map[int64]int{}
	for rows.Next() {
		var r TLSReportSummary
		if err := rows.Scan(&r.ID, &r.ReportID, &r.OrgName, &r.DateBegin, &r.DateEnd,
			&r.SuccessfulSessions, &r.FailedSessions); err != nil {
			return nil, fmt.Errorf("scan TLS report row: %w", err)
		}
		r.PolicyDomains = []string{}
		r.classify()
		index[r.ID] = len(out)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query TLS reports: %w", err)
	}
	if len(out) == 0 {
		return out, nil
	}

	ids := make([]any, 0, len(out))
	for _, r := range out {
		ids = append(ids, r.ID)
	}
	prow, err := s.query(ctx, s.db, `
		SELECT DISTINCT report_id, policy_domain FROM tlsrpt_policies
		WHERE report_id IN (?`+strings.Repeat(", ?", len(ids)-1)+`)
		ORDER BY report_id, policy_domain`, ids...)
	if err != nil {
		return nil, fmt.Errorf("query TLS report domains: %w", err)
	}
	defer func() { _ = prow.Close() }()
	for prow.Next() {
		var id int64
		var domain string
		if err := prow.Scan(&id, &domain); err != nil {
			return nil, fmt.Errorf("scan TLS report domain: %w", err)
		}
		if i, ok := index[id]; ok {
			out[i].PolicyDomains = append(out[i].PolicyDomains, domain)
		}
	}
	return out, prow.Err()
}

// GetTLSReportByID returns one TLS-RPT report as parsed.
func (s *Storage) GetTLSReportByID(ctx context.Context, id int64) (*parser.TLSReport, error) {
	var raw string
	if err := s.queryRow(ctx, s.db, "SELECT raw_report FROM tlsrpt_reports WHERE id = ?", id).Scan(&raw); err != nil {
		return nil, fmt.Errorf("query TLS report %d: %w", id, err)
	}
	var r parser.TLSReport
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("unmarshal TLS report %d: %w", id, err)
	}
	return &r, nil
}

// GetTLSStatistics summarises every stored TLS-RPT report: totals, each
// policy domain, and the failed sessions by result type.
func (s *Storage) GetTLSStatistics(ctx context.Context) (*TLSStatistics, error) {
	st := &TLSStatistics{Domains: []TLSDomainStats{}, FailureTypes: []TLSFailureTypeStats{}}
	if err := s.queryRow(ctx, s.db, `
		SELECT COUNT(*), COALESCE(SUM(successful_sessions), 0), COALESCE(SUM(failed_sessions), 0)
		FROM tlsrpt_reports`).Scan(&st.TotalReports, &st.SuccessfulSessions, &st.FailedSessions); err != nil {
		return nil, fmt.Errorf("query TLS totals: %w", err)
	}
	st.HasData = st.TotalReports > 0
	if total := st.SuccessfulSessions + st.FailedSessions; total > 0 {
		rate := float64(st.SuccessfulSessions) / float64(total) * 100
		st.SuccessRate = &rate
	}

	rows, err := s.query(ctx, s.db, `
		SELECT p.policy_domain,
		       COALESCE(SUM(p.successful_sessions), 0),
		       COALESCE(SUM(p.failed_sessions), 0),
		       MAX(r.date_end)
		FROM tlsrpt_policies p JOIN tlsrpt_reports r ON r.id = p.report_id
		GROUP BY p.policy_domain
		ORDER BY p.policy_domain`)
	if err != nil {
		return nil, fmt.Errorf("query TLS domains: %w", err)
	}
	for rows.Next() {
		var d TLSDomainStats
		if err := rows.Scan(&d.PolicyDomain, &d.SuccessfulSessions, &d.FailedSessions, &d.LastReport); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan TLS domain: %w", err)
		}
		st.Domains = append(st.Domains, d)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("query TLS domains: %w", err)
	}

	rows, err = s.query(ctx, s.db, `
		SELECT result_type, COALESCE(SUM(failed_sessions), 0)
		FROM tlsrpt_failures
		GROUP BY result_type
		ORDER BY 2 DESC, result_type`)
	if err != nil {
		return nil, fmt.Errorf("query TLS failure types: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var f TLSFailureTypeStats
		if err := rows.Scan(&f.ResultType, &f.FailedSessions); err != nil {
			return nil, fmt.Errorf("scan TLS failure type: %w", err)
		}
		st.FailureTypes = append(st.FailureTypes, f)
	}
	return st, rows.Err()
}
