package mcp

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
	"github.com/dmarcguardhq/parse-dmarc/internal/storage"
)

// TLSStatisticsOutput wraps the TLS-RPT statistics response.
type TLSStatisticsOutput struct {
	Statistics *storage.TLSStatistics `json:"statistics"`
}

// TLSReportsOutput wraps the TLS-RPT reports list response.
type TLSReportsOutput struct {
	Reports []storage.TLSReportSummary `json:"reports"`
	Count   int                        `json:"count"`
}

// TLSReportOutput wraps a single TLS-RPT report.
type TLSReportOutput struct {
	Report *parser.TLSReport `json:"report"`
}

// ParseTLSReportInput is used for parsing a raw TLS-RPT report.
type ParseTLSReportInput struct {
	ReportData string `json:"report_data" jsonschema:"base64 encoded TLS-RPT report data (gzip or JSON)"`
}

func (s *Server) registerTLSTools() {
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "get_tlsrpt_statistics",
		Description: "Get SMTP TLS Reporting (RFC 8460) statistics: successful and failed TLS sessions overall and per policy domain, and failed sessions by result type (certificate-expired, starttls-not-supported, sts-policy-fetch-error, ...).",
	}, s.getTLSStatistics)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "get_tlsrpt_reports",
		Description: "List TLS-RPT reports with pagination, newest first: reporter, policy domains, date range and session counts.",
	}, s.getTLSReports)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "get_tlsrpt_report_by_id",
		Description: "Get a TLS-RPT report by its database ID, with every policy (STS, TLSA or none) and the failure details: result type, sending MTA, receiving MX and IP, failed session count.",
	}, s.getTLSReportByID)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "parse_tlsrpt_report",
		Description: "Parse a raw TLS-RPT report. Accepts gzip or plain JSON, base64 encoded in report_data. Returns the parsed report.",
	}, s.parseTLSReport)
}

func (s *Server) getTLSStatistics(ctx context.Context, req *mcp.CallToolRequest, input EmptyInput) (*mcp.CallToolResult, TLSStatisticsOutput, error) {
	st, err := s.store.GetTLSStatistics(ctx)
	if err != nil {
		return nil, TLSStatisticsOutput{}, fmt.Errorf("get TLS-RPT statistics: %w", err)
	}
	return nil, TLSStatisticsOutput{Statistics: st}, nil
}

func (s *Server) getTLSReports(ctx context.Context, req *mcp.CallToolRequest, input PaginationInput) (*mcp.CallToolResult, TLSReportsOutput, error) {
	limit := input.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > storage.MaxReportLimit {
		limit = storage.MaxReportLimit
	}
	offset := max(input.Offset, 0)

	reports, err := s.store.GetTLSReports(ctx, limit, offset)
	if err != nil {
		return nil, TLSReportsOutput{}, fmt.Errorf("get TLS-RPT reports: %w", err)
	}
	if reports == nil {
		reports = []storage.TLSReportSummary{}
	}
	return nil, TLSReportsOutput{Reports: reports, Count: len(reports)}, nil
}

func (s *Server) getTLSReportByID(ctx context.Context, req *mcp.CallToolRequest, input ReportIDInput) (*mcp.CallToolResult, TLSReportOutput, error) {
	if input.ID <= 0 {
		return nil, TLSReportOutput{}, fmt.Errorf("invalid report ID: must be a positive integer")
	}
	r, err := s.store.GetTLSReportByID(ctx, input.ID)
	if err != nil {
		return nil, TLSReportOutput{}, fmt.Errorf("get TLS-RPT report: %w", err)
	}
	r.NormalizeForJSON()
	return nil, TLSReportOutput{Report: r}, nil
}

func (s *Server) parseTLSReport(ctx context.Context, req *mcp.CallToolRequest, input ParseTLSReportInput) (*mcp.CallToolResult, TLSReportOutput, error) {
	if input.ReportData == "" {
		return nil, TLSReportOutput{}, fmt.Errorf("report_data is required")
	}
	data, err := base64.StdEncoding.DecodeString(input.ReportData)
	if err != nil {
		return nil, TLSReportOutput{}, fmt.Errorf("decode base64 data: %w", err)
	}
	const maxReportSize = 10 * 1024 * 1024
	if len(data) > maxReportSize {
		return nil, TLSReportOutput{}, fmt.Errorf("report data exceeds maximum size of %d bytes", maxReportSize)
	}
	r, err := parser.ParseTLSReport(data)
	if err != nil {
		return nil, TLSReportOutput{}, fmt.Errorf("parse TLS-RPT report: %w", err)
	}
	r.NormalizeForJSON()
	return nil, TLSReportOutput{Report: r}, nil
}
