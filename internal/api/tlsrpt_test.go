package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
	"github.com/dmarcguardhq/parse-dmarc/internal/storage"
)

func TestTLSRoutes(t *testing.T) {
	store, err := storage.Open(context.Background(), storage.Options{Path: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	begin := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	if _, err := store.SaveTLSReport(context.Background(), &parser.TLSReport{
		OrganizationName: "Google Inc.", ReportID: "r1",
		DateRange: parser.TLSDateRange{Start: begin, End: begin.Add(24 * time.Hour)},
		Policies: []parser.TLSPolicyResult{{PolicyType: "sts", PolicyDomain: "example.com", SuccessfulSessions: 9, FailedSessions: 1,
			FailureDetails: []parser.TLSFailureDetail{{ResultType: "certificate-expired", FailedSessions: 1}}}},
	}); err != nil {
		t.Fatal(err)
	}

	log := zerolog.Nop()
	srv := NewServer(store, "127.0.0.1", 0, nil, &log, VersionInfo{})

	rec := httptest.NewRecorder()
	srv.handleTLSReports(rec, httptest.NewRequest("GET", "/api/tlsrpt/reports", nil))
	var list []storage.TLSReportSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0].Status != "fail" {
		t.Fatalf("reports: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	srv.handleTLSReportDetail(rec, httptest.NewRequest("GET", fmt.Sprintf("/api/tlsrpt/reports/%d", list[0].ID), nil))
	var detail parser.TLSReport
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil || len(detail.Policies) != 1 {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	srv.handleTLSReportDetail(rec, httptest.NewRequest("GET", "/api/tlsrpt/reports/999", nil))
	if rec.Code != 404 {
		t.Fatalf("missing report: status %d, want 404", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.handleTLSStatistics(rec, httptest.NewRequest("GET", "/api/tlsrpt/statistics", nil))
	var st storage.TLSStatistics
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || st.FailedSessions != 1 || len(st.FailureTypes) != 1 {
		t.Fatalf("statistics: %d %s", rec.Code, rec.Body.String())
	}
}
