package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/dmarcguardhq/parse-dmarc/internal/storage"
)

// handleTLSStatistics returns the TLS-RPT session statistics.
func (s *Server) handleTLSStatistics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st, err := s.storage.GetTLSStatistics(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, st)
}

// handleTLSReports returns a page of TLS-RPT reports.
func (s *Server) handleTLSReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit, offset := 50, 0
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = min(v, storage.MaxReportLimit)
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v >= 0 {
		offset = v
	}
	reports, err := s.storage.GetTLSReports(r.Context(), limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if reports == nil {
		reports = []storage.TLSReportSummary{}
	}
	s.writeJSON(w, reports)
}

// handleTLSReportDetail returns one TLS-RPT report.
func (s *Server) handleTLSReportDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/api/tlsrpt/reports/"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid report ID", http.StatusBadRequest)
		return
	}
	report, err := s.storage.GetTLSReportByID(r.Context(), id)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	report.NormalizeForJSON()
	s.writeJSON(w, report)
}
