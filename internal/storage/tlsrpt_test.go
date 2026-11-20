package storage

import (
	"context"
	"testing"
	"time"

	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
)

func tlsReport(org, id string, ok, failed int64) *parser.TLSReport {
	begin := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	r := &parser.TLSReport{
		OrganizationName: org,
		ReportID:         id,
		ContactInfo:      "tlsrpt@" + org,
		DateRange:        parser.TLSDateRange{Start: begin, End: begin.Add(24 * time.Hour)},
		Policies: []parser.TLSPolicyResult{{
			PolicyType:         parser.TLSPolicySTS,
			PolicyDomain:       "example.com",
			PolicyStrings:      []string{"version: STSv1", "mode: testing"},
			MXHosts:            []string{"mx.example.com"},
			SuccessfulSessions: ok,
			FailedSessions:     failed,
			FailureDetails:     []parser.TLSFailureDetail{},
		}},
	}
	if failed > 0 {
		r.Policies[0].FailureDetails = append(r.Policies[0].FailureDetails, parser.TLSFailureDetail{
			ResultType: "certificate-expired", ReceivingMXHostname: "mx.example.com", FailedSessions: failed,
		})
	}
	return r
}

func TestTLSReports(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Storage) {
		ctx := context.Background()

		for _, tc := range []struct {
			r    *parser.TLSReport
			want bool
		}{
			{tlsReport("google.com", "a", 90, 10), true},
			{tlsReport("google.com", "a", 90, 10), false},
			{tlsReport("microsoft.com", "a", 50, 0), true},
		} {
			saved, err := s.SaveTLSReport(ctx, tc.r)
			if err != nil {
				t.Fatal(err)
			}
			if saved != tc.want {
				t.Errorf("%s/%s: saved = %v, want %v", tc.r.OrganizationName, tc.r.ReportID, saved, tc.want)
			}
		}

		list, err := s.GetTLSReports(ctx, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 2 {
			t.Fatalf("got %d reports, want 2", len(list))
		}
		byOrg := map[string]TLSReportSummary{}
		for _, r := range list {
			byOrg[r.OrgName] = r
		}
		if g := byOrg["google.com"]; g.Status != "fail" || *g.SuccessRate != 90 || len(g.PolicyDomains) != 1 || g.PolicyDomains[0] != "example.com" {
			t.Errorf("google.com summary: %+v", g)
		}
		if m := byOrg["microsoft.com"]; m.Status != "pass" {
			t.Errorf("microsoft.com summary: %+v", m)
		}

		full, err := s.GetTLSReportByID(ctx, byOrg["google.com"].ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(full.Policies) != 1 || len(full.Policies[0].FailureDetails) != 1 || full.Policies[0].FailureDetails[0].ResultType != "certificate-expired" {
			t.Errorf("report detail: %+v", full)
		}

		st, err := s.GetTLSStatistics(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if st.TotalReports != 2 || st.SuccessfulSessions != 140 || st.FailedSessions != 10 || !st.HasData {
			t.Errorf("totals: %+v", st)
		}
		if len(st.Domains) != 1 || st.Domains[0].PolicyDomain != "example.com" || st.Domains[0].FailedSessions != 10 || st.Domains[0].LastReport == 0 {
			t.Errorf("domains: %+v", st.Domains)
		}
		if len(st.FailureTypes) != 1 || st.FailureTypes[0].ResultType != "certificate-expired" || st.FailureTypes[0].FailedSessions != 10 {
			t.Errorf("failure types: %+v", st.FailureTypes)
		}
	})
}
