package metrics

import (
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	return string(body)
}

func TestSnapshotReplacesEverySeries(t *testing.T) {
	m := New("test", "none", "now")
	m.SetSnapshot(Snapshot{
		TotalReports: 2,
		Domains: []DomainSnapshot{
			{Domain: "example.com", Messages: 10, CompliantMessages: 7, UnalignedMessages: 2, UnauthenticatedMessages: 1, LastReport: 1700000000, LastUnaligned: 1690000000},
			{Domain: "gone.example", Messages: 1},
		},
		TLSDomains:      []TLSDomainSnapshot{{Domain: "example.com", Successful: 9, Failed: 1, LastReport: 1700000000, LastFailure: 1700000000}},
		TLSFailureTypes: map[string]int64{"certificate-expired": 1},
	})
	out := scrape(t, m)
	for _, want := range []string{
		`parse_dmarc_dmarc_reports_total 2`,
		`parse_dmarc_dmarc_compliance_rate_by_domain{domain="example.com"} 70`,
		`parse_dmarc_dmarc_messages_by_class{class="unaligned",domain="example.com"} 2`,
		`parse_dmarc_dmarc_last_report_timestamp_seconds{domain="example.com"} 1.7e+09`,
		`parse_dmarc_dmarc_last_unaligned_timestamp_seconds{domain="example.com"} 1.69e+09`,
		`parse_dmarc_tlsrpt_sessions{domain="example.com",result="failed"} 1`,
		`parse_dmarc_tlsrpt_last_failure_timestamp_seconds{domain="example.com"} 1.7e+09`,
		`parse_dmarc_tlsrpt_failed_sessions_by_type{result_type="certificate-expired"} 1`,
		`gone.example`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape lacks %s", want)
		}
	}

	// A domain no longer in the store leaves the output with the next
	// snapshot instead of lingering at its last value.
	m.SetSnapshot(Snapshot{Domains: []DomainSnapshot{{Domain: "example.com", Messages: 10}}})
	if out := scrape(t, m); strings.Contains(out, "gone.example") {
		t.Error("a domain dropped from the snapshot is still served")
	}
}

func TestSnapshotCapsLabelValues(t *testing.T) {
	m := New("test", "none", "now")
	var domains []DomainSnapshot
	orgs := map[string]int{}
	for i := range MaxLabelValues + 50 {
		domains = append(domains, DomainSnapshot{Domain: fmt.Sprintf("d%03d.example", i), Messages: i + 1, LastReport: int64(i)})
		orgs[fmt.Sprintf("org%03d", i)] = i + 1
	}
	m.SetSnapshot(Snapshot{Domains: domains, Orgs: orgs})
	out := scrape(t, m)

	if n := strings.Count(out, "parse_dmarc_dmarc_messages_by_domain{"); n != MaxLabelValues {
		t.Errorf("%d domain series, want %d", n, MaxLabelValues)
	}
	if n := strings.Count(out, "parse_dmarc_dmarc_reports_by_org{"); n != MaxLabelValues {
		t.Errorf("%d org series, want %d", n, MaxLabelValues)
	}
	// The smallest domains are folded into "other", which keeps their sum
	// and their newest report.
	if !strings.Contains(out, `parse_dmarc_dmarc_messages_by_domain{domain="other"} 1326`) ||
		!strings.Contains(out, `parse_dmarc_dmarc_last_report_timestamp_seconds{domain="other"} 50`) {
		t.Errorf("other series wrong:\n%s", grep(out, `domain="other"`))
	}
	if !strings.Contains(out, `domain="d149.example"`) || strings.Contains(out, `domain="d000.example"`) {
		t.Error("the cap kept the wrong domains")
	}
}

func grep(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// Recording methods are safe without metrics.
func TestNilMetrics(t *testing.T) {
	var m *Metrics
	m.FetchCycle()
	m.SetSnapshot(Snapshot{})
	m.RecordIMAPConnection(true, 0)
}
