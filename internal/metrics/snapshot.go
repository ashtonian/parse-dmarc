package metrics

import (
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// MaxLabelValues caps the domains, reporters and TLS policy domains that get
// a series of their own. Their values come from report content, which
// anyone who can mail the report address controls; past the cap the
// smallest are summed under "other".
const MaxLabelValues = 100

// OtherLabel is the label value the series past MaxLabelValues share.
const OtherLabel = "other"

// Snapshot is the report statistics served at /metrics, read from the store
// at each refresh. Timestamps are Unix seconds, 0 for never.
type Snapshot struct {
	TotalReports      int
	TotalMessages     int
	CompliantMessages int
	ComplianceRate    float64
	UniqueSourceIPs   int
	UniqueDomains     int

	Domains      []DomainSnapshot
	Orgs         map[string]int
	Dispositions map[string]int
	SPFResults   map[string]int
	DKIMResults  map[string]int

	TLSDomains      []TLSDomainSnapshot
	TLSFailureTypes map[string]int64
}

// DomainSnapshot is one DMARC policy domain.
type DomainSnapshot struct {
	Domain                  string
	Messages                int
	CompliantMessages       int
	UnalignedMessages       int
	UnauthenticatedMessages int
	LastReport              int64
	LastUnaligned           int64
	LastUnauthenticated     int64
}

// TLSDomainSnapshot is one TLS-RPT policy domain.
type TLSDomainSnapshot struct {
	Domain      string
	Successful  int64
	Failed      int64
	LastReport  int64
	LastFailure int64
}

// snapshotCollector serves the latest Snapshot as constant metrics, so a
// refresh replaces every series at once: no scrape sees a half-written
// set, and a domain that is gone from the store is gone from the output.
type snapshotCollector struct {
	mu   sync.RWMutex
	snap *Snapshot

	totalReports, totalMessages, compliantMessages, complianceRate, uniqueIPs, uniqueDomains *prometheus.Desc

	messagesByDomain, complianceByDomain, reportsByOrg, messagesByDisposition, spfResults, dkimResults *prometheus.Desc

	messagesByClass, lastReport, lastUnaligned, lastUnauthenticated *prometheus.Desc

	tlsSessions, tlsLastReport, tlsLastFailure, tlsFailuresByType *prometheus.Desc
}

func newSnapshotCollector() *snapshotCollector {
	d := func(subsystem, name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, name), help, labels, nil)
	}
	return &snapshotCollector{
		totalReports:      d("dmarc", "reports_total", "Total number of DMARC reports in database"),
		totalMessages:     d("dmarc", "messages_total", "Total number of messages across all DMARC reports"),
		compliantMessages: d("dmarc", "compliant_messages_total", "Total number of DMARC-compliant messages"),
		complianceRate:    d("dmarc", "compliance_rate", "Overall DMARC compliance rate (0-100)"),
		uniqueIPs:         d("dmarc", "unique_source_ips", "Number of unique source IP addresses"),
		uniqueDomains:     d("dmarc", "unique_domains", "Number of unique domains"),

		messagesByDomain:      d("dmarc", "messages_by_domain", "Number of messages per domain", "domain"),
		complianceByDomain:    d("dmarc", "compliance_rate_by_domain", "DMARC compliance rate per domain (0-100)", "domain"),
		reportsByOrg:          d("dmarc", "reports_by_org", "Number of reports per reporting organization", "org_name"),
		messagesByDisposition: d("dmarc", "messages_by_disposition", "Number of messages per disposition type", "disposition"),
		spfResults:            d("dmarc", "spf_results", "Count of SPF authentication results", "result"),
		dkimResults:           d("dmarc", "dkim_results", "Count of DKIM authentication results", "result"),

		messagesByClass: d("dmarc", "messages_by_class",
			"Messages per domain by class: pass (aligned), unaligned (SPF or DKIM passed for another domain), unauthenticated (nothing passed)",
			"domain", "class"),
		lastReport: d("dmarc", "last_report_timestamp_seconds",
			"End of the newest DMARC report for the domain, Unix seconds", "domain"),
		lastUnaligned: d("dmarc", "last_unaligned_timestamp_seconds",
			"End of the newest DMARC report with an unaligned record for the domain, Unix seconds, 0 for none", "domain"),
		lastUnauthenticated: d("dmarc", "last_unauthenticated_timestamp_seconds",
			"End of the newest DMARC report with an unauthenticated record for the domain, Unix seconds, 0 for none", "domain"),

		tlsSessions: d("tlsrpt", "sessions",
			"TLS sessions reported per policy domain by result: successful or failed", "domain", "result"),
		tlsLastReport: d("tlsrpt", "last_report_timestamp_seconds",
			"End of the newest TLS-RPT report covering the policy domain, Unix seconds", "domain"),
		tlsLastFailure: d("tlsrpt", "last_failure_timestamp_seconds",
			"End of the newest TLS-RPT report with a failed session for the policy domain, Unix seconds, 0 for none", "domain"),
		tlsFailuresByType: d("tlsrpt", "failed_sessions_by_type",
			"Failed TLS sessions by RFC 8460 result type; unknown types are other", "result_type"),
	}
}

func (c *snapshotCollector) set(s Snapshot) {
	s.Domains = capDomains(s.Domains)
	s.TLSDomains = capTLSDomains(s.TLSDomains)
	s.Orgs = capCounts(s.Orgs)
	c.mu.Lock()
	c.snap = &s
	c.mu.Unlock()
}

// Describe implements prometheus.Collector.
func (c *snapshotCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.totalReports, c.totalMessages, c.compliantMessages, c.complianceRate, c.uniqueIPs, c.uniqueDomains,
		c.messagesByDomain, c.complianceByDomain, c.reportsByOrg, c.messagesByDisposition, c.spfResults, c.dkimResults,
		c.messagesByClass, c.lastReport, c.lastUnaligned, c.lastUnauthenticated,
		c.tlsSessions, c.tlsLastReport, c.tlsLastFailure, c.tlsFailuresByType,
	} {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *snapshotCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	s := c.snap
	c.mu.RUnlock()
	if s == nil {
		return
	}

	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	gauge(c.totalReports, float64(s.TotalReports))
	gauge(c.totalMessages, float64(s.TotalMessages))
	gauge(c.compliantMessages, float64(s.CompliantMessages))
	gauge(c.complianceRate, s.ComplianceRate)
	gauge(c.uniqueIPs, float64(s.UniqueSourceIPs))
	gauge(c.uniqueDomains, float64(s.UniqueDomains))

	for _, d := range s.Domains {
		gauge(c.messagesByDomain, float64(d.Messages), d.Domain)
		rate := 0.0
		if d.Messages > 0 {
			rate = float64(d.CompliantMessages) / float64(d.Messages) * 100
		}
		gauge(c.complianceByDomain, rate, d.Domain)
		gauge(c.messagesByClass, float64(d.CompliantMessages), d.Domain, "pass")
		gauge(c.messagesByClass, float64(d.UnalignedMessages), d.Domain, "unaligned")
		gauge(c.messagesByClass, float64(d.UnauthenticatedMessages), d.Domain, "unauthenticated")
		gauge(c.lastReport, float64(d.LastReport), d.Domain)
		gauge(c.lastUnaligned, float64(d.LastUnaligned), d.Domain)
		gauge(c.lastUnauthenticated, float64(d.LastUnauthenticated), d.Domain)
	}
	for org, n := range s.Orgs {
		gauge(c.reportsByOrg, float64(n), org)
	}
	for disp, n := range s.Dispositions {
		gauge(c.messagesByDisposition, float64(n), disp)
	}
	for result, n := range s.SPFResults {
		gauge(c.spfResults, float64(n), result)
	}
	for result, n := range s.DKIMResults {
		gauge(c.dkimResults, float64(n), result)
	}

	for _, d := range s.TLSDomains {
		gauge(c.tlsSessions, float64(d.Successful), d.Domain, "successful")
		gauge(c.tlsSessions, float64(d.Failed), d.Domain, "failed")
		gauge(c.tlsLastReport, float64(d.LastReport), d.Domain)
		gauge(c.tlsLastFailure, float64(d.LastFailure), d.Domain)
	}
	for t, n := range s.TLSFailureTypes {
		gauge(c.tlsFailuresByType, float64(n), t)
	}
}

// capDomains keeps the MaxLabelValues domains with the most messages and
// folds the rest into one "other" entry.
func capDomains(in []DomainSnapshot) []DomainSnapshot {
	if len(in) <= MaxLabelValues {
		return in
	}
	sorted := append([]DomainSnapshot(nil), in...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Messages > sorted[j].Messages })
	out := sorted[:MaxLabelValues-1:MaxLabelValues-1]
	other := DomainSnapshot{Domain: OtherLabel}
	for _, d := range sorted[MaxLabelValues-1:] {
		other.Messages += d.Messages
		other.CompliantMessages += d.CompliantMessages
		other.UnalignedMessages += d.UnalignedMessages
		other.UnauthenticatedMessages += d.UnauthenticatedMessages
		other.LastReport = max(other.LastReport, d.LastReport)
		other.LastUnaligned = max(other.LastUnaligned, d.LastUnaligned)
		other.LastUnauthenticated = max(other.LastUnauthenticated, d.LastUnauthenticated)
	}
	return append(out, other)
}

func capTLSDomains(in []TLSDomainSnapshot) []TLSDomainSnapshot {
	if len(in) <= MaxLabelValues {
		return in
	}
	sorted := append([]TLSDomainSnapshot(nil), in...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Successful+sorted[i].Failed > sorted[j].Successful+sorted[j].Failed
	})
	out := sorted[:MaxLabelValues-1:MaxLabelValues-1]
	other := TLSDomainSnapshot{Domain: OtherLabel}
	for _, d := range sorted[MaxLabelValues-1:] {
		other.Successful += d.Successful
		other.Failed += d.Failed
		other.LastReport = max(other.LastReport, d.LastReport)
		other.LastFailure = max(other.LastFailure, d.LastFailure)
	}
	return append(out, other)
}

func capCounts(in map[string]int) map[string]int {
	if len(in) <= MaxLabelValues {
		return in
	}
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(in))
	for k, v := range in {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v || (all[i].v == all[j].v && all[i].k < all[j].k) })
	out := make(map[string]int, MaxLabelValues)
	for i, e := range all {
		if i < MaxLabelValues-1 {
			out[e.k] = e.v
		} else {
			out[OtherLabel] += e.v
		}
	}
	return out
}
