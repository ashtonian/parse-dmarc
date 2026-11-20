package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// TLSReport is an SMTP TLS Reporting aggregate report (RFC 8460): for each
// policy a sending MTA applied to the domain's MX hosts, how many sessions
// negotiated TLS and why the others did not.
type TLSReport struct {
	OrganizationName string            `json:"organization_name"`
	ReportID         string            `json:"report_id"`
	ContactInfo      string            `json:"contact_info"`
	DateRange        TLSDateRange      `json:"date_range"`
	Policies         []TLSPolicyResult `json:"policies"`
}

// TLSDateRange is the UTC interval the report covers.
type TLSDateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// TLS-RPT policy types (RFC 8460 section 4.4).
const (
	TLSPolicySTS           = "sts"
	TLSPolicyTLSA          = "tlsa"
	TLSPolicyNoPolicyFound = "no-policy-found"
)

// TLSPolicyResult is one applied policy and its session counts.
type TLSPolicyResult struct {
	PolicyType         string             `json:"policy_type"`
	PolicyDomain       string             `json:"policy_domain"`
	PolicyStrings      []string           `json:"policy_strings"`
	MXHosts            []string           `json:"mx_hosts"`
	SuccessfulSessions int64              `json:"successful_sessions"`
	FailedSessions     int64              `json:"failed_sessions"`
	FailureDetails     []TLSFailureDetail `json:"failure_details"`
}

// TLSFailureDetail groups failed sessions that share a cause and endpoints.
type TLSFailureDetail struct {
	ResultType            string `json:"result_type"`
	SendingMTAIP          string `json:"sending_mta_ip,omitempty"`
	ReceivingMXHostname   string `json:"receiving_mx_hostname,omitempty"`
	ReceivingMXHelo       string `json:"receiving_mx_helo,omitempty"`
	ReceivingIP           string `json:"receiving_ip,omitempty"`
	FailedSessions        int64  `json:"failed_sessions"`
	AdditionalInformation string `json:"additional_information,omitempty"`
	FailureReasonCode     string `json:"failure_reason_code,omitempty"`
}

// TLSResultTypes are the result-type values RFC 8460 section 4.3 defines.
// Reporters may send others; metrics label those "other".
var TLSResultTypes = []string{
	"starttls-not-supported",
	"certificate-host-mismatch",
	"certificate-expired",
	"certificate-not-trusted",
	"validation-failure",
	"tlsa-invalid",
	"dnssec-invalid",
	"dane-required",
	"sts-policy-fetch-error",
	"sts-policy-invalid",
	"sts-webpki-invalid",
}

// ErrInvalidTLSRPT wraps every reason a JSON document is not a usable
// TLS-RPT report.
var ErrInvalidTLSRPT = errors.New("invalid TLS-RPT report")

// ParseTLSReport parses an RFC 8460 report: JSON, or JSON in gzip or zip.
func ParseTLSReport(data []byte) (*TLSReport, error) {
	return parseTLSRPT(data, time.Now())
}

func parseTLSRPT(data []byte, now time.Time) (*TLSReport, error) {
	doc, err := decompress(data)
	if err != nil {
		return nil, err
	}
	return parseTLSRPTJSON(doc, now)
}

// wireTLSReport is the report as RFC 8460 spells it. Fields reporters are
// known to send in more than one shape are decoded leniently.
type wireTLSReport struct {
	OrganizationName *string           `json:"organization-name"`
	DateRange        *wireTLSDateRange `json:"date-range"`
	ContactInfo      stringOrList      `json:"contact-info"`
	ReportID         *string           `json:"report-id"`
	Policies         *[]wirePolicy     `json:"policies"`
}

type wireTLSDateRange struct {
	Start string `json:"start-datetime"`
	End   string `json:"end-datetime"`
}

type wirePolicy struct {
	Policy struct {
		Type          string       `json:"policy-type"`
		Strings       stringOrList `json:"policy-string"`
		Domain        string       `json:"policy-domain"`
		MXHost        stringOrList `json:"mx-host"`
		MXHostPattern stringOrList `json:"mx-host-pattern"`
	} `json:"policy"`
	Summary struct {
		Successful sessionCount `json:"total-successful-session-count"`
		Failed     sessionCount `json:"total-failure-session-count"`
	} `json:"summary"`
	FailureDetails []wireFailureDetail `json:"failure-details"`
}

type wireFailureDetail struct {
	ResultType          string       `json:"result-type"`
	SendingMTAIP        string       `json:"sending-mta-ip"`
	ReceivingMXHostname string       `json:"receiving-mx-hostname"`
	ReceivingMXHelo     string       `json:"receiving-mx-helo"`
	ReceivingIP         string       `json:"receiving-ip"`
	FailedSessions      sessionCount `json:"failed-session-count"`
	AdditionalInfo      string       `json:"additional-information"`
	AdditionalInfoURI   string       `json:"additional-info-uri"`
	FailureReasonCode   string       `json:"failure-reason-code"`
}

func parseTLSRPTJSON(doc []byte, now time.Time) (*TLSReport, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var w wireTLSReport
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("%w: JSON parsing failed: %w", ErrInvalidTLSRPT, err)
	}

	switch {
	case w.OrganizationName == nil || strings.TrimSpace(*w.OrganizationName) == "":
		return nil, fmt.Errorf("%w: no organization-name", ErrInvalidTLSRPT)
	case w.ReportID == nil || strings.TrimSpace(*w.ReportID) == "":
		return nil, fmt.Errorf("%w: no report-id", ErrInvalidTLSRPT)
	case w.DateRange == nil:
		return nil, fmt.Errorf("%w: no date-range", ErrInvalidTLSRPT)
	case w.Policies == nil:
		return nil, fmt.Errorf("%w: no policies", ErrInvalidTLSRPT)
	}

	start, err := parseTLSTime(w.DateRange.Start, "start-datetime")
	if err != nil {
		return nil, err
	}
	end, err := parseTLSTime(w.DateRange.End, "end-datetime")
	if err != nil {
		return nil, err
	}
	if err := validateDateRange(start, end, now); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTLSRPT, err)
	}

	r := &TLSReport{
		OrganizationName: strings.TrimSpace(*w.OrganizationName),
		ReportID:         strings.TrimSpace(*w.ReportID),
		ContactInfo:      strings.Join(w.ContactInfo, ", "),
		DateRange:        TLSDateRange{Start: start.UTC(), End: end.UTC()},
		Policies:         make([]TLSPolicyResult, 0, len(*w.Policies)),
	}

	for i, wp := range *w.Policies {
		policyType := lowerTrim(wp.Policy.Type)
		switch policyType {
		case TLSPolicySTS, TLSPolicyTLSA, TLSPolicyNoPolicyFound:
		default:
			return nil, fmt.Errorf("%w: policy %d: unknown policy-type %q", ErrInvalidTLSRPT, i, wp.Policy.Type)
		}
		mx := wp.Policy.MXHost
		if len(mx) == 0 {
			mx = wp.Policy.MXHostPattern
		}

		p := TLSPolicyResult{
			PolicyType:         policyType,
			PolicyDomain:       strings.TrimSuffix(lowerTrim(wp.Policy.Domain), "."),
			PolicyStrings:      nonNil(wp.Policy.Strings),
			MXHosts:            nonNil(mx),
			SuccessfulSessions: int64(wp.Summary.Successful),
			FailedSessions:     int64(wp.Summary.Failed),
			FailureDetails:     make([]TLSFailureDetail, 0, len(wp.FailureDetails)),
		}
		if p.PolicyDomain == "" {
			return nil, fmt.Errorf("%w: policy %d: no policy-domain", ErrInvalidTLSRPT, i)
		}

		for _, wf := range wp.FailureDetails {
			info := strings.TrimSpace(wf.AdditionalInfo)
			if info == "" {
				info = strings.TrimSpace(wf.AdditionalInfoURI)
			}
			resultType := lowerTrim(wf.ResultType)
			if resultType == "" {
				return nil, fmt.Errorf("%w: policy %d: failure detail without result-type", ErrInvalidTLSRPT, i)
			}
			p.FailureDetails = append(p.FailureDetails, TLSFailureDetail{
				ResultType:            resultType,
				SendingMTAIP:          ipOrEmpty(wf.SendingMTAIP),
				ReceivingMXHostname:   strings.TrimSuffix(lowerTrim(wf.ReceivingMXHostname), "."),
				ReceivingMXHelo:       strings.TrimSpace(wf.ReceivingMXHelo),
				ReceivingIP:           ipOrEmpty(wf.ReceivingIP),
				FailedSessions:        int64(wf.FailedSessions),
				AdditionalInformation: info,
				FailureReasonCode:     strings.TrimSpace(wf.FailureReasonCode),
			})
		}
		r.Policies = append(r.Policies, p)
	}
	return r, nil
}

// PolicyDomains returns the distinct policy domains, sorted.
func (r *TLSReport) PolicyDomains() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range r.Policies {
		if !seen[p.PolicyDomain] {
			seen[p.PolicyDomain] = true
			out = append(out, p.PolicyDomain)
		}
	}
	sort.Strings(out)
	return out
}

// Sessions returns the successful and failed session totals.
func (r *TLSReport) Sessions() (successful, failed int64) {
	for _, p := range r.Policies {
		successful += p.SuccessfulSessions
		failed += p.FailedSessions
	}
	return successful, failed
}

// NormalizeForJSON makes every slice non-nil, as the MCP output schema
// requires arrays rather than null.
func (r *TLSReport) NormalizeForJSON() {
	if r == nil {
		return
	}
	if r.Policies == nil {
		r.Policies = []TLSPolicyResult{}
	}
	for i := range r.Policies {
		p := &r.Policies[i]
		p.PolicyStrings = nonNil(p.PolicyStrings)
		p.MXHosts = nonNil(p.MXHosts)
		if p.FailureDetails == nil {
			p.FailureDetails = []TLSFailureDetail{}
		}
	}
}

func parseTLSTime(v, field string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, fmt.Errorf("%w: no %s", ErrInvalidTLSRPT, field)
	}
	if len(v) > 64 {
		return time.Time{}, fmt.Errorf("%w: %s is too long", ErrInvalidTLSRPT, field)
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s %q is not an RFC 3339 date-time", ErrInvalidTLSRPT, field, v)
	}
	return t, nil
}

// ipOrEmpty keeps a well-formed address without its zone and drops anything
// else: the value is a free string on the wire and ends up in metrics and
// the dashboard.
func ipOrEmpty(v string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		return ""
	}
	return addr.WithZone("").String()
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// stringOrList decodes a JSON string or an array of strings. RFC 8460 makes
// contact-info a string and mx-host an array, and reporters send both
// shapes for both.
type stringOrList []string

func (s *stringOrList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		*s = nil
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var one string
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = splitNonEmpty([]string{one})
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("want a string or an array of strings: %w", err)
	}
	*s = splitNonEmpty(many)
	return nil
}

func splitNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// sessionCount decodes a non-negative integer that fits in 31 bits; null
// is zero. Booleans, fractions and strings are rejected.
type sessionCount int64

func (c *sessionCount) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		*c = 0
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("session count must be a number: %w", err)
	}
	v, err := n.Int64()
	if err != nil || v < 0 || v > math.MaxInt32 {
		return fmt.Errorf("session count %s is not an integer between 0 and %d", n, math.MaxInt32)
	}
	*c = sessionCount(v)
	return nil
}
