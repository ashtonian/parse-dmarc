package parser

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// The example report of RFC 8460 section 4.4, with its dates moved into the
// past of testNow.
const rfc8460Example = `{
  "organization-name": "Company-X",
  "date-range": {
    "start-datetime": "2026-11-18T00:00:00Z",
    "end-datetime": "2026-11-18T23:59:59Z"
  },
  "contact-info": "sts-reporting@company-x.example",
  "report-id": "5065427c-23d3-47ca-b6e0-946ea0e8c4be",
  "policies": [{
    "policy": {
      "policy-type": "sts",
      "policy-string": ["version: STSv1","mode: testing",
            "mx: *.mail.company-y.example","max_age: 86400"],
      "policy-domain": "company-y.example",
      "mx-host": ["*.mail.company-y.example"]
    },
    "summary": {
      "total-successful-session-count": 5326,
      "total-failure-session-count": 303
    },
    "failure-details": [{
      "result-type": "certificate-expired",
      "sending-mta-ip": "2001:db8:abcd:0012::1",
      "receiving-mx-hostname": "mx1.mail.company-y.example",
      "failed-session-count": 100
    }, {
      "result-type": "starttls-not-supported",
      "sending-mta-ip": "2001:db8:abcd:0013::1",
      "receiving-mx-hostname": "mx2.mail.company-y.example",
      "receiving-ip": "203.0.113.56",
      "failed-session-count": 200,
      "additional-information": "https://reports.company-x.example/report_info?id=5065427c-23d3#StarttlsNotSupported"
    }, {
      "result-type": "validation-failure",
      "sending-mta-ip": "198.51.100.62",
      "receiving-ip": "203.0.113.58",
      "receiving-mx-hostname": "mx-backup.mail.company-y.example",
      "failed-session-count": 3,
      "failure-reason-code": "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"
    }]
  }]
}`

func TestParseTLSRPTExample(t *testing.T) {
	for name, data := range map[string][]byte{
		"json":    []byte(rfc8460Example),
		"gzip":    gzipBytes(t, []byte(rfc8460Example)),
		"bom":     append(append([]byte{}, utf8BOM...), rfc8460Example...),
		"leading": []byte("\n  " + rfc8460Example),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := parse(data, testNow)
			if err != nil {
				t.Fatal(err)
			}
			if r.Kind != KindTLSRPT || r.TLSRPT == nil || r.DMARC != nil {
				t.Fatalf("got kind %q", r.Kind)
			}
			tr := r.TLSRPT
			if tr.OrganizationName != "Company-X" || tr.ReportID != "5065427c-23d3-47ca-b6e0-946ea0e8c4be" {
				t.Errorf("metadata: %+v", tr)
			}
			if got := tr.DateRange.Start; !got.Equal(time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)) {
				t.Errorf("start = %v", got)
			}
			ok, failed := tr.Sessions()
			if ok != 5326 || failed != 303 {
				t.Errorf("sessions = %d/%d, want 5326/303", ok, failed)
			}
			p := tr.Policies[0]
			if p.PolicyType != TLSPolicySTS || p.PolicyDomain != "company-y.example" || len(p.PolicyStrings) != 4 || len(p.MXHosts) != 1 {
				t.Errorf("policy: %+v", p)
			}
			if len(p.FailureDetails) != 3 {
				t.Fatalf("failure details: %d", len(p.FailureDetails))
			}
			fd := p.FailureDetails[0]
			if fd.ResultType != "certificate-expired" || fd.SendingMTAIP != "2001:db8:abcd:12::1" || fd.FailedSessions != 100 {
				t.Errorf("detail 0: %+v", fd)
			}
			if p.FailureDetails[2].FailureReasonCode != "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED" {
				t.Errorf("detail 2: %+v", p.FailureDetails[2])
			}
		})
	}
}

// Reporters disagree on shapes RFC 8460 fixes: contact-info as a list,
// mx-host as a string or under mx-host-pattern, null counts, the URI field
// name of an older draft.
func TestParseTLSRPTLenientShapes(t *testing.T) {
	doc := `{
	  "organization-name": "Microsoft Corporation",
	  "date-range": {"start-datetime": "2026-11-18T00:00:00Z", "end-datetime": "2026-11-19T00:00:00Z"},
	  "contact-info": ["tlsrpt@microsoft.example", "  "],
	  "report-id": "<133.abc@microsoft.example>",
	  "policies": [{
	    "policy": {"policy-type": "STS", "policy-domain": "Example.COM.", "mx-host-pattern": "mx.example.com"},
	    "summary": {"total-successful-session-count": 7, "total-failure-session-count": null},
	    "failure-details": [{"result-type": "Sts-Policy-Fetch-Error", "failed-session-count": 2,
	      "additional-info-uri": "https://example.com/why", "sending-mta-ip": "not-an-ip"}]
	  }, {
	    "policy": {"policy-type": "no-policy-found", "policy-domain": "example.com", "mx-host": "mx.example.com"},
	    "summary": {"total-successful-session-count": 1, "total-failure-session-count": 0}
	  }]
	}`
	tr, err := parseTLSRPT([]byte(doc), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if tr.ContactInfo != "tlsrpt@microsoft.example" {
		t.Errorf("contact info = %q", tr.ContactInfo)
	}
	p := tr.Policies[0]
	if p.PolicyType != "sts" || p.PolicyDomain != "example.com" || len(p.MXHosts) != 1 || p.MXHosts[0] != "mx.example.com" {
		t.Errorf("policy 0: %+v", p)
	}
	if p.FailedSessions != 0 || p.SuccessfulSessions != 7 {
		t.Errorf("counts: %+v", p)
	}
	fd := p.FailureDetails[0]
	if fd.ResultType != "sts-policy-fetch-error" || fd.AdditionalInformation != "https://example.com/why" || fd.SendingMTAIP != "" {
		t.Errorf("detail: %+v", fd)
	}
	if got := tr.PolicyDomains(); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("policy domains = %v", got)
	}
}

func TestParseTLSRPTRejects(t *testing.T) {
	valid := func(mutate func(string) string) string { return mutate(rfc8460Example) }
	cases := map[string]string{
		"no organization": valid(func(s string) string {
			return strings.Replace(s, `"organization-name": "Company-X",`, "", 1)
		}),
		"no report id": valid(func(s string) string {
			return strings.Replace(s, `"report-id": "5065427c-23d3-47ca-b6e0-946ea0e8c4be",`, "", 1)
		}),
		"no policies":     `{"organization-name":"x","report-id":"1","contact-info":"a","date-range":{"start-datetime":"2026-11-18T00:00:00Z","end-datetime":"2026-11-19T00:00:00Z"}}`,
		"bad policy type": valid(func(s string) string { return strings.Replace(s, `"policy-type": "sts"`, `"policy-type": "dane"`, 1) }),
		"negative count":  valid(func(s string) string { return strings.Replace(s, `5326`, `-1`, 1) }),
		"fractional":      valid(func(s string) string { return strings.Replace(s, `5326`, `1.5`, 1) }),
		"boolean count":   valid(func(s string) string { return strings.Replace(s, `5326`, `true`, 1) }),
		"bad date":        valid(func(s string) string { return strings.Replace(s, `2026-11-18T00:00:00Z`, `yesterday`, 1) }),
		"future":          valid(func(s string) string { return strings.ReplaceAll(s, `2026-11-18`, `2026-12-30`) }),
		"reversed": valid(func(s string) string {
			return strings.Replace(s, `"start-datetime": "2026-11-18T00:00:00Z"`, `"start-datetime": "2026-11-19T00:00:00Z"`, 1)
		}),
		"not json": `{"organization-name": `,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseTLSRPT([]byte(doc), testNow)
			if !errors.Is(err, ErrInvalidTLSRPT) {
				t.Fatalf("err = %v, want ErrInvalidTLSRPT", err)
			}
		})
	}
}

func TestParseRejectsUnknownDocument(t *testing.T) {
	_, err := parse([]byte("hello"), testNow)
	if !errors.Is(err, ErrUnknownReport) {
		t.Fatalf("err = %v, want ErrUnknownReport", err)
	}
}
