package archive

import (
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The expected hashes are the first 16 hex digits of
// printf '%s' '<identity JSON>' | shasum -a 256, computed outside Go.
func TestObjectKeys(t *testing.T) {
	tokyo := time.FixedZone("JST", 9*60*60)
	cases := []struct {
		name   string
		prefix string
		report Report
		want   Keys
	}{
		{
			name: "dmarc zip",
			report: Report{
				// ["dmarc","google.com","12345678901234567890","example.com"]
				Kind: KindDMARC, OrgName: "google.com", ReportID: "12345678901234567890", Domain: "example.com",
				Begin:       time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC),
				RawFilename: "google.com!example.com!1763596800!1763683199.zip",
			},
			want: Keys{
				Raw:    "raw/dmarc/year=2026/month=11/day=20/google.com_12345678901234567890_0dbd5d06fd190cf2.raw.zip",
				Parsed: "parsed/dmarc/year=2026/month=11/day=20/google.com_12345678901234567890_0dbd5d06fd190cf2.json",
			},
		},
		{
			name:   "domain case, local begin time and prefix",
			prefix: "archive/",
			report: Report{
				Kind: KindDMARC, OrgName: "google.com", ReportID: "12345678901234567890", Domain: "Example.COM",
				// 2026-11-20 20:30 UTC: the partition is the UTC date.
				Begin:       time.Date(2026, 11, 21, 5, 30, 0, 0, tokyo),
				RawFilename: "report.XML.GZ",
			},
			want: Keys{
				Raw:    "archive/raw/dmarc/year=2026/month=11/day=20/google.com_12345678901234567890_0dbd5d06fd190cf2.raw.xml.gz",
				Parsed: "archive/parsed/dmarc/year=2026/month=11/day=20/google.com_12345678901234567890_0dbd5d06fd190cf2.json",
			},
		},
		{
			name: "tlsrpt with unsafe characters",
			report: Report{
				// ["tlsrpt","AT&T <Mail>","2026-11-20T00:00:00Z_example.com","example.com,example.net"]
				Kind: KindTLSRPT, OrgName: "AT&T <Mail>", ReportID: "2026-11-20T00:00:00Z_example.com",
				Domain:      "example.com,example.net",
				Begin:       time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC),
				RawFilename: "att.com!example.com!1767571200!1767657599.json.gz",
			},
			want: Keys{
				Raw:    "raw/tlsrpt/year=2026/month=01/day=05/AT-T--Mail-_2026-11-20T00-00-00Z_example.com_5df7830d8c7d6f55.raw.json.gz",
				Parsed: "parsed/tlsrpt/year=2026/month=01/day=05/AT-T--Mail-_2026-11-20T00-00-00Z_example.com_5df7830d8c7d6f55.json",
			},
		},
		{
			name: "no reporter name",
			report: Report{
				// ["dmarc","","42","example.com"]
				Kind: KindDMARC, ReportID: "42", Domain: "example.com",
				Begin:       time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC),
				RawFilename: "report",
			},
			want: Keys{
				Raw:    "raw/dmarc/year=2026/month=11/day=20/-_42_8bcc8d7f53a2af15.raw.bin",
				Parsed: "parsed/dmarc/year=2026/month=11/day=20/-_42_8bcc8d7f53a2af15.json",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := objectKeys(tc.prefix, tc.report)
			if got != tc.want {
				t.Errorf("objectKeys:\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestIdentityHash(t *testing.T) {
	base := Report{Kind: KindDMARC, OrgName: "google.com", ReportID: "42", Domain: "example.com"}
	// ["dmarc","google.com","42","example.com"]
	if got, want := identityHash(base), "508411a0316eb6dc"; got != want {
		t.Fatalf("identityHash = %s, want %s", got, want)
	}

	// Each pair sanitizes to the same object name prefix, or differs only in
	// a field outside the name, so only the hash keeps the reports apart.
	distinct := []struct {
		name string
		a, b Report
	}{
		{"kind", base, Report{Kind: KindTLSRPT, OrgName: "google.com", ReportID: "42", Domain: "example.com"}},
		{"domain", base, Report{Kind: KindDMARC, OrgName: "google.com", ReportID: "42", Domain: "example.org"}},
		{"field boundary", Report{Kind: KindDMARC, OrgName: "a_b", ReportID: "c"}, Report{Kind: KindDMARC, OrgName: "a", ReportID: "b_c"}},
		{"replaced characters", Report{Kind: KindDMARC, OrgName: "é"}, Report{Kind: KindDMARC, OrgName: "è"}},
		{"truncated", Report{Kind: KindDMARC, OrgName: strings.Repeat("a", 64) + "1"}, Report{Kind: KindDMARC, OrgName: strings.Repeat("a", 64) + "2"}},
	}
	for _, tc := range distinct {
		t.Run(tc.name, func(t *testing.T) {
			if identityHash(tc.a) == identityHash(tc.b) {
				t.Errorf("reports %+v and %+v share hash %s", tc.a, tc.b, identityHash(tc.a))
			}
		})
	}
}

func TestSegment(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"google.com", "google.com"},
		{"Mail_Server-1.example", "Mail_Server-1.example"},
		{"AT&T <Mail>", "AT-T--Mail-"},
		{"a/b\\c:d", "a-b-c-d"},
		{"Яндекс", "------"},
		{"\xff\xfe", "--"},
		{"", ""},
		{strings.Repeat("x", 70), strings.Repeat("x", 64)},
		{strings.Repeat("é", 70), strings.Repeat("-", 64)},
	}
	for _, tc := range cases {
		if got := segment(tc.in); got != tc.want {
			t.Errorf("segment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestObjectNameReporter(t *testing.T) {
	cases := []struct {
		org, wantStart string
	}{
		{"", "-_1_"},
		{".hidden", "-hidden_1_"},
		{"_private", "-private_1_"},
		{"google.com", "google.com_1_"},
	}
	for _, tc := range cases {
		name := objectName(Report{Kind: KindDMARC, OrgName: tc.org, ReportID: "1"})
		if !strings.HasPrefix(name, tc.wantStart) {
			t.Errorf("objectName with org %q = %q, want it to start %q", tc.org, name, tc.wantStart)
		}
	}
}

func TestNormalizePrefix(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"/", ""},
		{"///", ""},
		{"dmarc", "dmarc/"},
		{"/dmarc/", "dmarc/"},
		{"dmarc//reports///", "dmarc/reports/"},
		{"//a/b", "a/b/"},
	}
	for _, tc := range cases {
		if got := normalizePrefix(tc.in); got != tc.want {
			t.Errorf("normalizePrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidatePrefix(t *testing.T) {
	cases := []struct {
		name    string
		prefix  string
		wantErr bool
	}{
		{"empty", "", false},
		{"nested", "team/dmarc/", false},
		{"dots inside a name", "v1.2/", false},
		{"dot element", "a/./b/", true},
		{"parent element", "a/../b/", true},
		{"control character", "a\tb/", true},
		{"invalid UTF-8", "a\xffb/", true},
		{"too long", strings.Repeat("a", maxPrefixLen) + "/", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePrefix(tc.prefix)
			if (err != nil) != tc.wantErr {
				t.Errorf("validatePrefix(%q) = %v, want error %v", tc.prefix, err, tc.wantErr)
			}
		})
	}
}

func TestRawExtension(t *testing.T) {
	cases := []struct {
		filename, want string
	}{
		{"report.xml", ".xml"},
		{"google.com!example.com!1!2.xml.gz", ".xml.gz"},
		{"REPORT.XML.GZ", ".xml.gz"},
		{"report.zip", ".zip"},
		{"report.json", ".json"},
		{"report.json.gz", ".json.gz"},
		{"report.gz", ".gz"},
		{"report.tar", ".bin"},
		{"xml", ".bin"},
		{"", ".bin"},
	}
	for _, tc := range cases {
		if got := rawExtension(tc.filename); got != tc.want {
			t.Errorf("rawExtension(%q) = %q, want %q", tc.filename, got, tc.want)
		}
	}
}

func TestRawContentType(t *testing.T) {
	gzipBytes := []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
	cases := []struct {
		name     string
		declared string
		data     []byte
		want     string
	}{
		{"declared", "application/gzip", gzipBytes, "application/gzip"},
		{"declared, normalized", `Application/GZIP; Name="report.xml.gz"`, gzipBytes, "application/gzip; name=report.xml.gz"},
		{"undeclared gzip", "", gzipBytes, "application/x-gzip"},
		{"undeclared XML", "", []byte(`<?xml version="1.0"?><feedback/>`), "text/xml; charset=utf-8"},
		{"unparsable", "not a type;;", gzipBytes, "application/x-gzip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rawContentType(tc.declared, tc.data); got != tc.want {
				t.Errorf("rawContentType = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMetadataValue(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"google.com", "google.com"},
		{"AT&T Mail", "AT%26T%20Mail"},
		{"é~", "%C3%A9~"},
		{"\xff", "%FF"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := metadataValue(tc.in); got != tc.want {
			t.Errorf("metadataValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// Cut on a character boundary: the value still decodes to a prefix of
	// the input.
	for _, in := range []string{strings.Repeat("a", 300), strings.Repeat("é", 100), strings.Repeat("a", 254) + "é"} {
		got := metadataValue(in)
		if len(got) > maxMetadataLen {
			t.Errorf("metadataValue of %d bytes is %d bytes, over %d", len(in), len(got), maxMetadataLen)
		}
		decoded, err := url.PathUnescape(got)
		if err != nil {
			t.Errorf("metadataValue = %q does not decode: %v", got, err)
			continue
		}
		if !utf8.ValidString(decoded) || !strings.HasPrefix(in, decoded) {
			t.Errorf("metadataValue decodes to %q, not a whole-character prefix of the input", decoded)
		}
	}
}
