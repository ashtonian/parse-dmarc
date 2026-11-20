package enrich

import (
	"maps"
	"strings"
	"testing"
)

func TestParseServiceMap(t *testing.T) {
	// parsedmarc's file has CRLF line ends, quoted names with commas, a key
	// with a root dot and internationalized keys; a spreadsheet export adds
	// a BOM.
	input := "\uFEFFbase_reverse_dns,name,type\r\n" +
		"Example.COM,Example Mail,Email Provider\r\n" +
		"example.net.,Example Hosting,Web Host\r\n" +
		"example.org,\"Example, Inc.\",ISP\r\n" +
		",,\r\n" +
		"\r\n" +
		"example.test,Example Test,\r\n" +
		"пример.испытание,Example IDN,ISP\r\n" +
		"example.com,Example Mail,Email Provider\r\n"
	got, err := parseServiceMap(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]service{
		"example.com":                   {name: "Example Mail", kind: "Email Provider"},
		"example.net":                   {name: "Example Hosting", kind: "Web Host"},
		"example.org":                   {name: "Example, Inc.", kind: "ISP"},
		"example.test":                  {name: "Example Test"},
		"xn--e1afmkfd.xn--80akhbyknj4f": {name: "Example IDN", kind: "ISP"},
	}
	if !maps.Equal(got, want) {
		t.Errorf("parseServiceMap\n got %v\nwant %v", got, want)
	}
}

func TestParseServiceMapErrors(t *testing.T) {
	const header = "base_reverse_dns,name,type\n"
	tests := []struct {
		name  string
		input string
	}{
		{"empty file", ""},
		{"wrong column name", "base_reverse_dns,service,type\n"},
		{"columns out of order", "name,base_reverse_dns,type\n"},
		{"missing column", "base_reverse_dns,name\nexample.com,Example\n"},
		{"extra column", "base_reverse_dns,name,type,note\n"},
		{"row with too few fields", header + "example.com,Example\n"},
		{"row with too many fields", header + "example.com,Example,ISP,extra\n"},
		{"row without domain", header + ",Example,ISP\n"},
		{"row without name", header + "example.com,,ISP\n"},
		{"domain that is only the root", header + ".,Example,ISP\n"},
		{"bare quote", header + "example.com,Ex\"ample,ISP\n"},
		{"conflicting duplicate", header + "example.com,Example,ISP\nEXAMPLE.com,Other,ISP\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseServiceMap(strings.NewReader(tt.input)); err == nil {
				t.Error("parseServiceMap succeeded, want an error")
			}
		})
	}
}

func TestWithServiceMapReportsPath(t *testing.T) {
	path := writeFile(t, "bad.csv", "domain,name,type\n")
	_, err := New(WithOffline(), WithServiceMap(path))
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("New error = %v, want one naming %s", err, path)
	}
}
