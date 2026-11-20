package enrich

import (
	"math"
	"path/filepath"
	"testing"
)

func TestIPDatabaseLayouts(t *testing.T) {
	var (
		ipinfo  = filepath.Join("testdata", "ipinfo-lite.mmdb")
		country = filepath.Join("testdata", "geolite2-country.mmdb")
		asn     = filepath.Join("testdata", "geolite2-asn.mmdb")
	)
	tests := []struct {
		name string
		dbs  []string
		ip   string
		want Source
	}{
		{
			name: "IPinfo Lite IPv4",
			dbs:  []string{ipinfo},
			ip:   "192.0.2.25",
			want: Source{Country: "US", ASN: 64496, ASName: "Example Mail Inc.", ASDomain: "example.com"},
		},
		{
			name: "IPinfo Lite IPv6",
			dbs:  []string{ipinfo},
			ip:   "2001:db8::1",
			want: Source{Country: "NL", ASN: 64498, ASName: "Example IPv6 B.V.", ASDomain: "example.org"},
		},
		{
			name: "GeoLite2 Country and ASN",
			dbs:  []string{country, asn},
			ip:   "192.0.2.25",
			want: Source{Country: "US", ASN: 64496, ASName: "EXAMPLE-MAIL"},
		},
		{
			name: "GeoLite2 IPv4-mapped",
			dbs:  []string{country, asn},
			ip:   "::ffff:198.51.100.7",
			want: Source{Country: "DE", ASN: 64497, ASName: "EXAMPLE-HOSTING"},
		},
		{
			name: "GeoLite2 IPv6",
			dbs:  []string{country, asn},
			ip:   "2001:db8:1::1",
			want: Source{Country: "NL", ASN: 64498, ASName: "EXAMPLE-V6"},
		},
		{
			name: "GeoLite2 Country alone",
			dbs:  []string{country},
			ip:   "192.0.2.25",
			want: Source{Country: "US"},
		},
		{
			name: "earlier database wins, later fills gaps",
			dbs:  []string{asn, ipinfo},
			ip:   "192.0.2.25",
			want: Source{Country: "US", ASN: 64496, ASName: "EXAMPLE-MAIL", ASDomain: "example.com"},
		},
		{
			name: "address in no database",
			dbs:  []string{ipinfo, country, asn},
			ip:   "203.0.113.7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []Option{WithOffline()}
			for _, db := range tt.dbs {
				opts = append(opts, WithIPDatabase(db))
			}
			e, err := New(opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = e.Close() }()

			want := tt.want
			want.IP = tt.ip
			want.Name = want.ASName
			if got := e.Lookup(t.Context(), tt.ip); got != want {
				t.Errorf("Lookup(%q)\n got %+v\nwant %+v", tt.ip, got, want)
			}
		})
	}
}

func TestCloseReleasesDatabases(t *testing.T) {
	e, err := New(WithOffline(), WithIPDatabase(filepath.Join("testdata", "ipinfo-lite.mmdb")))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := e.Lookup(t.Context(), "192.0.2.25"); got != (Source{IP: "192.0.2.25"}) {
		t.Errorf("Lookup after Close = %+v, want no database fields", got)
	}
	if err := e.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestIPRecordFields(t *testing.T) {
	tests := []struct {
		name        string
		rec         ipRecord
		wantCountry string
		wantASN     uint32
	}{
		{"IPinfo code wins over name", ipRecord{CountryCode: "us", Country: "United States"}, "US", 0},
		{"MaxMind country map", ipRecord{Country: map[string]any{"iso_code": "de"}}, "DE", 0},
		{"country map without code", ipRecord{Country: map[string]any{"geoname_id": uint64(1)}}, "", 0},
		{"string ASN", ipRecord{ASN: "AS64496"}, "", 64496},
		{"numeric ASN", ipRecord{ASN: uint64(64496)}, "", 64496},
		{"ASN above 32 bits", ipRecord{ASN: uint64(math.MaxUint32) + 1}, "", 0},
		{"MaxMind ASN wins", ipRecord{ASNumber: 64497, ASN: "AS64496"}, "", 64497},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rec.country(); got != tt.wantCountry {
				t.Errorf("country() = %q, want %q", got, tt.wantCountry)
			}
			if got := tt.rec.asn(); got != tt.wantASN {
				t.Errorf("asn() = %d, want %d", got, tt.wantASN)
			}
		})
	}
}

func TestParseASN(t *testing.T) {
	tests := []struct {
		in   string
		want uint32
	}{
		{"AS15169", 15169},
		{"as64496", 64496},
		{"64496", 64496},
		{" AS1 ", 1},
		{"AS4294967295", math.MaxUint32},
		{"AS4294967296", 0},
		{"AS", 0},
		{"ASX", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := parseASN(tt.in); got != tt.want {
			t.Errorf("parseASN(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
