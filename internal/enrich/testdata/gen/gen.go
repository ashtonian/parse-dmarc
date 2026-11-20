//go:build ignore

// Command gen writes the MMDB fixtures the enrich tests read: one database in
// the IPinfo Lite layout and a GeoLite2-Country and GeoLite2-ASN pair. Every
// network is a documentation range (RFC 5737, RFC 3849) and every AS number a
// documentation ASN (RFC 5398).
//
// mmdbwriter is not a dependency of this module, so run gen against a scratch
// copy of go.mod. From the repository root:
//
//	cp go.mod /tmp/gen.mod && cp go.sum /tmp/gen.sum
//	go get -modfile=/tmp/gen.mod github.com/maxmind/mmdbwriter@v1.2.0
//	go run -modfile=/tmp/gen.mod internal/enrich/testdata/gen/gen.go
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// buildEpoch is fixed so that regenerating leaves unchanged fixtures
// byte-identical.
const buildEpoch = 1767225600 // 2026-01-01T00:00:00Z

type network struct {
	cidr        string
	country     string
	countryCode string
	continent   string
	contCode    string
	geonameID   uint32
	asn         uint32
	asName      string // IPinfo's as_name
	asOrg       string // GeoLite2's autonomous_system_organization
	asDomain    string
}

// 203.0.113.0/24 is left out of every database: the tests use it for an
// address the databases do not know.
var networks = []network{
	{
		cidr: "192.0.2.0/24", country: "United States", countryCode: "US",
		continent: "North America", contCode: "NA", geonameID: 6252001,
		asn: 64496, asName: "Example Mail Inc.", asOrg: "EXAMPLE-MAIL", asDomain: "example.com",
	},
	{
		cidr: "198.51.100.0/24", country: "Germany", countryCode: "DE",
		continent: "Europe", contCode: "EU", geonameID: 2921044,
		asn: 64497, asName: "Example Hosting GmbH", asOrg: "EXAMPLE-HOSTING", asDomain: "example.net",
	},
	{
		cidr: "2001:db8::/32", country: "Netherlands", countryCode: "NL",
		continent: "Europe", contCode: "EU", geonameID: 2750405,
		asn: 64498, asName: "Example IPv6 B.V.", asOrg: "EXAMPLE-V6", asDomain: "example.org",
	},
}

func main() {
	out := flag.String("out", "internal/enrich/testdata", "directory to write the fixtures to")
	flag.Parse()

	databases := []struct {
		file, dbType string
		record       func(network) mmdbtype.Map
	}{
		{"ipinfo-lite.mmdb", "ipinfo lite.mmdb", ipinfoLite},
		{"geolite2-country.mmdb", "GeoLite2-Country", geoLite2Country},
		{"geolite2-asn.mmdb", "GeoLite2-ASN", geoLite2ASN},
	}
	for _, db := range databases {
		path := filepath.Join(*out, db.file)
		if err := write(path, db.dbType, db.record); err != nil {
			log.Fatalf("write %s: %v", path, err)
		}
		fmt.Println("wrote", path)
	}
}

// ipinfoLite is the IPinfo Lite record: country is the English name, the
// code is a sibling field, and the ASN is a string with an "AS" prefix.
func ipinfoLite(n network) mmdbtype.Map {
	return mmdbtype.Map{
		"country":        mmdbtype.String(n.country),
		"country_code":   mmdbtype.String(n.countryCode),
		"continent":      mmdbtype.String(n.continent),
		"continent_code": mmdbtype.String(n.contCode),
		"asn":            mmdbtype.String(fmt.Sprintf("AS%d", n.asn)),
		"as_name":        mmdbtype.String(n.asName),
		"as_domain":      mmdbtype.String(n.asDomain),
	}
}

// geoLite2Country is the GeoLite2-Country record, which DB-IP Lite Country
// shares: country is a map holding the ISO code and localized names.
func geoLite2Country(n network) mmdbtype.Map {
	country := mmdbtype.Map{
		"geoname_id": mmdbtype.Uint32(n.geonameID),
		"iso_code":   mmdbtype.String(n.countryCode),
		"names":      mmdbtype.Map{"en": mmdbtype.String(n.country)},
	}
	if n.contCode == "EU" {
		country["is_in_european_union"] = mmdbtype.Bool(true)
	}
	return mmdbtype.Map{
		"continent": mmdbtype.Map{
			"code":  mmdbtype.String(n.contCode),
			"names": mmdbtype.Map{"en": mmdbtype.String(n.continent)},
		},
		"country":            country,
		"registered_country": country,
	}
}

// geoLite2ASN is the GeoLite2-ASN record, which DB-IP Lite ASN shares.
func geoLite2ASN(n network) mmdbtype.Map {
	return mmdbtype.Map{
		"autonomous_system_number":       mmdbtype.Uint32(n.asn),
		"autonomous_system_organization": mmdbtype.String(n.asOrg),
	}
}

func write(path, dbType string, record func(network) mmdbtype.Map) error {
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		BuildEpoch:   buildEpoch,
		DatabaseType: dbType,
		Description:  map[string]string{"en": "Parse DMARC enrich test fixture"},
		// Documentation ranges are reserved; the writer refuses them otherwise.
		IncludeReservedNetworks: true,
		RecordSize:              24,
	})
	if err != nil {
		return err
	}
	for _, n := range networks {
		_, ipNet, err := net.ParseCIDR(n.cidr)
		if err != nil {
			return err
		}
		if err := tree.Insert(ipNet, record(n)); err != nil {
			return fmt.Errorf("insert %s: %w", n.cidr, err)
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := tree.WriteTo(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
