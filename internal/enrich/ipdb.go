package enrich

import (
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

type ipDatabase struct {
	path   string
	reader *maxminddb.Reader
}

// ipRecord holds the fields Source takes from every supported layout. The
// layouts disagree on two keys, so those decode untyped: IPinfo Lite's
// "country" is the country's name where MaxMind and DB-IP put a map, and its
// "asn" is a string such as "AS15169".
type ipRecord struct {
	// IPinfo Lite.
	CountryCode string `maxminddb:"country_code"`
	ASN         any    `maxminddb:"asn"`
	ASName      string `maxminddb:"as_name"`
	ASDomain    string `maxminddb:"as_domain"`

	// MaxMind GeoLite2 and DB-IP Lite.
	Country  any    `maxminddb:"country"`
	ASNumber uint32 `maxminddb:"autonomous_system_number"`
	ASOrg    string `maxminddb:"autonomous_system_organization"`
}

// lookupIPDatabases fills the fields still empty in src from each database in
// turn. A database that fails to decode the record contributes nothing.
func (e *Enricher) lookupIPDatabases(addr netip.Addr, src *Source) {
	for _, db := range e.ipDBs {
		var rec ipRecord
		if err := db.reader.Lookup(addr).Decode(&rec); err != nil {
			continue
		}
		if src.Country == "" {
			src.Country = rec.country()
		}
		if src.ASN == 0 {
			src.ASN = rec.asn()
		}
		if src.ASName == "" {
			src.ASName = rec.asName()
		}
		if src.ASDomain == "" {
			if d, err := canonicalDomain(rec.ASDomain); err == nil {
				src.ASDomain = d
			}
		}
	}
}

func (r ipRecord) country() string {
	if r.CountryCode != "" {
		return strings.ToUpper(r.CountryCode)
	}
	if m, ok := r.Country.(map[string]any); ok {
		if code, ok := m["iso_code"].(string); ok {
			return strings.ToUpper(code)
		}
	}
	return ""
}

func (r ipRecord) asn() uint32 {
	if r.ASNumber != 0 {
		return r.ASNumber
	}
	switch v := r.ASN.(type) {
	case string:
		return parseASN(v)
	case uint64:
		if v <= math.MaxUint32 {
			return uint32(v)
		}
	}
	return 0
}

func (r ipRecord) asName() string {
	if r.ASName != "" {
		return r.ASName
	}
	return r.ASOrg
}

// parseASN reads "AS15169" or "15169"; anything else is 0.
func parseASN(s string) uint32 {
	s = strings.TrimSpace(s)
	if len(s) > 2 && strings.EqualFold(s[:2], "AS") {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}
