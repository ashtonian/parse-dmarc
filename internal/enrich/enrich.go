// Package enrich attributes the source IP of a DMARC aggregate report record
// to the service that sent the mail, the way parsedmarc does, except that
// only a forward-confirmed reverse DNS name may name the sender.
//
// Whoever controls an address sets its PTR record, so a spammer can point
// their own IP at mail.google.com. Resolving the PTR name forward and finding
// the address among its A/AAAA answers (forward-confirmed reverse DNS) shows
// that the owner of the name agrees. A PTR that fails the check is still
// reported in Source.ReverseDNS and Source.BaseDomain, but never sets
// Source.Name or Source.Type.
//
// For each address:
//
//  1. Country and autonomous system come from the IP databases.
//  2. The PTR name is looked up and forward-confirmed. Its base domain is the
//     registrable domain under the public suffix list.
//  3. A verified base domain in the service map gives the name and type.
//  4. A verified base domain not in the map is the name, with no type.
//  5. Otherwise the AS domain in the service map gives the name and type.
//  6. Otherwise the AS name is the name.
//
// The service map (parsedmarc's base_reverse_dns_map.csv, CC BY-SA 4.0) and
// the IP databases (IPinfo Lite, MaxMind GeoLite2, DB-IP Lite, each under its
// own license) are files the operator downloads and names; Parse DMARC ships
// none of them.
package enrich

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Source is what is known about one sending address. A field that could not
// be determined is empty.
type Source struct {
	IP string `json:"ip"`
	// ReverseDNS is the first PTR name, lowercased, without the root dot.
	ReverseDNS string `json:"reverse_dns"`
	// ReverseDNSVerified reports that ReverseDNS resolves back to IP.
	ReverseDNSVerified bool `json:"reverse_dns_verified"`
	// BaseDomain is the registrable domain of ReverseDNS.
	BaseDomain string `json:"base_domain"`
	// Name and Type identify the sending service; Type is a service map
	// category such as "Email Provider".
	Name string `json:"name"`
	Type string `json:"type"`
	// Country is an ISO 3166-1 alpha-2 code.
	Country  string `json:"country"`
	ASN      uint32 `json:"asn"`
	ASName   string `json:"as_name"`
	ASDomain string `json:"as_domain"`
}

// Resolver is the DNS client an Enricher queries. *net.Resolver satisfies it.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Enricher looks up sources. It is safe for concurrent use until Close.
type Enricher struct {
	resolver Resolver // nil when offline
	timeout  time.Duration
	services map[string]service
	ipDBs    []ipDatabase
}

// New builds an Enricher, loading the service map and opening the IP
// databases the options name. Without options it queries the system resolver
// and has no service map or IP database.
func New(opts ...Option) (*Enricher, error) {
	o := options{resolver: net.DefaultResolver, timeout: DefaultLookupTimeout}
	for _, opt := range opts {
		if err := opt(&o); err != nil {
			return nil, err
		}
	}

	e := &Enricher{resolver: o.resolver, timeout: o.timeout}
	if o.serviceMap != "" {
		services, err := loadServiceMap(o.serviceMap)
		if err != nil {
			return nil, err
		}
		e.services = services
	}
	for _, path := range o.ipDatabases {
		reader, err := maxminddb.Open(path)
		if err != nil {
			_ = e.Close()
			return nil, fmt.Errorf("open IP database %s: %w", path, err)
		}
		e.ipDBs = append(e.ipDBs, ipDatabase{path: path, reader: reader})
	}
	return e, nil
}

// Close releases the IP databases. Lookups must not run concurrently with or
// after Close.
func (e *Enricher) Close() error {
	var errs []error
	for _, db := range e.ipDBs {
		if err := db.reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close IP database %s: %w", db.path, err))
		}
	}
	e.ipDBs = nil
	return errors.Join(errs...)
}

// Lookup enriches one address. Enrichment is best effort: a failed or timed
// out DNS query, or an address the IP databases do not hold, leaves the
// fields it would have filled empty. An unparsable ip yields Source{IP: ip}.
func (e *Enricher) Lookup(ctx context.Context, ip string) Source {
	src := Source{IP: ip}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return src
	}
	addr = addr.Unmap().WithZone("")

	e.lookupIPDatabases(addr, &src)
	if e.resolver != nil {
		e.lookupReverseDNS(ctx, addr, &src)
	}
	e.attribute(&src)
	return src
}

// LookupAll enriches each distinct address in ips with at most concurrency
// lookups in flight; below 1 means DefaultConcurrency. The map is keyed by
// the address as given. When ctx ends first, the map holds only the lookups
// that finished before it ended: a lookup cut short is left out rather than
// returned without its DNS fields.
func (e *Enricher) LookupAll(ctx context.Context, ips []string, concurrency int) map[string]Source {
	results := make(map[string]Source, len(ips))
	pending := make([]string, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			pending = append(pending, ip)
		}
	}
	if len(pending) == 0 {
		return results
	}
	if concurrency < 1 {
		concurrency = DefaultConcurrency
	}

	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		jobs = make(chan string)
	)
	for range min(concurrency, len(pending)) {
		wg.Go(func() {
			for ip := range jobs {
				src := e.Lookup(ctx, ip)
				if ctx.Err() != nil {
					continue
				}
				mu.Lock()
				results[ip] = src
				mu.Unlock()
			}
		})
	}
dispatch:
	for _, ip := range pending {
		if ctx.Err() != nil {
			break
		}
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func (e *Enricher) lookupReverseDNS(ctx context.Context, addr netip.Addr, src *Source) {
	ptrCtx, cancel := context.WithTimeout(ctx, e.timeout)
	names, _ := e.resolver.LookupAddr(ptrCtx, addr.String())
	cancel()
	// net.Resolver returns the well-formed names alongside an error when it
	// drops malformed ones, so the names are used whatever the error.
	if len(names) == 0 {
		return
	}
	name, err := canonicalDomain(names[0])
	if err != nil || name == "" {
		return
	}
	src.ReverseDNS = name
	src.BaseDomain = baseDomain(name)
	src.ReverseDNSVerified = e.forwardConfirms(ctx, name, addr)
}

// forwardConfirms reports whether name resolves to addr.
func (e *Enricher) forwardConfirms(ctx context.Context, name string, addr netip.Addr) bool {
	// An address literal "resolves" to itself without a query.
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	fwdCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	// The root dot makes the name absolute, so the resolver never tries it
	// under a resolv.conf search domain.
	answers, err := e.resolver.LookupIPAddr(fwdCtx, name+".")
	if err != nil {
		return false
	}
	for _, answer := range answers {
		got, ok := netip.AddrFromSlice(answer.IP)
		if ok && got.Unmap() == addr {
			return true
		}
	}
	return false
}

func (e *Enricher) attribute(src *Source) {
	if src.ReverseDNSVerified && src.BaseDomain != "" {
		if svc, ok := e.services[src.BaseDomain]; ok {
			src.Name, src.Type = svc.name, svc.kind
			return
		}
		src.Name = src.BaseDomain
		return
	}
	if asBase := baseDomain(src.ASDomain); asBase != "" {
		if svc, ok := e.services[asBase]; ok {
			src.Name, src.Type = svc.name, svc.kind
			return
		}
	}
	src.Name = src.ASName
}

// canonicalDomain lowercases name, drops the root dot and converts an
// internationalized name to the ASCII form DNS answers and the public suffix
// list use.
func canonicalDomain(name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for i := range len(name) {
		if name[i] >= 0x80 {
			return idna.Lookup.ToASCII(name)
		}
	}
	return name, nil
}

// baseDomain returns the registrable domain of a canonical name, or "" when
// it has none (a bare public suffix, a single label, an address literal).
func baseDomain(name string) string {
	if name == "" {
		return ""
	}
	base, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return ""
	}
	return base
}
