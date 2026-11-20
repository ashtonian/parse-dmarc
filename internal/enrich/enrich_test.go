package enrich

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The IP database fixtures (testdata/gen/gen.go) hold 192.0.2.0/24
// (US, AS64496, example.com), 198.51.100.0/24 (DE, AS64497, example.net) and
// 2001:db8::/32 (NL, AS64498, example.org). 203.0.113.0/24 is in none.
const testServiceMap = "base_reverse_dns,name,type\n" +
	"example.com,Example Mail,Email Provider\n" +
	"example.net,Example Hosting,Web Host\n"

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// newTestEnricher builds an Enricher over the IPinfo Lite fixture and
// testServiceMap.
func newTestEnricher(t *testing.T, opts ...Option) *Enricher {
	t.Helper()
	base := []Option{
		WithIPDatabase(filepath.Join("testdata", "ipinfo-lite.mmdb")),
		WithServiceMap(writeFile(t, "map.csv", testServiceMap)),
	}
	e, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Error(err)
		}
	})
	return e
}

// fakeResolver answers from fixed tables. Forward names are keyed with the
// root dot, so a relative lookup, one the search list could rewrite, misses.
type fakeResolver struct {
	ptr     map[string][]string
	forward map[string][]netip.Addr
	// hang names queries ("PTR <addr>", "IP <name>") that block until their
	// context ends.
	hang map[string]bool
	// delay holds every query that long.
	delay time.Duration
	// onQuery, when set, runs as each query starts.
	onQuery func(query string)

	mu          sync.Mutex
	queries     []string
	inFlight    int
	maxInFlight int
}

func (f *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	defer f.end()
	if err := f.begin(ctx, "PTR "+addr); err != nil {
		return nil, err
	}
	names, ok := f.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	return names, nil
}

func (f *fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	defer f.end()
	if err := f.begin(ctx, "IP "+host); err != nil {
		return nil, err
	}
	addrs, ok := f.forward[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	answers := make([]net.IPAddr, 0, len(addrs))
	for _, a := range addrs {
		// net.Resolver may return an IPv4 answer in its 16-byte form.
		answers = append(answers, net.IPAddr{IP: net.IP(a.AsSlice()).To16()})
	}
	return answers, nil
}

func (f *fakeResolver) begin(ctx context.Context, query string) error {
	f.mu.Lock()
	f.queries = append(f.queries, query)
	f.inFlight++
	f.maxInFlight = max(f.maxInFlight, f.inFlight)
	f.mu.Unlock()

	if f.onQuery != nil {
		f.onQuery(query)
	}
	if f.hang[query] {
		<-ctx.Done()
		return ctx.Err()
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (f *fakeResolver) end() {
	f.mu.Lock()
	f.inFlight--
	f.mu.Unlock()
}

func (f *fakeResolver) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.queries)
}

func (f *fakeResolver) peak() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxInFlight
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		ptr: map[string][]string{
			"198.51.100.7":  {"Relay.Example.COM."},
			"198.51.100.66": {"mail.example.com."},
			"2001:db8::25":  {"mx1.mail.example.org."},
			"203.0.113.10":  {"203.0.113.10."},
			"203.0.113.11":  {"gone.example.com."},
			"203.0.113.12":  {"first.example.net.", "second.example.com."},
			"203.0.113.13":  {"localhost."},
		},
		forward: map[string][]netip.Addr{
			"relay.example.com.":    addrs("192.0.2.1", "198.51.100.7"),
			"mail.example.com.":     addrs("192.0.2.25"),
			"mx1.mail.example.org.": addrs("2001:db8::25"),
			"203.0.113.10.":         addrs("203.0.113.10"),
			"first.example.net.":    addrs("203.0.113.12"),
			"second.example.com.":   addrs("203.0.113.12"),
			"localhost.":            addrs("203.0.113.13"),
		},
	}
}

func TestLookup(t *testing.T) {
	hosting := Source{Country: "DE", ASN: 64497, ASName: "Example Hosting GmbH", ASDomain: "example.net"}
	with := func(base Source, edit func(*Source)) Source {
		edit(&base)
		return base
	}

	tests := []struct {
		name string
		ip   string
		want Source
	}{
		{
			name: "verified PTR in the map names the service",
			ip:   "198.51.100.7",
			want: with(hosting, func(s *Source) {
				s.IP = "198.51.100.7"
				s.ReverseDNS, s.ReverseDNSVerified, s.BaseDomain = "relay.example.com", true, "example.com"
				s.Name, s.Type = "Example Mail", "Email Provider"
			}),
		},
		{
			name: "IPv4-mapped address is looked up as IPv4 and reported as given",
			ip:   "::ffff:198.51.100.7",
			want: with(hosting, func(s *Source) {
				s.IP = "::ffff:198.51.100.7"
				s.ReverseDNS, s.ReverseDNSVerified, s.BaseDomain = "relay.example.com", true, "example.com"
				s.Name, s.Type = "Example Mail", "Email Provider"
			}),
		},
		{
			name: "spoofed PTR is reported but the AS names the service",
			ip:   "198.51.100.66",
			want: with(hosting, func(s *Source) {
				s.IP = "198.51.100.66"
				s.ReverseDNS, s.BaseDomain = "mail.example.com", "example.com"
				s.Name, s.Type = "Example Hosting", "Web Host"
			}),
		},
		{
			name: "no PTR falls back to the AS domain in the map",
			ip:   "198.51.100.8",
			want: with(hosting, func(s *Source) {
				s.IP = "198.51.100.8"
				s.Name, s.Type = "Example Hosting", "Web Host"
			}),
		},
		{
			name: "verified PTR outside the map is named by its base domain",
			ip:   "2001:db8::25",
			want: Source{
				IP: "2001:db8::25", ReverseDNS: "mx1.mail.example.org", ReverseDNSVerified: true,
				BaseDomain: "example.org", Name: "example.org",
				Country: "NL", ASN: 64498, ASName: "Example IPv6 B.V.", ASDomain: "example.org",
			},
		},
		{
			name: "no PTR and an AS domain outside the map is named by the AS",
			ip:   "2001:db8::99",
			want: Source{
				IP: "2001:db8::99", Name: "Example IPv6 B.V.",
				Country: "NL", ASN: 64498, ASName: "Example IPv6 B.V.", ASDomain: "example.org",
			},
		},
		{
			name: "address literal as PTR name is never verified",
			ip:   "203.0.113.10",
			want: Source{IP: "203.0.113.10", ReverseDNS: "203.0.113.10"},
		},
		{
			name: "PTR name that does not resolve is not verified",
			ip:   "203.0.113.11",
			want: Source{IP: "203.0.113.11", ReverseDNS: "gone.example.com", BaseDomain: "example.com"},
		},
		{
			name: "only the first PTR name is used",
			ip:   "203.0.113.12",
			want: Source{
				IP: "203.0.113.12", ReverseDNS: "first.example.net", ReverseDNSVerified: true,
				BaseDomain: "example.net", Name: "Example Hosting", Type: "Web Host",
			},
		},
		{
			name: "verified PTR without a registrable domain does not name the service",
			ip:   "203.0.113.13",
			want: Source{IP: "203.0.113.13", ReverseDNS: "localhost", ReverseDNSVerified: true},
		},
		{
			name: "address known nowhere",
			ip:   "203.0.113.7",
			want: Source{IP: "203.0.113.7"},
		},
		{
			name: "invalid address",
			ip:   "not-an-ip",
			want: Source{IP: "not-an-ip"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestEnricher(t, WithResolver(newFakeResolver()))
			if got := e.Lookup(t.Context(), tt.ip); got != tt.want {
				t.Errorf("Lookup(%q)\n got %+v\nwant %+v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestLookupQueries(t *testing.T) {
	tests := []struct {
		ip   string
		want []string
	}{
		{"198.51.100.7", []string{"PTR 198.51.100.7", "IP relay.example.com."}},
		{"::ffff:198.51.100.7", []string{"PTR 198.51.100.7", "IP relay.example.com."}},
		{"198.51.100.8", []string{"PTR 198.51.100.8"}},
		{"203.0.113.10", []string{"PTR 203.0.113.10"}},
		{"not-an-ip", nil},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			r := newFakeResolver()
			e := newTestEnricher(t, WithResolver(r))
			e.Lookup(t.Context(), tt.ip)
			if got := r.seen(); !slices.Equal(got, tt.want) {
				t.Errorf("queries = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLookupTimeout(t *testing.T) {
	tests := []struct {
		name    string
		hang    string
		opts    []Option
		elapsed time.Duration
		want    Source
	}{
		{
			name:    "PTR query",
			hang:    "PTR 198.51.100.7",
			elapsed: DefaultLookupTimeout,
			want: Source{
				IP: "198.51.100.7", Name: "Example Hosting", Type: "Web Host",
				Country: "DE", ASN: 64497, ASName: "Example Hosting GmbH", ASDomain: "example.net",
			},
		},
		{
			name:    "forward confirmation",
			hang:    "IP relay.example.com.",
			elapsed: DefaultLookupTimeout,
			want: Source{
				IP: "198.51.100.7", ReverseDNS: "relay.example.com", BaseDomain: "example.com",
				Name: "Example Hosting", Type: "Web Host",
				Country: "DE", ASN: 64497, ASName: "Example Hosting GmbH", ASDomain: "example.net",
			},
		},
		{
			name:    "custom timeout",
			hang:    "PTR 198.51.100.7",
			opts:    []Option{WithLookupTimeout(300 * time.Millisecond)},
			elapsed: 300 * time.Millisecond,
			want: Source{
				IP: "198.51.100.7", Name: "Example Hosting", Type: "Web Host",
				Country: "DE", ASN: 64497, ASName: "Example Hosting GmbH", ASDomain: "example.net",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newFakeResolver()
				r.hang = map[string]bool{tt.hang: true}
				e := newTestEnricher(t, append([]Option{WithResolver(r)}, tt.opts...)...)

				start := time.Now()
				got := e.Lookup(t.Context(), "198.51.100.7")
				if elapsed := time.Since(start); elapsed != tt.elapsed {
					t.Errorf("Lookup took %s, want %s", elapsed, tt.elapsed)
				}
				if got != tt.want {
					t.Errorf("Lookup\n got %+v\nwant %+v", got, tt.want)
				}
			})
		})
	}
}

func TestOffline(t *testing.T) {
	r := newFakeResolver()
	e := newTestEnricher(t, WithResolver(r), WithOffline())

	got := e.Lookup(t.Context(), "198.51.100.7")
	want := Source{
		IP: "198.51.100.7", Name: "Example Hosting", Type: "Web Host",
		Country: "DE", ASN: 64497, ASName: "Example Hosting GmbH", ASDomain: "example.net",
	}
	if got != want {
		t.Errorf("Lookup\n got %+v\nwant %+v", got, want)
	}
	e.LookupAll(t.Context(), []string{"192.0.2.25", "2001:db8::25"}, 2)
	if q := r.seen(); len(q) != 0 {
		t.Errorf("offline enricher sent DNS queries %q", q)
	}

	// A later DNS option replaces WithOffline.
	online := newTestEnricher(t, WithOffline(), WithResolver(r))
	online.Lookup(t.Context(), "198.51.100.7")
	if len(r.seen()) == 0 {
		t.Error("WithResolver after WithOffline sent no DNS queries")
	}
}

func TestAttributionOrder(t *testing.T) {
	e := &Enricher{services: map[string]service{
		"example.com": {name: "Example Mail", kind: "Email Provider"},
		"example.net": {name: "Example Hosting", kind: "Web Host"},
	}}
	tests := []struct {
		name     string
		src      Source
		wantName string
		wantType string
	}{
		{
			name:     "verified PTR in map beats AS domain in map",
			src:      Source{ReverseDNSVerified: true, BaseDomain: "example.com", ASDomain: "example.net", ASName: "AS"},
			wantName: "Example Mail", wantType: "Email Provider",
		},
		{
			name:     "verified PTR outside map beats AS domain in map",
			src:      Source{ReverseDNSVerified: true, BaseDomain: "example.org", ASDomain: "example.net", ASName: "AS"},
			wantName: "example.org",
		},
		{
			name:     "unverified PTR in map yields to AS domain in map",
			src:      Source{BaseDomain: "example.com", ASDomain: "example.net", ASName: "AS"},
			wantName: "Example Hosting", wantType: "Web Host",
		},
		{
			name:     "unverified PTR in map yields to AS name",
			src:      Source{BaseDomain: "example.com", ASDomain: "example.org", ASName: "AS"},
			wantName: "AS",
		},
		{
			name:     "verified PTR without base domain yields to AS domain",
			src:      Source{ReverseDNSVerified: true, ReverseDNS: "localhost", ASDomain: "example.net"},
			wantName: "Example Hosting", wantType: "Web Host",
		},
		{
			name:     "AS domain matches by base domain",
			src:      Source{ASDomain: "mx.example.net", ASName: "AS"},
			wantName: "Example Hosting", wantType: "Web Host",
		},
		{
			name:     "AS name without AS domain",
			src:      Source{ASName: "AS"},
			wantName: "AS",
		},
		{
			name: "nothing known",
			src:  Source{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := tt.src
			e.attribute(&src)
			if src.Name != tt.wantName || src.Type != tt.wantType {
				t.Errorf("attribute() = (%q, %q), want (%q, %q)", src.Name, src.Type, tt.wantName, tt.wantType)
			}
		})
	}
}

func TestLookupAll(t *testing.T) {
	r := newFakeResolver()
	e := newTestEnricher(t, WithResolver(r))

	ips := []string{"198.51.100.7", "not-an-ip", "198.51.100.7", "2001:db8::25", "198.51.100.66"}
	got := e.LookupAll(t.Context(), ips, 2)

	reference := newTestEnricher(t, WithResolver(newFakeResolver()))
	want := map[string]Source{}
	for _, ip := range ips {
		want[ip] = reference.Lookup(t.Context(), ip)
	}
	if len(got) != len(want) {
		t.Fatalf("LookupAll returned %d sources, want %d: %+v", len(got), len(want), got)
	}
	for ip, w := range want {
		if got[ip] != w {
			t.Errorf("LookupAll[%q]\n got %+v\nwant %+v", ip, got[ip], w)
		}
	}

	ptrQueries := 0
	for _, q := range r.seen() {
		if strings.HasPrefix(q, "PTR 198.51.100.7") {
			ptrQueries++
		}
	}
	if ptrQueries != 1 {
		t.Errorf("duplicate address looked up %d times, want 1", ptrQueries)
	}

	if got := e.LookupAll(t.Context(), nil, 4); got == nil || len(got) != 0 {
		t.Errorf("LookupAll(nil) = %v, want an empty map", got)
	}
}

func TestLookupAllConcurrency(t *testing.T) {
	ips := make([]string, 20)
	for i := range ips {
		ips[i] = fmt.Sprintf("203.0.113.%d", 100+i)
	}
	tests := []struct {
		concurrency int
		want        int
	}{
		{concurrency: 1, want: 1},
		{concurrency: 3, want: 3},
		{concurrency: 0, want: DefaultConcurrency},
		{concurrency: 50, want: len(ips)},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.concurrency), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newFakeResolver()
				r.delay = time.Second
				e := newTestEnricher(t, WithResolver(r))

				got := e.LookupAll(t.Context(), ips, tt.concurrency)
				if len(got) != len(ips) {
					t.Errorf("LookupAll returned %d sources, want %d", len(got), len(ips))
				}
				if peak := r.peak(); peak != tt.want {
					t.Errorf("%d lookups in flight at once, want %d", peak, tt.want)
				}
			})
		})
	}
}

func TestLookupAllCancel(t *testing.T) {
	t.Run("before the call", func(t *testing.T) {
		e := newTestEnricher(t, WithResolver(newFakeResolver()))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if got := e.LookupAll(ctx, []string{"198.51.100.7", "2001:db8::25"}, 2); len(got) != 0 {
			t.Errorf("LookupAll after cancel = %+v, want nothing", got)
		}
	})

	t.Run("during the call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		r := newFakeResolver()
		r.onQuery = func(query string) {
			if query == "PTR 198.51.100.8" {
				cancel()
			}
		}
		e := newTestEnricher(t, WithResolver(r))

		got := e.LookupAll(ctx, []string{"198.51.100.7", "198.51.100.8", "2001:db8::25"}, 1)
		if len(got) != 1 || got["198.51.100.7"].Name != "Example Mail" {
			t.Errorf("LookupAll = %+v, want only the lookup that finished before cancel", got)
		}
	})
}

func TestNewOptionErrors(t *testing.T) {
	notMMDB := writeFile(t, "map.csv", testServiceMap)
	missing := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		name string
		opt  Option
	}{
		{"nil resolver", WithResolver(nil)},
		{"DNS server without port", WithDNSServer("192.0.2.53")},
		{"DNS server without host", WithDNSServer(":53")},
		{"DNS server port 0", WithDNSServer("192.0.2.53:0")},
		{"DNS server named port", WithDNSServer("192.0.2.53:domain")},
		{"zero timeout", WithLookupTimeout(0)},
		{"negative timeout", WithLookupTimeout(-time.Second)},
		{"empty service map path", WithServiceMap("")},
		{"missing service map", WithServiceMap(missing)},
		{"empty IP database path", WithIPDatabase("")},
		{"missing IP database", WithIPDatabase(missing)},
		{"IP database that is not an MMDB", WithIPDatabase(notMMDB)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := New(tt.opt)
			if err == nil {
				_ = e.Close()
				t.Fatal("New succeeded, want an error")
			}
		})
	}

	for _, server := range []string{"192.0.2.53:53", "[2001:db8::53]:53", "dns.example:5353"} {
		e, err := New(WithDNSServer(server))
		if err != nil {
			t.Errorf("WithDNSServer(%q): %v", server, err)
			continue
		}
		_ = e.Close()
	}
}

// TestWithDNSServer runs the real resolver against a DNS server on loopback.
func TestWithDNSServer(t *testing.T) {
	server, asked := serveDNS(t,
		map[string]string{"25.2.0.192.in-addr.arpa.": "relay.example.com."},
		map[string]netip.Addr{"relay.example.com.": netip.MustParseAddr("192.0.2.25")},
	)
	e := newTestEnricher(t, WithDNSServer(server))

	got := e.Lookup(t.Context(), "192.0.2.25")
	want := Source{
		IP: "192.0.2.25", ReverseDNS: "relay.example.com", ReverseDNSVerified: true,
		BaseDomain: "example.com", Name: "Example Mail", Type: "Email Provider",
		Country: "US", ASN: 64496, ASName: "Example Mail Inc.", ASDomain: "example.com",
	}
	if got != want {
		t.Errorf("Lookup\n got %+v\nwant %+v", got, want)
	}

	// Only the absolute names: no search-domain variant was tried.
	questions := asked()
	slices.Sort(questions)
	questions = slices.Compact(questions)
	wantQuestions := []string{
		"TypeA relay.example.com.",
		"TypeAAAA relay.example.com.",
		"TypePTR 25.2.0.192.in-addr.arpa.",
	}
	if !slices.Equal(questions, wantQuestions) {
		t.Errorf("server was asked %q, want %q", questions, wantQuestions)
	}
}

// serveDNS answers PTR and A queries from the given records on a loopback
// UDP port and returns its address and the questions it was asked. A name
// in neither table gets NXDOMAIN; any other query for a known name gets an
// empty answer.
func serveDNS(t *testing.T, ptr map[string]string, a map[string]netip.Addr) (string, func() []string) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu        sync.Mutex
		questions []string
		done      = make(chan struct{})
	)
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			resp, question, err := answerDNS(buf[:n], ptr, a)
			if err != nil {
				t.Errorf("answer DNS query: %v", err)
				continue
			}
			mu.Lock()
			questions = append(questions, question)
			mu.Unlock()
			_, _ = conn.WriteTo(resp, from)
		}
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		<-done
	})
	return conn.LocalAddr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(questions)
	}
}

func answerDNS(query []byte, ptr map[string]string, a map[string]netip.Addr) ([]byte, string, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return nil, "", err
	}
	q, err := p.Question()
	if err != nil {
		return nil, "", err
	}
	name := strings.ToLower(q.Name.String())
	target, hasPTR := ptr[name]
	addr, hasA := a[name]

	resp := dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		Authoritative:      true,
		RecursionDesired:   hdr.RecursionDesired,
		RecursionAvailable: true,
	}
	if !hasPTR && !hasA {
		resp.RCode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, resp)
	if err := b.StartQuestions(); err != nil {
		return nil, "", err
	}
	if err := b.Question(q); err != nil {
		return nil, "", err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, "", err
	}
	rh := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}
	switch {
	case q.Type == dnsmessage.TypePTR && hasPTR:
		target, err := dnsmessage.NewName(target)
		if err != nil {
			return nil, "", err
		}
		err = b.PTRResource(rh, dnsmessage.PTRResource{PTR: target})
		if err != nil {
			return nil, "", err
		}
	case q.Type == dnsmessage.TypeA && hasA:
		if err := b.AResource(rh, dnsmessage.AResource{A: addr.As4()}); err != nil {
			return nil, "", err
		}
	}
	msg, err := b.Finish()
	return msg, q.Type.String() + " " + name, err
}
