package enrich

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// DefaultLookupTimeout bounds each DNS query: the PTR lookup and the forward
// confirmation get one each.
const DefaultLookupTimeout = 2 * time.Second

// DefaultConcurrency is the number of lookups LookupAll runs at once when the
// caller does not choose.
const DefaultConcurrency = 8

type options struct {
	resolver    Resolver
	timeout     time.Duration
	serviceMap  string
	ipDatabases []string
}

// Option configures New. Options apply in order: WithResolver, WithDNSServer
// and WithOffline each replace the DNS choice of an earlier one.
type Option func(*options) error

// WithResolver queries r instead of the system resolver.
func WithResolver(r Resolver) Option {
	return func(o *options) error {
		if r == nil {
			return errors.New("resolver is nil")
		}
		o.resolver = r
		return nil
	}
}

// WithDNSServer sends every query to addr, a "host:port" such as
// "192.0.2.53:53", instead of the servers in the system configuration.
func WithDNSServer(addr string) Option {
	return func(o *options) error {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("parse DNS server %q: %w", addr, err)
		}
		if host == "" {
			return fmt.Errorf("parse DNS server %q: missing host", addr)
		}
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return fmt.Errorf("parse DNS server %q: port must be 1-65535", addr)
		}
		var dialer net.Dialer
		o.resolver = &net.Resolver{
			// Only the Go resolver dials through Dial; the cgo one would ask
			// the system's servers.
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		}
		return nil
	}
}

// WithLookupTimeout bounds each DNS query to d instead of
// DefaultLookupTimeout.
func WithLookupTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return fmt.Errorf("lookup timeout must be positive, got %s", d)
		}
		o.timeout = d
		return nil
	}
}

// WithOffline disables DNS: sources are attributed from the IP databases
// alone.
func WithOffline() Option {
	return func(o *options) error {
		o.resolver = nil
		return nil
	}
}

// WithServiceMap loads the reverse DNS service map at path, a CSV with the
// header base_reverse_dns,name,type such as parsedmarc's
// base_reverse_dns_map.csv. A later WithServiceMap replaces an earlier one.
func WithServiceMap(path string) Option {
	return func(o *options) error {
		if path == "" {
			return errors.New("service map path is empty")
		}
		o.serviceMap = path
		return nil
	}
}

// WithIPDatabase opens the MMDB file at path: IPinfo Lite, or MaxMind
// GeoLite2 or DB-IP Lite in their Country, City or ASN editions. It may be
// given more than once, as GeoLite2 splits country and ASN into two files;
// each field comes from the first database that has it.
func WithIPDatabase(path string) Option {
	return func(o *options) error {
		if path == "" {
			return errors.New("IP database path is empty")
		}
		o.ipDatabases = append(o.ipDatabases, path)
		return nil
	}
}
