package storage

import (
	"context"
	"testing"
	"time"

	"github.com/dmarcguardhq/parse-dmarc/internal/enrich"
)

func TestSources(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s *Storage) {
		ctx := context.Background()
		if _, err := s.SaveReport(ctx, identityReport("google.com", "s1", "example.com")); err != nil {
			t.Fatal(err)
		}

		missing, err := s.SourcesMissing(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(missing) != 1 || missing[0] != "192.0.2.1" {
			t.Fatalf("missing = %v, want the record's address", missing)
		}

		src := enrich.Source{IP: "192.0.2.1", ReverseDNS: "mail-a.example.net", ReverseDNSVerified: true,
			BaseDomain: "example.net", Name: "Example Mail", Type: "Email Provider", Country: "US", ASN: 64496, ASName: "EXAMPLE-AS"}
		if err := s.SaveSources(ctx, []enrich.Source{src}); err != nil {
			t.Fatal(err)
		}
		// Saving again updates the row.
		src.Name = "Example Mail Inc."
		if err := s.SaveSources(ctx, []enrich.Source{src}); err != nil {
			t.Fatal(err)
		}

		if missing, err = s.SourcesMissing(ctx, 10); err != nil || len(missing) != 0 {
			t.Fatalf("missing after save = %v, %v", missing, err)
		}

		todo, err := s.SourcesToLookUp(ctx, []string{"192.0.2.1", "198.51.100.1", "198.51.100.1", ""}, time.Now().Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(todo) != 1 || todo[0] != "198.51.100.1" {
			t.Fatalf("to look up = %v, want only the unknown address, once", todo)
		}
		// An entry older than the cutoff is looked up again.
		if todo, err = s.SourcesToLookUp(ctx, []string{"192.0.2.1"}, time.Now().Add(time.Hour)); err != nil || len(todo) != 1 {
			t.Fatalf("stale entry not returned: %v, %v", todo, err)
		}

		top, err := s.GetTopSourceIPs(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(top) != 1 || top[0].Name != "Example Mail Inc." || !top[0].ReverseDNSVerified || top[0].ASN != 64496 || top[0].Country != "US" {
			t.Fatalf("top sources = %+v", top)
		}
	})
}
