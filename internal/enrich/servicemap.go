package enrich

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// serviceMapHeader is the header of parsedmarc's base_reverse_dns_map.csv.
var serviceMapHeader = []string{"base_reverse_dns", "name", "type"}

// service is one service map row.
type service struct {
	name string
	kind string
}

func loadServiceMap(path string) (map[string]service, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("load service map: %w", err)
	}
	defer func() { _ = f.Close() }()

	services, err := parseServiceMap(f)
	if err != nil {
		return nil, fmt.Errorf("load service map %s: %w", path, err)
	}
	return services, nil
}

// parseServiceMap reads the CSV into a map keyed by canonical base domain.
// Rows whose fields are all blank are skipped. A row without a domain or a
// name, or one that maps an already mapped domain differently, is an error:
// the file is the operator's, and a typo should stop startup rather than
// silently misattribute senders.
func parseServiceMap(r io.Reader) (map[string]service, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = len(serviceMapHeader)
	cr.ReuseRecord = true

	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	for i := range header {
		header[i] = strings.ToLower(strings.TrimSpace(header[i]))
	}
	header[0] = strings.TrimPrefix(header[0], "\uFEFF")
	if !slices.Equal(header, serviceMapHeader) {
		return nil, fmt.Errorf("header is %q, want %q",
			strings.Join(header, ","), strings.Join(serviceMapHeader, ","))
	}

	services := make(map[string]service)
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return services, nil
		}
		if err != nil {
			return nil, err
		}
		line, _ := cr.FieldPos(0)

		domain := strings.TrimSpace(row[0])
		svc := service{name: strings.TrimSpace(row[1]), kind: strings.TrimSpace(row[2])}
		switch {
		case domain == "" && svc.name == "" && svc.kind == "":
			continue
		case domain == "":
			return nil, fmt.Errorf("line %d: base_reverse_dns is empty", line)
		case svc.name == "":
			return nil, fmt.Errorf("line %d: name is empty for %s", line, domain)
		}

		key, err := canonicalDomain(domain)
		if err == nil && key == "" {
			err = errors.New("not a domain")
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: base_reverse_dns %q: %w", line, domain, err)
		}
		if prev, ok := services[key]; ok && prev != svc {
			return nil, fmt.Errorf("line %d: %s is already mapped to %q (%s)", line, key, prev.name, prev.kind)
		}
		services[key] = svc
	}
}
