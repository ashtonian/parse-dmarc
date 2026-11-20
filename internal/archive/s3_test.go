package archive

import (
	"bytes"
	"compress/gzip"
	"crypto/md5" // #nosec G501 -- Content-MD5 is what S3 checks
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	fakeBucket    = "reports"
	fakeAccessKey = "test-access-key"
	fakeSecret    = "test-secret-key"
	// fakeElsewhere is a bucket the fake places in another region.
	fakeElsewhere = "elsewhere"
)

// fakeS3 is the part of the S3 API that New and Put use, path style:
// HeadBucket and PutObject. Requests not signed with fakeAccessKey get 403.
type fakeS3 struct {
	t *testing.T

	mu      sync.Mutex
	objects map[string]fakeObject
	puts    int
}

type fakeObject struct {
	body            []byte
	contentType     string
	contentEncoding string
	metadata        map[string]string
}

func newFakeS3(t *testing.T) *fakeS3 {
	return &fakeS3{t: t, objects: map[string]fakeObject{}}
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Authorization"), "Credential="+fakeAccessKey+"/") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")

	switch {
	case r.Method == http.MethodHead && key == "" && bucket == fakeElsewhere:
		w.Header().Set("X-Amz-Bucket-Region", "eu-west-1")
		w.WriteHeader(http.StatusMovedPermanently)
	case r.Method == http.MethodHead && key == "" && bucket == fakeBucket:
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodHead && key == "":
		w.WriteHeader(http.StatusNotFound)
	case r.Method == http.MethodPut && key != "" && bucket == fakeBucket:
		f.putObject(w, r, key)
	default:
		f.t.Errorf("fake S3: unexpected request %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func (f *fakeS3) putObject(w http.ResponseWriter, r *http.Request, key string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Errorf("fake S3: read body of %s: %v", key, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sum := md5.Sum(body) // #nosec G401 -- Content-MD5 is what S3 checks
	if r.Header.Get("Content-MD5") != base64.StdEncoding.EncodeToString(sum[:]) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `<Error><Code>BadDigest</Code><Message>Content-MD5 mismatch</Message></Error>`)
		return
	}

	meta := map[string]string{}
	for name, values := range r.Header {
		if strings.HasPrefix(name, "X-Amz-Meta-") {
			meta[strings.ToLower(strings.TrimPrefix(name, "X-Amz-Meta-"))] = values[0]
		}
	}

	f.mu.Lock()
	f.objects[key] = fakeObject{
		body:            body,
		contentType:     r.Header.Get("Content-Type"),
		contentEncoding: r.Header.Get("Content-Encoding"),
		metadata:        meta,
	}
	f.puts++
	f.mu.Unlock()

	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	w.WriteHeader(http.StatusOK)
}

func (f *fakeS3) snapshot() (map[string]fakeObject, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	objects := make(map[string]fakeObject, len(f.objects))
	for k, v := range f.objects {
		objects[k] = v
	}
	return objects, f.puts
}

// startTLSServer serves h over TLS and returns the server and a CA file that
// trusts its certificate. tlsConfig may be nil.
func startTLSServer(t *testing.T, h http.Handler, tlsConfig *tls.Config) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = tlsConfig
	// Handshakes the tests make fail on purpose would otherwise be logged.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, caFile
}

// startFakeS3 serves the fake over TLS and returns a config that trusts its
// certificate through CAFile.
func startFakeS3(t *testing.T) (*fakeS3, Config) {
	t.Helper()
	fake := newFakeS3(t)
	srv, caFile := startTLSServer(t, fake, nil)

	return fake, Config{
		Endpoint:        srv.URL,
		Bucket:          fakeBucket,
		AccessKeyID:     fakeAccessKey,
		SecretAccessKey: fakeSecret,
		Prefix:          "/archive//",
		PathStyle:       PathStylePath,
		CAFile:          caFile,
		Timeout:         5 * time.Second,
	}
}

func gzipBytes(t *testing.T, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := io.WriteString(zw, data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestS3Put(t *testing.T) {
	fake, cfg := startFakeS3(t)
	s, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	parsed := map[string]any{"org_name": "google.com", "report_id": "12345678901234567890", "messages": 3.0}
	report := Report{
		Kind:        KindDMARC,
		OrgName:     "google.com",
		ReportID:    "12345678901234567890",
		Domain:      "example.com",
		Begin:       time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC),
		Raw:         gzipBytes(t, `<?xml version="1.0"?><feedback/>`),
		RawFilename: "google.com!example.com!1763596800!1763683199.xml.gz",
		Parsed:      parsed,
	}
	want := Keys{
		Raw:    "archive/raw/dmarc/year=2026/month=11/day=20/google.com_12345678901234567890_0dbd5d06fd190cf2.raw.xml.gz",
		Parsed: "archive/parsed/dmarc/year=2026/month=11/day=20/google.com_12345678901234567890_0dbd5d06fd190cf2.json",
	}

	keys, err := s.Put(t.Context(), report)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if keys != want {
		t.Fatalf("Put keys:\n got %+v\nwant %+v", keys, want)
	}

	objects, _ := fake.snapshot()
	wantMeta := map[string]string{
		"kind":      "dmarc",
		"org-name":  "google.com",
		"report-id": "12345678901234567890",
		"domain":    "example.com",
	}

	raw, ok := objects[want.Raw]
	if !ok {
		t.Fatalf("raw object %s not written; have %v", want.Raw, keysOf(objects))
	}
	if !bytes.Equal(raw.body, report.Raw) {
		t.Error("raw object differs from the attachment")
	}
	if raw.contentType != "application/x-gzip" {
		t.Errorf("raw Content-Type = %q, want the sniffed application/x-gzip", raw.contentType)
	}
	if raw.contentEncoding != "" {
		t.Errorf("raw Content-Encoding = %q, want none: clients would decompress the original", raw.contentEncoding)
	}
	if !reflect.DeepEqual(raw.metadata, wantMeta) {
		t.Errorf("raw metadata = %v, want %v", raw.metadata, wantMeta)
	}

	parsedObj, ok := objects[want.Parsed]
	if !ok {
		t.Fatalf("parsed object %s not written; have %v", want.Parsed, keysOf(objects))
	}
	if parsedObj.contentType != "application/json" {
		t.Errorf("parsed Content-Type = %q, want application/json", parsedObj.contentType)
	}
	if !bytes.HasSuffix(parsedObj.body, []byte("}\n")) || bytes.Count(parsedObj.body, []byte("\n")) != 1 {
		t.Errorf("parsed object %q is not one compact JSON line", parsedObj.body)
	}
	var decoded map[string]any
	if err := json.Unmarshal(parsedObj.body, &decoded); err != nil {
		t.Fatalf("parsed object is not JSON: %v", err)
	}
	if !reflect.DeepEqual(decoded, parsed) {
		t.Errorf("parsed object = %v, want %v", decoded, parsed)
	}
	if !reflect.DeepEqual(parsedObj.metadata, wantMeta) {
		t.Errorf("parsed metadata = %v, want %v", parsedObj.metadata, wantMeta)
	}

	// A retry of the same report lands on the same two keys.
	again, err := s.Put(t.Context(), report)
	if err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if again != keys {
		t.Errorf("second Put keys = %+v, want %+v", again, keys)
	}
	objects, puts := fake.snapshot()
	if len(objects) != 2 || puts != 4 {
		t.Errorf("after two Puts: %d objects from %d writes, want 2 objects from 4 writes", len(objects), puts)
	}
}

func TestS3PutInvalidReport(t *testing.T) {
	fake, cfg := startFakeS3(t)
	s, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	valid := Report{
		Kind: KindDMARC, OrgName: "google.com", ReportID: "1", Domain: "example.com",
		Begin: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC), Raw: []byte("<feedback/>"), Parsed: struct{}{},
	}
	cases := []struct {
		name   string
		mutate func(*Report)
	}{
		{"unknown kind", func(r *Report) { r.Kind = "ruf" }},
		{"no begin time", func(r *Report) { r.Begin = time.Time{} }},
		{"no attachment", func(r *Report) { r.Raw = nil }},
		{"no parsed form", func(r *Report) { r.Parsed = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			tc.mutate(&r)
			if _, err := s.Put(t.Context(), r); !errors.Is(err, ErrInvalidReport) {
				t.Errorf("Put = %v, want ErrInvalidReport", err)
			}
		})
	}
	if objects, _ := fake.snapshot(); len(objects) != 0 {
		t.Errorf("invalid reports wrote %v", keysOf(objects))
	}
}

func TestNewChecksBucket(t *testing.T) {
	const secret = "rejected-secret-value"
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantIs  error
		wantMsg string
	}{
		{
			name:   "missing bucket",
			mutate: func(c *Config) { c.Bucket = "absent" },
			wantIs: ErrBucketNotFound,
		},
		{
			name:    "rejected credentials",
			mutate:  func(c *Config) { c.AccessKeyID, c.SecretAccessKey = "wrong-key", secret },
			wantMsg: "static credentials",
		},
		{
			name:    "bucket in another region",
			mutate:  func(c *Config) { c.Bucket = fakeElsewhere },
			wantMsg: "region eu-west-1, not us-east-1",
		},
		{
			name:    "unreadable CA file",
			mutate:  func(c *Config) { c.CAFile = filepath.Join(t.TempDir(), "missing.pem") },
			wantMsg: "read archive CA file",
		},
		{
			name:    "CA file without certificates",
			mutate:  func(c *Config) { c.CAFile = writeFile(t, "empty.pem", "not a certificate") },
			wantMsg: "no certificates found",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, cfg := startFakeS3(t)
			tc.mutate(&cfg)

			_, err := New(t.Context(), cfg)
			if err == nil {
				t.Fatal("New succeeded, want an error")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("New = %v, want %v", err, tc.wantIs)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("New = %q, want it to mention %q", err, tc.wantMsg)
			}
			if strings.Contains(err.Error(), cfg.SecretAccessKey) {
				t.Errorf("New error %q reveals the secret access key", err)
			}
		})
	}
}

// The transport trusts the CA file in place of the system roots and refuses
// TLS below 1.2.
func TestTransportTLS(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	current, currentCA := startTLSServer(t, ok, nil)
	legacy, legacyCA := startTLSServer(t, ok, &tls.Config{
		MinVersion: tls.VersionTLS10, // #nosec G402 -- the server the client must refuse
		MaxVersion: tls.VersionTLS11,
	})

	cases := []struct {
		name    string
		url     string
		caFile  string
		wantErr string
	}{
		{"trusted through the CA file", current.URL, currentCA, ""},
		{"system roots only", current.URL, "", "certificate"},
		{"TLS 1.1 server", legacy.URL, legacyCA, "protocol version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			transport, err := newTransport(Config{CAFile: tc.caFile, Timeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(transport.CloseIdleConnections)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := transport.RoundTrip(req)
			if err == nil {
				_ = resp.Body.Close()
			}
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("request failed: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("request error = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	valid := Config{Bucket: "reports"}
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"defaults", func(*Config) {}, false},
		{"https URL endpoint", func(c *Config) { c.Endpoint = "https://s3.example.com:8443" }, false},
		{"http URL endpoint", func(c *Config) { c.Endpoint = "http://minio:9000/" }, false},
		{"host and port endpoint", func(c *Config) { c.Endpoint = "s3.example.com:8443" }, false},
		{"static credentials", func(c *Config) { c.AccessKeyID, c.SecretAccessKey, c.SessionToken = "id", "secret", "token" }, false},
		{"virtual path style", func(c *Config) { c.PathStyle = PathStyleVirtual }, false},
		{"prefix", func(c *Config) { c.Prefix = "/team/dmarc" }, false},

		{"no bucket", func(c *Config) { c.Bucket = "" }, true},
		{"invalid bucket name", func(c *Config) { c.Bucket = "my bucket" }, true},
		{"unsupported scheme", func(c *Config) { c.Endpoint = "ftp://s3.example.com" }, true},
		{"endpoint with path", func(c *Config) { c.Endpoint = "https://s3.example.com/bucket" }, true},
		{"endpoint with query", func(c *Config) { c.Endpoint = "https://s3.example.com?region=x" }, true},
		{"unparsable endpoint", func(c *Config) { c.Endpoint = "https://[::1" }, true},
		{"access key without secret", func(c *Config) { c.AccessKeyID = "id" }, true},
		{"secret without access key", func(c *Config) { c.SecretAccessKey = "secret" }, true},
		{"session token alone", func(c *Config) { c.SessionToken = "token" }, true},
		{"unknown path style", func(c *Config) { c.PathStyle = "dns" }, true},
		{"negative timeout", func(c *Config) { c.Timeout = -time.Second }, true},
		{"parent prefix element", func(c *Config) { c.Prefix = "a/../b" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

// An endpoint that carries credentials is refused without repeating them.
func TestConfigValidateEndpointCredentials(t *testing.T) {
	for _, endpoint := range []string{"https://user:hunter2-secret@s3.example.com", "https://user:hunter2-secret@[::1"} {
		err := Config{Bucket: "reports", Endpoint: endpoint}.Validate()
		if err == nil {
			t.Errorf("Validate accepted endpoint %q", endpoint)
			continue
		}
		if strings.Contains(err.Error(), "hunter2-secret") {
			t.Errorf("Validate error %q reveals the endpoint password", err)
		}
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func keysOf(objects map[string]fakeObject) []string {
	keys := make([]string, 0, len(objects))
	for k := range objects {
		keys = append(keys, k)
	}
	return keys
}
