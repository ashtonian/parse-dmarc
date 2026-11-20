package archive

import (
	"context"
	"crypto/rand"
	"io"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

// The integration test runs against a real S3 server when these name it and
// an existing bucket, for example a local MinIO with a bucket archive-test:
//
//	PARSE_DMARC_TEST_S3_ENDPOINT=http://127.0.0.1:9000 PARSE_DMARC_TEST_S3_BUCKET=archive-test \
//	PARSE_DMARC_TEST_S3_ACCESS_KEY_ID=minio PARSE_DMARC_TEST_S3_SECRET_ACCESS_KEY=minio12345 \
//	  go test ./internal/archive/
//
// PARSE_DMARC_TEST_S3_REGION is optional. The test writes under a prefix of
// its own and removes what it wrote.
const (
	testS3EndpointEnv  = "PARSE_DMARC_TEST_S3_ENDPOINT"
	testS3BucketEnv    = "PARSE_DMARC_TEST_S3_BUCKET"
	testS3AccessKeyEnv = "PARSE_DMARC_TEST_S3_ACCESS_KEY_ID"
	testS3SecretEnv    = "PARSE_DMARC_TEST_S3_SECRET_ACCESS_KEY"
	testS3RegionEnv    = "PARSE_DMARC_TEST_S3_REGION"
)

func TestS3Integration(t *testing.T) {
	cfg := Config{
		Endpoint:        os.Getenv(testS3EndpointEnv),
		Bucket:          os.Getenv(testS3BucketEnv),
		AccessKeyID:     os.Getenv(testS3AccessKeyEnv),
		SecretAccessKey: os.Getenv(testS3SecretEnv),
		Region:          os.Getenv(testS3RegionEnv),
		Prefix:          "parse-dmarc-test/" + rand.Text(),
	}
	if cfg.Endpoint == "" || cfg.Bucket == "" || cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		t.Skipf("set %s, %s, %s and %s to run against a real S3 server",
			testS3EndpointEnv, testS3BucketEnv, testS3AccessKeyEnv, testS3SecretEnv)
	}

	s, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	report := Report{
		Kind:           KindTLSRPT,
		OrgName:        "Example Mail, Inc.",
		ReportID:       "2026-11-20T00:00:00Z_example.com",
		Domain:         "example.com,example.net",
		Begin:          time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC),
		Raw:            gzipBytes(t, `{"organization-name":"Example Mail, Inc."}`),
		RawFilename:    "example.net!example.com!1763596800!1763683199.json.gz",
		RawContentType: "application/tlsrpt+gzip",
		Parsed:         map[string]any{"organization-name": "Example Mail, Inc."},
	}
	keys, err := s.Put(t.Context(), report)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, key := range []string{keys.Raw, keys.Parsed} {
			if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
				t.Errorf("remove %s: %v", key, err)
			}
		}
	})

	parsed, err := encodeJSON(report.Parsed)
	if err != nil {
		t.Fatal(err)
	}
	checkStoredObject(t, s, keys.Raw, report.Raw, "application/tlsrpt+gzip")
	checkStoredObject(t, s, keys.Parsed, parsed, "application/json")

	if _, err := s.Put(t.Context(), report); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	var stored []string
	for obj := range s.client.ListObjects(t.Context(), s.bucket, minio.ListObjectsOptions{Prefix: s.prefix, Recursive: true}) {
		if obj.Err != nil {
			t.Fatalf("list %s: %v", s.prefix, obj.Err)
		}
		stored = append(stored, obj.Key)
	}
	want := []string{keys.Parsed, keys.Raw}
	slices.Sort(stored)
	slices.Sort(want)
	if !slices.Equal(stored, want) {
		t.Errorf("after two Puts the prefix holds %v, want %v", stored, want)
	}
}

func checkStoredObject(t *testing.T, s *S3, key string, wantBody []byte, wantType string) {
	t.Helper()
	obj, err := s.client.GetObject(t.Context(), s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	defer func() { _ = obj.Close() }()

	body, err := io.ReadAll(obj)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	if string(body) != string(wantBody) {
		t.Errorf("%s holds %q, want %q", key, body, wantBody)
	}
	info, err := obj.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", key, err)
	}
	if info.ContentType != wantType {
		t.Errorf("%s Content-Type = %q, want %q", key, info.ContentType, wantType)
	}
	if got := info.UserMetadata["Org-Name"]; got != "Example%20Mail%2C%20Inc." {
		t.Errorf("%s org-name metadata = %q, want the percent-encoded reporter", key, got)
	}
}
