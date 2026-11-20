package archive

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
)

// PathStyle selects where the bucket name goes in request URLs.
type PathStyle string

// Path styles.
const (
	// PathStyleAuto uses virtual-hosted style for AWS, Google and Aliyun
	// endpoints, except an https bucket whose name holds a dot, which the
	// wildcard certificate would not cover, and path style elsewhere.
	PathStyleAuto PathStyle = "auto"
	// PathStylePath puts the bucket in the path: https://host/bucket/key.
	PathStylePath PathStyle = "path"
	// PathStyleVirtual puts the bucket in the host: https://bucket.host/key.
	PathStyleVirtual PathStyle = "virtual"
)

// Defaults for unset Config fields.
const (
	DefaultRegion    = "us-east-1"
	DefaultPathStyle = PathStyleAuto
	DefaultTimeout   = 30 * time.Second
)

const (
	awsEndpoint = "s3.amazonaws.com"

	tcpKeepAlive          = 30 * time.Second
	idleConnTimeout       = 90 * time.Second
	expectContinueTimeout = time.Second
	// Ingestion writes one report, as two sequential objects, at a time.
	maxIdleConnsPerHost = 2
)

// ErrBucketNotFound is returned by New when the bucket does not exist.
var ErrBucketNotFound = errors.New("archive bucket does not exist")

// Config selects the archive bucket and how to reach it.
type Config struct {
	// Endpoint is the S3 API endpoint: a URL such as
	// https://s3.example.com:8443 or http://minio:9000, or a host:port, which
	// means https. Empty means AWS S3.
	Endpoint string
	// Bucket must exist already; New checks it.
	Bucket string
	// Region signs requests; default us-east-1. An AWS bucket in another
	// region needs its own.
	Region string

	// AccessKeyID and SecretAccessKey are static credentials, set together.
	// With neither set, credentials come from the first source that has
	// them: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, MINIO_ROOT_USER and
	// MINIO_ROOT_PASSWORD, the AWS shared credentials file, the mc config
	// file, then the EC2, ECS or EKS role.
	AccessKeyID     string
	SecretAccessKey string
	// SessionToken goes with temporary static credentials.
	SessionToken string

	// Prefix goes in front of every key. It is normalized to no leading
	// slash and one trailing slash.
	Prefix string
	// PathStyle is auto, path or virtual; default auto, which suits AWS and
	// self-hosted servers. Set virtual for a custom endpoint that only
	// serves virtual-hosted requests.
	PathStyle PathStyle
	// CAFile is a PEM bundle that verifies the endpoint's certificate, in
	// place of the system roots, for a server whose certificate a private CA
	// issued.
	CAFile string
	// Timeout bounds each S3 call, retries included; default 30s. minio-go
	// retries a failed attempt for up to about 8s, and a call that runs out
	// of time first reports only "context deadline exceeded", not why the
	// attempts failed.
	Timeout time.Duration
}

// Validate reports the first problem with c. Unset optional fields are
// valid: New applies their defaults.
func (c Config) Validate() error {
	if c.Bucket == "" {
		return errors.New("archive bucket is required")
	}
	if err := s3utils.CheckValidBucketName(c.Bucket); err != nil {
		return fmt.Errorf("archive bucket %q: %w", c.Bucket, err)
	}
	if _, _, err := parseEndpoint(c.Endpoint); err != nil {
		return err
	}
	if (c.AccessKeyID == "") != (c.SecretAccessKey == "") {
		return errors.New("archive access key ID and secret access key must be set together")
	}
	if c.SessionToken != "" && c.AccessKeyID == "" {
		return errors.New("archive session token needs an access key ID and secret access key")
	}
	switch c.PathStyle {
	case "", PathStyleAuto, PathStylePath, PathStyleVirtual:
	default:
		return fmt.Errorf("archive path style %q: must be auto, path or virtual", c.PathStyle)
	}
	if c.Timeout < 0 {
		return fmt.Errorf("archive timeout %s must not be negative", c.Timeout)
	}
	return validatePrefix(normalizePrefix(c.Prefix))
}

func (c Config) withDefaults() Config {
	if c.Region == "" {
		c.Region = DefaultRegion
	}
	if c.PathStyle == "" {
		c.PathStyle = DefaultPathStyle
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	c.Prefix = normalizePrefix(c.Prefix)
	return c
}

// parseEndpoint returns the host[:port] to dial and whether it speaks TLS.
// Errors never repeat the endpoint, which may carry credentials.
func parseEndpoint(endpoint string) (host string, secure bool, err error) {
	if endpoint == "" {
		return awsEndpoint, true, nil
	}
	raw := endpoint
	if !strings.Contains(endpoint, "://") {
		raw = "https://" + endpoint
	}
	u, err := url.Parse(raw)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return "", false, fmt.Errorf("parse archive endpoint: %w", err)
	}
	switch {
	case u.User != nil:
		return "", false, errors.New("archive endpoint must not carry credentials: set the access key ID and secret access key")
	case u.Scheme != "http" && u.Scheme != "https":
		return "", false, fmt.Errorf("archive endpoint scheme %q: must be http or https", u.Scheme)
	case u.Host == "":
		return "", false, errors.New("archive endpoint has no host")
	case u.Path != "" && u.Path != "/", u.RawQuery != "", u.Fragment != "":
		return "", false, fmt.Errorf("archive endpoint %s must be a host and port, without a path or query", u.Host)
	}
	return u.Host, u.Scheme == "https", nil
}

// S3 archives reports to an S3-compatible bucket. It is safe for concurrent
// use.
type S3 struct {
	client  *minio.Client
	bucket  string
	prefix  string
	timeout time.Duration
}

// New connects to the configured bucket and checks, with HeadBucket, that it
// exists and accepts the credentials. On AWS that check needs s3:ListBucket;
// Put needs s3:PutObject.
func New(ctx context.Context, cfg Config) (*S3, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	host, secure, err := parseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	transport, err := newTransport(cfg)
	if err != nil {
		return nil, err
	}
	client, err := minio.New(host, &minio.Options{
		Creds:        newCredentials(cfg),
		Secure:       secure,
		Transport:    transport,
		Region:       cfg.Region,
		BucketLookup: bucketLookup(cfg.PathStyle),
	})
	if err != nil {
		return nil, fmt.Errorf("create S3 client for %s: %w", host, err)
	}

	s := &S3{client: client, bucket: cfg.Bucket, prefix: cfg.Prefix, timeout: cfg.Timeout}
	if err := s.checkBucket(ctx, host, cfg); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *S3) checkBucket(ctx context.Context, host string, cfg Config) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		var resp minio.ErrorResponse
		if errors.As(err, &resp) && resp.Region != "" && resp.Region != cfg.Region {
			return fmt.Errorf("check bucket %q at %s: the bucket is in region %s, not %s: %w",
				s.bucket, host, resp.Region, cfg.Region, err)
		}
		return fmt.Errorf("check bucket %q at %s with %s: %w", s.bucket, host, credentialSource(cfg), err)
	}
	if !exists {
		return fmt.Errorf("%w: %q at %s", ErrBucketNotFound, s.bucket, host)
	}
	return nil
}

// Put writes r's attachment and its parsed form. The keys depend only on r,
// so writing the same report again overwrites both objects.
func (s *S3) Put(ctx context.Context, r Report) (Keys, error) {
	if err := r.validate(); err != nil {
		return Keys{}, err
	}
	parsed, err := encodeJSON(r.Parsed)
	if err != nil {
		return Keys{}, fmt.Errorf("encode %s report %q: %w", r.Kind, r.ReportID, err)
	}

	keys := objectKeys(s.prefix, r)
	meta := metadata(r)
	if err := s.putObject(ctx, keys.Raw, r.Raw, rawContentType(r.RawContentType, r.Raw), meta); err != nil {
		return Keys{}, err
	}
	if err := s.putObject(ctx, keys.Parsed, parsed, jsonContentType, meta); err != nil {
		return Keys{}, err
	}
	return keys, nil
}

func (s *S3) putObject(ctx context.Context, key string, body []byte, contentType string, meta map[string]string) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{
		ContentType:  contentType,
		UserMetadata: meta,
		// The server rejects a body damaged in transit, and buckets with
		// Object Lock refuse uploads without it.
		SendContentMd5: true,
	})
	if err != nil {
		return fmt.Errorf("put s3://%s/%s: %w", s.bucket, key, err)
	}
	return nil
}

func newTransport(cfg Config) (*http.Transport, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read archive CA file %s: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in archive CA file %s", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: tcpKeepAlive,
		}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: expectContinueTimeout,
		IdleConnTimeout:       idleConnTimeout,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		// A response body must reach the caller as stored, never decoded
		// in transit.
		DisableCompression: true,
	}, nil
}

func newCredentials(cfg Config) *credentials.Credentials {
	if cfg.AccessKeyID != "" {
		return credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken)
	}
	return credentials.NewChainCredentials([]credentials.Provider{
		&credentials.EnvAWS{},
		&credentials.EnvMinio{},
		&credentials.FileAWSCredentials{},
		&credentials.FileMinioClient{},
		// Fetched over the client's transport, so its timeouts apply.
		&credentials.IAM{},
	})
}

// credentialSource names where the credentials came from, for errors.
func credentialSource(cfg Config) string {
	if cfg.AccessKeyID != "" {
		return "static credentials"
	}
	return "the default credential chain"
}

func bucketLookup(style PathStyle) minio.BucketLookupType {
	switch style {
	case PathStylePath:
		return minio.BucketLookupPath
	case PathStyleVirtual:
		return minio.BucketLookupDNS
	default:
		return minio.BucketLookupAuto
	}
}
