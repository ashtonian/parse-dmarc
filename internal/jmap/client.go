// Package jmap reads report mail from one mailbox over JMAP (RFC 8620 core,
// RFC 8621 mail), for accounts such as Fastmail's that issue read-only API
// tokens.
//
// Nothing in this package can change the mailbox: Call sends only /get,
// /query, /changes and /queryChanges methods and refuses anything else before
// it reaches the network, and blobs are only downloaded. A read-only token
// therefore suffices, and with one the server enforces the same boundary.
//
// Every response body is read through a size limit (WithMaxResponseBytes,
// WithMaxBlobBytes), authenticated requests never follow a redirect to another
// host, and errors carry server text only after the token has been redacted
// from it. The package does no logging.
//
// A Client is safe for concurrent use. Fetch a Session at the start of each
// poll: the server may move its API or download URLs between sessions, and
// every other call is addressed through the Session it is given.
package jmap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	defaultMaxResponseBytes int64 = 8 << 20
	defaultMaxBlobBytes     int64 = 32 << 20

	// errorBodyLimit bounds how much of a non-2xx body is read looking for
	// problem details; errorTextBytes bounds how much server text an error
	// string carries.
	errorBodyLimit = 64 << 10
	errorTextBytes = 512

	maxRedirects = 10
)

// errRedirect marks a redirect the client refused to follow.
var errRedirect = errors.New("redirect refused")

// Client talks to one JMAP server with one bearer token.
type Client struct {
	sessionURL       string
	token            string
	http             *http.Client
	allowHTTP        bool
	maxResponseBytes int64
	maxBlobBytes     int64
	timeout          time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client, whose timeouts then apply instead of
// the defaults. Its redirect policy runs after the client's own, which still
// refuses to carry the token to another host.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.http = hc }
}

// WithTimeout bounds each request of the default HTTP client, which is 60
// seconds otherwise. It has no effect together with WithHTTPClient.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithInsecureHTTP allows http:// session, API and download URLs, for tests
// and local servers. The token then crosses the network in clear text.
func WithInsecureHTTP() Option {
	return func(c *Client) { c.allowHTTP = true }
}

// WithMaxResponseBytes bounds a session or API response body. The default is
// 8 MiB.
func WithMaxResponseBytes(n int64) Option {
	return func(c *Client) { c.maxResponseBytes = n }
}

// WithMaxBlobBytes bounds a downloaded blob. A larger blob is ErrBlobTooLarge,
// never a truncated message. The default is 32 MiB.
func WithMaxBlobBytes(n int64) Option {
	return func(c *Client) { c.maxBlobBytes = n }
}

// NewClient returns a client for the JMAP session resource at sessionURL,
// e.g. https://api.fastmail.com/jmap/session, authenticating with token.
// Without WithHTTPClient, each request times out after 60 seconds.
func NewClient(sessionURL, token string, opts ...Option) (*Client, error) {
	c := &Client{
		sessionURL:       sessionURL,
		token:            token,
		maxResponseBytes: defaultMaxResponseBytes,
		maxBlobBytes:     defaultMaxBlobBytes,
	}
	for _, opt := range opts {
		opt(c)
	}

	if token == "" {
		return nil, errors.New("JMAP token is empty")
	}
	// A token read from a file often keeps its trailing newline; sending it
	// would fail as an invalid header far from the cause.
	if strings.ContainsFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, errors.New("JMAP token contains whitespace or control characters")
	}
	if _, err := c.parseURL(sessionURL); err != nil {
		return nil, fmt.Errorf("JMAP session URL: %w", err)
	}
	if c.maxResponseBytes <= 0 {
		return nil, fmt.Errorf("max response bytes must be positive, got %d", c.maxResponseBytes)
	}
	if c.maxBlobBytes <= 0 {
		return nil, fmt.Errorf("max blob bytes must be positive, got %d", c.maxBlobBytes)
	}

	base := c.http
	if base == nil {
		base = defaultHTTPClient(c.timeout)
	}
	// A shallow copy shares the caller's transport and connection pool but
	// lets the redirect policy be installed without mutating their client.
	hc := *base
	next := base.CheckRedirect
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := c.checkRedirect(req, via); err != nil {
			return err
		}
		if next != nil {
			return next(req, via)
		}
		return nil
	}
	c.http = &hc

	return c, nil
}

// defaultTimeout bounds one request of the default HTTP client.
const defaultTimeout = 60 * time.Second

func defaultHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          16,
			MaxIdleConnsPerHost:   4,
			ForceAttemptHTTP2:     true,
		},
	}
}

// parseURL parses raw and checks it is an absolute URL the token may be sent
// to.
func (c *Client) parseURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("empty URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	return u, c.checkURL(u)
}

func (c *Client) checkURL(u *url.URL) error {
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && c.allowHTTP:
	case c.allowHTTP:
		return fmt.Errorf("URL %q must be http or https", u.Redacted())
	default:
		return fmt.Errorf("URL %q must be https", u.Redacted())
	}
	if u.Host == "" {
		return fmt.Errorf("URL %q has no host", u.Redacted())
	}
	if u.User != nil {
		return fmt.Errorf("URL %q must not carry credentials", u.Redacted())
	}
	return nil
}

// checkRedirect keeps every hop on the original request's host, so the bearer
// token is never handed to a host the session did not name.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("%w: stopped after %d redirects", errRedirect, maxRedirects)
	}
	from := via[0].URL
	if hostPort(req.URL) != hostPort(from) {
		return fmt.Errorf("%w: %s sent it to another host, %s", errRedirect, from.Host, req.URL.Host)
	}
	if err := c.checkURL(req.URL); err != nil {
		return fmt.Errorf("%w: %w", errRedirect, err)
	}
	return nil
}

func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// do sends req with the bearer token and returns the body of a 2xx response.
// A body over limit returns tooLarge instead of a truncated read.
func (c *Client) do(req *http.Request, limit int64, tooLarge error) ([]byte, error) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, c.statusError(resp)
	}
	if resp.ContentLength > limit {
		return nil, tooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, tooLarge
	}
	return body, nil
}

// sanitize prepares server-supplied text for an error string. The token is
// redacted before the text is cut, so the cut cannot leave a fragment of an
// echoed token behind.
func (c *Client) sanitize(s string) string {
	s = strings.ReplaceAll(s, c.token, "[redacted]")
	if len(s) > errorTextBytes {
		s = s[:errorTextBytes] + "..."
	}
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}
