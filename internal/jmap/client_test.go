package jmap

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func assertNoToken(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), testToken) {
		t.Fatalf("error carries the token: %v", err)
	}
}

func TestNewClientValidates(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		token   string
		opts    []Option
		wantErr string
	}{
		{name: "https", url: "https://api.fastmail.com/jmap/session", token: testToken},
		{name: "http refused", url: "http://api.fastmail.com/jmap/session", token: testToken, wantErr: "must be https"},
		{name: "http with WithInsecureHTTP", url: "http://127.0.0.1:8080/jmap/session", token: testToken, opts: []Option{WithInsecureHTTP()}},
		{name: "relative URL", url: "/jmap/session", token: testToken, wantErr: "must be https"},
		{name: "credentials in URL", url: "https://user:secret@api.fastmail.com/jmap/session", token: testToken, wantErr: "credentials"},
		{name: "empty token", url: "https://api.fastmail.com/jmap/session", wantErr: "token is empty"},
		{name: "token with newline", url: "https://api.fastmail.com/jmap/session", token: testToken + "\n", wantErr: "whitespace"},
		{name: "zero response limit", url: "https://api.fastmail.com/jmap/session", token: testToken, opts: []Option{WithMaxResponseBytes(0)}, wantErr: "response bytes"},
		{name: "negative blob limit", url: "https://api.fastmail.com/jmap/session", token: testToken, opts: []Option{WithMaxBlobBytes(-1)}, wantErr: "blob bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(tt.url, tt.token, tt.opts...)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewClient: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error carries the URL password: %v", err)
			}
		})
	}
}

// The default client must not inherit http.DefaultClient's lack of timeouts.
func TestDefaultHTTPClientHasTimeouts(t *testing.T) {
	c, err := NewClient("https://api.fastmail.com/jmap/session", testToken)
	if err != nil {
		t.Fatal(err)
	}
	if c.http.Timeout == 0 {
		t.Fatal("default client has no overall timeout")
	}
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default transport is %T", c.http.Transport)
	}
	if tr.TLSHandshakeTimeout == 0 || tr.ResponseHeaderTimeout == 0 {
		t.Fatal("default transport lacks TLS handshake or response header timeouts")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("default transport allows TLS below 1.2")
	}
}

func TestSession(t *testing.T) {
	f := newFastmail(t, fakeConfig{maxObjectsInGet: 4096})
	s := f.session(t, f.client(t))

	if s.APIURL != f.api.URL+"/jmap/api/" {
		t.Errorf("APIURL = %q", s.APIURL)
	}
	if !strings.HasPrefix(s.DownloadURL, f.content.URL) {
		t.Errorf("DownloadURL = %q, want it on the content host", s.DownloadURL)
	}
	want := CoreCapability{MaxSizeRequest: 10000000, MaxConcurrentRequests: 10, MaxCallsInRequest: 50, MaxObjectsInGet: 4096}
	if s.Core != want {
		t.Errorf("Core = %+v, want %+v", s.Core, want)
	}
	if _, ok := s.Capabilities["https://www.fastmail.com/dev/maskedemail"]; !ok {
		t.Error("vendor capability dropped")
	}

	id, acct, err := s.MailAccount()
	if err != nil {
		t.Fatal(err)
	}
	if id != testAccountID || !acct.IsReadOnly || !acct.IsPersonal || acct.Name != "reports@example.com" {
		t.Errorf("MailAccount = %s %+v", id, acct)
	}
	if _, ok := acct.AccountCapabilities[CapabilityMail]; !ok {
		t.Error("account lacks its mail capability")
	}
}

func TestMailAccountMissing(t *testing.T) {
	f := newFastmail(t, fakeConfig{editSession: func(s string) string {
		return strings.Replace(s, `"urn:ietf:params:jmap:mail": "u1a2b3c4d"`, `"urn:ietf:params:jmap:submission": "u1a2b3c4d"`, 1)
	}})
	s := f.session(t, f.client(t))
	if _, _, err := s.MailAccount(); err == nil {
		t.Fatal("want an error for a session without a primary mail account")
	}
}

// The token goes wherever the session points, so a session pointing at
// plain HTTP or at an unusable download template is refused up front.
func TestSessionRejectsUnsafeURLs(t *testing.T) {
	tests := []struct {
		name    string
		edit    func(string) string
		wantErr string
	}{
		{
			name:    "http apiUrl",
			edit:    func(s string) string { return strings.Replace(s, `"apiUrl": "https://`, `"apiUrl": "http://`, 1) },
			wantErr: "apiUrl",
		},
		{
			name: "http downloadUrl",
			edit: func(s string) string {
				return strings.Replace(s, `"downloadUrl": "https://`, `"downloadUrl": "http://`, 1)
			},
			wantErr: "downloadUrl",
		},
		{
			name:    "downloadUrl without blobId",
			edit:    func(s string) string { return strings.Replace(s, "{blobId}", "blob", 1) },
			wantErr: "{blobId}",
		},
		{
			name:    "missing apiUrl",
			edit:    func(s string) string { return strings.Replace(s, `"apiUrl"`, `"apiEndpoint"`, 1) },
			wantErr: "apiUrl",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFastmail(t, fakeConfig{editSession: tt.edit})
			_, err := f.client(t).Session(t.Context())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// A wrong or revoked token is ErrUnauthorized on every kind of request, and
// the error never echoes the token that was sent.
func TestUnauthorized(t *testing.T) {
	f := newFastmail(t, fakeConfig{emails: 1})
	s := f.session(t, f.client(t))
	const wrong = "fmu1-revoked-0000000000000000"
	revoked := f.clientWithToken(t, wrong)

	tests := []struct {
		name string
		run  func() error
	}{
		{"session", func() error { _, err := revoked.Session(t.Context()); return err }},
		{"api", func() error { _, err := revoked.Mailboxes(t.Context(), s, testAccountID); return err }},
		{"download", func() error {
			_, err := revoked.DownloadBlob(t.Context(), s, testAccountID, "G00000", "m.eml", "message/rfc822")
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("want ErrUnauthorized, got %v", err)
			}
			if strings.Contains(err.Error(), wrong) {
				t.Fatalf("error carries the token: %v", err)
			}
		})
	}
}

func TestRequestError(t *testing.T) {
	f := newFastmail(t, fakeConfig{apiHook: func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"type":"urn:ietf:params:jmap:error:limit","limit":"maxSizeRequest","status":400,"detail":"Request too large"}`))
		return true
	}})
	c := f.client(t)
	_, err := c.Mailboxes(t.Context(), f.session(t, c), testAccountID)

	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatalf("want *RequestError, got %v", err)
	}
	want := RequestError{Status: 400, Type: "urn:ietf:params:jmap:error:limit", Limit: "maxSizeRequest", Detail: "Request too large"}
	if *reqErr != want {
		t.Fatalf("got %+v, want %+v", *reqErr, want)
	}
}

func TestMethodError(t *testing.T) {
	f := newFastmail(t, fakeConfig{})
	c := f.client(t)
	_, err := c.QueryEmailIDs(t.Context(), f.session(t, c), "u-not-mine", reportMailboxID)

	var methodErr *MethodError
	if !errors.As(err, &methodErr) {
		t.Fatalf("want *MethodError, got %v", err)
	}
	if methodErr.Method != "Email/query" || methodErr.Type != "accountNotFound" {
		t.Fatalf("got %+v", *methodErr)
	}
}

// A proxy error page is no problem document: the error carries the status and
// a bounded, token-free piece of the body.
func TestNon2xxWithoutProblemDocument(t *testing.T) {
	page := "<html><body>Bad Gateway. Request header: Bearer " + testToken + "</body></html>" + strings.Repeat("x", 100<<10)
	f := newFastmail(t, fakeConfig{apiHook: func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(page))
		return true
	}})
	c := f.client(t)
	_, err := c.Mailboxes(t.Context(), f.session(t, c), testAccountID)
	if err == nil || !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), "Bad Gateway") {
		t.Fatalf("want an HTTP 502 error with a body snippet, got %v", err)
	}
	assertNoToken(t, err)
	if len(err.Error()) > 2*errorTextBytes {
		t.Fatalf("error is %d bytes, want the body cut short", len(err.Error()))
	}
}

func TestResponseLimit(t *testing.T) {
	f := newFastmail(t, fakeConfig{})
	full := f.client(t)
	s := f.session(t, full)

	if _, err := f.client(t, WithMaxResponseBytes(256)).Mailboxes(t.Context(), s, testAccountID); err == nil || !strings.Contains(err.Error(), "exceeds 256 bytes") {
		t.Fatalf("want a response limit error, got %v", err)
	}
	if _, err := f.client(t, WithMaxResponseBytes(256)).Session(t.Context()); err == nil {
		t.Fatal("want a session over the limit refused")
	}
}

// A same-host redirect such as /.well-known/jmap is followed with the token;
// a redirect to another host is refused before the token reaches it.
func TestRedirects(t *testing.T) {
	f := newFastmail(t, fakeConfig{})
	var otherHits atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		f.serveSession(w, r)
	}))
	t.Cleanup(other.Close)

	tests := []struct {
		name    string
		start   string
		refused bool
	}{
		{"same host", f.api.URL + "/.well-known/jmap", false},
		{"other host", f.api.URL + "/redirect?to=" + url.QueryEscape(other.URL+"/jmap/session"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.start, testToken, WithHTTPClient(f.api.Client()))
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Session(t.Context())
			if !tt.refused {
				if err != nil {
					t.Fatalf("Session: %v", err)
				}
				return
			}
			if !errors.Is(err, errRedirect) {
				t.Fatalf("want a refused redirect, got %v", err)
			}
			if n := otherHits.Load(); n != 0 {
				t.Fatalf("other host received %d requests", n)
			}
		})
	}
}

// The caller's own redirect policy still runs, after the host check.
func TestRedirectKeepsCallerPolicy(t *testing.T) {
	f := newFastmail(t, fakeConfig{})
	hc := *f.api.Client()
	var called atomic.Bool
	hc.CheckRedirect = func(*http.Request, []*http.Request) error {
		called.Store(true)
		return errors.New("caller says no")
	}
	c, err := NewClient(f.api.URL+"/.well-known/jmap", testToken, WithHTTPClient(&hc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Session(t.Context()); err == nil || !called.Load() {
		t.Fatalf("want the caller's CheckRedirect to refuse, got %v", err)
	}
}

func TestCallRefusesWriteMethods(t *testing.T) {
	f := newFastmail(t, fakeConfig{})
	c := f.client(t)
	s := f.session(t, c)

	for _, method := range []string{"Email/set", "Mailbox/set", "Email/import", "Email/copy", "Blob/copy", "EmailSubmission/set", "Email/parse", "Core/echo", "get", "/get"} {
		t.Run(method, func(t *testing.T) {
			_, err := c.Call(t.Context(), s, []string{CapabilityCore, CapabilityMail}, Invocation{Name: method, Args: json.RawMessage(`{}`), CallID: "0"})
			if !errors.Is(err, errWriteMethod) {
				t.Fatalf("want %s refused, got %v", method, err)
			}
		})
	}
	// A refused call in a batch stops the whole batch.
	get, _ := NewInvocation("Mailbox/get", "a", map[string]any{"accountId": testAccountID})
	set, _ := NewInvocation("Mailbox/set", "b", map[string]any{"accountId": testAccountID})
	if _, err := c.Call(t.Context(), s, []string{CapabilityCore, CapabilityMail}, get, set); !errors.Is(err, errWriteMethod) {
		t.Fatalf("want the batch refused, got %v", err)
	}
	if got := f.receivedMethods(); len(got) != 0 {
		t.Fatalf("server received %v", got)
	}
}

// Responses are matched to calls by call id, whatever order they arrive in,
// and a call left unanswered is an error.
func TestCallMatchesByCallID(t *testing.T) {
	answer := func(w http.ResponseWriter, r *http.Request, keep func([]Invocation) []Invocation) {
		var req struct {
			MethodCalls []Invocation `json:"methodCalls"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var out []Invocation
		for _, call := range req.MethodCalls {
			out = append(out, Invocation{Name: call.Name, Args: json.RawMessage(`{"echo":"` + call.CallID + `"}`), CallID: call.CallID})
		}
		writeJSON(w, map[string]any{"methodResponses": keep(out), "sessionState": "s"})
	}
	tests := []struct {
		name    string
		keep    func([]Invocation) []Invocation
		wantErr bool
	}{
		{"reversed", func(in []Invocation) []Invocation {
			out := make([]Invocation, len(in))
			for i, inv := range in {
				out[len(in)-1-i] = inv
			}
			return out
		}, false},
		{"one missing", func(in []Invocation) []Invocation { return in[1:] }, true},
		{"unknown call id", func(in []Invocation) []Invocation {
			in[0].CallID = "zz"
			return in
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFastmail(t, fakeConfig{apiHook: func(w http.ResponseWriter, r *http.Request) bool {
				answer(w, r, tt.keep)
				return true
			}})
			c := f.client(t)
			calls := []Invocation{
				{Name: "Mailbox/get", Args: json.RawMessage(`{}`), CallID: "m"},
				{Name: "Email/query", Args: json.RawMessage(`{}`), CallID: "q"},
				{Name: "Email/get", Args: json.RawMessage(`{}`), CallID: "g"},
			}
			got, err := c.Call(t.Context(), f.session(t, c), []string{CapabilityCore, CapabilityMail}, calls...)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for i, call := range calls {
				if got[i].CallID != call.CallID || got[i].Name != call.Name || string(got[i].Args) != `{"echo":"`+call.CallID+`"}` {
					t.Errorf("response %d = %s %s %s, want the answer to %s", i, got[i].Name, got[i].CallID, got[i].Args, call.CallID)
				}
			}
		})
	}
}

func TestCallHonoursSessionLimits(t *testing.T) {
	f := newFastmail(t, fakeConfig{})
	c := f.client(t)
	s := *f.session(t, c)
	s.Core.MaxCallsInRequest = 1
	calls := []Invocation{
		{Name: "Mailbox/get", CallID: "a"},
		{Name: "Mailbox/get", CallID: "b"},
	}
	if _, err := c.Call(t.Context(), &s, []string{CapabilityMail}, calls...); err == nil || !strings.Contains(err.Error(), "maxCallsInRequest") {
		t.Fatalf("want a maxCallsInRequest error, got %v", err)
	}

	s.Core.MaxCallsInRequest = 0
	s.Core.MaxSizeRequest = 64
	big, _ := NewInvocation("Email/get", "a", map[string]any{"ids": strings.Split(strings.Repeat("M00000,", 20), ",")})
	if _, err := c.Call(t.Context(), &s, []string{CapabilityMail}, big); err == nil || !strings.Contains(err.Error(), "maxSizeRequest") {
		t.Fatalf("want a maxSizeRequest error, got %v", err)
	}
	if got := f.receivedMethods(); len(got) != 0 {
		t.Fatalf("server received %v", got)
	}
}

// One Client and Session serve concurrent intake work.
func TestConcurrentUse(t *testing.T) {
	f := newFastmail(t, fakeConfig{emails: 40, maxObjectsInGet: 7})
	c := f.client(t)
	s := f.session(t, c)

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 8 {
		wg.Go(func() {
			ids, err := c.QueryEmailIDs(t.Context(), s, testAccountID, reportMailboxID)
			if err != nil {
				errs <- err
				return
			}
			emails, _, err := c.GetEmails(t.Context(), s, testAccountID, ids)
			if err != nil {
				errs <- err
				return
			}
			if _, err := c.DownloadBlob(t.Context(), s, testAccountID, emails[0].BlobID, "m.eml", "message/rfc822"); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
