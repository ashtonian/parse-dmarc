package jmap

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testToken     = "fmu1-3f9c2a7d-0123456789abcdef0123456789abcdef-0-0"
	testAccountID = "u1a2b3c4d"
)

// fastmailSession is shaped like api.fastmail.com/jmap/session for an account
// with a read-only token. {{API}} and {{CONTENT}} become the fake's servers,
// the second standing in for www.fastmailusercontent.com.
const fastmailSession = `{
  "username": "reports@example.com",
  "apiUrl": "{{API}}/jmap/api/",
  "downloadUrl": "{{CONTENT}}/jmap/download/{accountId}/{blobId}/{name}?type={type}",
  "uploadUrl": "{{API}}/jmap/upload/{accountId}/",
  "eventSourceUrl": "{{API}}/jmap/event/",
  "state": "cyrus-12046746;p-5;vfs-0",
  "capabilities": {
    "urn:ietf:params:jmap:core": {
      "maxSizeUpload": 250000000,
      "maxConcurrentUpload": 10,
      "maxSizeRequest": 10000000,
      "maxConcurrentRequests": 10,
      "maxCallsInRequest": 50,
      {{MAXGET}}
      "maxObjectsInSet": 4096,
      "collationAlgorithms": ["i;ascii-numeric", "i;ascii-casemap", "i;octet"]
    },
    "urn:ietf:params:jmap:mail": {},
    "urn:ietf:params:jmap:submission": {},
    "https://www.fastmail.com/dev/maskedemail": {}
  },
  "accounts": {
    "u1a2b3c4d": {
      "name": "reports@example.com",
      "isPersonal": true,
      "isReadOnly": true,
      "accountCapabilities": {
        "urn:ietf:params:jmap:core": {},
        "urn:ietf:params:jmap:mail": {
          "maxMailboxesPerEmail": 1000,
          "maxMailboxDepth": null,
          "maxSizeMailboxName": 490,
          "maxSizeAttachmentsPerEmail": 50000000,
          "emailQuerySortOptions": ["receivedAt", "from", "to", "subject", "size"],
          "mayCreateTopLevelMailbox": false
        }
      }
    }
  },
  "primaryAccounts": {
    "urn:ietf:params:jmap:core": "u1a2b3c4d",
    "urn:ietf:params:jmap:mail": "u1a2b3c4d"
  }
}`

// fastmailMailboxes has the report folder nested as Reports/julep, a second
// julep under Archive, and a DMARC folder under the inbox.
const fastmailMailboxes = `[
  {"id": "mb-inbox", "name": "Inbox", "parentId": null, "role": "inbox"},
  {"id": "mb-archive", "name": "Archive", "parentId": null, "role": "archive"},
  {"id": "mb-reports", "name": "Reports", "parentId": null, "role": null},
  {"id": "mb-julep", "name": "julep", "parentId": "mb-reports", "role": null},
  {"id": "mb-archive-julep", "name": "julep", "parentId": "mb-archive", "role": null},
  {"id": "mb-dmarc", "name": "DMARC", "parentId": "mb-inbox", "role": null}
]`

// quietLog drops the handshake errors httptest servers log when a test ends
// with a connection still being set up.
var quietLog = log.New(io.Discard, "", 0)

// reportMailboxID is the mailbox the fake's emails are in.
const reportMailboxID = "mb-julep"

type fakeConfig struct {
	// emails is the number of emails in Reports/julep.
	emails int
	// maxObjectsInGet is enforced on Email/get; it is advertised in the
	// session unless hideMaxObjectsInGet is set.
	maxObjectsInGet     int
	hideMaxObjectsInGet bool
	// queryLimit caps the limit of an Email/query, as servers may.
	queryLimit     int
	ignorePosition bool
	// total, when set, is the Email/query total reported instead of the real
	// one.
	total int
	// blobs are served in addition to the emails' raw messages.
	blobs map[string][]byte
	// chunkedDownloads streams blobs without a Content-Length.
	chunkedDownloads bool
	// editSession rewrites the session JSON before it is served.
	editSession func(string) string
	// apiHook, when it returns true, has answered an API request itself.
	apiHook func(w http.ResponseWriter, r *http.Request) bool
}

type fakeFastmail struct {
	cfg     fakeConfig
	api     *httptest.Server
	content *httptest.Server
	emails  []Email
	blobs   map[string][]byte

	mu        sync.Mutex
	methods   []string
	downloads []download
}

// download is what the content server decoded from a download URL.
type download struct {
	name, mediaType string
}

func newFastmail(t *testing.T, cfg fakeConfig) *fakeFastmail {
	t.Helper()
	f := &fakeFastmail{cfg: cfg, blobs: map[string][]byte{}}
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := range cfg.emails {
		id := fmt.Sprintf("M%05d", i)
		blobID := fmt.Sprintf("G%05d", i)
		f.emails = append(f.emails, Email{
			ID:         id,
			BlobID:     blobID,
			MessageID:  []string{fmt.Sprintf("%d@google.com", i)},
			ReceivedAt: start.Add(time.Duration(i) * time.Minute),
			Subject:    fmt.Sprintf("Report domain: example.com Submitter: google.com Report-ID: %d", i),
			From:       []EmailAddress{{Email: "noreply-dmarc-support@google.com"}},
			Size:       4096,
		})
		f.blobs[blobID] = []byte("From: noreply-dmarc-support@google.com\r\nSubject: report " + strconv.Itoa(i) + "\r\n\r\nbody")
	}
	for id, blob := range cfg.blobs {
		f.blobs[id] = blob
	}

	content := http.NewServeMux()
	content.HandleFunc("GET /jmap/download/{accountId}/{blobId}/{name}", f.serveDownload)
	f.content = httptest.NewUnstartedServer(content)
	f.content.Config.ErrorLog = quietLog
	f.content.StartTLS()
	t.Cleanup(f.content.Close)

	api := http.NewServeMux()
	api.HandleFunc("GET /jmap/session", f.serveSession)
	api.HandleFunc("GET /.well-known/jmap", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/jmap/session", http.StatusTemporaryRedirect)
	})
	api.HandleFunc("GET /redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("to"), http.StatusFound)
	})
	api.HandleFunc("POST /jmap/api/", f.serveAPI)
	f.api = httptest.NewUnstartedServer(api)
	f.api.Config.ErrorLog = quietLog
	f.api.StartTLS()
	t.Cleanup(f.api.Close)

	return f
}

// client returns a Client for the fake. Both servers present httptest's one
// certificate, so the API server's client trusts the content server too.
func (f *fakeFastmail) client(t *testing.T, opts ...Option) *Client {
	t.Helper()
	return f.clientWithToken(t, testToken, opts...)
}

func (f *fakeFastmail) clientWithToken(t *testing.T, token string, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{WithHTTPClient(f.api.Client())}, opts...)
	c, err := NewClient(f.api.URL+"/jmap/session", token, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fakeFastmail) session(t *testing.T, c *Client) *Session {
	t.Helper()
	s, err := c.Session(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// receivedMethods returns every method name the API has been sent.
func (f *fakeFastmail) receivedMethods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.methods)
}

func (f *fakeFastmail) receivedDownloads() []download {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.downloads)
}

func authorized(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer "+testToken
}

func (f *fakeFastmail) serveSession(w http.ResponseWriter, r *http.Request) {
	if !authorized(r) {
		http.Error(w, "Authorization header not a valid format", http.StatusUnauthorized)
		return
	}
	maxGet := ""
	if f.cfg.maxObjectsInGet > 0 && !f.cfg.hideMaxObjectsInGet {
		maxGet = fmt.Sprintf(`"maxObjectsInGet": %d,`, f.cfg.maxObjectsInGet)
	}
	body := strings.NewReplacer("{{API}}", f.api.URL, "{{CONTENT}}", f.content.URL, "{{MAXGET}}", maxGet).Replace(fastmailSession)
	if f.cfg.editSession != nil {
		body = f.cfg.editSession(body)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func (f *fakeFastmail) serveAPI(w http.ResponseWriter, r *http.Request) {
	if !authorized(r) {
		http.Error(w, "Authorization header not a valid format", http.StatusUnauthorized)
		return
	}
	if f.cfg.apiHook != nil && f.cfg.apiHook(w, r) {
		return
	}

	var req struct {
		Using       []string     `json:"using"`
		MethodCalls []Invocation `json:"methodCalls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, "urn:ietf:params:jmap:error:notRequest", err.Error())
		return
	}
	if !slices.Contains(req.Using, CapabilityMail) {
		writeProblem(w, "urn:ietf:params:jmap:error:unknownCapability", "mail capability not requested")
		return
	}

	responses := make([]Invocation, 0, len(req.MethodCalls))
	for _, call := range req.MethodCalls {
		f.mu.Lock()
		f.methods = append(f.methods, call.Name)
		f.mu.Unlock()

		name, args := f.dispatch(call)
		raw, err := json.Marshal(args)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		responses = append(responses, Invocation{Name: name, Args: raw, CallID: call.CallID})
	}
	writeJSON(w, map[string]any{"methodResponses": responses, "sessionState": "cyrus-12046746;p-5;vfs-0"})
}

func (f *fakeFastmail) dispatch(call Invocation) (string, any) {
	var args struct {
		AccountID string   `json:"accountId"`
		IDs       []string `json:"ids"`
		Filter    struct {
			InMailbox string `json:"inMailbox"`
		} `json:"filter"`
		Position       int  `json:"position"`
		Limit          int  `json:"limit"`
		CalculateTotal bool `json:"calculateTotal"`
	}
	if err := json.Unmarshal(call.Args, &args); err != nil {
		return "error", map[string]string{"type": "invalidArguments", "description": err.Error()}
	}
	if args.AccountID != testAccountID {
		return "error", map[string]string{"type": "accountNotFound"}
	}

	switch call.Name {
	case "Mailbox/get":
		return call.Name, map[string]any{
			"accountId": testAccountID,
			"state":     "m1",
			"list":      json.RawMessage(fastmailMailboxes),
			"notFound":  []string{},
		}

	case "Email/query":
		var ids []string
		if args.Filter.InMailbox == reportMailboxID {
			for _, e := range f.emails {
				ids = append(ids, e.ID)
			}
		}
		limit, capped := args.Limit, false
		if f.cfg.queryLimit > 0 && (limit == 0 || limit > f.cfg.queryLimit) {
			limit, capped = f.cfg.queryLimit, true
		}
		position := args.Position
		if f.cfg.ignorePosition {
			position = 0
		}
		page := ids[min(position, len(ids)):min(position+limit, len(ids))]
		resp := map[string]any{
			"accountId":           testAccountID,
			"queryState":          "q1",
			"canCalculateChanges": true,
			"position":            position,
			"ids":                 page,
		}
		if args.CalculateTotal {
			total := len(ids)
			if f.cfg.total > 0 {
				total = f.cfg.total
			}
			resp["total"] = total
		}
		if capped {
			resp["limit"] = limit
		}
		return call.Name, resp

	case "Email/get":
		if f.cfg.maxObjectsInGet > 0 && len(args.IDs) > f.cfg.maxObjectsInGet {
			return "error", map[string]string{"type": "requestTooLarge"}
		}
		list := []Email{}
		notFound := []string{}
		// Answer in reverse: /get promises no order.
		for _, id := range slices.Backward(args.IDs) {
			i := slices.IndexFunc(f.emails, func(e Email) bool { return e.ID == id })
			if i < 0 {
				notFound = append(notFound, id)
				continue
			}
			list = append(list, f.emails[i])
		}
		return call.Name, map[string]any{"accountId": testAccountID, "state": "e1", "list": list, "notFound": notFound}
	}
	return "error", map[string]string{"type": "unknownMethod"}
}

func (f *fakeFastmail) serveDownload(w http.ResponseWriter, r *http.Request) {
	if !authorized(r) {
		http.Error(w, "Authorization header not a valid format", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	f.downloads = append(f.downloads, download{name: r.PathValue("name"), mediaType: r.URL.Query().Get("type")})
	f.mu.Unlock()

	blob, ok := f.blobs[r.PathValue("blobId")]
	if r.PathValue("accountId") != testAccountID || !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", r.URL.Query().Get("type"))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", r.PathValue("name")))
	if !f.cfg.chunkedDownloads {
		w.Header().Set("Content-Length", strconv.Itoa(len(blob)))
		_, _ = w.Write(blob)
		return
	}
	half := len(blob) / 2
	_, _ = w.Write(blob[:half])
	w.(http.Flusher).Flush()
	_, _ = w.Write(blob[half:])
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": typ, "status": http.StatusBadRequest, "detail": detail})
}
