package jmapintake

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"

	"github.com/dmarcguardhq/parse-dmarc/internal/config"
	"github.com/dmarcguardhq/parse-dmarc/internal/intake"
	"github.com/dmarcguardhq/parse-dmarc/internal/jmap"
)

const token = "fmu1-test-token"

func reportMail(subject string) string {
	return "From: noreply-dmarc-support@google.com\r\n" +
		"Subject: " + subject + "\r\n" +
		"Message-ID: <" + subject + "@google.com>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nReport attached.\r\n" +
		"--b\r\nContent-Type: application/xml\r\n" +
		"Content-Disposition: attachment; filename=\"google.com!example.com!1!2.xml\"\r\n\r\n" +
		"<feedback/>\r\n--b--\r\n"
}

// fakeServer is a minimal JMAP server: one account, a Reports/julep folder
// holding the given messages, and a log of every method called.
type fakeServer struct {
	*httptest.Server
	readOnly bool
	messages map[string]string // email id -> raw message, in id order

	mu      sync.Mutex
	methods []string
}

func newFakeServer(t *testing.T, readOnly bool, messages map[string]string) *fakeServer {
	t.Helper()
	f := &fakeServer{readOnly: readOnly, messages: messages}
	mux := http.NewServeMux()
	mux.HandleFunc("/session", f.session)
	mux.HandleFunc("/api", f.api)
	mux.HandleFunc("/download/", f.download)
	f.Server = httptest.NewServer(f.auth(mux))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeServer) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (f *fakeServer) session(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"apiUrl":      f.URL + "/api",
		"downloadUrl": f.URL + "/download/{accountId}/{blobId}/{name}?type={type}",
		"uploadUrl":   f.URL + "/upload/{accountId}/",
		"capabilities": map[string]any{
			jmap.CapabilityCore: map[string]any{"maxObjectsInGet": 100, "maxCallsInRequest": 16},
			jmap.CapabilityMail: map[string]any{},
		},
		"accounts": map[string]any{
			"acct1": map[string]any{"name": "reports@example.com", "isPersonal": true, "isReadOnly": f.readOnly},
		},
		"primaryAccounts": map[string]string{jmap.CapabilityMail: "acct1"},
	})
}

func (f *fakeServer) api(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MethodCalls []jmap.Invocation `json:"methodCalls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var out []jmap.Invocation
	for _, call := range req.MethodCalls {
		f.mu.Lock()
		f.methods = append(f.methods, call.Name)
		f.mu.Unlock()

		var resp any
		switch call.Name {
		case "Mailbox/get":
			resp = map[string]any{"list": []map[string]any{
				{"id": "mb-inbox", "name": "Inbox", "parentId": nil, "role": "inbox"},
				{"id": "mb-reports", "name": "Reports", "parentId": nil},
				{"id": "mb-julep", "name": "julep", "parentId": "mb-reports"},
			}}
		case "Email/query":
			ids := make([]string, 0, len(f.messages))
			for i := range len(f.messages) {
				ids = append(ids, fmt.Sprintf("e%d", i+1))
			}
			var args struct {
				Position int `json:"position"`
			}
			_ = json.Unmarshal(call.Args, &args)
			page := ids[min(args.Position, len(ids)):]
			resp = map[string]any{"ids": page, "position": args.Position, "total": len(ids)}
		case "Email/get":
			var args struct {
				IDs []string `json:"ids"`
			}
			_ = json.Unmarshal(call.Args, &args)
			var list []map[string]any
			for _, id := range args.IDs {
				raw := f.messages[id]
				subject := strings.TrimPrefix(strings.Split(raw, "\r\n")[1], "Subject: ")
				list = append(list, map[string]any{
					"id": id, "blobId": "blob-" + id, "messageId": []string{subject + "@google.com"},
					"receivedAt": "2026-11-18T10:00:00Z", "subject": subject,
					"from": []map[string]string{{"email": "noreply-dmarc-support@google.com"}}, "size": len(raw),
				})
			}
			resp = map[string]any{"list": list, "notFound": []string{}}
		default:
			resp = map[string]any{"type": "unknownMethod"}
			call.Name = "error"
		}
		args, _ := json.Marshal(resp)
		out = append(out, jmap.Invocation{Name: call.Name, Args: args, CallID: call.CallID})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"methodResponses": out, "sessionState": "s1"})
}

func (f *fakeServer) download(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	id := strings.TrimPrefix(parts[3], "blob-")
	raw, ok := f.messages[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write([]byte(raw))
}

type memLedger map[string]string

func (l memLedger) ProcessedKeys(_ context.Context, source string, keys []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, k := range keys {
		if _, ok := l[source+"|"+k]; ok {
			out[k] = true
		}
	}
	return out, nil
}

func (l memLedger) MarkProcessed(_ context.Context, source, key, outcome, _ string) error {
	l[source+"|"+key] = outcome
	return nil
}

func newSource(t *testing.T, f *fakeServer, ledger intake.Ledger) *Source {
	t.Helper()
	log := zerolog.Nop()
	cfg := &config.JMAPConfig{SessionURL: f.URL + "/session", Token: token, Mailbox: "Reports/julep", RequireReadOnly: true, TimeoutSeconds: 5}
	s, err := New(cfg, ledger, &log, jmap.WithInsecureHTTP())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCycleRecordsOutcomesInTheLedger(t *testing.T) {
	f := newFakeServer(t, true, map[string]string{
		"e1": reportMail("stored"),
		"e2": reportMail("retry"),
		"e3": "From: someone@example.com\r\nSubject: chatter\r\n\r\nno report\r\n",
	})
	ledger := memLedger{}
	s := newSource(t, f, ledger)

	var handled []intake.Message
	handle := func(_ context.Context, msg intake.Message) intake.Outcome {
		handled = append(handled, msg)
		if msg.Subject == "retry" {
			return intake.OutcomeRetry
		}
		return intake.OutcomeStored
	}
	if err := s.Cycle(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if len(handled) != 2 {
		t.Fatalf("handled %d messages, want the 2 with a report", len(handled))
	}
	if m := handled[0]; m.Key != "e1" || m.MessageID != "<stored@google.com>" || len(m.Attachments) != 1 || m.From != "noreply-dmarc-support@google.com" {
		t.Fatalf("message: %+v", m)
	}
	want := memLedger{"jmap://acct1/mb-julep|e1": "stored", "jmap://acct1/mb-julep|e3": "invalid"}
	if fmt.Sprint(ledger) != fmt.Sprint(want) {
		t.Fatalf("ledger = %v, want %v", ledger, want)
	}

	handled = nil
	if err := s.Cycle(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if len(handled) != 1 || handled[0].Key != "e2" {
		t.Fatalf("second cycle handled %v, want only the retry", handled)
	}

	// Only reads reach the server.
	for _, m := range f.methods {
		if !strings.HasSuffix(m, "/get") && !strings.HasSuffix(m, "/query") {
			t.Errorf("method %s sent", m)
		}
	}
}

func TestCycleRefusesWritableToken(t *testing.T) {
	f := newFakeServer(t, false, map[string]string{"e1": reportMail("stored")})
	s := newSource(t, f, memLedger{})
	called := false
	err := s.Cycle(context.Background(), func(context.Context, intake.Message) intake.Outcome {
		called = true
		return intake.OutcomeStored
	})
	if !errors.Is(err, ErrTokenCanWrite) {
		t.Fatalf("err = %v, want ErrTokenCanWrite", err)
	}
	if called {
		t.Fatal("a message was read with a writable token")
	}
}

func TestCycleRejectedToken(t *testing.T) {
	f := newFakeServer(t, true, nil)
	log := zerolog.Nop()
	cfg := &config.JMAPConfig{SessionURL: f.URL + "/session", Token: "wrong", Mailbox: "INBOX", RequireReadOnly: true}
	s, err := New(cfg, memLedger{}, &log, jmap.WithInsecureHTTP())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Cycle(context.Background(), nil); !errors.Is(err, jmap.ErrUnauthorized) {
		t.Fatalf("err = %v, want jmap.ErrUnauthorized", err)
	}
}
