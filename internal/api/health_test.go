package api

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/dmarcguardhq/parse-dmarc/internal/storage"
)

func TestHealthEndpoints(t *testing.T) {
	store, err := storage.Open(context.Background(), storage.Options{Path: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	log := zerolog.Nop()
	srv := NewServer(store, "127.0.0.1", 0, nil, &log, VersionInfo{})

	for _, tc := range []struct {
		name    string
		handler func(rec *httptest.ResponseRecorder)
		want    int
	}{
		{"live", func(rec *httptest.ResponseRecorder) { srv.handleHealthz(rec, httptest.NewRequest("GET", "/healthz", nil)) }, 200},
		{"ready", func(rec *httptest.ResponseRecorder) { srv.handleReadyz(rec, httptest.NewRequest("GET", "/readyz", nil)) }, 200},
	} {
		rec := httptest.NewRecorder()
		tc.handler(rec)
		if rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, rec.Code, tc.want)
		}
	}

	// A closed database is not ready, and the process is still live.
	_ = store.Close()
	rec := httptest.NewRecorder()
	srv.handleReadyz(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 503 {
		t.Errorf("ready with a closed database: status %d, want 503", rec.Code)
	}
	rec = httptest.NewRecorder()
	srv.handleHealthz(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Errorf("live with a closed database: status %d, want 200", rec.Code)
	}
}
