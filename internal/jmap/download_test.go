package jmap

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestExpandURITemplate(t *testing.T) {
	const fastmail = "https://www.fastmailusercontent.com/jmap/download/{accountId}/{blobId}/{name}?type={type}"
	tests := []struct {
		name    string
		tmpl    string
		vars    map[string]string
		want    string
		wantErr bool
	}{
		{
			name: "fastmail report attachment",
			tmpl: fastmail,
			vars: map[string]string{"accountId": "u1a2b3c4d", "blobId": "G4f2a-1", "name": "fastmail.com!example.com!1!2.xml.gz", "type": "application/gzip"},
			want: "https://www.fastmailusercontent.com/jmap/download/u1a2b3c4d/G4f2a-1/fastmail.com%21example.com%211%212.xml.gz?type=application%2Fgzip",
		},
		{
			name: "values cannot add segments or parameters",
			tmpl: fastmail,
			vars: map[string]string{"accountId": "a", "blobId": "../b", "name": "x y/z?w#v", "type": "text/plain; charset=utf-8&evil=1"},
			want: "https://www.fastmailusercontent.com/jmap/download/a/..%2Fb/x%20y%2Fz%3Fw%23v?type=text%2Fplain%3B%20charset%3Dutf-8%26evil%3D1",
		},
		{
			name: "unreserved characters stay",
			tmpl: "https://h/{v}",
			vars: map[string]string{"v": "AZaz09-._~"},
			want: "https://h/AZaz09-._~",
		},
		{
			name: "non-ASCII is percent-encoded UTF-8",
			tmpl: "https://h/{name}",
			vars: map[string]string{"name": "rapport-é.xml"},
			want: "https://h/rapport-%C3%A9.xml",
		},
		{
			name: "undefined variable expands to nothing",
			tmpl: "https://h/{blobId}?type={type}",
			vars: map[string]string{"blobId": "b"},
			want: "https://h/b?type=",
		},
		{name: "unclosed expression", tmpl: "https://h/{blobId", wantErr: true},
		{name: "stray closing brace", tmpl: "https://h/}{blobId}", wantErr: true},
		{name: "level 2 operator", tmpl: "https://h/{+path}", wantErr: true},
		{name: "query operator", tmpl: "https://h/x{?type}", wantErr: true},
		{name: "variable list", tmpl: "https://h/{a,b}", wantErr: true},
		{name: "prefix modifier", tmpl: "https://h/{name:3}", wantErr: true},
		{name: "empty expression", tmpl: "https://h/{}", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandURITemplate(tt.tmpl, tt.vars)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// The download host is not the API host on Fastmail. The name and type the
// caller passes must reach that server intact, including characters that
// are delimiters in a URL.
func TestDownloadBlob(t *testing.T) {
	report := []byte{0x1f, 0x8b, 0x08, 0x00, 'r', 'e', 'p', 'o', 'r', 't'}
	f := newFastmail(t, fakeConfig{blobs: map[string][]byte{"Gb1": report}})
	c := f.client(t)
	s := f.session(t, c)

	const name = "google.com!example.com!1/2 #3.xml.gz"
	got, err := c.DownloadBlob(t.Context(), s, testAccountID, "Gb1", name, "application/gzip")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, report) {
		t.Fatalf("got %q, want %q", got, report)
	}
	if d := f.receivedDownloads(); len(d) != 1 || d[0] != (download{name: name, mediaType: "application/gzip"}) {
		t.Fatalf("server decoded %+v", d)
	}

	if _, err := c.DownloadBlob(t.Context(), s, testAccountID, "G-missing", "", ""); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want a 404 for an unknown blob, got %v", err)
	}
}

// A blob over the limit is an error whether or not the server announces its
// length; a blob exactly at the limit is not.
func TestDownloadBlobLimit(t *testing.T) {
	const limit = 1024
	blobs := map[string][]byte{
		"at-limit":   bytes.Repeat([]byte("a"), limit),
		"over-limit": bytes.Repeat([]byte("a"), limit+1),
	}
	tests := []struct {
		name    string
		blob    string
		chunked bool
		wantErr bool
	}{
		{"at limit with length", "at-limit", false, false},
		{"at limit chunked", "at-limit", true, false},
		{"over limit with length", "over-limit", false, true},
		{"over limit chunked", "over-limit", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFastmail(t, fakeConfig{blobs: blobs, chunkedDownloads: tt.chunked})
			c := f.client(t, WithMaxBlobBytes(limit))
			got, err := c.DownloadBlob(t.Context(), f.session(t, c), testAccountID, tt.blob, "m.eml", "message/rfc822")
			if tt.wantErr {
				if !errors.Is(err, ErrBlobTooLarge) {
					t.Fatalf("want ErrBlobTooLarge, got %v (%d bytes)", err, len(got))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, blobs[tt.blob]) {
				t.Fatalf("got %d bytes, want %d", len(got), len(blobs[tt.blob]))
			}
		})
	}
}
