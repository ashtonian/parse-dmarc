package jmap

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestResolveMailbox(t *testing.T) {
	var boxes []Mailbox
	if err := json.Unmarshal([]byte(fastmailMailboxes), &boxes); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		path    string
		wantID  string
		wantErr string
	}{
		{path: "INBOX", wantID: "mb-inbox"},
		{path: "inbox", wantID: "mb-inbox"},
		{path: "Inbox", wantID: "mb-inbox"},
		{path: "INBOX/DMARC", wantID: "mb-dmarc"},
		{path: "Reports", wantID: "mb-reports"},
		{path: "Reports/julep", wantID: "mb-julep"},
		{path: "Archive/julep", wantID: "mb-archive-julep"},
		{path: "id:mb-julep", wantID: "mb-julep"},
		{path: "reports/julep", wantErr: `no top-level folder "reports"`},
		{path: "Reports/missing", wantErr: `no folder "missing" in "Reports"`},
		{path: "DMARC", wantErr: `no top-level folder "DMARC"`},
		{path: "julep", wantErr: `no top-level folder "julep"`},
		{path: "Reports//julep", wantErr: "empty segment"},
		{path: "Reports/julep/", wantErr: "empty segment"},
		{path: "", wantErr: "empty mailbox path"},
		{path: "id:mb-nope", wantErr: `no mailbox with id "mb-nope"`},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := ResolveMailbox(boxes, tt.path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want error containing %q, got %v (%+v)", tt.wantErr, err, got)
				}
				// The error names what is missing, not what exists.
				if strings.Contains(err.Error(), "Archive") {
					t.Fatalf("error lists other mailboxes: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != tt.wantID {
				t.Fatalf("got %s, want %s", got.ID, tt.wantID)
			}
		})
	}

	if _, err := ResolveMailbox([]Mailbox{{ID: "a", Name: "Inbox"}}, "INBOX"); err == nil {
		t.Fatal("want an error when no mailbox has the inbox role")
	}
}

func TestMailboxes(t *testing.T) {
	f := newFastmail(t, fakeConfig{})
	c := f.client(t)
	boxes, err := c.Mailboxes(t.Context(), f.session(t, c), testAccountID)
	if err != nil {
		t.Fatal(err)
	}
	julep, err := ResolveMailbox(boxes, "Reports/julep")
	if err != nil {
		t.Fatal(err)
	}
	if julep != (Mailbox{ID: "mb-julep", Name: "julep", ParentID: "mb-reports"}) {
		t.Fatalf("got %+v", julep)
	}
}

func emailIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("M%05d", i)
	}
	return ids
}

func TestQueryEmailIDsPages(t *testing.T) {
	tests := []struct {
		name string
		cfg  fakeConfig
	}{
		{"empty mailbox", fakeConfig{}},
		{"one short page", fakeConfig{emails: 12}},
		{"exactly one page", fakeConfig{emails: queryPageSize}},
		{"several pages", fakeConfig{emails: 3*queryPageSize + 5}},
		{"server caps the page", fakeConfig{emails: 601, queryLimit: 100}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFastmail(t, tt.cfg)
			c := f.client(t)
			ids, err := c.QueryEmailIDs(t.Context(), f.session(t, c), testAccountID, reportMailboxID)
			if err != nil {
				t.Fatal(err)
			}
			if want := emailIDs(tt.cfg.emails); !slices.Equal(ids, want) {
				t.Fatalf("got %d ids, want all %d oldest first", len(ids), len(want))
			}
		})
	}
}

func TestQueryEmailIDsIgnoredPosition(t *testing.T) {
	f := newFastmail(t, fakeConfig{emails: 600, ignorePosition: true})
	c := f.client(t)
	_, err := c.QueryEmailIDs(t.Context(), f.session(t, c), testAccountID, reportMailboxID)
	if err == nil || !strings.Contains(err.Error(), "ignores position") {
		t.Fatalf("want an error for a server that ignores position, got %v", err)
	}
}

func TestQueryEmailIDsTooMany(t *testing.T) {
	f := newFastmail(t, fakeConfig{emails: 3, total: maxQueryIDs + 1})
	c := f.client(t)
	_, err := c.QueryEmailIDs(t.Context(), f.session(t, c), testAccountID, reportMailboxID)
	if err == nil || !strings.Contains(err.Error(), "over the limit") {
		t.Fatalf("want an error over %d emails, got %v", maxQueryIDs, err)
	}
}

// The fake refuses an Email/get over its maxObjectsInGet with requestTooLarge,
// so these pass only if the client chunks.
func TestGetEmailsChunks(t *testing.T) {
	tests := []struct {
		name string
		cfg  fakeConfig
	}{
		{"session limit", fakeConfig{emails: 20, maxObjectsInGet: 3}},
		{"default limit when unstated", fakeConfig{emails: 120, maxObjectsInGet: defaultMaxObjectsInGet, hideMaxObjectsInGet: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFastmail(t, tt.cfg)
			c := f.client(t)
			s := f.session(t, c)

			want := emailIDs(tt.cfg.emails)
			slices.Reverse(want)
			ids := append([]string{"M-gone"}, want...)
			ids = append(ids, want[0], "M-deleted")

			emails, notFound, err := c.GetEmails(t.Context(), s, testAccountID, ids)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, len(emails))
			for i, e := range emails {
				got[i] = e.ID
			}
			if !slices.Equal(got, want) {
				t.Fatalf("got %d emails %v..., want %d in the order asked", len(got), got[:min(3, len(got))], len(want))
			}
			if !slices.Equal(notFound, []string{"M-gone", "M-deleted"}) {
				t.Fatalf("notFound = %v", notFound)
			}
			if e := emails[len(emails)-1]; e.BlobID != "G00000" || e.ReceivedAt.IsZero() || e.From[0].Email != "noreply-dmarc-support@google.com" || e.MessageID[0] != "0@google.com" {
				t.Fatalf("email decoded as %+v", e)
			}
		})
	}
}

// The whole intake path, from session to raw message, reads only.
func TestIntakeIssuesOnlyReadMethods(t *testing.T) {
	f := newFastmail(t, fakeConfig{emails: 5, maxObjectsInGet: 2})
	c := f.client(t)
	s := f.session(t, c)

	accountID, _, err := s.MailAccount()
	if err != nil {
		t.Fatal(err)
	}
	boxes, err := c.Mailboxes(t.Context(), s, accountID)
	if err != nil {
		t.Fatal(err)
	}
	box, err := ResolveMailbox(boxes, "Reports/julep")
	if err != nil {
		t.Fatal(err)
	}
	ids, err := c.QueryEmailIDs(t.Context(), s, accountID, box.ID)
	if err != nil {
		t.Fatal(err)
	}
	emails, _, err := c.GetEmails(t.Context(), s, accountID, ids)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range emails {
		raw, err := c.DownloadBlob(t.Context(), s, accountID, e.BlobID, e.ID+".eml", "message/rfc822")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(raw), "From: noreply-dmarc-support@google.com") {
			t.Fatalf("blob %s = %q", e.BlobID, raw)
		}
	}

	for _, m := range f.receivedMethods() {
		if !strings.HasSuffix(m, "/get") && !strings.HasSuffix(m, "/query") {
			t.Errorf("intake sent %s", m)
		}
	}
}
