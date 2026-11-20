package jmap

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	queryPageSize = 256
	// maxQueryIDs bounds one mailbox listing. A mailbox past it holds years
	// of unprocessed reports and needs clearing out before intake can keep
	// up anyway.
	maxQueryIDs = 100_000

	// defaultMaxObjectsInGet applies when the session states no limit.
	defaultMaxObjectsInGet = 50
	// maxGetChunk keeps an Email/get response far below the response limit
	// where the server allows thousands of objects per call.
	maxGetChunk = 256
)

// Mailbox is a folder, with the properties needed to find one by path.
type Mailbox struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// ParentID is empty for a top-level mailbox.
	ParentID string `json:"parentId"`
	// Role is the RFC 8621 role, e.g. inbox or archive, or empty.
	Role string `json:"role"`
}

// Email holds the properties intake needs to pick a message and download it.
type Email struct {
	ID string `json:"id"`
	// BlobID addresses the raw RFC 5322 message for DownloadBlob.
	BlobID string `json:"blobId"`
	// MessageID holds the Message-ID header's ids, without angle brackets.
	MessageID  []string       `json:"messageId"`
	ReceivedAt time.Time      `json:"receivedAt"`
	Subject    string         `json:"subject"`
	From       []EmailAddress `json:"from"`
	Size       int64          `json:"size"`
}

// EmailAddress is one address of a From header.
type EmailAddress struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Mailboxes returns every mailbox of the account.
func (c *Client) Mailboxes(ctx context.Context, s *Session, accountID string) ([]Mailbox, error) {
	if accountID == "" {
		return nil, errors.New("list mailboxes: empty account id")
	}
	// ids null asks for every mailbox; the server refuses that with
	// requestTooLarge only past maxObjectsInGet, far above any folder count.
	args := struct {
		AccountID  string   `json:"accountId"`
		IDs        []string `json:"ids"`
		Properties []string `json:"properties"`
	}{accountID, nil, []string{"id", "name", "parentId", "role"}}

	var resp struct {
		List []Mailbox `json:"list"`
	}
	if err := c.invoke(ctx, s, "Mailbox/get", args, &resp); err != nil {
		return nil, fmt.Errorf("list mailboxes: %w", err)
	}
	return resp.List, nil
}

// ResolveMailbox finds the mailbox a configured path names: "id:" followed by
// a mailbox id, INBOX in any case for the inbox role, or folder names joined
// by "/" from the top level down, each matched exactly. A first segment of
// INBOX is the inbox too, so IMAP-style paths such as INBOX/DMARC keep
// working. A mailbox whose own name contains "/" is reachable only by id.
func ResolveMailbox(boxes []Mailbox, path string) (Mailbox, error) {
	if id, ok := strings.CutPrefix(path, "id:"); ok {
		i := slices.IndexFunc(boxes, func(b Mailbox) bool { return b.ID == id })
		if i < 0 {
			return Mailbox{}, fmt.Errorf("no mailbox with id %q", id)
		}
		return boxes[i], nil
	}
	if path == "" {
		return Mailbox{}, errors.New("empty mailbox path")
	}

	segments := strings.Split(path, "/")
	var current Mailbox
	for depth, name := range segments {
		if name == "" {
			return Mailbox{}, fmt.Errorf("mailbox path %q has an empty segment", path)
		}

		var i int
		if depth == 0 && strings.EqualFold(name, "INBOX") {
			i = slices.IndexFunc(boxes, func(b Mailbox) bool { return b.Role == "inbox" })
			if i < 0 {
				return Mailbox{}, fmt.Errorf("mailbox path %q: no mailbox has the inbox role", path)
			}
		} else {
			parentID := ""
			if depth > 0 {
				parentID = current.ID
			}
			i = slices.IndexFunc(boxes, func(b Mailbox) bool { return b.ParentID == parentID && b.Name == name })
			if i < 0 && depth == 0 {
				return Mailbox{}, fmt.Errorf("mailbox path %q: no top-level folder %q", path, name)
			}
			if i < 0 {
				return Mailbox{}, fmt.Errorf("mailbox path %q: no folder %q in %q", path, name, strings.Join(segments[:depth], "/"))
			}
		}
		current = boxes[i]
	}
	return current, nil
}

// QueryEmailIDs lists the ids of every email in a mailbox, oldest received
// first. It pages by position, shrinking the page to a limit the server
// enforces, and fails rather than loops on a server that ignores position.
// Mail moved out of the mailbox while paging can shift a later email out of
// this listing; the next poll lists it.
func (c *Client) QueryEmailIDs(ctx context.Context, s *Session, accountID, mailboxID string) ([]string, error) {
	if accountID == "" || mailboxID == "" {
		return nil, errors.New("query emails: empty account or mailbox id")
	}

	type comparator struct {
		Property    string `json:"property"`
		IsAscending bool   `json:"isAscending"`
	}
	type filter struct {
		InMailbox string `json:"inMailbox"`
	}
	type query struct {
		AccountID      string       `json:"accountId"`
		Filter         filter       `json:"filter"`
		Sort           []comparator `json:"sort"`
		Position       int          `json:"position"`
		Limit          int          `json:"limit"`
		CalculateTotal bool         `json:"calculateTotal"`
	}
	args := query{
		AccountID:      accountID,
		Filter:         filter{InMailbox: mailboxID},
		Sort:           []comparator{{Property: "receivedAt", IsAscending: true}},
		Limit:          queryPageSize,
		CalculateTotal: true,
	}

	var ids []string
	seen := make(map[string]struct{})
	for {
		var resp struct {
			IDs   []string `json:"ids"`
			Total *int     `json:"total"`
			// Limit is present only when the server capped the one asked for.
			Limit int `json:"limit"`
		}
		if err := c.invoke(ctx, s, "Email/query", args, &resp); err != nil {
			return nil, fmt.Errorf("query emails in mailbox %s at position %d: %w", mailboxID, args.Position, err)
		}
		if resp.Total != nil && *resp.Total > maxQueryIDs {
			return nil, fmt.Errorf("mailbox %s holds %d emails, over the limit of %d", mailboxID, *resp.Total, maxQueryIDs)
		}
		if resp.Limit > 0 && resp.Limit < args.Limit {
			args.Limit = resp.Limit
		}
		if len(resp.IDs) == 0 {
			break
		}

		added := 0
		for _, id := range resp.IDs {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
			added++
		}
		if added == 0 {
			return nil, fmt.Errorf("query emails in mailbox %s: page at position %d repeats earlier ids; the server ignores position", mailboxID, args.Position)
		}
		if len(ids) > maxQueryIDs {
			return nil, fmt.Errorf("mailbox %s holds more than %d emails", mailboxID, maxQueryIDs)
		}

		args.Position += len(resp.IDs)
		if resp.Total != nil && args.Position >= *resp.Total {
			break
		}
	}
	return ids, nil
}

// GetEmails fetches the emails with the given ids, in the order given and
// without repeats, chunked by the server's maxObjectsInGet. Ids the server
// does not know, typically mail moved or deleted since the query, come back
// in notFound instead of failing the batch.
func (c *Client) GetEmails(ctx context.Context, s *Session, accountID string, ids []string) (emails []Email, notFound []string, err error) {
	if accountID == "" {
		return nil, nil, errors.New("get emails: empty account id")
	}
	if s == nil {
		return nil, nil, errors.New("get emails: nil session")
	}

	unique := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			unique = append(unique, id)
		}
	}

	chunk := s.Core.MaxObjectsInGet
	if chunk <= 0 {
		chunk = defaultMaxObjectsInGet
	}
	chunk = min(chunk, maxGetChunk)

	type get struct {
		AccountID  string   `json:"accountId"`
		IDs        []string `json:"ids"`
		Properties []string `json:"properties"`
	}
	properties := []string{"id", "blobId", "messageId", "receivedAt", "subject", "from", "size"}

	found := make(map[string]Email, len(unique))
	for start := 0; start < len(unique); start += chunk {
		batch := unique[start:min(start+chunk, len(unique))]
		var resp struct {
			List []Email `json:"list"`
		}
		if err := c.invoke(ctx, s, "Email/get", get{accountID, batch, properties}, &resp); err != nil {
			return nil, nil, fmt.Errorf("get emails %d to %d of %d: %w", start+1, start+len(batch), len(unique), err)
		}
		for _, e := range resp.List {
			found[e.ID] = e
		}
	}

	emails = make([]Email, 0, len(found))
	for _, id := range unique {
		if e, ok := found[id]; ok {
			emails = append(emails, e)
		} else {
			notFound = append(notFound, id)
		}
	}
	return emails, notFound, nil
}
