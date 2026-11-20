package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Capability URIs this client uses.
const (
	CapabilityCore = "urn:ietf:params:jmap:core"
	CapabilityMail = "urn:ietf:params:jmap:mail"
)

// Session is the server's session resource (RFC 8620 section 2). The client
// never modifies a Session, so one can be shared between goroutines; callers
// should treat it as read-only too.
type Session struct {
	// Capabilities maps each server capability URI to its raw object.
	Capabilities map[string]json.RawMessage `json:"capabilities"`
	// Core is the decoded urn:ietf:params:jmap:core capability.
	Core            CoreCapability     `json:"-"`
	Accounts        map[string]Account `json:"accounts"`
	PrimaryAccounts map[string]string  `json:"primaryAccounts"`
	APIURL          string             `json:"apiUrl"`
	// DownloadURL is an RFC 6570 template over accountId, blobId, name and
	// type.
	DownloadURL    string `json:"downloadUrl"`
	UploadURL      string `json:"uploadUrl"`
	EventSourceURL string `json:"eventSourceUrl"`
	State          string `json:"state"`
}

// CoreCapability holds the server limits this client reads. Zero means the
// server did not state the limit. Call enforces MaxCallsInRequest and
// MaxSizeRequest and GetEmails chunks by MaxObjectsInGet; MaxConcurrentRequests
// is for the caller, as the client does not queue requests.
type CoreCapability struct {
	MaxSizeRequest        int64 `json:"maxSizeRequest"`
	MaxConcurrentRequests int   `json:"maxConcurrentRequests"`
	MaxCallsInRequest     int   `json:"maxCallsInRequest"`
	MaxObjectsInGet       int   `json:"maxObjectsInGet"`
}

// Account is one account the token can access.
type Account struct {
	Name       string `json:"name"`
	IsPersonal bool   `json:"isPersonal"`
	// IsReadOnly is true for a Fastmail read-only API token.
	IsReadOnly bool `json:"isReadOnly"`
	// AccountCapabilities maps capability URIs to their per-account objects.
	AccountCapabilities map[string]json.RawMessage `json:"accountCapabilities"`
}

// Session fetches the session resource. It rejects a session whose API or
// download URL the token must not be sent to.
func (c *Client) Session(ctx context.Context) (*Session, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.sessionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("get JMAP session: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	body, err := c.do(req, c.maxResponseBytes, fmt.Errorf("JMAP session exceeds %d bytes", c.maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("get JMAP session: %w", err)
	}

	var s Session
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("decode JMAP session: %w", err)
	}
	if raw, ok := s.Capabilities[CapabilityCore]; ok {
		if err := json.Unmarshal(raw, &s.Core); err != nil {
			return nil, fmt.Errorf("decode %s capability: %w", CapabilityCore, err)
		}
	}
	if err := c.checkSession(&s); err != nil {
		return nil, fmt.Errorf("check JMAP session: %w", err)
	}
	return &s, nil
}

func (c *Client) checkSession(s *Session) error {
	if _, err := c.parseURL(s.APIURL); err != nil {
		return fmt.Errorf("apiUrl: %w", err)
	}
	// RFC 8620 requires all four variables; without these two the URL cannot
	// address a blob at all.
	if !strings.Contains(s.DownloadURL, "{accountId}") || !strings.Contains(s.DownloadURL, "{blobId}") {
		return fmt.Errorf("downloadUrl %q lacks {accountId} or {blobId}", s.DownloadURL)
	}
	sample, err := expandURITemplate(s.DownloadURL, map[string]string{
		"accountId": "a", "blobId": "b", "name": "n", "type": "t",
	})
	if err != nil {
		return fmt.Errorf("downloadUrl: %w", err)
	}
	if _, err := c.parseURL(sample); err != nil {
		return fmt.Errorf("downloadUrl: %w", err)
	}
	return nil
}

// MailAccount returns the id and details of the primary mail account.
func (s *Session) MailAccount() (string, Account, error) {
	id := s.PrimaryAccounts[CapabilityMail]
	if id == "" {
		return "", Account{}, errors.New("JMAP session has no primary mail account; the token may lack mail scope")
	}
	acct, ok := s.Accounts[id]
	if !ok {
		return "", Account{}, fmt.Errorf("primary mail account %s is not among the session's accounts", id)
	}
	return id, acct, nil
}
