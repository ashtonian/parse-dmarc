package jmap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// ErrUnauthorized is returned when the server answers 401 or 403: the token is
// wrong, revoked, or lacks the scope the request needs.
var ErrUnauthorized = errors.New("jmap: token rejected")

// ErrBlobTooLarge is returned by DownloadBlob for a blob over the
// WithMaxBlobBytes limit.
var ErrBlobTooLarge = errors.New("jmap: blob exceeds size limit")

// RequestError is a request-level error (RFC 8620 section 3.6.1): the server
// rejected the whole request with an RFC 7807 problem document.
type RequestError struct {
	Status int
	// Type is the problem type, e.g. urn:ietf:params:jmap:error:limit.
	Type string
	// Limit names the exceeded limit, e.g. maxSizeRequest, when Type is
	// urn:ietf:params:jmap:error:limit.
	Limit  string
	Detail string
}

func (e *RequestError) Error() string {
	msg := fmt.Sprintf("jmap request error (HTTP %d) %s", e.Status, e.Type)
	if e.Limit != "" {
		msg += " " + e.Limit
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// MethodError is a method-level error (RFC 8620 section 3.6.2): the request
// was processed but one method call in it failed.
type MethodError struct {
	// Method is the call that failed, e.g. Email/query.
	Method string
	// Type is the error type, e.g. accountNotFound or requestTooLarge.
	Type        string
	Description string
}

func (e *MethodError) Error() string {
	msg := fmt.Sprintf("jmap %s error %s", e.Method, e.Type)
	if e.Description != "" {
		msg += ": " + e.Description
	}
	return msg
}

// statusError turns a non-2xx response into ErrUnauthorized, a *RequestError
// when the body is a problem document, or an error carrying a body snippet.
func (c *Client) statusError(resp *http.Response) error {
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("HTTP %d: %w", resp.StatusCode, ErrUnauthorized)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	// Servers disagree on the Content-Type of problem documents, so the body
	// decides.
	if trimmed := bytes.TrimSpace(body); bytes.HasPrefix(trimmed, []byte("{")) {
		var p struct {
			Type   string `json:"type"`
			Limit  string `json:"limit"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(trimmed, &p) == nil && p.Type != "" {
			return &RequestError{
				Status: resp.StatusCode,
				Type:   c.sanitize(p.Type),
				Limit:  c.sanitize(p.Limit),
				Detail: c.sanitize(p.Detail),
			}
		}
	}
	return fmt.Errorf("HTTP %d: %q", resp.StatusCode, c.sanitize(string(body)))
}

func (c *Client) methodError(method string, args json.RawMessage) error {
	var e struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(args, &e); err != nil {
		return fmt.Errorf("decode %s error response: %w", method, err)
	}
	return &MethodError{
		Method:      method,
		Type:        c.sanitize(e.Type),
		Description: c.sanitize(e.Description),
	}
}
