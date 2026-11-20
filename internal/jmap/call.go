package jmap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// errWriteMethod marks a method call refused because it could change state.
var errWriteMethod = errors.New("not a read-only method")

// Invocation is one method call or response, the [name, arguments, call id]
// triple of RFC 8620 section 3.2.
type Invocation struct {
	Name   string
	Args   json.RawMessage
	CallID string
}

// NewInvocation encodes args as the arguments of a call to method.
func NewInvocation(method, callID string, args any) (Invocation, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return Invocation{}, fmt.Errorf("encode %s arguments: %w", method, err)
	}
	return Invocation{Name: method, Args: raw, CallID: callID}, nil
}

// MarshalJSON encodes the invocation as its wire triple; nil Args become {}.
func (inv Invocation) MarshalJSON() ([]byte, error) {
	args := inv.Args
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	return json.Marshal([3]any{inv.Name, args, inv.CallID})
}

// UnmarshalJSON decodes the invocation from its wire triple.
func (inv *Invocation) UnmarshalJSON(data []byte) error {
	var parts []json.RawMessage
	if err := json.Unmarshal(data, &parts); err != nil {
		return err
	}
	if len(parts) != 3 {
		return fmt.Errorf("invocation has %d elements, want 3", len(parts))
	}
	if err := json.Unmarshal(parts[0], &inv.Name); err != nil {
		return fmt.Errorf("invocation name: %w", err)
	}
	if err := json.Unmarshal(parts[2], &inv.CallID); err != nil {
		return fmt.Errorf("invocation call id: %w", err)
	}
	inv.Args = parts[1]
	return nil
}

// isReadOnlyMethod reports whether a method only reads, per the standard
// method kinds of RFC 8620 section 5. Everything else, /set, /copy, /import
// and any extension, is treated as a write.
func isReadOnlyMethod(name string) bool {
	typ, method, ok := strings.Cut(name, "/")
	if !ok || typ == "" {
		return false
	}
	switch method {
	case "get", "query", "changes", "queryChanges":
		return true
	}
	return false
}

// Call sends calls as one API request and returns the responses in the order
// of calls, matched by call id. A call whose method is not /get, /query,
// /changes or /queryChanges is refused before anything is sent. A method that
// failed on the server is a *MethodError; a rejected request is a
// *RequestError.
func (c *Client) Call(ctx context.Context, s *Session, using []string, calls ...Invocation) ([]Invocation, error) {
	if s == nil {
		return nil, errors.New("JMAP call without a session")
	}
	if len(calls) == 0 {
		return nil, errors.New("JMAP call without method calls")
	}
	if limit := s.Core.MaxCallsInRequest; limit > 0 && len(calls) > limit {
		return nil, fmt.Errorf("%d method calls exceed the server's maxCallsInRequest of %d", len(calls), limit)
	}

	names := make([]string, len(calls))
	index := make(map[string]int, len(calls))
	for i, inv := range calls {
		if !isReadOnlyMethod(inv.Name) {
			return nil, fmt.Errorf("%s: %w", inv.Name, errWriteMethod)
		}
		if inv.CallID == "" {
			return nil, fmt.Errorf("%s: empty call id", inv.Name)
		}
		if _, dup := index[inv.CallID]; dup {
			return nil, fmt.Errorf("duplicate call id %q", inv.CallID)
		}
		index[inv.CallID] = i
		names[i] = inv.Name
	}
	op := strings.Join(names, ", ")

	body, err := json.Marshal(struct {
		Using       []string     `json:"using"`
		MethodCalls []Invocation `json:"methodCalls"`
	}{using, calls})
	if err != nil {
		return nil, fmt.Errorf("encode JMAP request %s: %w", op, err)
	}
	if limit := s.Core.MaxSizeRequest; limit > 0 && int64(len(body)) > limit {
		return nil, fmt.Errorf("JMAP request %s is %d bytes, over the server's maxSizeRequest of %d", op, len(body), limit)
	}
	apiURL, err := c.parseURL(s.APIURL)
	if err != nil {
		return nil, fmt.Errorf("JMAP apiUrl: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("JMAP request %s: %w", op, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	data, err := c.do(req, c.maxResponseBytes, fmt.Errorf("JMAP response exceeds %d bytes", c.maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("JMAP request %s: %w", op, err)
	}

	var resp struct {
		MethodResponses []Invocation `json:"methodResponses"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("decode JMAP response to %s: %w", op, err)
	}

	out := make([]Invocation, len(calls))
	answered := make([]bool, len(calls))
	for _, r := range resp.MethodResponses {
		i, ok := index[r.CallID]
		if !ok {
			return nil, fmt.Errorf("JMAP response %s has unknown call id %q", r.Name, r.CallID)
		}
		// Only write methods may answer one call more than once (RFC 8620
		// section 3.4), so a second answer here means a confused server.
		if answered[i] {
			return nil, fmt.Errorf("JMAP response repeats call id %q", r.CallID)
		}
		answered[i] = true
		if r.Name == "error" {
			return nil, c.methodError(calls[i].Name, r.Args)
		}
		out[i] = r
	}
	for i, call := range calls {
		if !answered[i] {
			return nil, fmt.Errorf("JMAP response lacks an answer to %s (call id %q)", call.Name, call.CallID)
		}
	}
	return out, nil
}

// invoke runs one mail method and decodes its response arguments into out.
func (c *Client) invoke(ctx context.Context, s *Session, method string, args, out any) error {
	inv, err := NewInvocation(method, "0", args)
	if err != nil {
		return err
	}
	resps, err := c.Call(ctx, s, []string{CapabilityCore, CapabilityMail}, inv)
	if err != nil {
		return err
	}
	if resps[0].Name != method {
		return fmt.Errorf("%s answered as %s", method, resps[0].Name)
	}
	if err := json.Unmarshal(resps[0].Args, out); err != nil {
		return fmt.Errorf("decode %s response: %w", method, err)
	}
	return nil
}
