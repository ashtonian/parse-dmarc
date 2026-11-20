package jmap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// DownloadBlob fetches a blob, typically an Email's BlobID for the raw
// message. name and mediaType fill the download URL's {name} and {type}, which
// the server echoes as the file name and Content-Type; empty values become
// "blob" and application/octet-stream. A blob over the WithMaxBlobBytes limit
// is ErrBlobTooLarge.
func (c *Client) DownloadBlob(ctx context.Context, s *Session, accountID, blobID, name, mediaType string) ([]byte, error) {
	if s == nil {
		return nil, errors.New("download blob: nil session")
	}
	if accountID == "" || blobID == "" {
		return nil, errors.New("download blob: empty account or blob id")
	}
	if name == "" {
		name = "blob"
	}
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}

	raw, err := expandURITemplate(s.DownloadURL, map[string]string{
		"accountId": accountID,
		"blobId":    blobID,
		"name":      name,
		"type":      mediaType,
	})
	if err != nil {
		return nil, fmt.Errorf("download blob %s: downloadUrl: %w", blobID, err)
	}
	if _, err := c.parseURL(raw); err != nil {
		return nil, fmt.Errorf("download blob %s: %w", blobID, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, fmt.Errorf("download blob %s: %w", blobID, err)
	}
	data, err := c.do(req, c.maxBlobBytes, fmt.Errorf("%w of %d bytes", ErrBlobTooLarge, c.maxBlobBytes))
	if err != nil {
		return nil, fmt.Errorf("download blob %s: %w", blobID, err)
	}
	return data, nil
}

// expandURITemplate expands the RFC 6570 level 1 expressions ({var}) that RFC
// 8620 uses for downloadUrl. Values are percent-encoded except for unreserved
// characters, so a name or media type cannot add a path segment or query
// parameter. An undefined variable expands to nothing, as RFC 6570 says.
func expandURITemplate(tmpl string, vars map[string]string) (string, error) {
	var b strings.Builder
	rest := tmpl
	for {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			if strings.IndexByte(rest, '}') >= 0 {
				return "", fmt.Errorf("URI template %q has an unmatched }", tmpl)
			}
			b.WriteString(rest)
			return b.String(), nil
		}
		length := strings.IndexByte(rest[open:], '}')
		if length < 0 {
			return "", fmt.Errorf("URI template %q has an unclosed {", tmpl)
		}
		literal, name := rest[:open], rest[open+1:open+length]
		if strings.IndexByte(literal, '}') >= 0 {
			return "", fmt.Errorf("URI template %q has an unmatched }", tmpl)
		}
		if !isVarName(name) {
			return "", fmt.Errorf("URI template %q: expression {%s} is beyond level 1", tmpl, name)
		}
		b.WriteString(literal)
		b.WriteString(percentEncode(vars[name]))
		rest = rest[open+length+1:]
	}
}

// isVarName reports whether s is a plain variable name, which rules out the
// operators, modifiers and variable lists of levels 2 to 4.
func isVarName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '_':
		case ch == '.' && i > 0:
		default:
			return false
		}
	}
	return true
}

// percentEncode encodes every byte of s outside RFC 3986's unreserved set.
func percentEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
			ch == '-' || ch == '.' || ch == '_' || ch == '~' {
			b.WriteByte(ch)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[ch>>4])
		b.WriteByte(hex[ch&0x0f])
	}
	return b.String()
}
