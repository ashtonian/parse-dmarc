package intake

import (
	"bytes"
	"io"
	"strings"

	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
	"github.com/rs/zerolog"
)

// maxNestDepth bounds recursion into forwarded/embedded messages.
const maxNestDepth = 4

// CollectAttachments walks a raw MIME message and returns the report
// attachments in it, DMARC or TLS-RPT, descending into embedded messages
// (Google reports relayed through Exchange or Outlook arrive as a
// message/rfc822 attachment wrapping the real .zip).
func CollectAttachments(log *zerolog.Logger, r io.Reader) []Attachment {
	return (&walker{log: log}).collect(r, 0)
}

type walker struct {
	log *zerolog.Logger
}

func (c *walker) collect(r io.Reader, depth int) []Attachment {
	if depth > maxNestDepth {
		c.log.Warn().Msg("max nesting depth reached; skipping embedded message")
		return nil
	}

	mr, err := mail.CreateReader(r)
	if err != nil {
		c.log.Warn().Err(err).Msg("failed to create mail reader")
		return nil
	}
	defer func() { _ = mr.Close() }()

	var attachments []Attachment
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.log.Warn().Err(err).Msg("error reading part")
			break
		}

		// Reports do not always arrive as a formal attachment: Fastmail
		// sends its aggregate reports with Content-Disposition: inline,
		// which go-message surfaces as *mail.InlineHeader (it uses the
		// same type for text/* parts with no disposition at all). Both
		// types wrap a message.Header, and AttachmentHeader.Filename
		// already reads the disposition filename with a Content-Type name
		// fallback, so wrap the inline header and leave the decision to
		// isDMARCAttachment below.
		var h *mail.AttachmentHeader
		inline := false
		switch ph := part.Header.(type) {
		case *mail.AttachmentHeader:
			h = ph
		case *mail.InlineHeader:
			h = &mail.AttachmentHeader{Header: ph.Header}
			inline = true
		default:
			continue
		}

		filename, _ := h.Filename()
		contentType, _, _ := h.ContentType()

		// An unnamed inline text part is the human-readable body of the
		// mail, not a report. Skip it before reading so a large HTML body
		// is neither buffered nor content-sniffed: a body that merely
		// quotes "<feedback" must not turn into an attachment.
		if inline && filename == "" && strings.HasPrefix(strings.ToLower(contentType), "text/") {
			continue
		}

		data, err := io.ReadAll(part.Body)
		if err != nil {
			c.log.Warn().Err(err).Msg("error reading attachment")
			continue
		}

		if isEmbeddedMessage(contentType, filename, data) {
			attachments = append(attachments, c.collect(bytes.NewReader(data), depth+1)...)
			continue
		}

		// Outlook's binary .msg (OLE compound file) needs a CFB reader;
		// log it instead of silently dropping. Add a parser if it shows up often.
		if bytes.HasPrefix(data, []byte{0xd0, 0xcf, 0x11, 0xe0}) {
			c.log.Warn().Str("filename", filename).Msg("unsupported Outlook .msg (OLE) attachment; ask the sender to forward as .eml")
			continue
		}

		if isReportAttachment(filename, contentType, data) {
			attachments = append(attachments, Attachment{Filename: filename, ContentType: contentType, Data: data})
		} else {
			c.log.Debug().
				Str("filename", filename).
				Str("content_type", contentType).
				Msg("skipping attachment that does not look like a report")
		}
	}

	return attachments
}

// isEmbeddedMessage reports whether the attachment is itself an email message.
func isEmbeddedMessage(contentType, filename string, data []byte) bool {
	if strings.HasPrefix(strings.ToLower(contentType), "message/rfc822") {
		return true
	}
	lower := strings.ToLower(filename)
	if !strings.HasSuffix(lower, ".eml") && !strings.HasSuffix(lower, ".msg") {
		return false
	}
	// .msg is ambiguous: rfc822 text from most relays, OLE binary from Outlook.
	return bytes.Contains(headOf(data), []byte(":"))
}

func headOf(data []byte) []byte {
	if len(data) > 512 {
		return data[:512]
	}
	return data
}

// isReportAttachment reports whether an attachment is likely an aggregate
// report, DMARC or TLS-RPT: by filename, by the TLS-RPT media types of RFC
// 8460 section 5.3, or, for senders using opaque names, by sniffing the
// content.
func isReportAttachment(filename, contentType string, data []byte) bool {
	lower := strings.ToLower(filename)
	if strings.HasSuffix(lower, ".xml") ||
		strings.HasSuffix(lower, ".gz") ||
		strings.HasSuffix(lower, ".zip") ||
		strings.HasSuffix(lower, ".json") ||
		strings.Contains(lower, "dmarc") ||
		strings.Contains(lower, "tlsrpt") {
		return true
	}

	switch strings.ToLower(contentType) {
	case "application/tlsrpt+gzip", "application/tlsrpt+json":
		return true
	}

	// Content sniff: gzip/zip magic, a raw <feedback> document, or a raw
	// TLS-RPT JSON report.
	head := headOf(data)
	return bytes.HasPrefix(data, []byte{0x1f, 0x8b}) ||
		bytes.HasPrefix(data, []byte("PK\x03\x04")) ||
		bytes.Contains(head, []byte("<feedback")) ||
		(bytes.HasPrefix(bytes.TrimSpace(head), []byte("{")) && bytes.Contains(head, []byte(`"organization-name"`)))
}
