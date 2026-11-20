package intake

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

const feedbackXML = `<?xml version="1.0"?><feedback><report_metadata><report_id>1</report_id></report_metadata></feedback>`

func zipped(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("google.com!example.com!1!2.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(feedbackXML)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipped(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(feedbackXML)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Fastmail sends its aggregate reports as an inline part carrying a filename,
// alongside a plain text body that must not be picked up as a report.
func TestCollectAttachmentsInlineDisposition(t *testing.T) {
	msg := "From: reports@fastmaildmarc.com\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
		"This is an aggregate report for example.com.\r\n" +
		"--b\r\nContent-Type: application/gzip\r\n" +
		"Content-Disposition: inline; filename=\"fastmail.com!example.com!1!2.xml.gz\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		encodeB64(gzipped(t)) + "\r\n--b--\r\n"

	log := zerolog.Nop()
	atts := CollectAttachments(&log, strings.NewReader(msg))
	if len(atts) != 1 {
		t.Fatalf("want 1 attachment, got %d", len(atts))
	}
	if atts[0].Filename != "fastmail.com!example.com!1!2.xml.gz" {
		t.Fatalf("want filename from the inline part, got %q", atts[0].Filename)
	}
	if !bytes.HasPrefix(atts[0].Data, []byte{0x1f, 0x8b}) {
		t.Fatalf("want gzip payload, got %x", atts[0].Data)
	}
}

// A text/xml report carrying only a Content-Type name parameter and no
// Content-Disposition is an InlineHeader to go-message as well; the name
// fallback must still pick it up.
func TestCollectAttachmentsInlineNameOnly(t *testing.T) {
	msg := "From: reporter@example.com\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/xml; name=\"reporter.example!example.com!1!2.xml\"\r\n\r\n" +
		feedbackXML + "\r\n--b--\r\n"

	log := zerolog.Nop()
	atts := CollectAttachments(&log, strings.NewReader(msg))
	if len(atts) != 1 {
		t.Fatalf("want 1 attachment, got %d", len(atts))
	}
	if atts[0].Filename != "reporter.example!example.com!1!2.xml" {
		t.Fatalf("want filename from the Content-Type name parameter, got %q", atts[0].Filename)
	}
}

// An unnamed inline body is never a report, even when it quotes the
// "<feedback" element the content sniff looks for.
func TestCollectAttachmentsInlineBodyIsNotAReport(t *testing.T) {
	msg := "From: someone@example.com\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" +
		"<p>The report's <feedback> element was empty.</p>\r\n--b--\r\n"

	log := zerolog.Nop()
	if atts := CollectAttachments(&log, strings.NewReader(msg)); len(atts) != 0 {
		t.Fatalf("want 0 attachments from an HTML-only body, got %d", len(atts))
	}
}

// A Google report relayed as a message/rfc822 attachment (the ".msg" case).
func TestCollectAttachmentsNestedMessage(t *testing.T) {
	inner := "From: noreply-dmarc-support@google.com\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=in\r\n\r\n" +
		"--in\r\nContent-Type: application/zip\r\n" +
		"Content-Disposition: attachment; filename=\"report.zip\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		encodeB64(zipped(t)) + "\r\n--in--\r\n"

	outer := "From: relay@example.com\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=out\r\n\r\n" +
		"--out\r\nContent-Type: message/rfc822\r\n" +
		"Content-Disposition: attachment; filename=\"Report domain.msg\"\r\n\r\n" +
		inner + "\r\n--out--\r\n"

	log := zerolog.Nop()
	atts := CollectAttachments(&log, strings.NewReader(outer))
	if len(atts) != 1 {
		t.Fatalf("want 1 attachment, got %d", len(atts))
	}
	if !bytes.HasPrefix(atts[0].Data, []byte("PK\x03\x04")) {
		t.Fatalf("want zip payload, got %q", atts[0].Data[:4])
	}
}

func TestIsReportAttachment(t *testing.T) {
	cases := []struct {
		name, filename, contentType string
		data                        string
		want                        bool
	}{
		{"raw feedback XML, opaque name", "opaque.bin", "application/octet-stream", feedbackXML, true},
		{"PNG", "logo.png", "image/png", "\x89PNG", false},
		{"TLS-RPT gzip media type", "report", "application/tlsrpt+gzip", "x", true},
		{"TLS-RPT JSON media type", "report", "application/tlsrpt+json", "x", true},
		{"TLS-RPT file name", "google.com!example.com!1!2!001.json.gz", "", "x", true},
		{"raw TLS-RPT JSON, opaque name", "opaque.bin", "", `{"organization-name":"x","policies":[]}`, true},
		{"other JSON", "opaque.bin", "", `{"hello":"world"}`, false},
	}
	for _, tc := range cases {
		if got := isReportAttachment(tc.filename, tc.contentType, []byte(tc.data)); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func encodeB64(b []byte) string {
	e := base64.StdEncoding.EncodeToString(b)
	var out []string
	for len(e) > 76 {
		out, e = append(out, e[:76]), e[76:]
	}
	return strings.Join(append(out, e), "\r\n")
}
