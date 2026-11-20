package parser

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

// Kind is the type of an aggregate report.
type Kind string

const (
	// KindDMARC is a DMARC aggregate report (RFC 7489, RFC 9990).
	KindDMARC Kind = "dmarc"
	// KindTLSRPT is an SMTP TLS Reporting report (RFC 8460).
	KindTLSRPT Kind = "tlsrpt"
)

// Report is one parsed aggregate report; exactly one of DMARC and TLSRPT is
// set, as Kind says.
type Report struct {
	Kind   Kind
	DMARC  *Feedback
	TLSRPT *TLSReport
}

// ErrUnknownReport is returned for a document that is neither DMARC XML nor
// TLS-RPT JSON.
var ErrUnknownReport = errors.New("not a DMARC or TLS-RPT aggregate report")

// Parse decompresses data and parses the report inside it. A DMARC report
// is XML and a TLS-RPT report JSON, so the document's first character
// decides which parser reads it.
func Parse(data []byte) (*Report, error) {
	return parse(data, time.Now())
}

func parse(data []byte, now time.Time) (*Report, error) {
	doc, err := decompress(data)
	if err != nil {
		return nil, err
	}
	switch firstByte(doc) {
	case '<':
		fb, err := parseFeedbackXML(doc, now)
		if err != nil {
			return nil, err
		}
		return &Report{Kind: KindDMARC, DMARC: fb}, nil
	case '{':
		tr, err := parseTLSRPTJSON(doc, now)
		if err != nil {
			return nil, err
		}
		return &Report{Kind: KindTLSRPT, TLSRPT: tr}, nil
	default:
		return nil, fmt.Errorf("%w: document starts with neither '<' nor '{'", ErrUnknownReport)
	}
}

func firstByte(doc []byte) byte {
	doc = bytes.TrimLeft(bytes.TrimPrefix(doc, utf8BOM), " \t\r\n")
	if len(doc) == 0 {
		return 0
	}
	return doc[0]
}
