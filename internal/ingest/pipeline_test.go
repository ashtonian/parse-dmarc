package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"

	"github.com/dmarcguardhq/parse-dmarc/internal/intake"
	"github.com/dmarcguardhq/parse-dmarc/internal/parser"
)

const goodReport = `<?xml version="1.0"?><feedback><report_metadata><org_name>google.com</org_name>` +
	`<report_id>1</report_id><date_range><begin>1609459200</begin><end>1609545600</end></date_range>` +
	`</report_metadata><policy_published><domain>example.com</domain><p>none</p></policy_published>` +
	`<record><row><source_ip>192.0.2.1</source_ip><count>1</count><policy_evaluated><disposition>none</disposition>` +
	`</policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record></feedback>`

type fakeStore struct {
	err   error
	saved map[string]bool
}

func (s *fakeStore) SaveReport(_ context.Context, fb *parser.Feedback) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	if s.saved == nil {
		s.saved = map[string]bool{}
	}
	key := fb.ReportMetadata.OrgName + "/" + fb.ReportMetadata.ReportID
	if s.saved[key] {
		return false, nil
	}
	s.saved[key] = true
	return true, nil
}

func message(attachments ...string) intake.Message {
	msg := intake.Message{Key: "1", MessageID: "<1@example.com>"}
	for _, a := range attachments {
		msg.Attachments = append(msg.Attachments, intake.Attachment{Filename: "r.xml", Data: []byte(a)})
	}
	return msg
}

func TestHandleOutcomes(t *testing.T) {
	log := zerolog.Nop()
	cases := []struct {
		name  string
		store *fakeStore
		msg   intake.Message
		want  intake.Outcome
	}{
		{"a report that parses is stored", &fakeStore{}, message(goodReport), intake.OutcomeStored},
		{"a duplicate is stored all the same", &fakeStore{saved: map[string]bool{"google.com/1": true}}, message(goodReport), intake.OutcomeStored},
		{"one good report among bad ones", &fakeStore{}, message("<garbage", goodReport), intake.OutcomeStored},
		{"nothing parses", &fakeStore{}, message("<garbage", "PK nope"), intake.OutcomeInvalid},
		{"no attachments", &fakeStore{}, message(), intake.OutcomeInvalid},
		{"the store fails", &fakeStore{err: errors.New("database is down")}, message(goodReport), intake.OutcomeRetry},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(tc.store, nil, &log)
			if got := p.Handle(context.Background(), tc.msg); got != tc.want {
				t.Fatalf("outcome = %v, want %v", got, tc.want)
			}
		})
	}
}

// A cancelled fetch leaves its message for the next cycle.
func TestHandleCancelledIsRetry(t *testing.T) {
	log := zerolog.Nop()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := New(&fakeStore{}, nil, &log).Handle(ctx, message(goodReport)); got != intake.OutcomeRetry {
		t.Fatalf("outcome = %v, want retry", got)
	}
}
