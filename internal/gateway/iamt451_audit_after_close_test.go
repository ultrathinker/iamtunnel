package gateway

// IAMT-451, a follow-up. The journal is closed by whoever opened it, after
// the gateway has closed. A write that arrived after that - a late
// goroutine, or none at all in production but the stop itself - failed
// with "log is closed", and the gateway published it as the audit journal
// breaking: audit-health.json rewritten to ok:false in a data directory
// the gateway had already let go of. In the tests that was a file left in
// a temporary directory being removed (a TempDir cleanup failure under
// load); in production, a stopped gateway's last word on its journal would
// have been a failure that never happened.

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestIAMT451_AWriteAfterTheGatewayClosedDoesNotRepublishItsAuditState(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.gw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := f.log.Close(); err != nil {
		t.Fatalf("log.Close: %v", err)
	}

	f.gw.appendEvent(events.Event{Type: events.EventDoorClose, Actor: "gateway", Object: f.machineID, Result: "ok"})

	h, found, err := ReadAuditHealth(f.gw.cfg.DataDir)
	if err != nil || !found {
		t.Fatalf("audit-health.json: found=%v err=%v", found, err)
	}
	if !h.OK {
		t.Fatalf("a write after Close republished the audit state as broken: %+v", h)
	}
}
