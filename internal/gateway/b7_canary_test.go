package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// B7 security canary: an admin's first live-tail request is journalled once;
// continuation polls must not create another session.watch event.
func TestCanary_B7_AdminTailWritesSessionWatch(t *testing.T) {
	f := newFixture(t, nil)
	cast := filepath.Join(t.TempDir(), "admin-live.cast")
	if err := os.WriteFile(cast, []byte("live\n"), 0o600); err != nil {
		t.Fatalf("write live cast: %v", err)
	}
	const sessionID = "admin-live-session"
	f.gw.live.add(sessionID, cast, f.machineID)

	body := []byte(`{"proto":1,"id":"` + sessionID + `","offset":0,"limit":1024}`)
	if _, cerr := cmdSessionsTail(f.gw, "admin", f.clock.Now(), body); cerr != nil {
		t.Fatalf("first admin tail: %v", cerr)
	}

	got, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionWatch}})
	if err != nil {
		t.Fatalf("read session.watch events: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("first admin tail wrote %d session.watch events, want 1", len(got))
	}
	if got[0].Actor != "admin" || got[0].Object != sessionID {
		t.Fatalf("event actor/object = %q/%q, want admin/%q", got[0].Actor, got[0].Object, sessionID)
	}

	continuation := []byte(`{"proto":1,"id":"` + sessionID + `","offset":5,"limit":1024}`)
	if _, cerr := cmdSessionsTail(f.gw, "admin", f.clock.Now(), continuation); cerr != nil {
		t.Fatalf("continuation admin tail: %v", cerr)
	}
	got, _, err = f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionWatch}})
	if err != nil {
		t.Fatalf("read continuation events: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("continuation tail wrote %d session.watch events, want exactly 1", len(got))
	}
}
