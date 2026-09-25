package gateway

// The maintainer's canary: a live session can be followed by the very
// identifier the product itself printed.
//
// Found by the maintainer on 19.09.2026. They connected, opened the Live
// window, pressed Watch — and saw "read 0 of 0 bytes" and "the session
// has ended" while typing into that session's terminal themselves. The
// recording was being written all along: the file on the gateway grew.
//
// The cause is two different identifiers of one session. `sessions active`
// prints the ACL identifier ("session:1"), while the live registration
// went under the journal identifier ("<nanoseconds>-<person>-<machine>").
// All READERS of the registry already assumed the first: the machine-side
// path compares it with s.ID.String(), and the seam test inserts it by
// hand exactly that way. Only the production registration used the second.
//
// Worst of all is the shape of the failure: `sessions.tail` on an unknown
// identifier answers not with an error but with a correct "nothing to
// follow" — indistinguishable from an empty session. Which means live
// session viewing never worked AT ALL and from nowhere except the test
// that inserted the key itself.

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// TestCanary_LiveTailAnswersTheIdSessionsActivePrints.
//
// The canary: put `g.live.add(sessionID, ...)` back into human_role.go —
// the test will say exactly what the maintainer saw.
func TestCanary_LiveTailAnswersTheIdSessionsActivePrints(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// A shell session that STAYS open: what is being tested is watching
	// one that is still happening.
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "session did not become active", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	// The id the product itself prints.
	active, err := root.SessionsActive()
	if err != nil {
		t.Fatalf("sessions.active: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("sessions.active = %+v, want exactly one live session", active)
	}
	id := active[0].ID

	// And that same id, handed straight back, must find the transcript.
	var total int64
	var live bool
	var got string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tail, terr := root.SessionsTail(id, 0, 1<<16)
		if terr != nil {
			t.Fatalf("sessions.tail %q: %v", id, terr)
		}
		total, live = tail.Total, tail.Live
		if total > 0 {
			b, derr := base64.StdEncoding.DecodeString(tail.Data)
			if derr != nil {
				// The CLI decodes it, so a non-base64 body is a contract
				// break rather than a detail of this test.
				t.Fatalf("sessions.tail: data is not base64: %v", derr)
			}
			got = string(b)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if total == 0 {
		t.Fatalf("sessions.tail %q returned 0 bytes for the identifier sessions.active has just printed — "+
			"this is exactly what the maintainer saw as \"read 0 of 0 bytes\" on a session they were typing into themselves; "+
			"the failure arrives as a correct \"nothing to follow\" and is indistinguishable from an empty session", id)
	}
	if !live {
		t.Errorf("sessions.tail %q said live=false about a session that is running right now — "+
			"the window prints \"the session has ended\" from this field and stops reading on", id)
	}
	if strings.TrimSpace(got) == "" {
		t.Error("the transcript is empty at a non-zero size — the wrong file is being read")
	}
}
