package gateway

// F-03 of the round-1 review (24.09.2026): the branch of
// serveHumanSession that refuses a session because the audit journal
// cannot write (IAMT-451) wrote its own session.drop into that same
// journal. The write cannot succeed - the journal is exactly what is
// broken - so all it did was count one more lost record that never
// existed, and the person was turned away with the reason nowhere an
// operator could read it. What still works there is the gateway's own
// log, and that is where the refusal now goes.

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestR1MXF03_ASessionRefusedForTheJournalIsNotWrittenIntoIt(t *testing.T) {
	diag := &iamt451Lines{}
	f := newFixture(t, func(c *Config) { c.Diagnostics = diag })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// The journal fails from here on; every attempt is counted, so the
	// test can tell "the refusal wrote nothing" from "the refusal wrote
	// something nobody could see".
	var attempts atomic.Int64
	seam := func(events.Event) error {
		attempts.Add(1)
		return errors.New("write events.jsonl: there is not enough space on the disk")
	}
	f.gw.journalAppendFn.Store(&seam)
	defer f.gw.journalAppendFn.Store(nil)

	// The login itself is the write that turns the audit state to failing -
	// the state this refusal exists for.
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	// The login's own record is the write that turns the audit state to
	// failing, and the gateway may still be writing it when the client's
	// Dial returns: wait for the state rather than for the clock.
	waitUntil(t, "the audit state did not turn failing after the login's lost write", func() bool {
		return f.gw.auditRefusal() != nil
	})

	before := attempts.Load()
	hs := openHumanSession(t, client, f)
	// The gateway refuses at once and closes the channel: readLeftoverText
	// returns on that close, so everything the refusal did is behind us.
	text := hs.readLeftoverText(5 * time.Second)
	if !strings.Contains(text, "Access to this machine is currently unavailable") {
		t.Fatalf("the gateway did not refuse the session (it said %q), so this test is not about the refusal branch", text)
	}
	if got := attempts.Load() - before; got != 0 {
		t.Errorf("the refusal tried to write %d more journal entries into the journal that is refusing it (F-03): the write cannot succeed, and all it does is count a lost record that never existed", got)
	}

	// The reason the person was turned away is readable where the gateway
	// can still write, with the person and the machine in it.
	log := diag.String()
	if !strings.Contains(log, f.person) || !strings.Contains(log, f.machineID) {
		t.Errorf("the gateway's own log does not say that %s was refused a session to %s, and the journal cannot say it either:\n%s", f.person, f.machineID, log)
	}
}
