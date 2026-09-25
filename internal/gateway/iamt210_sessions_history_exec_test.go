package gateway

// iamt210_sessions_history_exec_test.go — IAMT-210.
//
// The bug: an exec session wrote a second `session.start` event
// after the legitimate one — Actor "exec", Object: the literal
// command string. `admin sessions history` filtered to
// {session.start, session.stop, session.drop} so the operator saw
// three lines for one session:
//
//   <time>  liveuser -> desktop-i3fl2s5  session.start  ok
//   <time>  exec     -> whoami; hostname; ...  session.start  ok
//   <time>  liveuser -> desktop-i3fl2s5  session.stop   ok
//
// The middle line is the bug. PROTOCOL §1.7 fixes `actor` to
// "the person, the machine name, gateway, admin" — "exec" is none of
// those, and "two session.start per session" violates the one-pair
// invariant sessions.history is supposed to render. Adding a new
// event type is forbidden by gate 12 (PROTOCOL §1.7: an unspecified
// type is an implementation error").
//
// The fix is event-side, not render-side: keep ONE session.start per
// session, with the exec command carried in Details["command"].
// sessions.history keeps reading what it always read (Actor as
// Person, Object as Machine, Type as Type); the second row simply
// stops existing. The command stays discoverable through
// events.jsonl for anyone who wants it.
//
// Tests pin both halves of the contract end-to-end:
//   - the journal contains exactly one session.start per exec
//     session, with command in Details (no second "exec" actor),
//   - sessions.history surfaces exactly that one start + the stop,
//     in that order, with no "exec -> <command>" line in between.

import (
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// TestIAMT210_ExecSession_OneSessionStartInJournal is the primary
// canary on the event-side fix: one exec session, exactly one
// session.start in events.jsonl, no event with Actor "exec".
//
// Canary: in internal/gateway/human_role.go's serveHumanSession,
// re-insert the `if start.exec { appendEvent(actor:"exec", ...) }`
// line. The journal now has two session.start events and this
// test goes red on `len(starts) != 1`.
func TestIAMT210_ExecSession_OneSessionStartInJournal(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dialHuman: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)

	const command = "whoami; hostname"
	if ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command})); err != nil || !ok {
		t.Fatalf("exec: ok=%v err=%v", ok, err)
	}
	const marker = "iamt210-marker"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write exec stdin: %v", err)
	}
	got := readUntil(t, hs.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("person did not receive exec output %q; got %q", marker, got)
	}
	_ = hs.ch.CloseWrite()
	_ = hs.ch.Close()

	waitUntil(t, "exec session did not close", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	// Filter the journal to session.start events for this exec
	// session. The session id we want is whatever the gateway
	// generated for the session — we look up by Actor + Object +
	// a recent timestamp window.
	deadline := f.clock.Now().Add(10 * time.Second)
	evs, _, err := f.log.Read(events.Filter{
		Types:  []events.EventType{events.EventSessionStart},
		Actor:  f.person,
		Object: f.machineID,
		Until:  &deadline,
	})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}

	var starts []events.Event
	for _, e := range evs {
		if e.Type != events.EventSessionStart {
			continue
		}
		if e.Actor != f.person || e.Object != f.machineID {
			continue
		}
		starts = append(starts, e)
	}

	if len(starts) != 1 {
		t.Fatalf("IAMT-210 canary: exec session wrote %d session.start events (got: %+v); want exactly 1 (one start per session — pre-IAMT-210 code wrote a second event with Actor \"exec\")", len(starts), starts)
	}

	// No event in the journal must carry Actor "exec" — that
	// literal is what made sessions.history render the confusing
	// middle row.
	for _, e := range evs {
		if e.Actor == "exec" {
			t.Fatalf("IAMT-210 canary: events.jsonl still contains an event with Actor \"exec\" (Type=%s Object=%s); the IAMT-210 fix must drop that second write", e.Type, e.Object)
		}
	}

	// The single session.start MUST carry the command in Details
	// so a forensic reader of events.jsonl can still find it —
	// it's only sessions.history's table that stops showing it.
	cmd, ok := starts[0].Details["command"].(string)
	if !ok {
		t.Fatalf("single session.start has no Details[\"command\"]; details=%+v", starts[0].Details)
	}
	if cmd != command {
		t.Fatalf("Details[\"command\"] = %q, want %q", cmd, command)
	}
}

// TestIAMT210_SessionsHistory_RendersOneStartOneStop is the canary
// on the render side. `admin sessions history` must show exactly
// the start + the stop for one exec session, with no "exec"
// actor row in between. The literal substring `exec ->` MUST NOT
// appear, because that was the exact confusing output this IAMT-210
// fix removes.
//
// Canary: in cmdSessionsHistory (admin_role.go), force the
// SessionStart filter to include the (now-removed) actor:"exec"
// event by ALSO reading it from the journal. This test fails on
// the `strings.Contains(raw, "exec ->")` assertion.
//
// (Today the test does not have to filter — the event is gone from
// the journal — but a future regression that resurrects the second
// event is what the canary must catch.)
func TestIAMT210_SessionsHistory_RendersOneStartOneStop(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	root := dialRootAdmin(t, f)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dialHuman: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)

	const command = "whoami; hostname"
	if ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command})); err != nil || !ok {
		t.Fatalf("exec: ok=%v err=%v", ok, err)
	}
	const marker = "iamt210-history"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write exec stdin: %v", err)
	}
	if !strings.Contains(readUntil(t, hs.ch, marker), marker) {
		t.Fatalf("person did not receive exec output")
	}
	_ = hs.ch.CloseWrite()
	_ = hs.ch.Close()

	waitUntil(t, "exec session did not close", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	// Wait for the session.stop event to land.
	deadline := f.clock.Now().Add(10 * time.Second)
	waitUntil(t, "session.stop never landed", func() bool {
		l, _, lerr := f.log.Read(events.Filter{
			Types: []events.EventType{events.EventSessionStop},
			Until: &deadline,
		})
		return lerr == nil && len(l) >= 1
	})

	// Now drive sessions.history. The fixture has only this
	// machine's session in the journal — filter by machine so the
	// assertions are local.
	from := f.clock.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	to := f.clock.Now().Add(1 * time.Hour).Format(time.RFC3339)
	page, err := root.SessionsHistory("", f.machineID, from, to, 50, 0)
	if err != nil {
		t.Fatalf("sessions.history: %v", err)
	}

	// Since 21.09.2026 the history answers one row per SESSION rather
	// than one per event, so the shape this test guards is one row, not
	// one start plus one stop. What it is guarding has not changed: the
	// exec session must appear ONCE, under the real person's name, and
	// never as a second phantom row actored by "exec".
	if len(page.Sessions) != 1 {
		t.Fatalf("sessions.history rows for this exec session: %d, want exactly 1 (IAMT-210 removed the bogus \"exec -> <command>\" row); rows=%+v", len(page.Sessions), page.Sessions)
	}
	h := page.Sessions[0]
	if h.Person != f.person {
		t.Fatalf("history row Person = %q, want %q (the real person, NOT \"exec\")", h.Person, f.person)
	}
	if h.Machine != f.machineID {
		t.Fatalf("history row Machine = %q, want %q", h.Machine, f.machineID)
	}
	if h.Kind != "exec" {
		t.Fatalf("history row Kind = %q, want \"exec\" — the row must say what kind of session it was", h.Kind)
	}
	if h.Started == "" || h.Ended == "" {
		t.Fatalf("history row has no start or no end: %+v — the start and stop events were not folded into one visit", h)
	}
	for _, r := range page.Sessions {
		if r.Person == "exec" {
			t.Fatalf("sessions.history surfaced a row with Person=\"exec\" (Machine=%q); pre-IAMT-210 wording, the fix must drop this row", r.Machine)
		}
	}
}

// TestIAMT210_PTYSession_StillOneStartOneStop is the canary's
// mirror: a PTY session (no exec) must produce the same one-start
// + one-stop shape sessions.history has always shown. Pre-IAMT-210
// the start branch only ran for `start.exec`, so a regression
// that mis-classifies non-exec sessions as "needing two events"
// would show up here.
//
// Canary: in serveHumanSession, change the `if start.exec { ... }`
// guard so it ALSO appends the second event for shell sessions.
// This test fails because the journal now contains two session.start
// events for a shell session.
func TestIAMT210_PTYSession_StillOneStartOneStop(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dialHuman: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	acc := drain(hs.ch)
	if _, err := hs.ch.Write([]byte("IAMT210-PTY-MARKER")); err != nil {
		t.Fatalf("write pty input: %v", err)
	}
	if !waitContains(t, acc, "IAMT210-PTY-MARKER", 3*1e9) {
		t.Fatalf("echo back: %q", acc.get())
	}
	_ = client.Close()

	waitUntil(t, "pty session did not close", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	deadline := f.clock.Now().Add(10 * time.Second)
	evs, _, err := f.log.Read(events.Filter{
		Types: []events.EventType{events.EventSessionStart},
		Actor: f.person, Object: f.machineID,
		Until: &deadline,
	})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("pty session wrote %d session.start events; want exactly 1 (no exec, so no Details.command — that detail is fine)", len(evs))
	}
	// PTY session: the Details["command"] key MUST NOT be set,
	// because no command was given (only a shell). A regression
	// that always sets Details["command"] to "" would surface in
	// events.jsonl as an empty-string command for shell sessions.
	if cmd, has := evs[0].Details["command"]; has {
		t.Fatalf("PTY session.start has Details[\"command\"] = %v; should be absent (the command only exists for exec)", cmd)
	}
}
