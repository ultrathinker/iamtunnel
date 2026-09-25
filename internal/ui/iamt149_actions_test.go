//go:build windows

package ui

// iamt149_actions_test.go covers the two guards every one of the three
// live actions (registerThisMachine, saveConnectionString, refreshMachines)
// makes BEFORE it starts a goroutine (live.go): an empty box is
// refused without touching the network, and a Frame built without a
// runtime (the offscreen shot, every other test in this package) says so
// instead of silently doing nothing.
//
// Round 3 fix: the "refuses an empty box" tests originally set a plain
// bool from inside Actions.Enrol/SaveConnection and checked it
// immediately after the synchronous call returned. That is wrong on two
// counts caught by hand-tracing the code (re-derived by reading begin()
// in live.go, not by running the suite): first, a bool written on
// one goroutine and read on another without a happens-before edge is a
// data race the -race gate (gate 5) would catch; second, and worse, it
// PROVED NOTHING — even with the empty-code guard deleted, the call to
// Actions.Enrol happens inside the goroutine begin() spawns, which has
// had no chance to run yet at the instant registerThisMachine() returns,
// so the bool reads false either way. Both tests below now wait on a
// closed channel with a bounded timeout instead: a real call closes the
// channel promptly (begin() starts its goroutine immediately), so a
// timeout is legitimate proof of absence, not just "not yet".
import (
	"context"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// guardWait bounds how long a "refuses" test waits for a call that must
// never come. begin() starts its goroutine synchronously and the fake
// Actions closures below do nothing but close a channel, so a real call
// arrives in well under a millisecond; this is generous margin, not a
// tuned deadline.
const guardWait = 200 * time.Millisecond

// newBareFrame lives in r2a_ui_testhelpers_test.go: tests tagged for
// linux and darwin call it too, and this file is windows-only.

func TestRegisterThisMachineRefusesAnEmptyCode(t *testing.T) {
	f := newBareFrame(t)
	called := make(chan struct{})
	f.cfg.Actions.Enrol = func(code string) (string, string, error) {
		close(called)
		return "", "", nil
	}

	f.registerThisMachine()

	select {
	case <-called:
		t.Fatalf("registerThisMachine called Actions.Enrol with an empty box — it must refuse before touching the network")
	case <-time.After(guardWait):
		// Nothing arrived: the guard held. begin() would have started its
		// goroutine (and it would have closed the channel) well inside
		// this window if the empty-code check had been removed.
	}

	got := f.saidUnder(ctlSetupRegister)
	if got.key != design.BadKey {
		t.Errorf("saidUnder(%q).key = %v, want design.BadKey", ctlSetupRegister, got.key)
	}
	if got.text == "" {
		t.Errorf("saidUnder(%q).text is empty — the refusal must say what to do", ctlSetupRegister)
	}
}

func TestRegisterThisMachineWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	f.editor(ctlSetupRegister).SetText("iamtunnel-enrol://gateway.example:2222#SHA256:x:secret")
	// f.cfg.Actions.Enrol left nil — a Frame built the way Shot() builds
	// one, or the way any other test in this package builds one. This
	// path returns before begin() is ever reached, so it is genuinely
	// synchronous — no goroutine, no wait needed.

	f.registerThisMachine()

	got := f.saidUnder(ctlSetupRegister)
	if got.text != noRuntime {
		t.Errorf("saidUnder(%q).text = %q, want the noRuntime sentence %q", ctlSetupRegister, got.text, noRuntime)
	}
	if got.key != design.BadKey {
		t.Errorf("saidUnder(%q).key = %v, want design.BadKey", ctlSetupRegister, got.key)
	}
}

func TestSaveConnectionStringRefusesAnEmptyBox(t *testing.T) {
	f := newBareFrame(t)
	called := make(chan struct{})
	f.cfg.Actions.SaveConnection = func(s, name string, replace bool) (string, error) {
		close(called)
		return "", nil
	}

	f.saveConnectionString(false)

	select {
	case <-called:
		t.Fatalf("saveConnectionString called Actions.SaveConnection with an empty box — it must refuse before touching the network")
	case <-time.After(guardWait):
	}

	if got := f.saidUnder(ctlClientSave); got.key != design.BadKey || got.text == "" {
		t.Errorf("saidUnder(%q) = %+v, want a non-empty BadKey refusal", ctlClientSave, got)
	}
}

func TestSaveConnectionStringWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	f.editor(ctlClientSave).SetText("iamtunnel://gateway.example:2222/alice#SHA256:x")

	f.saveConnectionString(false)

	if got := f.saidUnder(ctlClientSave); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctlClientSave, got, noRuntime)
	}
}

func TestRefreshMachinesWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)

	f.refreshMachines()

	if got := f.saidUnder(ctlClientRefresh); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctlClientRefresh, got, noRuntime)
	}
}

// TestRefreshMachinesCallsActionsWithContext proves the one thing that IS
// safe to assert about the success path without racing the background
// goroutine begin() starts: the function value is reached at all, and it
// is reached with a live, non-nil context. It does not assert anything
// about f.snap or f.saidUnder afterwards — those move on the goroutine,
// on a schedule this test does not control. This was already
// channel-based before round 3; it is the pattern the two guards above
// now follow too.
func TestRefreshMachinesCallsActionsWithContext(t *testing.T) {
	f := newBareFrame(t)
	seen := make(chan bool, 1)
	f.cfg.Actions.Machines = func(ctx context.Context) ([]MachineAccess, error) {
		seen <- ctx != nil
		return nil, nil
	}

	f.refreshMachines()

	// The call itself happens on the goroutine begin() starts, so this
	// waits for it rather than checking the instant refreshMachines()
	// returns — but it does not wait forever: a build that stopped
	// calling Actions.Machines at all must fail the test, not hang it.
	select {
	case ok := <-seen:
		if !ok {
			t.Errorf("Actions.Machines was called with a nil context")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("refreshMachines did not call Actions.Machines within 2s")
	}
}
