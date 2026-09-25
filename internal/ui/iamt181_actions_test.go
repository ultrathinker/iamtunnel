//go:build windows

package ui

// iamt181_actions_test.go covers the same two guards iamt149_actions_test.go
// covers for the three IAMT-149 actions, now for the four IAMT-181 ones
// (Server Start/Stop, Admin Grant/Revoke): a Frame built without a
// runtime says so instead of silently doing nothing, and — where there is
// one to check — an empty required box is refused before begin() ever
// starts a goroutine. The "refuses" checks use the same closed-channel +
// bounded-wait pattern iamt149_actions_test.go's round 3 fix established:
// a plain bool read immediately after the synchronous call proves
// nothing, because a real call (if the guard were missing) happens on
// begin()'s own goroutine, not before the call returns.

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

func TestStartServerWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	// Rights granted on purpose (1.3): without them startServer answers
	// with the elevation refusal and never reaches the runtime check,
	// which is the subject of THIS test. Pressing Start without rights is
	// pinned separately, in screens_windows_test.go.
	f.cfg.HasAdminRights = true

	f.startServer()

	if got := f.saidUnder(ctlServerStart); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctlServerStart, got, noRuntime)
	}
}

func TestStopServerWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)

	f.stopServer()

	if got := f.saidUnder(ctlServerStop); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctlServerStop, got, noRuntime)
	}
}

func TestGrantAccessRefusesAnEmptyPersonOrMachine(t *testing.T) {
	f := newBareFrame(t)
	called := make(chan struct{})
	f.cfg.Actions.AdminGrant = func(person, machine, until string) (string, error) {
		close(called)
		return "", nil
	}
	// person left empty; machine filled in — either being blank must refuse.
	f.editor(ctlAdminGrant + "/machine").SetText("win-srv01")

	f.grantAccess()

	select {
	case <-called:
		t.Fatalf("grantAccess called Actions.AdminGrant with an empty person — it must refuse before touching the network")
	case <-time.After(guardWait):
	}

	got := f.saidUnder(ctlAdminGrant)
	if got.key != design.BadKey || got.text == "" {
		t.Errorf("saidUnder(%q) = %+v, want a non-empty BadKey refusal", ctlAdminGrant, got)
	}
}

func TestGrantAccessWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	f.editor(ctlAdminGrant + "/person").SetText("alice")
	f.editor(ctlAdminGrant + "/machine").SetText("win-srv01")

	f.grantAccess()

	if got := f.saidUnder(ctlAdminGrant); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctlAdminGrant, got, noRuntime)
	}
}

func TestRevokeAccessWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	const ctl = "admin/revoke/0"

	f.revokeAccess(ctl, "alice", "win-srv01")

	if got := f.saidUnder(ctl); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctl, got, noRuntime)
	}
}
