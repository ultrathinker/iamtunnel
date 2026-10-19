package ui

import (
	"testing"
	"time"
)

// A window opened before the first REGISTER used to treat the machine as
// unregistered until it was restarted: Settings had no "registration" row
// after a successful REGISTER (16.10.2026).
func TestR153_SettingsKnowsAMachineTheWindowJustRegistered(t *testing.T) {
	f := newBareFrame(t)
	f.cfg.Enrolled = false
	if f.registered() {
		t.Fatal("a machine that was never registered reads as registered")
	}
	f.cfg.Actions.Enrol = func(code string) (string, string, error) {
		return "win-srv01", `EXAMPLE\dana`, nil
	}
	f.editor(ctlSetupRegister).SetText("iamtunnel-enrol://192.0.2.10:2027#x:y")
	f.registerThisMachine()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.takeSnapshot()
		if f.registered() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("after a successful REGISTER the window still treats the machine as unregistered")
}
