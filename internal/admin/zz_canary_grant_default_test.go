package admin

import "testing"

// Canary for IAMT-400, the maintainer's decision of 2026-09-20.
//
// A grant issued without an explicit capability must default to exec,
// not shell.
//
// This is not a matter of taste. On an exec grant, the gateway sees the
// whole command before a single byte reaches the machine — so any
// safety mode (warn, ask, block) has a moment to act. On a shell grant,
// individual keystrokes travel over the channel; there is no moment at
// which the command exists as a string, so NO safety mode can apply
// there at all.
//
// The default is what a person gets who never thought about the
// choice. Handing them "no safety net at all" is wrong.
func TestCanary_IAMT400_GrantDefaultsToExec(t *testing.T) {
	// No actual wire needed here: exactly the default branch is under
	// test, so this calls the same place GrantsGrant does, without a
	// network.
	got := grantCapsOrDefault(nil)
	if len(got) != 1 || got[0] != "exec" {
		t.Errorf("CANARY IAMT-400: a grant with no explicit capability gets %v, want [exec]. "+
			"shell means \"the safety net does not work at all\" — that is not what a person "+
			"gets by default when they did not think about the choice", got)
	}

	if got := grantCapsOrDefault([]string{"shell"}); len(got) != 1 || got[0] != "shell" {
		t.Errorf("CANARY IAMT-400: an explicitly requested shell turned into %v — "+
			"the default has no right to override a deliberate choice", got)
	}
	if got := grantCapsOrDefault([]string{""}); len(got) != 1 || got[0] != "exec" {
		t.Errorf("CANARY IAMT-400: an empty capability string gave %v, want it to behave "+
			"like no choice at all, i.e. [exec]", got)
	}
}
