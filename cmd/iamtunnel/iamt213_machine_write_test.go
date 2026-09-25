package main

// IAMT-213 round 2: the machine role's own data is locked to
// SYSTEM/Administrators, so from a non-elevated console "enrol" fails
// on a permission error. classifyMachinePathErr turns that failure
// into the denied class with the same "Run as administrator" hint the
// elevation gate uses, instead of a bare "Access is denied". These
// assertions pin the class and the wording — no elevation or ACL work
// needed, so the test is platform-independent.

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// TestIAMT213_MachineDataDeniedNamesTheFix pins the classification:
// a permission failure on a machine-data path is exitDenied (4) and
// names the fix; any other failure stays an environment error (3).
//
// Canary: drop the os.IsPermission branch from classifyMachinePathErr
// (or route the machine helpers back through classifyPathErr) and this
// goes red on its own line.
func TestIAMT213_MachineDataDeniedNamesTheFix(t *testing.T) {
	denied := classifyMachinePathErr(fs.ErrPermission, `C:\ProgramData\iamtunnel\machine.key`)
	var ce *cliError
	if !errors.As(denied, &ce) {
		t.Fatalf("classifyMachinePathErr(permission) = %v (%T), want a *cliError", denied, denied)
	}
	if ce.code != exitDenied {
		t.Errorf("classifyMachinePathErr(permission): exit code = %d, want exitDenied (%d)", ce.code, exitDenied)
	}
	for _, want := range []string{
		`machine data is restricted to administrators`,
		`Run as administrator`,
	} {
		if !strings.Contains(denied.Error(), want) {
			t.Errorf("denied message %q must contain %q", denied.Error(), want)
		}
	}

	other := classifyMachinePathErr(errors.New("boom"), `C:\ProgramData\iamtunnel\machine.id`)
	var ce2 *cliError
	if !errors.As(other, &ce2) {
		t.Fatalf("classifyMachinePathErr(other) = %v (%T), want a *cliError", other, other)
	}
	if ce2.code != exitEnv {
		t.Errorf("classifyMachinePathErr(other): exit code = %d, want exitEnv (%d)", ce2.code, exitEnv)
	}
}
