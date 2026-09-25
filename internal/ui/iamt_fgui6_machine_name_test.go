//go:build windows || linux || darwin

package ui

// iamt_fgui6_machine_name_test.go — F-GUI-6 (review round 25,
// MEDIUM, confirmed): an ordinary user with a root-owned 0700 server
// data directory cannot read machine.id at all — os.Stat/os.ReadFile
// both fail with a permission error, not "file not found". The Server
// tab's "machine" fact used to render that through
// design.Fact("machine", orDash(...)), which prints a bare "—" —
// indistinguishable from "there genuinely is no machine name to show",
// the exact "unknown read as false/absent" mistake round 3 (F-GUI-2)
// already fixed for sshd/tunnel/door/recording/sessions, one layer over.

import "testing"

func TestFGUI6_MachineNameTextIsUnknownNotDash(t *testing.T) {
	got := machineNameText(SetupState{MachineNameUnknown: true})
	if got == "—" || got == "" {
		t.Fatalf("machineNameText(unknown) = %q, want an honest \"unknown\" sentence, not a dash indistinguishable from a genuinely absent name (F-GUI-6)", got)
	}

	// A genuinely absent name (the id file read cleanly and is empty, or
	// enrolment never happened) is unaffected: still the ordinary dash.
	if got := machineNameText(SetupState{}); got != "—" {
		t.Fatalf("machineNameText(genuinely absent) = %q, want the ordinary dash", got)
	}

	// A known name is unaffected.
	if got := machineNameText(SetupState{MachineName: "lin-ubu-vm"}); got != "lin-ubu-vm" {
		t.Fatalf("machineNameText(known) = %q, want the name verbatim", got)
	}
}
