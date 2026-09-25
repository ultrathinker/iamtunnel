//go:build windows

package ui

// zz_accept_d2a_rename_gui_test.go — the GUI half of D-2a's canaries,
// driven at the same actions layer zz_accept_m10_extend_gui_test.go drives
// extendAccess: no rendered frame, just the form machinery. What is
// actually D-2a's here is small and exactly bounded: the box opens
// cleared and an EMPTY box or the unchanged name is refused before
// anything travels, and the machines row speaks by its ID — the thing a
// rename does not touch — never by the label that just changed.

import (
	"testing"
	"time"
)

func TestD2aRenameFormClearsTheBoxOnOpen(t *testing.T) {
	f := newBareFrame(t)
	ctl := "admin/rename/person/alice"
	f.editor(ctl + "/box").SetText("alicia")

	f.renameForm(ctl)
	if !f.disclosedForm(ctl) {
		t.Fatal("renameForm did not open the form")
	}
	if got := f.editor(ctl + "/box").Text(); got != "" {
		t.Errorf("box holds %q after the form opened, want it cleared — a name left over from a previous open must never look like the one being applied now", got)
	}

	f.renameForm(ctl)
	if f.disclosedForm(ctl) {
		t.Fatal("renameForm did not close the form on the second press")
	}
}

func TestD2aRenamePersonRefusesAnEmptyBox(t *testing.T) {
	f := newBareFrame(t)
	ctl := "admin/rename/person/alice"
	f.renameForm(ctl) // a fresh form, box empty

	asked := make(chan string, 1)
	f.cfg.Actions.AdminRenamePerson = func(from, to string) (string, error) {
		asked <- to
		return "", nil
	}

	f.renamePerson(ctl, "alice")

	select {
	case to := <-asked:
		t.Fatalf("an empty box reached the gateway as to=%q — a press with nothing typed must be refused, not sent", to)
	case <-time.After(guardWait):
	}

	if said := f.saidUnder(ctl); said.text == "" {
		t.Error("the refusal left no word under the form — the reader is left pressing a button that silently does nothing")
	}
}

func TestD2aRenamePersonRefusesTheSameName(t *testing.T) {
	f := newBareFrame(t)
	ctl := "admin/rename/person/alice"
	f.renameForm(ctl)
	f.editor(ctl + "/box").SetText("alice")

	asked := make(chan string, 1)
	f.cfg.Actions.AdminRenamePerson = func(from, to string) (string, error) {
		asked <- to
		return "", nil
	}

	f.renamePerson(ctl, "alice")

	select {
	case to := <-asked:
		t.Fatalf("the unchanged name reached the gateway as to=%q — renaming alice to alice can only be a miscount, not a request", to)
	case <-time.After(guardWait):
	}
}

func TestD2aRenameMachineSpeaksByIDNotByLabel(t *testing.T) {
	f := newBareFrame(t)
	f.snap.Admin.Machines = []AdminMachine{{ID: "vm1", Name: "old-box"}}
	ctl := "admin/rename/machine/vm1"
	f.renameForm(ctl)
	f.editor(ctl + "/box").SetText("win-box")

	asked := make(chan [2]string, 1)
	f.cfg.Actions.AdminRenameMachine = func(id, name string) (string, error) {
		asked <- [2]string{id, name}
		return "renamed", nil
	}

	f.renameMachine(ctl, "vm1")

	select {
	case got := <-asked:
		if got[0] != "vm1" {
			t.Fatalf("rename asked for machine %q, want the id — the label is what changed, not the machine", got[0])
		}
		if got[1] != "win-box" {
			t.Fatalf("rename asked for label %q, want win-box from the box", got[1])
		}
	case <-time.After(guardWait):
		t.Fatal("renameMachine asked the gateway nothing")
	}
}

func TestD2aRenameMachineRefusesItsCurrentLabel(t *testing.T) {
	f := newBareFrame(t)
	f.snap.Admin.Machines = []AdminMachine{{ID: "vm1", Name: "old-box"}}
	ctl := "admin/rename/machine/vm1"
	f.renameForm(ctl)
	f.editor(ctl + "/box").SetText("old-box")

	asked := make(chan string, 1)
	f.cfg.Actions.AdminRenameMachine = func(id, name string) (string, error) {
		asked <- name
		return "", nil
	}

	f.renameMachine(ctl, "vm1")

	select {
	case name := <-asked:
		t.Fatalf("the machine's current label reached the gateway as name=%q — the snapshot already says that is what it is called", name)
	case <-time.After(guardWait):
	}
}

func TestD2aRenameWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	ctl := "admin/rename/person/alice"
	f.renameForm(ctl)
	f.editor(ctl + "/box").SetText("alicia")
	// AdminRenamePerson deliberately left nil: a Frame without a runtime
	// (the offscreen shot) must say so, never silently do nothing.

	f.renamePerson(ctl, "alice")

	if said := f.saidUnder(ctl); said.text == "" {
		t.Error("no runtime and no word about it — the button read as dead rather than unavailable")
	}
}
