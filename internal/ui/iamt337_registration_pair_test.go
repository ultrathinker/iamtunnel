package ui

// iamt337_registration_pair_test.go — the window has to say WHOSE
// registration it is driving.
//
// Until 1.4 the question could not be asked: a machine held exactly one
// registration, so "this machine" and "this registration" were the same
// thing and the name alone answered both. 1.4 makes a registration the
// pair (machine, name), one per person, because two programmers share one
// Windows box over Remote Desktop — each with his own account, his own
// data directory, his own door line and his own audit trail.
//
// On that box both of them can have this window open at the same moment,
// in two sessions, showing the same "machine" row. If that row carries
// only the name, each of them is looking at a fact that does not
// distinguish him from his colleague — and the first thing either would
// do on seeing something unexpected is assume it is his.

import "testing"

// TestIAMT337_TheMachineRowNamesTheAccountItIsBoundTo. The account is
// not decoration: it is what the gateway verified by logging in as it
// during enrolment, and the account whose authorized_keys carries the
// door line.
//
// Canary: drop the pair branch from machineNameText and this goes red on
// "does not name the account".
func TestIAMT337_TheMachineRowNamesTheAccountItIsBoundTo(t *testing.T) {
	got := machineNameText(SetupState{MachineName: "office-pc", OSUser: `EXAMPLE\dana`})
	if got != `office-pc (EXAMPLE\dana)` {
		t.Errorf("the machine row reads %q — it does not name the account this registration is bound to, so on a machine two people share it does not say which of them the window is driving", got)
	}
}

// TestIAMT337_TwoRegistrationsOnOneMachineReadDifferently is the same
// point put as the thing that must not happen: two people, one box, two
// windows open at once, and a row that reads the same in both.
func TestIAMT337_TwoRegistrationsOnOneMachineReadDifferently(t *testing.T) {
	dana := machineNameText(SetupState{MachineName: "office-pc", OSUser: `EXAMPLE\dana`})
	erik := machineNameText(SetupState{MachineName: "lab-pc", OSUser: `EXAMPLE\erik`})
	if dana == erik {
		t.Fatalf("both registrations on one machine draw the same row (%q) — neither person can tell his own from his colleague's", dana)
	}
}

// TestIAMT337_ARegistrationFromBeforeThisReleaseStillReadsAsItAlwaysDid.
// An enrolment record written by 1.3 carries no account at all. Drawing
// "office-pc ()" — or worse, a dash where the name belongs — would make
// an upgraded machine look broken; the name alone is exactly what those
// builds always showed and remains a true statement.
func TestIAMT337_ARegistrationFromBeforeThisReleaseStillReadsAsItAlwaysDid(t *testing.T) {
	if got := machineNameText(SetupState{MachineName: "office-pc"}); got != "office-pc" {
		t.Errorf("a pre-1.4 registration draws %q, want the bare name", got)
	}
}

// TestIAMT337_CannotReadStillBeatsTheName is the tri-state this screen
// has made since F-GUI-2, checked again now that the row has a second
// source: "could not read it" and "read it, here it is" are different
// claims, and the first must not be softened into a name plus an account
// that were never read.
func TestIAMT337_CannotReadStillBeatsTheName(t *testing.T) {
	got := machineNameText(SetupState{MachineName: "office-pc", OSUser: `EXAMPLE\dana`, MachineNameUnknown: true})
	if got == `office-pc (EXAMPLE\dana)` {
		t.Fatal("a registration that could not be read drew as though it had been read")
	}
	if got == "" || got == "—" {
		t.Errorf("the unreadable case draws %q — it must say it could not be read, not look like an absent name", got)
	}
}
