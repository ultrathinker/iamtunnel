//go:build windows

package ui

// iamt151_update_snapshot_test.go is the canary for IAMT-151: the maintainer's
// decision to widen the closed method set of Frame by EXACTLY one method
// for handing the window new state, and nothing it touches beyond the
// snapshot itself. The whitelist entry in TestVerifyNoFourthInvariantSwitch
// (verify_iamt66_test.go) only proves the METHOD NAME is allowed to exist;
// this file proves what it is allowed to DO. Being in package ui (not
// ui_test) is deliberate: the checks read Frame's unexported fields
// directly, so a bug that resets the theme or the tab through some path
// the exported getters do not cover would still be caught, and the check
// does not depend on where the recording strip happens to land in the
// picture (it moves the tab strip down when it appears, which would make
// a fixed pixel region a false positive or a false negative depending on
// luck).
//
// The method was UpdateSnapshot(Snapshot) until 21.09.2026 and is now
// ApplyLiveUpdate(LiveUpdate). The invariant did not change; the argument
// did. See live_update.go for why a whole Snapshot was the wrong thing to
// hand over: the poll behind this door knows three facts, so a shadow
// copy of everything else had to be kept beside the window and written to
// by hand, and the day somebody forgot one of those writes a tab filled
// and blanked itself every three seconds.

import (
	"testing"
	"time"
)

// TestLiveUpdateMovesOnlyTheSnapshot builds one Frame, picks a theme and
// a tab that are NOT the frame's defaults (so a bug that silently resets
// either to a default would still be caught), applies an update
// dramatically different from the state the frame was built with, and
// checks: the theme did not move, the selected tab did not move, the
// elevation notice's visibility did not move, the underlying *design.Theme
// value is the very same pointer (CheckThemeSync was not re-triggered by
// the update), and the snapshot the screens will draw from next DID change.
func TestLiveUpdateMovesOnlyTheSnapshot(t *testing.T) {
	f, err := NewFrame(FrameConfig{
		Enrolled:       false,
		InitialTab:     TabAdmin, // not the frame's own default (TabClient)
		HasAdminRights: false,    // banner visible — must stay visible afterwards
		ForceTheme:     ThemeDark,
		Snap:           Snapshot{}, // no session yet: Recording() == false
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	if f.snap.Server.AccessOpen() {
		t.Fatalf("test bug: the zero snapshot already reports Recording() == true")
	}
	wantDark := f.IsDark()
	wantTab := f.CurrentTab()
	wantNotice := f.tabs.NoticeVisible()
	wantTheme := f.theme
	if !wantDark {
		t.Fatalf("test bug: ForceTheme: ThemeDark did not produce IsDark() == true")
	}
	if wantTab != TabAdmin {
		t.Fatalf("test bug: InitialTab: TabAdmin did not produce CurrentTab() == %q, got %q", TabAdmin, wantTab)
	}
	if !wantNotice {
		t.Fatalf("test bug: HasAdminRights: false did not make the elevation notice visible")
	}

	// An update as different as a real one gets, right after START and a
	// specialist connecting: recording on, waiting on, sshd on, and an
	// identity where there was none. If the door reached anything beyond
	// f.snap, this is the update most likely to disturb it — a
	// zero-to-zero one would prove nothing.
	f.ApplyLiveUpdate(LiveUpdate{
		Server: ServerState{
			Waiting:     true,
			SshdRunning: true,
			Door:        DoorState{State: "open"},
			Sessions: []Session{
				{Person: "alice", Started: time.Now(), Until: time.Now().Add(time.Hour)},
			},
		},
		Identity:      &AdminIdentity{Person: "alice", Gateway: "gw.example:2222"},
		IdentityKnown: true,
		At:            time.Now(),
	})

	// The value is parked; a Layout pass is what actually moves it into
	// f.snap (see takeSnapshot in live.go), exactly as the live window's
	// own event loop draws a frame after Invalidate. Drive one pass the
	// same way the offscreen shot does, then look at what moved and what
	// did not.
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render after ApplyLiveUpdate: %v", err)
	}

	if got := f.IsDark(); got != wantDark {
		t.Fatalf("ApplyLiveUpdate moved the theme: IsDark() = %v, want %v", got, wantDark)
	}
	if got := f.CurrentTab(); got != wantTab {
		t.Fatalf("ApplyLiveUpdate moved the selected tab: CurrentTab() = %q, want %q", got, wantTab)
	}
	if got := f.tabs.NoticeVisible(); got != wantNotice {
		t.Fatalf("ApplyLiveUpdate moved the elevation notice's visibility: NoticeVisible() = %v, want %v", got, wantNotice)
	}
	if f.theme != wantTheme {
		t.Fatalf("ApplyLiveUpdate replaced the live *design.Theme value — it must touch only the snapshot")
	}
	if !f.snap.Server.AccessOpen() {
		t.Fatalf("ApplyLiveUpdate did not take effect: f.snap.Server.AccessOpen() is still false after an update carrying a live session")
	}
	if f.snap.Admin.ThisMachine == nil || f.snap.Admin.ThisMachine.Person != "alice" {
		t.Fatalf("ApplyLiveUpdate did not carry the identity through: %+v", f.snap.Admin.ThisMachine)
	}
	if !f.snap.Client.Configured {
		t.Fatal("an update carrying an identity left Client.Configured false — " +
			"the Join card would go on insisting this machine has not joined")
	}
}

// TestLiveUpdateLeavesTheRestOfTheStateAlone is the defect the whole
// change exists for, stated as a test.
//
// The poll used to hand over a WHOLE Snapshot, assembled from a shadow
// copy that cmd/iamtunnel kept beside the window. Anything the window had
// learned for itself and the shadow had not — a history page, the detail
// line under Set up — was overwritten with nothing three seconds later.
// The maintainer watched exactly that happen to History on 21.09.2026: the
// list appeared, and a second and a half later it was empty.
//
// A LiveUpdate cannot do it. It has nowhere to put a history page.
func TestLiveUpdateLeavesTheRestOfTheStateAlone(t *testing.T) {
	f, err := NewFrame(FrameConfig{Enrolled: true, HasAdminRights: true})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	// What the window learned for itself, the way a finished action
	// reports it.
	f.reviseSnapshot(func(s *Snapshot) {
		s.History = HistoryPage{Total: 3, Rows: []HistoryRow{
			{SessionID: "s1", Person: "alice", Machine: "laptop"},
		}}
		s.Setup.MachineName = "laptop"
		s.Setup.Status = "enrolled"
		s.Setup.Detail = EnrolledDetail
		s.Admin.People = []Person{{Name: "alice", Admin: true}}
		s.Admin.RiskMode = RiskMode{Mode: "ask", Classifier: "both", ClassifierKey: true}
		s.Client.Machines = []MachineAccess{{Name: "laptop", Online: true}}
	})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render: %v", err)
	}

	// Three seconds later, the tick.
	f.ApplyLiveUpdate(LiveUpdate{Server: ServerState{SshdRunning: true}})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render after the tick: %v", err)
	}

	if len(f.snap.History.Rows) != 1 {
		t.Errorf("the poll blanked the history page: %d rows left, want 1 — "+
			"this is the defect the maintainer met on 21.09.2026", len(f.snap.History.Rows))
	}
	if f.snap.Setup.Detail != EnrolledDetail {
		t.Errorf("the poll blanked Setup.Detail: %q", f.snap.Setup.Detail)
	}
	if f.snap.Setup.MachineName != "laptop" {
		t.Errorf("the poll blanked Setup.MachineName: %q", f.snap.Setup.MachineName)
	}
	if len(f.snap.Admin.People) != 1 {
		t.Errorf("the poll blanked the people list: %d left, want 1", len(f.snap.Admin.People))
	}
	if f.snap.Admin.RiskMode.Classifier != "both" || !f.snap.Admin.RiskMode.ClassifierKey {
		t.Errorf("the poll blanked the classifier facts: %+v", f.snap.Admin.RiskMode)
	}
	if len(f.snap.Client.Machines) != 1 {
		t.Errorf("the poll blanked the machine list: %d left, want 1", len(f.snap.Client.Machines))
	}
	if !f.snap.Server.SshdRunning {
		t.Error("the poll did not deliver what it IS for: Server.SshdRunning is still false")
	}
}

// TestLiveUpdateKeepsHeldWhenTheGatewayCouldNotBeAsked separates
// "nothing is held" from "could not ask".
//
// A held command is an agent stopped mid-work with a five-minute clock
// running. A gateway that is briefly unreachable is not evidence that
// the offer was withdrawn, and a list blanked on a failed read retracts
// a question the person may be halfway through reading.
func TestLiveUpdateKeepsHeldWhenTheGatewayCouldNotBeAsked(t *testing.T) {
	f, err := NewFrame(FrameConfig{Enrolled: true, HasAdminRights: true})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	f.reviseSnapshot(func(s *Snapshot) {
		s.Client.Held = []HeldCommand{{ApprovalID: "a1", Machine: "laptop", Command: "rm -rf /"}}
	})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render: %v", err)
	}

	// HeldKnown false: the tick could not ask.
	f.ApplyLiveUpdate(LiveUpdate{Server: ServerState{SshdRunning: true}})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render after the unreachable tick: %v", err)
	}
	if len(f.snap.Client.Held) != 1 {
		t.Fatalf("a tick that could not reach the gateway withdrew the held command — "+
			"%d left, want 1", len(f.snap.Client.Held))
	}

	// HeldKnown true with an empty list: the gateway answered, and the
	// answer is that nothing is held. That one DOES clear it.
	f.ApplyLiveUpdate(LiveUpdate{Server: ServerState{SshdRunning: true}, HeldKnown: true})
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render after the answered tick: %v", err)
	}
	if len(f.snap.Client.Held) != 0 {
		t.Fatalf("the gateway said nothing is held and the list still shows %d — "+
			"an answered empty list must clear it, or an approved command never leaves the screen",
			len(f.snap.Client.Held))
	}
}
