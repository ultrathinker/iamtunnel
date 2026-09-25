//go:build windows || linux || darwin

package ui

import (
	"os"
	"strings"
	"testing"
)

// Canary: switching gateways erases EVERYTHING the previous one
// answered.
//
// 22.09.2026. Two gateways are not two settings of one product but
// two different worlds: each has its own machines, its own people,
// its own grants, its own history. The single thing they share is
// the key in the client's directory.
//
// Hence the one real danger of this function. A window that switched
// to the work gateway and left the list of personal machines on
// screen shows a TRUE list of the WRONG world -- and the buttons
// under it already act on the new gateway. It is the same kind of
// lie as the empty transcript: it looks like an answer.
//
// The test keeps the list of fields that must be zeroed. If another
// gateway answer is added to the snapshot, add it here too, or it
// will survive the switch silently.
func TestCanary_SwitchingGatewaysDropsTheOldAnswers(t *testing.T) {
	f := &Frame{}
	f.snap = Snapshot{
		Client: ClientState{
			Machines: []MachineAccess{{Name: "personal-nas"}},
			Held:     []HeldCommand{{ApprovalID: "a1", Command: "rm -rf /"}},
		},
		Admin: AdminState{
			People:         []Person{{Name: "alice"}},
			Machines:       []AdminMachine{{Name: "personal-nas"}},
			Grants:         []Grant{{Person: "alice", Machine: "personal-nas"}},
			ActiveSessions: []Session{{Person: "alice"}},
			ThisMachine:    &AdminIdentity{Person: "admin", Gateway: "home:2022"},
			RiskMode:       RiskMode{Mode: "strict", Classifier: "ai", ClassifierKey: true},
			AuditProblem:   "the audit journal is not being written",
			Pairing:        &PairingWindow{Pin: "123456", Ref: "home-ref"},
		},
		History: HistoryPage{Rows: []HistoryRow{{SessionID: "s1"}}, Total: 1},
	}

	f.forgetTheOtherGatewaysAnswers()

	// reviseSnapshot writes the NEXT frame, not the one on screen
	// (live.go): a Snapshot is an immutable value and the window swaps
	// it in when it draws. So the question this test asks is "what will
	// the very next frame show", which is the moment that matters --
	// between the press and the new gateway's first reply.
	if f.pending == nil {
		t.Fatal("the switch did not prepare a new frame at all")
	}
	f.snap = *f.pending

	for _, bad := range []struct {
		what string
		left bool
	}{
		{"Client.Machines", len(f.snap.Client.Machines) != 0},
		{"Client.Held", len(f.snap.Client.Held) != 0},
		{"Admin.People", len(f.snap.Admin.People) != 0},
		{"Admin.Machines", len(f.snap.Admin.Machines) != 0},
		{"Admin.Grants", len(f.snap.Admin.Grants) != 0},
		{"Admin.ActiveSessions", len(f.snap.Admin.ActiveSessions) != 0},
		{"Admin.ThisMachine", f.snap.Admin.ThisMachine != nil},
		// R1-CX F-16: three gateway answers added to the snapshot after
		// this list and surviving the switch: the previous gateway's
		// protection mode and classifier key, its journal trouble, and
		// the PIN of its pairing window.
		{"Admin.RiskMode", f.snap.Admin.RiskMode != (RiskMode{})},
		{"Admin.AuditProblem", f.snap.Admin.AuditProblem != ""},
		{"Admin.Pairing", f.snap.Admin.Pairing != nil},
		{"History.Rows", len(f.snap.History.Rows) != 0},
		{"History.Total", f.snap.History.Total != 0},
	} {
		if bad.left {
			t.Errorf("%s survived the gateway switch. That is ANOTHER gateway's list on screen, "+
				"with buttons under it already acting on the new one -- a truthful answer about the wrong world", bad.what)
		}
	}
}

// Canary: the switch has no password, and there is nowhere for one
// to come from.
//
// All authentication in the product is a key in the client's
// directory, one per machine, and each gateway already holds its
// public half. A password input here would be a ritual with no
// protocol behind it: it would verify nothing, yet it would teach a
// person to type a password when a program asks -- the very habit
// phishing exists for.
func TestCanary_NoPasswordOnTheClientTab(t *testing.T) {
	for _, name := range []string{"gateways.go", "screens.go"} {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)
		// widget.Editor.Mask is the only way to draw a password field;
		// its appearance on these screens is the finding.
		if strings.Contains(text, ".Mask =") {
			t.Errorf("%s draws a field with masked input. There is nothing to type into it in this product: "+
				"authentication is a key, and each gateway already holds its public half", name)
		}
	}
}
