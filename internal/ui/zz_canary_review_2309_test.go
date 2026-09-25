//go:build windows || linux || darwin

package ui

// Three findings from the review of yesterday's batch, 23.09.2026.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Export writes only inside the folder a person named.
//
// The file name is assembled from three pieces, and yesterday two of
// them were sanitised: the person and the machine -- obvious words
// from the gateway. The timestamp was skipped, because time is a
// number. But historyWhen, given an unparsed date, hands out the
// gateway's RAW string, and exportFileName changed only the colons
// and spaces in it: a "started" of the form "../../x" produced a name
// that filepath.Join resolves two directories ABOVE the chosen one.
//
// The gateway is trusted, and still: the export's single promise is
// that it writes where it was told. A name assembled from somebody
// else's words cannot keep that promise until the filter has passed
// EVERY piece.
func TestExportFileNameNeverLeavesTheChosenFolder(t *testing.T) {
	hostile := []string{
		"../../escaped",
		`..\..\escaped`,
		"/etc/passwd",
		`C:\Windows\System32\x`,
		"..",
	}
	const dir = "/tmp/export"
	for _, started := range hostile {
		row := HistoryRow{Started: started, Person: "bob", Machine: "srv"}
		name := exportFileName(row, 1)
		if strings.ContainsAny(name, `/\`) {
			t.Errorf("a path separator remained in the file name: started=%q -> %q", started, name)
		}
		full := filepath.Join(dir, name)
		if filepath.Dir(full) != filepath.Clean(dir) {
			t.Errorf("the record escapes the chosen folder: started=%q -> %q", started, full)
		}
	}
}

// An ordinary timestamp must stay readable all the same: a filter
// that swallows it too fixes one thing and breaks another -- a folder
// of three hundred files is sorted by that very timestamp.
func TestExportFileNameKeepsAReadableTimestamp(t *testing.T) {
	row := HistoryRow{
		Started: time.Date(2026, 9, 22, 14, 3, 5, 0, time.UTC).Format(time.RFC3339),
		Person:  "bob", Machine: "srv",
	}
	name := exportFileName(row, 7)
	if !strings.HasPrefix(name, "007_2026-09-22_") {
		t.Errorf("the timestamp stopped being readable in the file name: %q", name)
	}
}

// "The time ran out" is not "somebody has already taken it".
//
// For an expired token ClaimPending became false, and the card told
// the person "Already claimed": that is, somebody has become the
// administrator of your gateway. Nobody had -- the term simply ran
// out. The fix belongs right here, in place; the person would have
// gone looking for a non-existent colleague on our hint.
func TestGatewayClaimAbsentTextTellsExpiredFromSpent(t *testing.T) {
	base := GatewayState{Supported: true, Installed: true}

	pending := gatewayClaimAbsentText(GatewayState{Supported: true, Installed: true, ClaimPending: true})
	expired := gatewayClaimAbsentText(GatewayState{Supported: true, Installed: true, ClaimExpired: true})
	spent := gatewayClaimAbsentText(base)

	if expired == spent {
		t.Fatal("an expired line and a spent one are described in the same words -- two different facts stuck together again")
	}
	if expired == pending {
		t.Fatal("an expired line is described as still good")
	}
	if strings.Contains(strings.ToLower(expired), "already claimed") {
		t.Errorf("an expired token is declared spent: %q", expired)
	}
	if !strings.Contains(expired, "rebootstrap") {
		t.Errorf("the explanation does not name the way out -- reissuing the string: %q", expired)
	}
}

// The cross next to a gateway asks a second time.
//
// What goes away is not "one row of a list" but the whole connection
// string: the address, the person and the pinned fingerprint of the
// gateway's key. It can be brought back only by an administrator of
// that gateway, and if the entry was the last one the machine is left
// connected to nothing. In this same product "forget identity" and
// "remove a person" are confirmed twice; here a single press was
// enough.
func TestForgettingAGatewayAsksTwice(t *testing.T) {
	calls := make(chan string, 4)
	f := newForgetTestFrame(func(name string) (string, error) {
		calls <- name
		return "forgotten", nil
	})

	const ctl = ctlClientGateways + "/0/forget"
	f.forgetGateway(ctl, "Work")

	// Wait a LITTLE rather than check instantly: forgetting runs in a
	// separate goroutine, and "has not got round to it yet" looks
	// exactly like "did not". A canary that catches the first catches
	// it by accident.
	select {
	case name := <-calls:
		t.Fatalf("the first press already forgot the gateway %q -- without asking anything", name)
	case <-time.After(300 * time.Millisecond):
	}
	if !f.confirming[ctl] {
		t.Fatal("the first press did not arm the confirmation, so the second will confirm nothing either")
	}
	question := f.saidUnder(ctlClientGateways).text
	if !strings.Contains(question, "Work") {
		t.Errorf("the question does not name which gateway is being forgotten: %q", question)
	}
	if !strings.Contains(strings.ToLower(question), "again") {
		t.Errorf("the question does not say that another press is needed: %q", question)
	}

	f.forgetGateway(ctl, "Work")
	select {
	case name := <-calls:
		if name != "Work" {
			t.Errorf("the second press forgot the wrong gateway: %q", name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the second press did nothing -- the confirmation has become a refusal")
	}
}

// And only one cross is armed at a time: a question that has left the
// screen cannot stay answerable.
func TestArmingOneForgetDisarmsTheOthers(t *testing.T) {
	f := newForgetTestFrame(func(string) (string, error) { return "", nil })

	first := ctlClientGateways + "/0/forget"
	second := ctlClientGateways + "/1/forget"
	f.forgetGateway(first, "Home")
	f.forgetGateway(second, "Work")

	if f.confirming[first] {
		t.Error("the first cross stayed armed while the second is being asked -- the next press on it will go through without a question")
	}
	if !f.confirming[second] {
		t.Error("the second cross is not armed")
	}
}

func newForgetTestFrame(drop func(string) (string, error)) *Frame {
	f := &Frame{
		confirming: make(map[string]bool),
		said:       make(map[string]saying),
		working:    make(map[string]bool),
	}
	f.cfg.Actions.ClientForgetGateway = drop
	return f
}
