package gateway

import (
	"testing"
)

// The canary: a history row and a recording are stitched together by
// sessionId.
//
// 22.09.2026. The window standing on a History row holds the SESSION
// identifier. recordings.fetch accepts a different identifier — the hash
// of the recording's path on the gateway, which cannot be derived from a
// history row at all. While recordings.list did not return sessionId,
// these two halves of the product could not be joined, and the Transcript
// button in History opened an empty window.
//
// The test checks exactly the seam: one and the same real session must be
// recognizable both in sessions.history and in recordings.list, and its
// mode must say which reader opens the bytes.
func TestCanary_RecordingJoinsItsHistoryRow(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	root := dialRootAdmin(t, f)
	recordOneSession(t, f)
	f.waitSessionEnd(t, "session never reached its terminal event")

	recs, err := root.RecordingsList(f.machineID, "", "")
	if err != nil {
		t.Fatalf("recordings.list: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected exactly one recording, got %d", len(recs))
	}
	rec := recs[0]
	if rec.SessionID == "" {
		t.Fatal("recordings.list says nothing about sessionId. A history row holds exactly that, " +
			"while recordings.fetch accepts only the id-hash of the path — without sessionId these two ends cannot be stitched, " +
			"and the Transcript button in History opens an empty window")
	}
	if rec.ID == "" {
		t.Fatal("recordings.list did not name the id — by it and only by it are the bytes read")
	}
	if rec.ID == rec.SessionID {
		t.Error("id and sessionId are equal: these are different things, and if they became one, " +
			"one of the two has stopped being itself")
	}

	page, err := root.SessionsHistory("", f.machineID, "", "", 50, 0)
	if err != nil {
		t.Fatalf("sessions.history: %v", err)
	}
	found := false
	for _, r := range page.Sessions {
		if r.SessionID == rec.SessionID {
			found = true
			break
		}
	}
	if !found {
		var seen []string
		for _, r := range page.Sessions {
			seen = append(seen, r.SessionID)
		}
		t.Fatalf("the recording named itself session %q, but history does not know such a session: %v. "+
			"This is the seam: if two verbs name one session differently, "+
			"there is nothing to tie a history row to its recording with", rec.SessionID, seen)
	}

	// mode is the choice of reader. An empty value means asciicast (a
	// terminal session), "exec" — a line-by-line journal of one command.
	// There must be no third: an unknown value leads the reader into
	// plausible garbage instead of an error.
	switch rec.Mode {
	case "", "exec":
	default:
		t.Errorf("recordings.list named an unknown mode %q — the reader is chosen by it", rec.Mode)
	}
}
