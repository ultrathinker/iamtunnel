package core

import "testing"

// The maintainer's own probe, not part of the delivered work: after a
// door.sanitize is sent for a corrupted marker, what does the automaton
// issue when the machine does not answer in time?
func TestOrchProbe_SanitizeTimeoutRetry(t *testing.T) {
	m := testMachine(t)
	if _, err := m.Apply(Input{Event: Status, Installed: true, DoorID: "not-a-uuid"}); err != nil {
		t.Fatalf("status: %v", err)
	}
	cmds, err := m.Apply(Input{Event: Timeout})
	if err != nil {
		t.Fatalf("timeout: %v", err)
	}
	for _, c := range cmds {
		t.Logf("retry command: op=%q doorID=%q reason=%q", c.Op, c.DoorID, c.Reason)
	}
	if len(cmds) == 1 && cmds[0].Op == "door.close" && cmds[0].DoorID == "" {
		t.Fatalf("retry after sanitize timeout is door.close with an EMPTY door id")
	}
}
