package core

import "testing"

// The maintainer's second probe: the late-reply/retired path also takes a
// door id straight from the machine. Is it validated the same way?
func TestOrchProbe2_LateReplyDoorIDValidated(t *testing.T) {
	for _, id := range []string{"", "late-door", "../../etc/passwd", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeeeZZZ"} {
		m := testMachine(t)
		apply(t, m, Input{Event: Status})
		apply(t, m, Input{Event: Reservation})
		apply(t, m, Input{Event: Timeout})
		cmds := apply(t, m, Input{Event: LateReply, Retired: true, DoorID: id})
		for _, c := range cmds {
			t.Logf("id=%q -> op=%q doorID=%q", id, c.Op, c.DoorID)
			if c.Op == "door.close" && !validDoorID(c.DoorID) {
				t.Errorf("door.close carries an invalid machine-supplied id %q", c.DoorID)
			}
		}
	}
}
