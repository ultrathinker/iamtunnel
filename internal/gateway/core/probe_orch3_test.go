package core

import "testing"

// The maintainer's third probe: the report claims openingSuccess and
// closingSuccess only ever compare the machine-supplied id and never
// let it reach an outgoing command. Check that by exhaustion, not by
// reading: drive every path that ends in one of them with rubbish ids
// and assert no command carries a name that fails validDoorID.
func TestOrchProbe3_NoCommandCarriesAnUnvalidatedName(t *testing.T) {
	rubbish := []string{"", "x", "../../etc/passwd", "late-door",
		"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", "00000000-0000-0000-0000-00000000000"}
	check := func(t *testing.T, where string, cmds []Command) {
		t.Helper()
		for _, c := range cmds {
			if c.DoorID != "" && !validDoorID(c.DoorID) {
				t.Errorf("%s: command %q carries an unvalidated door id %q", where, c.Op, c.DoorID)
			}
		}
	}
	for _, id := range rubbish {
		t.Run("openingSuccess/"+id, func(t *testing.T) {
			m := testMachine(t)
			apply(t, m, Input{Event: Status})
			apply(t, m, Input{Event: Reservation})
			cmds, err := m.Apply(Input{Event: Success, DoorID: id})
			if err != nil {
				return // a protocol refusal is a legitimate outcome
			}
			check(t, "openingSuccess", cmds)
		})
		t.Run("closingSuccess/"+id, func(t *testing.T) {
			m := testMachine(t)
			apply(t, m, Input{Event: Status})
			apply(t, m, Input{Event: Reservation})
			apply(t, m, Input{Event: Success})
			apply(t, m, Input{Event: CancelReservation})
			cmds, err := m.Apply(Input{Event: Success, DoorID: id, Own: true})
			if err != nil {
				return
			}
			check(t, "closingSuccess", cmds)
		})
	}
}
