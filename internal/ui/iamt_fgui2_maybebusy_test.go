//go:build windows || linux || darwin

package ui

// iamt_fgui2_maybebusy_test.go — F-GUI-2 (review round 20, HIGH,
// confirmed): pollServerStatus correctly builds ServerState{Unknown:
// true} when it cannot learn the truth, but Recording()/Busy() never
// consult Unknown — every other field stays at its Go zero value, so a
// screen that gates the Stop control (or the recording strip) on
// Busy()/Recording() alone silently draws "definitely idle" over a
// server that may in fact be busy, its door open, a session recording.
// MaybeBusy is the one predicate every such screen decision must use
// instead. Pure function, no window needed.

import "testing"

func TestFGUI2_MaybeBusyIsTrueWheneverUnknown(t *testing.T) {
	cases := []struct {
		name string
		s    ServerState
		want bool
	}{
		{"unknown, otherwise a bare zero value", ServerState{Unknown: true}, true},
		{"unknown, even if every other field also looks idle", ServerState{Unknown: true, Waiting: false, Door: DoorState{State: "closed"}}, true},
		{"known and genuinely idle", ServerState{}, false},
		{"known and waiting", ServerState{Waiting: true}, true},
		{"known and recording", ServerState{Sessions: []Session{{}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.MaybeBusy(); got != tc.want {
				t.Fatalf("MaybeBusy() = %v, want %v — an unknown status must never be treated as demonstrably idle (F-GUI-2)", got, tc.want)
			}
		})
	}
}
