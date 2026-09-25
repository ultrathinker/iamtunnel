//go:build windows || linux || darwin

package ui

import "testing"

// The guide chart marks nobody's progress (21.09.2026).
//
// This replaces two canaries that guarded the opposite: IAMT-397 taught
// step 4 to read the gateway's view so a target machine's step would tick
// on the administrator's screen. The reckoning worked; the premise did
// not. One window is all four roles, and nothing on disk says which role
// the person looking means, so any mark is a guess -- and the maintainer
// was shown step 1, an over-SSH step on the gateway, framed as their place.
//
// The rule now is absolute and therefore cheap to guard: whatever the
// snapshot says, no step comes back Here and no step comes back Done. A
// future attempt to reintroduce a mark from local facts reddens here.
func TestCanary_GuideMarksNoProgressForAnySnapshot(t *testing.T) {
	snaps := map[string]Snapshot{
		"empty":     {},
		"joined":    {Admin: AdminState{ThisMachine: &AdminIdentity{}}},
		"enrolled":  {Setup: SetupState{Status: "verified"}, Server: ServerState{Running: true}},
		"granted":   {Admin: AdminState{Grants: []Grant{{}}, Machines: []AdminMachine{{State: "verified", Online: true}}}},
		"inSession": {Server: ServerState{Sessions: []Session{{}}}},
	}
	for name, snap := range snaps {
		for i, st := range guideSteps(snap) {
			if st.Here {
				t.Errorf("snapshot %s: step %d (%q) came back Here -- the guide must point at no step, "+
					"because this window cannot know which of the four roles the person means", name, i+1, st.Number)
			}
			if st.Done {
				t.Errorf("snapshot %s: step %d (%q) came back Done -- the guide shows the process, not progress", name, i+1, st.Number)
			}
		}
	}
}
