package gateway

import "testing"

// The canary: only an administrator may change a grant's mode.
//
// On 21.09.2026 the maintainer suggested showing the mode in the
// machine's row on the CLIENT tab and toggling it with a click.
// Showing -- yes. Toggling from there -- only with an administrator's
// key, and that is not a piece of styling: it is the one thing the
// exec mode exists for at all.
//
// The CLIENT tab belongs to whoever DIALS IN. If the one dialing in
// can widen access from "one command" to "a full shell" themselves,
// the narrow mode protects against nothing: an AI agent given exec
// will press that button first thing. The window shows the toggle only
// to a client carrying an administrator's identity, but the window
// does not decide -- the gateway decides, by the key.
//
// The check looks into the gateway's command table, not at the screen:
// the screen can be bypassed by sending the request directly. Removing
// adminOnly from grants.set-caps -- turns red right here.
func TestCanary_SetCapsIsAdminOnly(t *testing.T) {
	cmd, ok := commandTable["grants.set-caps"]
	if !ok {
		t.Fatal("the gateway no longer knows grants.set-caps -- the mode window and the CLI call a command that does not exist")
	}
	if !cmd.adminOnly {
		t.Error("grants.set-caps stopped being adminOnly: whoever dials in could widen their own " +
			"access from exec to shell, and the whole point of the narrow mode would be gone")
	}

	// And along the way: the neighbours sharing the same responsibility.
	// If adminOnly is lifted from them, access can be widened by a side
	// door -- grant yourself a new grant or tear down someone else's.
	for _, name := range []string{"grants.grant", "grants.revoke", "people.remove", "machines.remove"} {
		c, ok := commandTable[name]
		if !ok {
			t.Errorf("the gateway no longer knows %s", name)
			continue
		}
		if !c.adminOnly {
			t.Errorf("%s stopped being adminOnly", name)
		}
	}
}
