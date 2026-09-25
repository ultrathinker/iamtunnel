package gateway

// IAMT-440 (extra): IAMT-440 gave sessions.kill a text of its own, and every
// other way an administrator ends a session while leaving the access in
// place still told the person "Session closed: the grant was revoked." -
// and the journal's session.drop said "access revoked by administrator".
// Narrowing a grant to commands, moving its deadline closer and renaming
// the person all end live sessions through the same revocation that a
// real revoke uses; changing a machine's OS account ended them with a
// reason the message had no line for. Each of them sent the person to ask
// for access they still had.

import (
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestIAMT440_AnEndThatLeavesTheAccessDoesNotSayRevoked(t *testing.T) {
	for _, tc := range []struct {
		name string
		act  func(t *testing.T, f *fixture, root *admin.Conn)
		want string
	}{
		{"grants.set-caps from shell to exec", func(t *testing.T, f *fixture, root *admin.Conn) {
			if _, _, err := root.GrantsSetCaps(f.person, f.machineID, "exec"); err != nil {
				t.Fatal(err)
			}
		}, "changed your access to this machine"},
		{"grants.extend to an earlier deadline", func(t *testing.T, f *fixture, root *admin.Conn) {
			until := f.clock.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339)
			if _, _, _, err := root.GrantsExtend(f.person, f.machineID, until); err != nil {
				t.Fatal(err)
			}
		}, "changed your access to this machine"},
		{"people.rename", func(t *testing.T, f *fixture, root *admin.Conn) {
			if _, err := root.PeopleRename(f.person, f.person+"-renamed"); err != nil {
				t.Fatal(err)
			}
		}, "renamed you"},
		{"machines.set-user", func(t *testing.T, f *fixture, root *admin.Conn) {
			if err := root.MachinesSetUser(f.machineID, `MACHINE\other`); err != nil {
				t.Fatal(err)
			}
		}, "changed the account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.connectMachine(fakeMachineBehavior{})
			f.waitMachineOnline(t)
			rootKey := genSigner(t)
			addPerson(t, f, "root", "admin", rootKey)
			root := dialAdmin(t, f, "root", rootKey)

			client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer client.Close()
			hs := openHumanSession(t, client, f)
			hs.shell(t)
			waitUntil(t, "the session did not start", func() bool { return len(f.gw.aclE.Sessions()) == 1 })

			tc.act(t, f, root)
			text := readAll(t, hs.ch, 2*time.Second)
			if strings.Contains(text, "revoked") || !strings.Contains(text, tc.want) {
				t.Errorf("after %s the person reads %q, want %q and no \"revoked\"", tc.name, text, tc.want)
			}
			evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range evs {
				if e.Result == acl.DenyGrantRevoked.String() {
					t.Errorf("after %s the journal says %q", tc.name, e.Result)
				}
			}
		})
	}
}
