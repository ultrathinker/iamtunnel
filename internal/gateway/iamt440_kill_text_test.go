package gateway

// IAMT-440 (kill text): a person whose session an administrator ended with
// sessions.kill read "Session closed: the grant was revoked." - which was
// not true (the grant stands, and a fresh login is let in at once) and sent
// them to ask for access they still had. The journal always knew better
// ("session ended by administrator"); now the person does too.

import (
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
)

func TestIAMT440_EachEndIsNamedForWhatItWas(t *testing.T) {
	for _, tc := range []struct {
		reason acl.DenyReason
		want   string
	}{
		{acl.DenyGrantExpired, "the grant expired"},
		{acl.DenyGrantRevoked, "the grant was revoked"},
		{acl.DenyKeyRemoved, "the key it was opened with was removed"},
		{acl.DenyAdminKilled, "an administrator ended this session"},
	} {
		if got := sessionClosedMessage(tc.reason); !strings.Contains(got, tc.want) {
			t.Errorf("%v: the person reads %q, want %q in it", tc.reason, got, tc.want)
		}
	}
	if got := sessionClosedMessage(acl.DenyAdminKilled); strings.Contains(got, "revoked") {
		t.Errorf("a killed session is told its grant was revoked: %q", got)
	}
}

func TestIAMT440_AKilledSessionIsToldAnAdministratorEndedIt(t *testing.T) {
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

	active, err := root.SessionsActive()
	if err != nil || len(active) != 1 {
		t.Fatalf("sessions.active: %v %v", active, err)
	}
	if err := root.SessionsKill(active[0].ID, "iamt-440"); err != nil {
		t.Fatalf("sessions.kill: %v", err)
	}
	text := readAll(t, hs.ch, 2*time.Second)
	if strings.Contains(text, "revoked") || !strings.Contains(text, "an administrator ended this session") {
		t.Fatalf("the person whose session was killed reads %q", text)
	}
}
