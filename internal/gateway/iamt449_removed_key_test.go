package gateway

// IAMT-449: a person's connection kept every right its key had at the
// handshake. The command path remembered only the person's name, and
// runCommand checked that name's role afresh on every command - never
// whether the key that opened the connection was still the person's. A key
// removed with people.keys.remove, or with its person, went on running
// commands on a connection it had opened before - people.keys.add among
// them, which puts a key back for good - and a session to a machine opened
// with it went on as if nothing had happened.

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func iamt449AddKey(t *testing.T, f *fixture, person string, key ssh.Signer) {
	t.Helper()
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.People {
			if st.People[i].Name == person {
				st.People[i].Keys = append(st.People[i].Keys, state.Key{Fingerprint: fingerprintOf(t, key.PublicKey()),
					Pub: authorizedLine(key.PublicKey()), Added: state.NewZonedTime(f.clock.Now())})
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("add a key to %s: %v", person, err)
	}
}

func iamt449HasKey(f *fixture, person, fp string) bool {
	st := f.store.Get()
	for _, p := range st.People {
		if p.Name != person {
			continue
		}
		for _, k := range p.Keys {
			if k.Fingerprint == fp {
				return true
			}
		}
	}
	return false
}

// iamt449CommandLogin opens a command login ("<person>") with key and
// returns a channel that is closed when the gateway ends the connection.
func iamt449CommandLogin(t *testing.T, f *fixture, person string, key ssh.Signer) <-chan struct{} {
	t.Helper()
	c, err := dialHumanClient(f.addr, &ssh.ClientConfig{
		User:            person,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("command login as %s: %v", person, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ended := make(chan struct{})
	go func() {
		_ = c.Wait()
		close(ended)
	}()
	return ended
}

func iamt449Ended(ch <-chan struct{}) func() bool {
	return func() bool {
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}
}

func TestIAMT449_ARemovedKeyRunsNoCommandOnAConnectionItOpenedBefore(t *testing.T) {
	f := newFixture(t, nil)
	stolenKey, ownKey := genSigner(t), genSigner(t)
	addPerson(t, f, "root", "admin", stolenKey)
	iamt449AddKey(t, f, "root", ownKey)
	stolen := dialAdmin(t, f, "root", stolenKey)
	if _, err := stolen.Whoami(); err != nil {
		t.Fatalf("precondition: whoami on the connection: %v", err)
	}

	// The key leaves the person's keys the way people.keys.remove takes it
	// out - but straight through the store, so that nothing the removal
	// command does afterwards can stand in for the check before a command.
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.People {
			if st.People[i].Name == "root" {
				st.People[i].Keys = st.People[i].Keys[1:]
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("remove the key: %v", err)
	}
	if iamt449HasKey(f, "root", fingerprintOf(t, stolenKey.PublicKey())) {
		t.Fatal("setup: the key is still root's")
	}

	planted := genSigner(t)
	_, err := stolen.PeopleKeysAdd("root", authorizedLine(planted.PublicKey()))
	if iamt449HasKey(f, "root", fingerprintOf(t, planted.PublicKey())) {
		t.Fatalf("a key already removed from root ran people.keys.add on the connection it had open, and gave root a key of its choosing (err=%v)", err)
	}
	if err == nil {
		t.Fatal("people.keys.add on the removed key's connection reported success")
	}
}

func TestIAMT449_RemovingAKeyClosesTheConnectionsItOpened(t *testing.T) {
	f := newFixture(t, nil)
	oldKey, newKey := genSigner(t), genSigner(t)
	addPerson(t, f, "root", "admin", oldKey)
	iamt449AddKey(t, f, "root", newKey)
	idle := iamt449CommandLogin(t, f, "root", oldKey)
	self := dialAdmin(t, f, "root", oldKey)
	other := dialAdmin(t, f, "root", newKey)

	// The key is removed over a connection it opened itself: that command
	// is answered first, and then its connection goes with the others.
	if err := self.PeopleKeysRemove("root", fingerprintOf(t, oldKey.PublicKey())); err != nil {
		t.Fatalf("people.keys.remove of the key the command came in on: %v", err)
	}
	waitUntil(t, "a connection opened with a key that has since been removed is still open", iamt449Ended(idle))
	if _, err := self.Whoami(); err == nil {
		t.Error("the connection that removed its own key still runs commands")
	}
	if _, err := other.Whoami(); err != nil {
		t.Errorf("a connection opened with the person's other key was cut as well: %v", err)
	}
}

func TestIAMT449_RemovingAPersonClosesTheirConnections(t *testing.T) {
	f := newFixture(t, nil)
	rootKey, bobKey := genSigner(t), genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	addPerson(t, f, "bob", "admin", bobKey)
	bob := iamt449CommandLogin(t, f, "bob", bobKey)
	root := dialAdmin(t, f, "root", rootKey)

	if _, err := root.PeopleRemove("bob"); err != nil {
		t.Fatalf("people.remove: %v", err)
	}
	waitUntil(t, "a connection of a person who has since been removed is still open", iamt449Ended(bob))
}

func TestIAMT449_RemovingAKeyEndsTheSessionItOpened(t *testing.T) {
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
	waitUntil(t, "the session did not become active", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	if err := root.PeopleKeysRemove(f.person, fingerprintOf(t, f.personKey.PublicKey())); err != nil {
		t.Fatalf("people.keys.remove: %v", err)
	}
	waitUntil(t, "a session opened with a key that has since been removed is still running, door open", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})
	if got, want := f.lastSessionDropResult(f.person, f.machineID), acl.DenyKeyRemoved.String(); got != want {
		t.Errorf("the session's session.drop says %q, want %q", got, want)
	}
}
