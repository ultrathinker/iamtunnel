package gateway

// R1-CX F-07 (review of 22-23.09): serveCommandSession checked the
// key in one state read and then ran the command without anything binding
// the two together, so an administrator's revocation could land between
// the check and the command -- and the command ran anyway, changing the
// state after a completed revocation. The keyGate binds them: a command
// holds the gate for reading across the check and the whole command, a
// key-revoking command holds it for writing, so the revocation either
// waits for the in-flight command (which then ran while its key was
// still registered) or lands first and the check refuses what follows.

import (
	"sync"
	"testing"
	"time"
)

func TestR1CX_F07_RevocationEitherBeatsOrWaitsForTheInFlightCommand(t *testing.T) {
	f := newFixture(t, nil)
	aKey, bKey, spare := genSigner(t), genSigner(t), genSigner(t)
	addPerson(t, f, "root", "admin", aKey)
	addPerson(t, f, "second", "admin", bKey)
	a := dialAdmin(t, f, "root", aKey)
	b := dialAdmin(t, f, "second", bKey)

	// Park A between the key check and the dispatch: the exact window the
	// finding names. The barrier releases when this test says so, and
	// only A's session stops there.
	parked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	afterKeyCheckFn = func(person, command string) {
		if person != "root" || command != "people.keys.add" {
			return
		}
		once.Do(func() { close(parked) })
		<-release
	}
	defer func() { afterKeyCheckFn = nil }()

	spareLine := authorizedLine(spare.PublicKey())
	aDone := make(chan error, 1)
	go func() {
		_, err := a.PeopleKeysAdd("second", spareLine)
		aDone <- err
	}()
	<-parked

	// While A sits in the window, B revokes A's key.
	bDone := make(chan error, 1)
	go func() { bDone <- b.PeopleKeysRemove("root", fingerprintOf(t, aKey.PublicKey())) }()

	// Could the revocation finish while A was still parked? With nothing
	// binding the check to the dispatch it does, at once; bound by the
	// gate it cannot, because A holds the gate until its command is done.
	var bErr error
	bLanded := func() bool {
		select {
		case bErr = <-bDone:
			return true
		case <-time.After(2 * time.Second):
			return false
		}
	}
	landed := bLanded()
	close(release)
	// The gateway side of A's session applies its command some time after
	// the release; wait until it is done before reading the state.
	waitUntil(t, "A's command session never finished after the release", func() bool {
		return f.gw.serveCmdInFlight.Load() == 0
	})

	if landed {
		// The revocation finished while A was in the window, so A's
		// command belongs to a key the gateway had already revoked: it
		// must not have changed the state after that.
		if err := <-aDone; err == nil {
			t.Error("people.keys.add answered ok on a key the gateway had already revoked")
		}
		if iamt449HasKey(f, "second", fingerprintOf(t, spare.PublicKey())) {
			t.Fatal("the command of a key the gateway had already revoked still changed the state (people.keys.add applied after people.keys.remove had finished)")
		}
		if bErr != nil {
			t.Fatalf("people.keys.remove: %v", bErr)
		}
		return
	}

	// The revocation instead waited for the in-flight command: A ran
	// while its key was still registered, so its change is legitimate --
	// and the revocation must then have landed, ending A's connection.
	if err := <-aDone; err != nil {
		t.Fatalf("people.keys.add that ran before the revocation landed: %v", err)
	}
	if !iamt449HasKey(f, "second", fingerprintOf(t, spare.PublicKey())) {
		t.Fatal("the command that ran before the revocation landed left no key behind")
	}
	waitUntil(t, "the revocation never completed after the command it waited for", func() bool {
		select {
		case bErr = <-bDone:
			return true
		default:
			return false
		}
	})
	if bErr != nil {
		t.Fatalf("people.keys.remove: %v", bErr)
	}
	waitUntil(t, "the connection of the revoked key stayed alive", func() bool {
		_, werr := a.Whoami()
		return werr != nil
	})
}
