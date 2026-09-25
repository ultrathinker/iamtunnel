package gateway

// R1-CX F-04 (review of 22-23.09): people.keys.remove carried no
// guard for the last administrator key. people.remove has refused to take
// the last administrator record since 21.09.2026, but the key next to the
// record was unprotected: the only administrator could remove their own
// last key, be told ok, and lose every connection that key had opened to
// the command loop's cutRemovedKeys -- leaving an administrator record
// nobody can authenticate as, recoverable only by rebootstrap. The removal
// is refused while it would leave the state without a single administrator
// key; every other removal stays an ordinary errand.

import "testing"

func TestR1CX_F04_LastKeyOfTheLastAdministratorIsRefused(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	fp := fingerprintOf(t, rootKey.PublicKey())
	err := root.PeopleKeysRemove("root", fp)
	if err == nil {
		t.Fatal("people.keys.remove of the last administrator's last key must be refused: it would leave nobody who may sign in to administer the gateway")
	}
	if !iamt449HasKey(f, "root", fp) {
		t.Fatal("the refused removal still took the key out of the state")
	}
}

func TestR1CX_F04_TakingOneOfSeveralKeysStaysAnErrand(t *testing.T) {
	f := newFixture(t, nil)
	keep, drop := genSigner(t), genSigner(t)
	addPerson(t, f, "root", "admin", keep)
	iamt449AddKey(t, f, "root", drop)
	root := dialAdmin(t, f, "root", keep)

	if err := root.PeopleKeysRemove("root", fingerprintOf(t, drop.PublicKey())); err != nil {
		t.Fatalf("removing one of two administrator keys must stay an ordinary errand: %v", err)
	}
	if !iamt449HasKey(f, "root", fingerprintOf(t, keep.PublicKey())) {
		t.Fatal("the key that was to stay is gone")
	}
}

func TestR1CX_F04_AnotherAdministratorWithAKeyUnblocksTheRemoval(t *testing.T) {
	f := newFixture(t, nil)
	rootKey, bobKey := genSigner(t), genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	addPerson(t, f, "bob", "admin", bobKey)
	root := dialAdmin(t, f, "root", rootKey)

	// Bob's last key can go while root keeps theirs: root can put a key
	// back for bob, so nobody is locked out for good.
	if err := root.PeopleKeysRemove("bob", fingerprintOf(t, bobKey.PublicKey())); err != nil {
		t.Fatalf("removing the last key of an administrator while another administrator keeps a key: %v", err)
	}
	// With bob left keyless, root's own last key is the last administrator
	// key the gateway has, so the same refusal as for a sole administrator.
	if err := root.PeopleKeysRemove("root", fingerprintOf(t, rootKey.PublicKey())); err == nil {
		t.Fatal("removing the last administrator key left in the gateway (the other administrator has none) must be refused")
	}
	if !iamt449HasKey(f, "root", fingerprintOf(t, rootKey.PublicKey())) {
		t.Fatal("the refused removal still took the key out of the state")
	}
}
