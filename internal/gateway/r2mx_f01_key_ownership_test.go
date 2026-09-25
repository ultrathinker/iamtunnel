package gateway

// R2-MX F-01 of the round-2 review (24.09.2026), medium:
// people.keys.add checked the fingerprint against the keys of the person
// being edited and against nothing else, so a key that already belonged to
// another person - or to a machine - travelled all the way into the state
// transaction. What stopped it there was the state validator
// (state/validate.go, "keys must be uniquely owned"), which is the right
// barrier for the file and the wrong voice for the administrator: the
// answer read "updated state validation failed: duplicate key fingerprint
// ... shared between person ...", which sounds like a fault of the gateway
// rather than an answer about the key, and names the other owner only by
// accident of its wording.
//
// Nothing may reach the file through the validator (both write paths, Store
// .Update and Store.Set, run it before committing), so what this test holds
// the command to is the answer: the refusal has to be the command's own,
// it has to name the identity the key belongs to - and the state must be
// left exactly as it was either way.

import (
	"errors"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/admin"
)

func TestR2MXF01_AKeyBelongingToAnotherIdentityIsRefusedByName(t *testing.T) {
	f := newFixture(t, nil)
	rootKey, aliceKey := genSigner(t), genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	addPerson(t, f, "carol", "user", aliceKey)
	addPerson(t, f, "bob", "user", genSigner(t))
	root := dialAdmin(t, f, "root", rootKey)

	cases := []struct {
		what  string
		line  string
		owner string
	}{
		{"another person's key", authorizedLine(aliceKey.PublicKey()), `person "carol"`},
		{"the machine's key", authorizedLine(f.machineKey.PublicKey()), `machine "vm1"`},
	}
	for _, tc := range cases {
		_, err := root.PeopleKeysAdd("bob", tc.line)
		if err == nil {
			t.Fatalf("bob was given %s although it already belongs to %s: one fingerprint would then stand for two identities, and §6.1 wants fingerprint -> identity to be a function", tc.what, tc.owner)
		}
		var cerr *admin.CommandError
		if !errors.As(err, &cerr) {
			t.Fatalf("the refusal of %s is not the gateway's own error envelope: %v", tc.what, err)
		}
		if cerr.Code != "E_CONFLICT" {
			t.Errorf("%s was refused with %s, want E_CONFLICT: the key exists, it is simply not bob's", tc.what, cerr.Code)
		}
		if strings.Contains(cerr.Message, "state validation failed") {
			t.Errorf("%s was refused with %q: that is the state validator reporting a fault of the gateway's own state, not the command answering about the key, and the administrator is left to work out which of the two it was (F-01)", tc.what, cerr.Message)
		}
		if !strings.Contains(cerr.Message, "registered for "+tc.owner) {
			t.Errorf("%s was refused with %q, want the answer to name the identity the key already belongs to (%s): without it a typo and a key that moved look the same (F-01)", tc.what, cerr.Message, tc.owner)
		}
	}

	// The refusal is a refusal: neither identity changed, and bob has the
	// one key he came with.
	st := f.store.Get()
	for _, p := range st.People {
		if p.Name == "bob" && len(p.Keys) != 1 {
			t.Errorf("bob carries %d keys after two refused additions, want the one he was added with: %+v", len(p.Keys), p.Keys)
		}
		if p.Name == "carol" && len(p.Keys) != 1 {
			t.Errorf("carol carries %d keys, want the one she was added with: %+v", len(p.Keys), p.Keys)
		}
	}
}
