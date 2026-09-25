package gateway

// The maintainer's canary: the first administrator is named admin.
//
// Found by the maintainer on 19.09.2026: the name was derived from the key
// fingerprint, and they met themselves as "a60lyahqwz0z9is6o" -- on every
// screen and typed by hand into every grant. A name from a fingerprint
// remains what PAIRING mints: people dial in that way again and again,
// and two of them must not collide. Bootstrap happens exactly once per
// gateway, before anyone exists at all, and its name may be obvious.

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestCanary_TheFirstAdminIsCalledAdmin.
//
// The canary: put personNameFromFingerprint back into runBootstrap -- the
// test prints the very name the maintainer saw.
func TestCanary_TheFirstAdminIsCalledAdmin(t *testing.T) {
	st := &state.State{}
	const fp = "SHA256:VHcYlXQPy+pny9JSYsyO0OoExJyZfiiWy11VbnWLpLg"

	if got := firstAdminName(st, fp); got != "admin" {
		t.Errorf("the first administrator was named %q, want \"admin\" -- a name you cannot pronounce aloud you also cannot use: it gets typed by hand into every grant", got)
	}
}

// TestCanary_TheNameFallsBackWhenAdminIsTaken.
//
// state.json gets edited by hand and restored from a backup. Two people
// with the same name is a defect far worse than an ugly name.
//
// The canary: drop the taken-name check -- the test catches the collision.
func TestCanary_TheNameFallsBackWhenAdminIsTaken(t *testing.T) {
	st := &state.State{People: []state.Person{{Name: "admin", Role: "user"}}}
	const fp = "SHA256:VHcYlXQPy+pny9JSYsyO0OoExJyZfiiWy11VbnWLpLg"

	got := firstAdminName(st, fp)
	if got == "admin" {
		t.Fatal("the name admin was issued a second time -- the gateway would end up with two people of one name")
	}
	if want := personNameFromFingerprint(fp); got != want {
		t.Errorf("the fallback name = %q, want %q -- the fallback path must be exactly what pairing mints", got, want)
	}
}
