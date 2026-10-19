package main

import (
	"errors"
	"strings"
	"testing"
)

// A refused enrol code is not an unreachable gateway: the window said
// "could not reach the gateway" for a gateway that had answered, and left
// out the one cause that cost a quarter of an hour on 16.10.2026 - the
// address blocked after repeated failed sign-ins.
func TestR153_EnrolRefusalNamesTheThreeCauses(t *testing.T) {
	err := errors.New("admin: dial 192.0.2.10:2027: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")
	if !authRefused(err) {
		t.Fatal("authRefused does not recognise the SSH layer's refusal")
	}
	if authRefused(errors.New("dial tcp 192.0.2.10:2027: i/o timeout")) {
		t.Fatal("a timeout was taken for a refusal")
	}
	got := enrolRefusal("192.0.2.10:2027", err)
	for _, want := range []string{"192.0.2.10:2027", "15 minutes", "already used", "blocked", "rate limited until"} {
		if !strings.Contains(got, want) {
			t.Errorf("the refusal text lacks %q: %s", want, got)
		}
	}
	if strings.Contains(got, "could not reach") {
		t.Errorf("a gateway that answered is described as unreachable: %s", got)
	}
}
