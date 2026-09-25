package main

// R2-CX F-07: hardening the gateway's data directory replaced its DACL and
// left its owner alone - SetNamedSecurityInfo was given no owner. An owner
// can always rewrite a DACL, so a directory another account had made in
// advance (--data-dir on a path it could create; and %ProgramData% lets
// every signed-in user create folders, the default path included) stayed
// that account's to reopen after install locked it: the host key, the
// bootstrap token and the journal with it. The binary's directory has had
// its owner handed to Administrators since IAMT-445; the data directory
// never had.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR2CX_F07_ADataDirectoryAnotherAccountOwnsIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gateway")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r2cxSetOwner(t, dir, r2cxGuests)
	err := hardenGatewayDirACL(dir, false, nil)
	if err == nil {
		t.Fatalf("the data directory was locked and left to its owner %s, who can rewrite its DACL whenever they like (owner now: %s)", r2cxGuests, r2cxOwner(t, dir))
	}
	if !strings.Contains(err.Error(), r2cxGuests) && !strings.Contains(err.Error(), "Guests") {
		t.Fatalf("the refusal does not name the owner it refuses: %v", err)
	}
}

func TestR2CX_F07_AFileInTheDataDirectoryAnotherAccountOwnsIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gateway")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, hostkeyFileName)
	if err := os.WriteFile(planted, []byte("a key somebody else chose"), 0o600); err != nil {
		t.Fatal(err)
	}
	r2cxSetOwner(t, planted, r2cxGuests)
	if err := hardenGatewayDataTree(dir, false, nil); err == nil {
		t.Fatalf("hardening accepted %s, which %s owns - install would go on to use a host key another account chose and can still rewrite", planted, r2cxGuests)
	}
}

func TestR2CX_F07_HardeningHandsTheDataDirectoryToAdministrators(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gateway")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "state.json")
	if err := os.WriteFile(child, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The person running install owns what they made: trusted, and
	// still handed over, so that no personal account stays able to
	// rewrite the DACL from outside an elevated console.
	me := r2cxMe(t)
	r2cxSetOwner(t, dir, me)
	r2cxSetOwner(t, child, me)
	if err := hardenGatewayDataTree(dir, false, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, child} {
		if got := r2cxOwner(t, p); got != "S-1-5-32-544" {
			t.Errorf("%s is owned by %s after hardening, not by Administrators - its owner can rewrite the DACL install just set", p, got)
		}
	}
}
