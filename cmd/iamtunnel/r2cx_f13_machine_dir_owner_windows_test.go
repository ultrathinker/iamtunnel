package main

// R2-CX F-13: the machine's data directory is locked by hardenServerDir
// (enrol, server start) through winkeys.LockDownDirACL/LockDownFileACL,
// which replaced the DACL and passed no owner - applyProtectedDACL even
// read the owner out of its descriptor and threw it away. A directory
// another account had made in advance, chosen with --data-dir, stayed that
// account's after the lockdown: an owner can always rewrite the DACL, and
// the machine's private key and its control.json with it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR2CX_F13_AMachineDirectoryAnotherAccountOwnsIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "machine")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r2cxSetOwner(t, dir, r2cxGuests)
	err := hardenServerDir(dir, false)
	if err == nil {
		t.Fatalf("the machine directory was locked and left to its owner %s, who can rewrite its DACL whenever they like (owner now: %s)", r2cxGuests, r2cxOwner(t, dir))
	}
	if !strings.Contains(err.Error(), r2cxGuests) && !strings.Contains(err.Error(), "Guests") {
		t.Fatalf("the refusal does not name the owner it refuses: %v", err)
	}
}

func TestR2CX_F13_AFileInTheMachineDirectoryAnotherAccountOwnsIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "machine")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(dir, "control.json")
	if err := os.WriteFile(planted, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	r2cxSetOwner(t, planted, r2cxGuests)
	if err := hardenServerDir(dir, false); err == nil {
		t.Fatalf("hardening accepted %s, which %s owns - the machine would go on trusting a file another account can still rewrite", planted, r2cxGuests)
	}
}

func TestR2CX_F13_HardeningHandsTheMachineDirectoryToAdministrators(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "machine")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "machine.id")
	if err := os.WriteFile(child, []byte("win-vm"), 0o600); err != nil {
		t.Fatal(err)
	}
	me := r2cxMe(t)
	r2cxSetOwner(t, dir, me)
	r2cxSetOwner(t, child, me)
	if err := hardenServerDir(dir, false); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, child} {
		if got := r2cxOwner(t, p); got != "S-1-5-32-544" {
			t.Errorf("%s is owned by %s after hardening, not by Administrators - its owner can rewrite the DACL the machine just set", p, got)
		}
	}
}
