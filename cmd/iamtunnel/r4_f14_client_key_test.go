package main

// r4_f14_client_key_test.go — R4 F-14, the terminal's half: a person can
// print the public key they hand the administrator before any connection
// string is saved (the window shows the same key on Client → Key).

import (
	"os"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/client"
)

func TestR4F14_ClientKeyPrintsThePublicKeyWithNothingSaved(t *testing.T) {
	out, errs, code := driveInDir(t, t.TempDir(), "client", "key")
	if code != exitOK {
		t.Fatalf("R4 F-14: \"client key\" failed on a fresh machine: code=%d errs=%q", code, errs)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "ssh-ed25519 ") {
		t.Fatalf("\"client key\" printed %q, want one OpenSSH public key line", out)
	}
}

// review finding R4 N-01: "client key" is a write — EnsureKey creates the private
// key — so it passes the same foreign-data-directory gate as every other
// client verb (IAMT-333). The two landed in parallel branches.
func TestR4F14_ClientKeyRefusesAForeignDataDirBeforeWriting(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, iamt333ForeignReason, nil)
	_, errs, code := driveElevated(t, true, nil, "client", "key", "--data-dir", dir)
	if code != exitDenied {
		t.Fatalf("review finding R4 N-01: an elevated \"client key\" into a foreign directory: code=%d errs=%q, want exitDenied", code, errs)
	}
	if _, err := os.Stat(client.KeyPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("the refusal came after the private key was written (%v)", err)
	}
	if _, errs, code := driveElevated(t, true, nil, "client", "key", "--data-dir", dir, "--accept-foreign-data-dir"); code != exitOK {
		t.Fatalf("--accept-foreign-data-dir must let it through: code=%d errs=%q", code, errs)
	}
}
