//go:build windows

package client_test

// keys_acl_windows_test.go — M-9d (code review 23.09.2026, review F-08):
// the client key had no access list of its own on Windows. A file there
// inherits whatever its folder grants, so a --data-dir on a shared disk
// made the person's private key — their whole identity, SPEC §3.1 —
// readable by every local account, and checkKeyFilePerms was a no-op
// that could not notice.
//
// Both halves are pinned here: a key created by this build carries its
// own protected access list naming exactly the account that owns it, and
// an existing key that other accounts can read is refused with the
// command that fixes it (the Windows twin of the Unix chmod 600 refusal).
//
// icacls stands in for the person or the other build that arranged the
// bad access list: it is the tool the refusal itself names, and every
// change it makes lands in a t.TempDir(), never on this machine's real
// files.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// aclTestAccount is the SID of the account running the tests — the one
// account a key belongs to.
func aclTestAccount(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read this account's SID: %v", err)
	}
	return user.User.Sid.String()
}

// icacls runs an access-list change in the test's own temporary
// directory, and fails the test when the host refuses it.
func icacls(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("icacls", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %v: %v (%s)", args, err, out)
	}
}

// writeKeyFileAt writes a real ed25519 key in the PEM shape the product
// uses, by plain os.WriteFile — i.e. the way a build without the access
// list wrote one: whatever the folder grants, the file has.
func writeKeyFileAt(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "iamtunnel client key")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
}

// TestM9dFreshClientKeyIsLockedToThisAccount is the creation half: the
// key must carry its own access list — protected, naming this account
// and nobody else — from the moment it exists.
func TestM9dFreshClientKeyIsLockedToThisAccount(t *testing.T) {
	dir := t.TempDir()
	if _, err := client.EnsureKey(dir); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	path := client.KeyPath(dir)

	protected, err := winkeys.DACLProtected(path)
	if err != nil {
		t.Fatalf("read the key's access list: %v", err)
	}
	if !protected {
		t.Errorf("the fresh key carries no access list of its own (SE_DACL_PROTECTED is clear) — Windows then gives it the permissions of its folder, so a key generated with --data-dir on a shared disk is readable by every local account (M-9d, review F-08)")
	}

	names, err := winkeys.ReadDACL(path)
	if err != nil {
		t.Fatalf("read the key's access list: %v", err)
	}
	me := aclTestAccount(t)
	found := false
	for _, name := range names {
		if name == me {
			found = true
			continue
		}
		if name == `NT AUTHORITY\SYSTEM` || name == `BUILTIN\Administrators` {
			continue // they can take ownership of anything on the box anyway
		}
		t.Errorf("the fresh key is readable by %s (access list %v) — the private key is the person's own identity and must name only the account that owns it (M-9d, review F-08)", name, names)
	}
	if !found {
		t.Errorf("the fresh key's access list is %v and does not name this account (%s) — the person must keep access to their own key (M-9d, review F-08)", names, me)
	}

	// The lock must not cost the owner anything: the key still loads, and
	// it is the same key.
	first, err := client.EnsureKey(dir)
	if err != nil {
		t.Fatalf("the locked key cannot be read back: %v", err)
	}
	again, err := client.EnsureKey(dir)
	if err != nil {
		t.Fatalf("second read of the locked key: %v", err)
	}
	if string(first.PublicKey().Marshal()) != string(again.PublicKey().Marshal()) {
		t.Error("the key changed between two reads — the access list must not make the client regenerate an identity")
	}
}

// TestM9dKeyOthersCanReadIsRefused is the check half: an existing key
// whose access this account does not control is refused, in words, with
// the command that fixes it — and never silently re-permissioned or
// replaced.
func TestM9dKeyOthersCanReadIsRefused(t *testing.T) {
	t.Run("a key that inherits a folder anyone can read", func(t *testing.T) {
		dir := t.TempDir()
		// The finding's scenario: a data directory on a disk that lets
		// every local account in.
		icacls(t, dir, "/grant", "*S-1-1-0:(OI)(CI)(R)")
		path := client.KeyPath(dir)
		writeKeyFileAt(t, path)
		want, err := client.EnsureKey(dir)
		if err != nil {
			t.Fatalf("EnsureKey on a key that only inherits its folder's permissions: %v", err)
		}
		if protected, perr := winkeys.DACLProtected(path); perr != nil || !protected {
			t.Errorf("the key still carries no access list of its own after being read (protected=%v, err=%v) — Windows cannot tell a reader who inherits what from a folder any account can read, so the client gives the file the list a fresh key is born with instead of leaving the identity shared (M-9d, review F-08)", protected, perr)
		}
		names, derr := winkeys.ReadDACL(path)
		if derr != nil {
			t.Fatalf("read the key's access list: %v", derr)
		}
		me := aclTestAccount(t)
		for _, name := range names {
			if name != me && name != `NT AUTHORITY\SYSTEM` && name != `BUILTIN\Administrators` {
				t.Errorf("the key is readable by %s (access list %v) after EnsureKey — the account that was just closed out must stay closed out (M-9d, review F-08)", name, names)
			}
		}
		// Closing the exposure must not cost the person their identity:
		// the same key loads, unchanged.
		again, err := client.EnsureKey(dir)
		if err != nil {
			t.Fatalf("the restricted key cannot be read back: %v", err)
		}
		if string(again.PublicKey().Marshal()) != string(want.PublicKey().Marshal()) {
			t.Error("the key changed while its access list was being fixed — the client must never regenerate an identity to fix permissions")
		}
	})

	t.Run("a key carrying an explicit entry for Everyone", func(t *testing.T) {
		dir := t.TempDir()
		path := client.KeyPath(dir)
		writeKeyFileAt(t, path)
		// An access list of its own, with the wrong account in it: the
		// shape that survives the protected-bit check above.
		icacls(t, path, "/inheritance:r", "/grant", "*S-1-1-0:(R)")

		_, err := client.EnsureKey(dir)
		if err == nil {
			t.Errorf("EnsureKey used a key whose own access list grants Everyone read — the refusal must name the account, not merely the missing list (M-9d, review F-08)")
			return
		}
		if !strings.Contains(err.Error(), "Everyone") {
			t.Errorf("the refusal is %q — it must name the account that can read the key", err)
		}
	})

	t.Run("a properly locked key is accepted", func(t *testing.T) {
		// The positive control for both rows above: after the fix the
		// very same file, restricted the way the refusal asks, loads.
		dir := t.TempDir()
		path := client.KeyPath(dir)
		writeKeyFileAt(t, path)
		icacls(t, path, "/inheritance:r", "/grant:r", "*"+aclTestAccount(t)+":F")

		if _, err := client.EnsureKey(dir); err != nil {
			t.Errorf("EnsureKey refused a key that is locked to this account exactly as the refusal asks: %v", err)
		}
	})
}
