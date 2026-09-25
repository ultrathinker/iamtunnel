//go:build windows

// Windows ACL tests. layer 1 of the door: after Install, the
// file's DACL must contain exactly the two ACEs we set, and the
// SE_DACL_PROTECTED flag must be on. We lock down, read back via
// the Win32 API, and assert. No exported setters, no env vars, no
// build-tag kill switch — the test depends only on the public
// Door.Install surface.

package winkeys

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestInstall_NarrowsACLToAdminsAndSystem asserts that after
// Install, the file's DACL contains exactly two ACEs (Administrators
// and SYSTEM, both FullControl) and that SE_DACL_PROTECTED is set.
// The producer (Install via lockDownACL) writes the DACL; the test
// reads it back via ReadDACL / DACLProtected, which walk the
// SECURITY_DESCRIPTOR ourselves and the protected control flag
// ourselves — a green test means the producer matches the
// requirements SPEC §6.3 places on the file's ACL.
func TestInstall_NarrowsACLToAdminsAndSystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testkeys")
	if err := os.WriteFile(path, []byte("seed\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := NewDoor(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Install(randomDoorID(t), TestKey); err != nil {
		t.Fatalf("Install: %v", err)
	}

	names, err := ReadDACL(path)
	if err != nil {
		t.Fatalf("ReadDACL: %v", err)
	}
	want := []string{`BUILTIN\Administrators`, `NT AUTHORITY\SYSTEM`}
	sort.Strings(names)
	if len(names) != len(want) {
		t.Fatalf("expected exactly %d ACEs, got %d: %v", len(want), len(names), names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("ACE[%d]: got %q want %q", i, names[i], want[i])
		}
	}

	protected, err := DACLProtected(path)
	if err != nil {
		t.Fatalf("DACLProtected: %v", err)
	}
	if !protected {
		t.Errorf("SE_DACL_PROTECTED not set after Install")
	}
}

// TestInstall_DoesNotWidenACL asserts that running Install twice
// keeps the DACL exactly the two ACEs we set, and never widens to
// the user's inherited entries. A red test under a "Install
// forgets to set SE_DACL_PROTECTED" bug: the second LockDown would
// happily inherit the user's token-default ACEs in addition.
func TestInstall_DoesNotWidenACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testkeys")
	if err := os.WriteFile(path, []byte("seed\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := NewDoor(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	idA := randomDoorID(t)
	idB := randomDoorID(t)
	if err := d.Install(idA, TestKey); err != nil {
		t.Fatal(err)
	}
	if err := d.Install(idB, TestKey); err != nil {
		t.Fatal(err)
	}
	names, _ := ReadDACL(path)
	if len(names) != 2 {
		t.Errorf("expected 2 ACEs after two Installs, got %d: %v", len(names), names)
	}
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	if !got[`BUILTIN\Administrators`] || !got[`NT AUTHORITY\SYSTEM`] {
		t.Errorf("expected Administrators+SYSTEM, got %v", names)
	}
}

// TestInstall_ProtectedFlagStaysOn re-checks the SE_DACL_PROTECTED
// flag after a second Install. The flag is part of the SPEC
// requirement, not a one-shot.
func TestInstall_ProtectedFlagStaysOn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testkeys")
	if err := os.WriteFile(path, []byte("seed\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := NewDoor(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := d.Install(randomDoorID(t), TestKey); err != nil {
			t.Fatal(err)
		}
		protected, _ := DACLProtected(path)
		if !protected {
			t.Fatalf("SE_DACL_PROTECTED gone after %d installs", i)
		}
	}
}
