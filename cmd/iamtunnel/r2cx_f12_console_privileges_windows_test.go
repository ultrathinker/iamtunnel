package main

// R2-CX F-12, found by the gates: the lock opens every object through a
// handle that asks for the data right that pins a directory and for
// WRITE_OWNER, and an object's DACL need not grant either - a file whose
// DACL is nothing but an operator's explicit DENY (IAMT-315) could no
// longer be opened to be refused, or, under --replace-acl, locked:
// "Access is denied". Tests run from Git Bash never saw it: its children
// start with the backup and restore privileges enabled, and the lock's
// FILE_FLAG_BACKUP_SEMANTICS then passes the DACL by. From a console,
// where an administrator holds both disabled, the gates did. These tests
// switch both off first, as a console has them.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// r2cxAsAConsole disables the backup and restore privileges on this
// process's token for the test, as an elevated console starts with them.
func r2cxAsAConsole(t *testing.T) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SeBackupPrivilege", "SeRestorePrivilege"} {
		var luid windows.LUID
		n, err := windows.UTF16PtrFromString(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
			t.Fatal(err)
		}
		off := windows.Tokenprivileges{PrivilegeCount: 1}
		off.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: 0}
		var previous windows.Tokenprivileges
		var size uint32
		if err := windows.AdjustTokenPrivileges(token, false, &off, uint32(unsafe.Sizeof(previous)), &previous, &size); err != nil {
			token.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil) })
	}
	t.Cleanup(func() { token.Close() })
}

func TestR2CX_F12_AFileWithOnlyAnExplicitDenyIsStillRefusedFromAConsole(t *testing.T) {
	requireWritableLockedFiles(t)
	path := filepath.Join(t.TempDir(), "hostkey-like")
	if err := os.WriteFile(path, []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := hardenGatewayFileACL(path, false, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	attachExplicitDenyACE(t, path, "S-1-5-32-546", 0x1F01FF)
	relaxACLOnCleanup(t, path)
	r2cxAsAConsole(t)

	err := hardenGatewayFileACL(path, false, nil)
	var fdr *winkeys.ForeignDenyRefusalError
	if !errors.As(err, &fdr) {
		t.Fatalf("from a console, a file whose DACL is an explicit DENY was answered %T: %v - want the IAMT-315 refusal, which needs the file opened first", err, err)
	}
}

func TestR2CX_F12_ADataDirectoryWithOnlyExplicitDeniesIsLockedUnderReplaceACLFromAConsole(t *testing.T) {
	requireWritableLockedFiles(t)
	dir := filepath.Join(t.TempDir(), "gateway")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "state.json")
	if err := os.WriteFile(child, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := hardenGatewayDataTree(dir, false, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	attachExplicitDenyACE(t, child, "S-1-5-32-546", 0x1F01FF)
	attachExplicitDenyACE(t, dir, "S-1-5-32-546", 0x1F01FF)
	relaxACLOnCleanup(t, child, dir)
	r2cxAsAConsole(t)

	if err := hardenGatewayDataTree(dir, true, io.Discard); err != nil {
		t.Fatalf("from a console, --replace-acl could not lock a data directory whose DACLs are explicit DENYs: %v", err)
	}
	for _, p := range []string{dir, child} {
		if protected, err := winkeys.DACLProtected(p); err != nil || !protected {
			t.Errorf("%s is not locked after --replace-acl (protected=%v, err=%v)", p, protected, err)
		}
	}
}
