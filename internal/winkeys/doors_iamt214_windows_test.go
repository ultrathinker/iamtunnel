//go:build windows

// IAMT-214 canary tests. The defect: the protected {SYSTEM,
// Administrators} DACL was applied only by Install AFTER the rename,
// so close (Remove), sweep (SweepStale / door.sanitize) and the
// doorwatch close rewrote the key file through a tmp file that
// inherits the containing directory's ACL — the live finding was
// Authenticated Users:(I)(RX) and AreAccessRulesProtected=False after
// a close.
//
// The fix under test: writeAtomicBytes locks the tmp file's DACL down
// BEFORE renameForReplace, and every rewrite path of this package
// goes through writeAtomicBytes. Each test below seeds the key file
// with a plain INHERITED ACL — the state a real file is found in —
// drives one write path through its public seam, then reads the final
// file's DACL back via GetNamedSecurityInfo and asserts: protected,
// exactly two ALLOW ACEs (S-1-5-18 and S-1-5-32-544, full control,
// SIDs — never localized names), zero inherited ACEs.
//
// A red test under the regression: remove the protectTmpBeforeReplace
// call from writeAtomicBytes (doors.go) and the close/sweep/sanitize/
// doorwatch tests go red on their own assert line — the final file is
// again the unprotected inherited-DACL file.

package winkeys

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// requireWritableLockedFiles skips the test when the process token is
// not elevated. IAMT-214 moves the DACL lockdown to before the rename:
// the writer needs DELETE on the already-locked tmp file, and an
// Administrators ACE only matches an elevated token. That mirrors
// production exactly — every command that writes the key file or the
// machine data directory is elevation-gated (requireServerElevation) —
// so a non-elevated test process has no way to exercise the fix at
// all.
func requireWritableLockedFiles(t *testing.T) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer token.Close()
	if !token.IsElevated() {
		t.Skip("ACL tests need an elevated test process: the write path locks the tmp file to SYSTEM/Administrators BEFORE renaming it, so a non-elevated token cannot move it into place. Run go test from an administrator console (the product itself refuses non-elevated for every command that writes these files).")
	}
}

// aceInfo is one ACE read back from a DACL — including inherited ones,
// which ReadDACL deliberately skips: the point of IAMT-214 is that
// none are left at all.
type aceInfo struct {
	sid          string // SID in string form (S-1-…), never a localized name
	mask         uint32 // ACCESS_MASK as stored in the ACE
	allow        bool   // ACCESS_ALLOWED_ACE (false: ACCESS_DENIED)
	inheritFlags uint8  // OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE bits
	inherited    bool   // INHERITED_ACE flag
}

// readDACLFull walks the whole DACL of path via GetNamedSecurityInfo,
// copying it into Go memory first — the same walk ReadDACL does, but
// keeping inherited entries, masks, ACE type and inheritance flags.
func readDACLFull(t *testing.T, path string) []aceInfo {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, daclSecurityInfo)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	sdBytes := unsafe.Slice((*byte)(unsafe.Pointer(sd)), 20)
	sdCopy := make([]byte, 20)
	copy(sdCopy, sdBytes)
	daclOff := *(*uint32)(unsafe.Pointer(&sdCopy[16]))
	if daclOff == 0 {
		return nil
	}
	daclPtr := unsafe.Add(unsafe.Pointer(sd), daclOff)
	daclSize := int(*(*uint16)(unsafe.Add(daclPtr, 2)))
	if daclSize < 8 || daclSize > 64*1024 {
		t.Fatalf("implausible DACL size %d for %s", daclSize, path)
	}
	daclBuf := unsafe.Slice((*byte)(daclPtr), daclSize)
	daclCopy := make([]byte, daclSize)
	copy(daclCopy, daclBuf)

	aceCount := int(*(*uint16)(unsafe.Pointer(&daclCopy[4])))
	off := 8
	var out []aceInfo
	for i := 0; i < aceCount; i++ {
		if off+4 > daclSize {
			t.Fatalf("ACE index %d past DACL end (off=%d size=%d) for %s", i, off, daclSize, path)
		}
		aceSize := int(*(*uint16)(unsafe.Pointer(&daclCopy[off+2])))
		sidPtr := (*windows.SID)(unsafe.Pointer(&daclCopy[off+8]))
		sidLen := windows.GetLengthSid(sidPtr)
		if sidLen == 0 || off+8+int(sidLen) > daclSize {
			t.Fatalf("ACE index %d: unreadable SID for %s", i, path)
		}
		sidCopy, err := sidPtr.Copy()
		if err != nil {
			t.Fatalf("ACE index %d: copy SID: %v", i, err)
		}
		out = append(out, aceInfo{
			sid:          sidCopy.String(),
			mask:         *(*uint32)(unsafe.Pointer(&daclCopy[off+4])),
			allow:        daclCopy[off] == 0,     // ACCESS_ALLOWED_ACE_TYPE
			inheritFlags: daclCopy[off+1] & 0x0B, // OBJECT|CONTAINER|INHERIT_ONLY
			inherited:    daclCopy[off+1]&aceInheritedFlag != 0,
		})
		off += aceSize
	}
	return out
}

// assertLockedDACL asserts the exact post-write state IAMT-214
// promises for the key file: SE_DACL_PROTECTED, exactly two
// ACCESS_ALLOWED ACEs — S-1-5-18 and S-1-5-32-544, both full control —
// and zero inherited ACEs. label names the write path so a red test
// names the path that lost the guarantee.
func assertLockedDACL(t *testing.T, label, path string) {
	t.Helper()
	prot, err := DACLProtected(path)
	if err != nil {
		t.Fatalf("IAMT-214 %s: DACLProtected: %v", label, err)
	}
	if !prot {
		t.Errorf("IAMT-214 %s: after the write the key file DACL must be protected (SE_DACL_PROTECTED), got protected=false — inherited directory entries leak in", label)
	}
	aces := readDACLFull(t, path)
	var inherited []aceInfo
	for _, a := range aces {
		if a.inherited {
			inherited = append(inherited, a)
		}
	}
	if len(inherited) != 0 {
		t.Errorf("IAMT-214 %s: after the write the key file has %d inherited ACE(s) %v, want exactly zero", label, len(inherited), inherited)
	}
	if len(aces) != 2 {
		t.Errorf("IAMT-214 %s: after the write the key file DACL must hold exactly 2 ACEs (SYSTEM + Administrators), got %d: %v", label, len(aces), aces)
	}
	for _, wantSID := range []string{"S-1-5-18", "S-1-5-32-544"} {
		found := false
		for _, a := range aces {
			if a.sid != wantSID {
				continue
			}
			found = true
			if !a.allow {
				t.Errorf("IAMT-214 %s: key file ACE for %s must be ACCESS_ALLOWED, got a deny ACE", label, wantSID)
			}
			if a.mask != uint32(genericAll) && a.mask&uint32(fileAllAccess) != uint32(fileAllAccess) {
				t.Errorf("IAMT-214 %s: key file DACL must grant %s full control, got mask %#x", label, wantSID, a.mask)
			}
		}
		if !found {
			t.Errorf("IAMT-214 %s: key file DACL must grant %s, got trustees %v", label, wantSID, aces)
		}
	}
}

// seedInheritedKeyFile writes the initial key file content the way a
// real file is found: freshly created, carrying an inherited
// (unprotected) DACL from its directory. The precondition is asserted
// so the test fails loudly — not silently passes — if the environment
// hands out protected files.
func seedInheritedKeyFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	prot, err := DACLProtected(path)
	if err != nil {
		t.Fatal(err)
	}
	if prot {
		t.Fatalf("IAMT-214 precondition: freshly seeded %s must carry an inherited (unprotected) DACL, got protected=true", path)
	}
	if aces := readDACLFull(t, path); len(aces) == 0 {
		t.Fatalf("IAMT-214 precondition: freshly seeded %s must inherit ACEs from its parent directory, got an empty DACL", path)
	}
}

// testUserSID returns the test process's own user SID.
func testUserSID(t *testing.T) *windows.SID {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer token.Close()
	du, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	sid, err := du.User.Sid.Copy()
	if err != nil {
		t.Fatalf("copy user SID: %v", err)
	}
	return sid
}

// relaxACLOnCleanup registers a cleanup that grants the test process's
// own user full control on each path, so t.TempDir() can delete the
// files the product just locked to SYSTEM/Administrators. An owner can
// always rewrite the DACL (implicit WRITE_DAC), so the restore works at
// any elevation. Only ever called on paths inside t.TempDir().
func relaxACLOnCleanup(t *testing.T, paths ...string) {
	t.Cleanup(func() {
		user := testUserSID(t)
		rp := &runtime.Pinner{}
		defer rp.Unpin()
		rp.Pin(user)
		sd, err := windows.BuildSecurityDescriptor(nil, nil, []windows.EXPLICIT_ACCESS{{
			AccessPermissions: genericAll,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       0,
			Trustee: windows.TRUSTEE{
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_USER,
				TrusteeValue:             windows.TrusteeValueFromSID(user),
			},
		}}, nil, nil)
		if err != nil {
			t.Logf("cleanup: BuildSecurityDescriptor: %v", err)
			return
		}
		_, _, dacl, _, err := extractACLFromSD(sd)
		if err != nil {
			t.Logf("cleanup: extract DACL: %v", err)
			return
		}
		for _, p := range paths {
			if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, daclSecurityInfo|protectedDaclSec, nil, nil, dacl, nil); err != nil {
				t.Logf("cleanup: relax ACL on %s: %v", p, err)
			}
		}
	})
}

// ─── the five write paths ────────────────────────────────────────────────

// TestIAMT214_OpenLeavesProtectedDACL drives the open path (server
// door.open → Door.Install) against a file with an inherited ACL.
func TestIAMT214_OpenLeavesProtectedDACL(t *testing.T) {
	requireWritableLockedFiles(t)
	path := filepath.Join(t.TempDir(), "administrators_authorized_keys")
	seedInheritedKeyFile(t, path, "third-party key stays\r\n")
	relaxACLOnCleanup(t, path)

	d, err := NewDoor(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Install(randomDoorID(t), TestKey); err != nil {
		t.Fatalf("Install: %v", err)
	}
	assertLockedDACL(t, "open", path)
}

// TestIAMT214_CloseLeavesProtectedDACL drives the close path (server
// door.close / self-close / teardown → Door.Remove) — the path the
// live defect was found on. Canary: remove protectTmpBeforeReplace
// from writeAtomicBytes and this test goes red on its own line.
func TestIAMT214_CloseLeavesProtectedDACL(t *testing.T) {
	requireWritableLockedFiles(t)
	path := filepath.Join(t.TempDir(), "administrators_authorized_keys")
	id := randomDoorID(t)
	seedInheritedKeyFile(t, path, "third-party key stays\r\n"+FormatLine(id, TestKey)+"\r\n")
	relaxACLOnCleanup(t, path)

	d, err := NewDoor(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Remove(id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	assertLockedDACL(t, "close", path)

	lines, err := d.ReadLines()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if IsOursID(l, id) {
			t.Fatalf("close removed no line — the DACL below was checked on an unrewritten file: %q", l)
		}
	}
}

// TestIAMT214_SweepLeavesProtectedDACL drives the sweep path (server
// start / reconnect → Door.SweepStale).
func TestIAMT214_SweepLeavesProtectedDACL(t *testing.T) {
	requireWritableLockedFiles(t)
	path := filepath.Join(t.TempDir(), "administrators_authorized_keys")
	seedInheritedKeyFile(t, path, "third-party key stays\r\n"+FormatLine(randomDoorID(t), TestKey)+"\r\n")
	relaxACLOnCleanup(t, path)

	d, err := NewDoor(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := d.SweepStale("")
	if err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	if n == 0 {
		t.Fatal("sweep removed 0 lines — the DACL below was checked on an unrewritten file")
	}
	assertLockedDACL(t, "sweep", path)
}

// TestIAMT214_SanitizeLeavesProtectedDACL drives the sanitize path.
// door.sanitize is Door.SweepStale("") on the server side
// (internal/server/door.go), aimed at a CORRUPT door line; the seed
// below carries one so the sweep rewrites the file exactly the way
// sanitize does.
func TestIAMT214_SanitizeLeavesProtectedDACL(t *testing.T) {
	requireWritableLockedFiles(t)
	path := filepath.Join(t.TempDir(), "administrators_authorized_keys")
	corrupt := Options + " ssh-ed25519 not-a-base64-key!! iamtunnel-door=zz"
	seedInheritedKeyFile(t, path, "third-party key stays\r\n"+corrupt+"\r\n")
	relaxACLOnCleanup(t, path)

	d, err := NewDoor(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := d.SweepStale("")
	if err != nil {
		t.Fatalf("SweepStale (sanitize): %v", err)
	}
	if n == 0 {
		t.Fatal("sanitize removed 0 corrupt lines — the DACL below was checked on an unrewritten file")
	}
	assertLockedDACL(t, "sanitize", path)
}

// TestIAMT214_DoorwatchCloseLeavesProtectedDACL drives the doorwatch
// close path: RunWatchdog's single-path removal removeOnceAndAudit —
// the exact function the doorwatch child calls after the parent dies.
func TestIAMT214_DoorwatchCloseLeavesProtectedDACL(t *testing.T) {
	requireWritableLockedFiles(t)
	path := filepath.Join(t.TempDir(), "administrators_authorized_keys")
	id := randomDoorID(t)
	seedInheritedKeyFile(t, path, "third-party key stays\r\n"+FormatLine(id, TestKey)+"\r\n")
	relaxACLOnCleanup(t, path)

	if err := removeOnceAndAudit(path, id, nil); err != nil {
		t.Fatalf("removeOnceAndAudit: %v", err)
	}
	assertLockedDACL(t, "doorwatch close", path)
}
