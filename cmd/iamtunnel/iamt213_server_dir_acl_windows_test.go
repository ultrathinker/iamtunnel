//go:build windows

// IAMT-213 canary tests. The defect: the server role's data directory
// was created with os.MkdirAll(dir, 0o700), which on Windows sets no
// ACL at all — the directory inherits the stock ProgramData entries
// (Users read + create), and machine.key inherits Users:(I)(RX): any
// local user could read the machine's private key.
//
// The fix under test: hardenServerDir applies the protected
// {SYSTEM, Administrators} DACL with (OI)(CI) inheritance to the
// directory and heals everything already inside it (called by enrol
// before any secret is written and by server start before anything is
// read), while atomicWriteMachineBytes / generateMachineSigner lock
// each machine file's DACL down before the rename makes it visible
// under its real name. The shared atomicWriteBytes /
// atomicWriteJSON / generateSigner stay untouched — they also serve
// non-machine data (recordings, bootstrap token, gateway hostkey).
// The DACL primitive is winkeys' own (LockDownFileACL /
// LockDownDirACL) — these tests only read the result back.
//
// Canaries:
//   - revert LockDownDirACL's mask to GENERIC_ALL → the directory
//     asserts go red ("must hold exactly 2 ACEs … got 4");
//   - remove winkeys.LockDownDirACL from hardenServerDir → the
//     directory asserts go red on their own line;
//   - remove winkeys.LockDownFileACL from generateMachineSigner → the
//     machine.key assert goes red; remove it from
//     atomicWriteMachineBytes → the machine.id assert goes red;
//   - remove the hardenServerDirChildren walk → the healing test's
//     file/subdirectory asserts go red;
//   - move the lockdown back into the SHARED atomicWriteBytes →
//     TestIAMT213_GenericWriteStaysInherited goes red.

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// requireWritableLockedFiles skips the test when the process token is
// not elevated: the product write path locks the tmp file to
// SYSTEM/Administrators BEFORE renaming it, so a non-elevated token
// cannot move it into place. This mirrors production — enrol and
// server start write machine-owned material that a non-admin must not
// be able to write (or read).
func requireWritableLockedFiles(t *testing.T) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer token.Close()
	if !token.IsElevated() {
		t.Skip("ACL tests need an elevated test process: the write path locks the tmp file to SYSTEM/Administrators BEFORE renaming it. Run go test from an administrator console.")
	}
}

const (
	testGenericAll    uint32 = 0x10000000
	testProtectedDacl        = 0x80000000 // SE_DACL_PROTECTED for SetNamedSecurityInfo
	testFileAllAccess uint32 = 0x1F01FF   // FILE_ALL_ACCESS
	testOICI          uint8  = 0x3        // OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
)

// aceInfo is one ACE read back from a DACL — including inherited ones:
// the point of IAMT-213 is that none are left at all.
type aceInfo struct {
	sid          string
	mask         uint32
	allow        bool
	inheritFlags uint8
	inherited    bool
}

// readDACLFull walks the whole DACL of path via GetNamedSecurityInfo,
// copying it into Go memory first.
func readDACLFull(t *testing.T, path string) []aceInfo {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
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
			allow:        daclCopy[off] == 0, // ACCESS_ALLOWED_ACE_TYPE
			inheritFlags: daclCopy[off+1] & testOICI,
			inherited:    daclCopy[off+1]&0x10 != 0, // INHERITED_ACE
		})
		off += aceSize
	}
	return out
}

// assertTwoTrusteeACEs is the shared core: protected, exactly two
// ACCESS_ALLOWED ACEs (S-1-5-18 and S-1-5-32-544, full control), zero
// inherited ACEs. wantInherit selects the directory variant (every ACE
// carries (OI)(CI)) or the file variant (no inheritance flags).
func assertTwoTrusteeACEs(t *testing.T, label, path string, wantInherit bool) {
	t.Helper()
	prot, err := winkeys.DACLProtected(path)
	if err != nil {
		t.Fatalf("IAMT-213 %s: DACLProtected(%s): %v", label, path, err)
	}
	if !prot {
		t.Errorf("IAMT-213 %s: %s DACL must be protected (SE_DACL_PROTECTED), got protected=false — inherited ProgramData entries leak in", label, path)
	}
	aces := readDACLFull(t, path)
	var inherited []aceInfo
	for _, a := range aces {
		if a.inherited {
			inherited = append(inherited, a)
		}
	}
	if len(inherited) != 0 {
		t.Errorf("IAMT-213 %s: %s has %d inherited ACE(s) %v, want exactly zero", label, path, len(inherited), inherited)
	}
	if len(aces) != 2 {
		t.Errorf("IAMT-213 %s: %s DACL must hold exactly 2 ACEs (SYSTEM + Administrators), got %d: %v", label, path, len(aces), aces)
	}
	for _, wantSID := range []string{"S-1-5-18", "S-1-5-32-544"} {
		found := false
		for _, a := range aces {
			if a.sid != wantSID {
				continue
			}
			found = true
			if !a.allow {
				t.Errorf("IAMT-213 %s: ACE for %s on %s must be ACCESS_ALLOWED, got a deny ACE", label, wantSID, path)
			}
			if a.mask != testGenericAll && a.mask&testFileAllAccess != testFileAllAccess {
				t.Errorf("IAMT-213 %s: DACL of %s must grant %s full control, got mask %#x", label, path, wantSID, a.mask)
			}
			if wantInherit && a.inheritFlags != testOICI {
				t.Errorf("IAMT-213 %s: DACL of directory %s must grant %s with (OI)(CI) inheritance, got flags %#x", label, path, wantSID, a.inheritFlags)
			}
			if !wantInherit && a.inheritFlags != 0 {
				t.Errorf("IAMT-213 %s: DACL of file %s must grant %s without inheritance flags, got flags %#x", label, path, wantSID, a.inheritFlags)
			}
		}
		if !found {
			t.Errorf("IAMT-213 %s: DACL of %s must grant %s, got trustees %v", label, path, wantSID, aces)
		}
	}
}

// assertLockedDirDACL / assertLockedFileDACL name the two object kinds
// explicitly so a red test names the exact producer.
func assertLockedDirDACL(t *testing.T, label, path string) {
	t.Helper()
	assertTwoTrusteeACEs(t, label, path, true)
}

func assertLockedFileDACL(t *testing.T, label, path string) {
	t.Helper()
	assertTwoTrusteeACEs(t, label, path, false)
}

// assertInheritedACL asserts the "as found in reality" precondition: a
// freshly created object carries an unprotected, inherited DACL. If
// the environment hands out protected objects the test stops instead
// of silently passing.
func assertInheritedACL(t *testing.T, label, path string) {
	t.Helper()
	prot, err := winkeys.DACLProtected(path)
	if err != nil {
		t.Fatal(err)
	}
	if prot {
		t.Fatalf("IAMT-213 precondition: freshly created %s (%s) must carry an inherited (unprotected) DACL, got protected=true", label, path)
	}
	if aces := readDACLFull(t, path); len(aces) == 0 {
		t.Fatalf("IAMT-213 precondition: freshly created %s (%s) must inherit ACEs from its parent, got an empty DACL", label, path)
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
// own user full control on each path (with (OI)(CI) so children stay
// deletable too), so t.TempDir() can delete what the product locked to
// SYSTEM/Administrators. An owner can always rewrite the DACL
// (implicit WRITE_DAC). Only ever called on paths inside t.TempDir().
func relaxACLOnCleanup(t *testing.T, paths ...string) {
	t.Cleanup(func() {
		user := testUserSID(t)
		rp := &runtime.Pinner{}
		defer rp.Unpin()
		rp.Pin(user)
		sd, err := windows.BuildSecurityDescriptor(nil, nil, []windows.EXPLICIT_ACCESS{{
			AccessPermissions: windows.ACCESS_MASK(testGenericAll),
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
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
		sdPtr := unsafe.Pointer(sd)
		daclOff := *(*uint32)(unsafe.Add(sdPtr, 16))
		if daclOff == 0 {
			return
		}
		dacl := (*windows.ACL)(unsafe.Add(sdPtr, daclOff))
		for _, p := range paths {
			if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|testProtectedDacl, nil, nil, dacl, nil); err != nil {
				t.Logf("cleanup: relax ACL on %s: %v", p, err)
			}
		}
	})
}

// TestIAMT213_EnrolPathProtectsDirAndMachineKey drives the enrol write
// path against a data directory that does not exist yet: harden
// (creates and locks the directory), generate the machine key through
// the machine variant enrol really uses, write machine.id through the
// machine write — then both the directory and every file must carry
// the protected two-trustee DACL, the directory with (OI)(CI) and the
// specific FILE_ALL_ACCESS mask (one ACE per trustee, no generic-ACE
// canonicalization split).
func TestIAMT213_EnrolPathProtectsDirAndMachineKey(t *testing.T) {
	requireWritableLockedFiles(t)
	base := filepath.Join(t.TempDir(), "iamtunnel")

	if err := hardenServerDir(base, false); err != nil {
		t.Fatalf("hardenServerDir: %v", err)
	}
	keyPath := filepath.Join(base, "machine.key")
	if _, err := loadOrGenerateMachineSigner(keyPath); err != nil {
		t.Fatalf("loadOrGenerateMachineSigner: %v", err)
	}
	idPath := filepath.Join(base, "machine.id")
	if err := atomicWriteMachineBytes(idPath, []byte("machine-1234")); err != nil {
		t.Fatalf("atomicWriteMachineBytes: %v", err)
	}
	relaxACLOnCleanup(t, base, keyPath, idPath)

	assertLockedDirDACL(t, "enrol: directory", base)
	assertLockedFileDACL(t, "enrol: machine.key", keyPath)
	assertLockedFileDACL(t, "enrol: machine.id", idPath)
}

// TestIAMT213_HealsExistingBadDirAndFiles reproduces the live finding:
// a data directory an older binary created with inherited
// Users-readable entries, machine.key inside it inheriting the same —
// hardenServerDir must fix the directory, the file and a
// subdirectory, in place, without manual steps.
func TestIAMT213_HealsExistingBadDirAndFiles(t *testing.T) {
	requireWritableLockedFiles(t)
	base := filepath.Join(t.TempDir(), "iamtunnel")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(base, "machine.key")
	if err := os.WriteFile(keyPath, []byte("stale machine key bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(base, "journal")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	assertInheritedACL(t, "directory", base)
	assertInheritedACL(t, "machine.key", keyPath)

	if err := hardenServerDir(base, false); err != nil {
		t.Fatalf("hardenServerDir: %v", err)
	}
	relaxACLOnCleanup(t, base, keyPath)

	assertLockedDirDACL(t, "heal: directory", base)
	assertLockedFileDACL(t, "heal: existing machine.key", keyPath)
	assertLockedDirDACL(t, "heal: subdirectory", sub)
}

// TestIAMT213_GenericWriteStaysInherited is the round-2 canary for the
// SHARED write helper. atomicWriteBytes also serves non-machine data —
// downloaded recordings (admin_exec.go), the gateway bootstrap token
// and the gateway hostkey (gateway.go) — and an administrator must
// keep reading their own files from a normal console, so it must NOT
// lock the DACL down; only the atomicWriteMachineBytes variant may.
//
// Canary: move winkeys.LockDownFileACL back into atomicWriteBytes and
// this test goes red on its own line.
func TestIAMT213_GenericWriteStaysInherited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generic-role-file")
	if err := atomicWriteBytes(path, []byte("payload")); err != nil {
		t.Fatalf("atomicWriteBytes: %v", err)
	}
	prot, err := winkeys.DACLProtected(path)
	if err != nil {
		t.Fatalf("DACLProtected: %v", err)
	}
	if prot {
		t.Errorf("IAMT-213 round 2: a file written by the SHARED atomicWriteBytes must keep its inherited (unprotected) DACL — the lockdown belongs to atomicWriteMachineBytes only, got protected=true")
	}
}
