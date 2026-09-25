//go:build windows

// iamt312_gateway_exe_dir_acl_windows_test.go — IAMT-312: the gateway
// service's virtual account needs read+execute on the directory holding
// the binary the SCM starts, or "sc start" fails with Access is denied
// even after the binary is moved to C:\Program Files\iamtunnel (RUNBOOK
// §1.5) — a live Windows box needed an explicit icacls grant there on
// top of the move. hardenGatewayExeDirACL is the product half of that
// grant.
//
// Canaries:
//
//  1. drop any of the four trustees from hardenGatewayExeDirACL or
//     forget SE_DACL_PROTECTED — the matching assertion of
//     TestIAMT312_ExeDirACLFourTrustees turns red;
//  2. give the service account/BUILTIN\Users more than read+execute
//     (full access, say) — the mask check there turns red.
//
// Every ACL operation happens only on paths inside t.TempDir() (gate
// 11); system directories are untouched. The test requires an elevated
// token and is otherwise skipped with an explanation (gate 10) — like
// IAMT-257/213.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// TestIAMT312_ExeDirACLFourTrustees — hardenGatewayExeDirACL on a fresh
// directory: a protected DACL with exactly four ACCESS_ALLOWED ACEs —
// SYSTEM and Administrators with full access, BUILTIN\Users and the
// service account with read+execute — each (OI)(CI), so files copied in
// later inherit the same rights.
func TestIAMT312_ExeDirACLFourTrustees(t *testing.T) {
	requireWritableLockedFiles(t)
	dir := filepath.Join(t.TempDir(), "iamtunnel")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := hardenGatewayExeDirACL(dir, false, nil); err != nil {
		t.Fatalf("hardenGatewayExeDirACL: %v", err)
	}
	relaxACLOnCleanup(t, dir)

	prot, err := winkeys.DACLProtected(dir)
	if err != nil {
		t.Fatalf("DACLProtected(%s): %v", dir, err)
	}
	if !prot {
		t.Errorf("IAMT-312: DACL %s must be protected (SE_DACL_PROTECTED) — inherited ACEs from C:\\Program Files must not leak in unexamined", dir)
	}

	aces := readDACLFull(t, dir)
	var inherited []aceInfo
	for _, a := range aces {
		if a.inherited {
			inherited = append(inherited, a)
		}
	}
	if len(inherited) != 0 {
		t.Errorf("IAMT-312: %s carries %d inherited ACEs %v, want zero", dir, len(inherited), inherited)
	}
	if len(aces) != 4 {
		t.Fatalf("IAMT-312: DACL %s must carry exactly 4 ACEs (SYSTEM, Administrators, BUILTIN\\Users, %s), got %d: %v",
			dir, gatewayServiceAccountName, len(aces), aces)
	}

	serviceSID := gatewayServiceSIDString(t)
	fullControl := []string{"S-1-5-18", "S-1-5-32-544"}
	readExecute := []string{"S-1-5-32-545", serviceSID}

	find := func(sid string) (aceInfo, bool) {
		for _, a := range aces {
			if a.sid == sid {
				return a, true
			}
		}
		return aceInfo{}, false
	}

	for _, sid := range fullControl {
		a, found := find(sid)
		if !found {
			t.Errorf("IAMT-312: DACL %s must grant %s access, actual trustees: %v", dir, sid, aces)
			continue
		}
		if !a.allow {
			t.Errorf("IAMT-312: ACE for %s on %s must be ACCESS_ALLOWED, not deny", sid, dir)
		}
		if a.mask != testGenericAll && a.mask&testFileAllAccess != testFileAllAccess {
			t.Errorf("IAMT-312: DACL %s must give %s full control, got mask %#x", dir, sid, a.mask)
		}
		if a.inheritFlags != testOICI {
			t.Errorf("IAMT-312: DACL %s must give %s inheritance (OI)(CI), got flags %#x", dir, sid, a.inheritFlags)
		}
	}
	for _, sid := range readExecute {
		a, found := find(sid)
		if !found {
			t.Errorf("IAMT-312: DACL %s must grant %s access, actual trustees: %v", dir, sid, aces)
			continue
		}
		if !a.allow {
			t.Errorf("IAMT-312: ACE for %s on %s must be ACCESS_ALLOWED, not deny", sid, dir)
		}
		if a.mask != uint32(gatewayExeDirReadExecute) {
			t.Errorf("IAMT-312: DACL %s must give %s exactly read+execute (%#x), got mask %#x — more than that defeats the point of not running the service as an admin", dir, sid, uint32(gatewayExeDirReadExecute), a.mask)
		}
		if a.inheritFlags != testOICI {
			t.Errorf("IAMT-312: DACL %s must give %s inheritance (OI)(CI), got flags %#x", dir, sid, a.inheritFlags)
		}
	}
}

// TestIAMT312_ExeFileACLFourTrustees is the round-5 canary for review
// finding 1's second half: (OI)(CI) inheritance on the directory reaches
// only objects created afterward, so a binary that already sits there
// keeps whatever ACL it had before — hardenGatewayExeFileACL must be
// asserted against the FILE's own DACL directly, not inferred from the
// directory's.
//
// Canary: reduce hardenGatewayExeFileACL to just calling
// hardenGatewayExeDirACL (without applying an ACL to the file itself) —
// this test turns red, because the pre-created file keeps its original
// ACL, trimmed here to a single non-production trustee.
func TestIAMT312_ExeFileACLFourTrustees(t *testing.T) {
	requireWritableLockedFiles(t)
	dir := t.TempDir()
	exe := filepath.Join(dir, "iamtunnel.exe")
	if err := os.WriteFile(exe, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := hardenGatewayExeFileACL(exe, false, nil); err != nil {
		t.Fatalf("hardenGatewayExeFileACL: %v", err)
	}
	relaxACLOnCleanup(t, exe)

	prot, err := winkeys.DACLProtected(exe)
	if err != nil {
		t.Fatalf("DACLProtected(%s): %v", exe, err)
	}
	if !prot {
		t.Errorf("IAMT-312 round 5: DACL %s must be protected (SE_DACL_PROTECTED) — the file's pre-existing ACL must not survive unexamined", exe)
	}

	aces := readDACLFull(t, exe)
	if len(aces) != 4 {
		t.Fatalf("IAMT-312 round 5: DACL %s must carry exactly 4 ACEs (SYSTEM, Administrators, BUILTIN\\Users, %s), got %d: %v",
			exe, gatewayServiceAccountName, len(aces), aces)
	}

	serviceSID := gatewayServiceSIDString(t)
	fullControl := []string{"S-1-5-18", "S-1-5-32-544"}
	readExecute := []string{"S-1-5-32-545", serviceSID}

	find := func(sid string) (aceInfo, bool) {
		for _, a := range aces {
			if a.sid == sid {
				return a, true
			}
		}
		return aceInfo{}, false
	}

	for _, sid := range fullControl {
		a, found := find(sid)
		if !found {
			t.Errorf("IAMT-312 round 5: DACL %s must grant %s access, actual trustees: %v", exe, sid, aces)
			continue
		}
		if a.mask != testGenericAll && a.mask&testFileAllAccess != testFileAllAccess {
			t.Errorf("IAMT-312 round 5: DACL %s must give %s full control, got mask %#x", exe, sid, a.mask)
		}
	}
	for _, sid := range readExecute {
		a, found := find(sid)
		if !found {
			t.Errorf("IAMT-312 round 5: DACL %s must grant %s access, actual trustees: %v", exe, sid, aces)
			continue
		}
		if a.mask != uint32(gatewayExeDirReadExecute) {
			t.Errorf("IAMT-312 round 5: DACL %s must give %s exactly read+execute (%#x), got mask %#x", exe, sid, uint32(gatewayExeDirReadExecute), a.mask)
		}
		// A file has nothing to propagate an ACE to — unlike the
		// directory case, no (OI)(CI) is expected here.
		if a.inheritFlags != 0 {
			t.Errorf("IAMT-312 round 5: DACL %s must give %s no inheritance flags on a file, got %#x", exe, sid, a.inheritFlags)
		}
	}
}
