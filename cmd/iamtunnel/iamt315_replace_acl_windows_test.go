//go:build windows

// iamt315_replace_acl_windows_test.go — IAMT-315: "install wipes an
// explicit DENY an administrator had placed". On Windows install builds
// the hardened DACL (SYSTEM + Administrators + the service SID, for the
// gateway) out of allow-ACEs only and writes it through
// SetNamedSecurityInfo — no foreign ACE is blended into the new DACL.
// That means an explicit (non-inherited) ACCESS_DENIED an operator had
// earlier placed on the data directory or its files quietly disappears.
// The remedy is read before write: GetNamedSecurityInfo + a DACL walk,
// and refuse (or, under --replace-acl, proceed + report) on every
// non-inherited DENY. Inherited DENYs are not the operator's decision
// about THIS object — they arrived from the parent and SE_DACL_PROTECTED
// discards them at write anyway; we ignore them.
//
// Canaries (one per assertion):
//   - drop the GetNamedSecurityInfo/DACL walk from
//     applyGatewayProtectedACL or applyProtectedDACL —
//     TestIAMT315_RefusesExplicitDenyOnFile turns red on "hardening
//     silently dropped an explicit DENY ACE";
//   - treat replaceACL=true as "always refuse" —
//     TestIAMT315_ReplaceACLProceedsAndListsRemoved turns red;
//   - start counting inherited DENYs as "foreign" —
//     TestIAMT315_InheritedDenyDoesNotTriggerRefusal turns red;
//   - drop the replaceACL flag from setupGatewayService or forget to
//     thread it through cmdGatewayInstallOrRun —
//     TestIAMT315_InstallCLIThreadsReplaceACLThrough turns red;
//   - forget to return *ForeignDenyRefusalError out of gateway_service
//     or fail to branch the exit code on exitDenied —
//     TestIAMT315_InstallRefusesAndReturnsExit4 turns red.
//
// All ACL operations run on paths inside t.TempDir() (gate 11): system
// services, the registry and real system directories are untouched.
// The ACL tests require an elevated token and are otherwise skipped
// with an explanation (gate 10) — like the IAMT-213/257 tests.

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// attachExplicitDenyACE REPLACES path's DACL with a single explicit
// ACCESS_DENIED ACE for the given trustee SID (and access mask) —
// used by the refusal tests where the test never tries to access the
// object after the DENY lands. The full-install tests below need
// appendExplicitDenyACE instead — REPLACING the DACL strips every
// Allow ACE, so the test process then has no access (an empty Allow
// set means implicit-deny for everyone, even an admin).
func attachExplicitDenyACE(t *testing.T, path, trusteeSID string, mask uint32) {
	t.Helper()
	sid, err := windows.StringToSid(trusteeSID)
	if err != nil {
		t.Fatalf("StringToSid(%s): %v", trusteeSID, err)
	}
	trustee := windows.TRUSTEE{
		MultipleTrustee:          nil,
		MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
		TrusteeForm:              windows.TRUSTEE_IS_SID,
		TrusteeType:              windows.TRUSTEE_IS_USER,
		TrusteeValue:             windows.TrusteeValueFromSID(sid),
	}
	sd, err := windows.BuildSecurityDescriptor(
		nil, nil,
		[]windows.EXPLICIT_ACCESS{{
			AccessPermissions: windows.ACCESS_MASK(mask),
			AccessMode:        windows.DENY_ACCESS,
			Inheritance:       0,
			Trustee:           trustee,
		}},
		nil, nil,
	)
	if err != nil {
		t.Fatalf("BuildSecurityDescriptor: %v", err)
	}
	sdBytes := readSDBytes(t, sd)
	daclOff := readU32(sdBytes, 16)
	if daclOff == 0 {
		t.Fatalf("BuildSecurityDescriptor returned a security descriptor without a DACL")
	}
	dacl := (*windows.ACL)(unsafeAdd(unsafe.Pointer(sd), uintptr(daclOff)))
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil,
		dacl,
		nil,
	); err != nil {
		t.Fatalf("SetNamedSecurityInfo(%s): %v", path, err)
	}
}

// appendExplicitDenyACE ADDS the specified ACCESS_DENIED ACE to
// path's existing DACL, preserving every existing ACE so the test
// process can still access the object. Unlike attachExplicitDenyACE,
// which REPLACES the DACL with only the new DENY (and therefore
// strips every Allow ACE — the test process then has NO access
// because the only ACE left denies some other principal, and an
// empty allow set means implicit-deny for everyone), this helper is
// what the install tests need: the protected DACL from a previous
// hardenGatewayDirACL (which grants Administrators FullControl)
// stays in place alongside the operator's DENY for BUILTIN\Guests,
// exactly the real-world shape.
//
// The walk reads the SD's DACL byte-for-byte (same pattern as
// walkDACLForForeignDeny below), converts each non-inherited ACE
// to a windows.EXPLICIT_ACCESS, appends the new DENY, then writes
// the rebuilt SD via SetNamedSecurityInfo. Inherited ACEs (the
// INHERITED_ACE flag) are skipped — they belong to the parent and
// are re-applied by Windows on write anyway; copying them verbatim
// would let Windows canonicalise them in unpredictable ways
// depending on the parent's DACL at the moment of the rebuild.
func appendExplicitDenyACE(t *testing.T, path, trusteeSID string, mask uint32) {
	t.Helper()
	sid, err := windows.StringToSid(trusteeSID)
	if err != nil {
		t.Fatalf("StringToSid(%s): %v", trusteeSID, err)
	}

	// 1. Read the existing SD's DACL.
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	sdBytes := readSDBytes(t, sd)
	daclOff := readU32(sdBytes, 16)
	if daclOff == 0 {
		t.Fatalf("appendExplicitDenyACE(%s): no DACL", path)
	}
	daclPtr := unsafeAdd(unsafe.Pointer(sd), uintptr(daclOff))
	daclSize := int(readU16(daclPtr, 2))
	if daclSize < 8 || daclSize > 64*1024 {
		t.Fatalf("appendExplicitDenyACE(%s): implausible DACL size %d", path, daclSize)
	}
	daclBuf := unsafe.Slice((*byte)(daclPtr), daclSize)
	daclCopy := make([]byte, daclSize)
	copy(daclCopy, daclBuf)
	aceCount := int(readU16(unsafe.Pointer(&daclCopy[0]), 4))

	// 2. Collect existing non-inherited ACEs.
	var eas []windows.EXPLICIT_ACCESS
	off := 8
	for i := 0; i < aceCount; i++ {
		if off+4 > daclSize {
			t.Fatalf("ACE %d past DACL end in %s", i, path)
		}
		aceType := daclCopy[off]
		aceFlags := daclCopy[off+1]
		aceSize := int(readU16(unsafe.Pointer(&daclCopy[0]), off+2))
		sidPtr := (*windows.SID)(unsafe.Pointer(&daclCopy[off+8]))
		sidLen := windows.GetLengthSid(sidPtr)
		if sidLen == 0 || off+8+int(sidLen) > daclSize {
			off += aceSize
			continue
		}
		// Skip inherited ACEs — they belong to the parent, not to
		// THIS object's explicit decision, and copying them
		// verbatim would let Windows canonicalise them in
		// unpredictable ways.
		if aceFlags&0x10 != 0 {
			off += aceSize
			continue
		}
		sidCopy, err := sidPtr.Copy()
		if err != nil {
			off += aceSize
			continue
		}
		mode := windows.ACCESS_MODE(windows.GRANT_ACCESS)
		if aceType == 1 { // ACCESS_DENIED_ACE_TYPE
			mode = windows.ACCESS_MODE(windows.DENY_ACCESS)
		}
		eas = append(eas, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.ACCESS_MASK(readU32(daclCopy, off+4)),
			AccessMode:        mode,
			Inheritance:       uint32(aceFlags) & 0x3,
			Trustee: windows.TRUSTEE{
				MultipleTrustee:          nil,
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_USER,
				TrusteeValue:             windows.TrusteeValueFromSID(sidCopy),
			},
		})
		off += aceSize
	}

	// 3. Append the new DENY ACE.
	eas = append(eas, windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.ACCESS_MASK(mask),
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       0,
		Trustee: windows.TRUSTEE{
			MultipleTrustee:          nil,
			MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
			TrusteeForm:              windows.TRUSTEE_IS_SID,
			TrusteeType:              windows.TRUSTEE_IS_USER,
			TrusteeValue:             windows.TrusteeValueFromSID(sid),
		},
	})

	// 4. Build the new SD and write back.
	newSD, err := windows.BuildSecurityDescriptor(nil, nil, eas, nil, nil)
	if err != nil {
		t.Fatalf("BuildSecurityDescriptor: %v", err)
	}
	newSDBytes := readSDBytes(t, newSD)
	newDACLOff := readU32(newSDBytes, 16)
	if newDACLOff == 0 {
		t.Fatalf("BuildSecurityDescriptor returned no DACL")
	}
	newDACL := (*windows.ACL)(unsafeAdd(unsafe.Pointer(newSD), uintptr(newDACLOff)))
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil,
		newDACL,
		nil,
	); err != nil {
		t.Fatalf("SetNamedSecurityInfo(%s): %v", path, err)
	}
}

// walkDACLForForeignDeny is iamt257's readDACLFull restricted to
// what iamt315 needs. Imported here so the test self-contains its
// ACL-walk helpers without depending on the iamt213 test file's
// package-private functions.
func walkDACLForForeignDeny(t *testing.T, sd *windows.SECURITY_DESCRIPTOR) []aceInfo {
	t.Helper()
	sdBytes := readSDBytes(t, sd)
	daclOff := readU32(sdBytes, 16)
	if daclOff == 0 {
		return nil
	}
	daclPtr := unsafeAdd(unsafe.Pointer(sd), uintptr(daclOff))
	daclSize := int(readU16(daclPtr, 2))
	if daclSize < 8 || daclSize > 64*1024 {
		t.Fatalf("implausible DACL size %d", daclSize)
	}
	daclBuf := unsafe.Slice((*byte)(daclPtr), daclSize)
	daclCopy := make([]byte, daclSize)
	copy(daclCopy, daclBuf)
	aceCount := int(readU16(unsafe.Pointer(&daclCopy[0]), 4))
	off := 8
	var out []aceInfo
	for i := 0; i < aceCount; i++ {
		if off+4 > daclSize {
			t.Fatalf("ACE index %d past DACL end (off=%d size=%d)", i, off, daclSize)
		}
		aceSize := int(readU16(unsafe.Pointer(&daclCopy[0]), off+2))
		sidPtr := (*windows.SID)(unsafe.Pointer(&daclCopy[off+8]))
		sidLen := windows.GetLengthSid(sidPtr)
		if sidLen == 0 || off+8+int(sidLen) > daclSize {
			off += aceSize
			continue
		}
		sidCopy, err := sidPtr.Copy()
		if err != nil {
			off += aceSize
			continue
		}
		out = append(out, aceInfo{
			sid:          sidCopy.String(),
			mask:         readU32(daclCopy, off+4),
			allow:        daclCopy[off] == 0, // ACCESS_ALLOWED_ACE_TYPE
			inheritFlags: daclCopy[off+1] & testOICI,
			inherited:    daclCopy[off+1]&0x10 != 0, // INHERITED_ACE
		})
		off += aceSize
	}
	return out
}

// hasExplicitDenyFor returns true if path has at least one
// non-inherited ACCESS_DENIED ACE for the given SID string. Inherited
// DENYs are skipped — they came from a parent and are not the
// operator's local decision.
func hasExplicitDenyFor(t *testing.T, path, sidString string) bool {
	t.Helper()
	for _, a := range walkDACLForForeignDeny(t, mustGetSD(t, path)) {
		if !a.allow && a.sid == sidString && !a.inherited {
			return true
		}
	}
	return false
}

// hasInheritedDenyFor returns true if path has at least one
// inherited DENY ACE for the given SID string. Used by the inherited-
// deny test to assert the precondition.
func hasInheritedDenyFor(t *testing.T, path, sidString string) bool {
	t.Helper()
	for _, a := range walkDACLForForeignDeny(t, mustGetSD(t, path)) {
		if !a.allow && a.sid == sidString && a.inherited {
			return true
		}
	}
	return false
}

// mustGetSD fetches the SD for path and fails the test on error.
func mustGetSD(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	return sd
}

// captureStderr swaps os.Stderr with a pipe-backed buffer for the
// duration of fn and returns what fn wrote to it. Used by the
// standalone hardenGatewayFileACL / winkeys.LockDownFileACL tests
// that drive the helper directly and so DO pass os.Stderr as the
// report writer (production has no source-of-truth that mentions
// os.Stderr — both winkeys.reportForeignDeny and
// cmd/iamtunnel.reportGatewayForeignDeny take the writer as a
// parameter and never reach for the global; these tests pass the
// OS-level writers explicitly to assert the write shape).
// Production install goes through runGatewayInstall's `s.out`, not
// through either of these direct-helper paths.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = orig
	})
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	return <-done
}

// The IAMT-315 production helpers (winkeys.reportForeignDeny and
// cmd/iamtunnel.reportGatewayForeignDeny) take the writer as a
// parameter and never reach for os.Stderr directly — there is no
// package-level reporter variable, so there is no exported mutable
// writer a future maintainer could flip to silence the report. The
// standalone helper tests drive
// hardenGatewayFileACL (or winkeys.LockDownFileACL) directly and
// pass os.Stderr as the report writer so captureStderr (the
// os.Stderr swap) catches what was written. Production install goes
// through runGatewayInstall's s.out, not these direct-helper paths.

// TestIAMT315_RefusesExplicitDenyOnFile — on a fresh file carrying an
// explicit ACCESS_DENIED ACE for BUILTIN\Guests (S-1-5-32-546),
// hardenGatewayFileACL must refuse, return
// *winkeys.ForeignDenyRefusalError and NOT touch the file's DACL.
//
// Canary: remove CheckForeignExplicitDeny from applyGatewayProtectedACL
// (or from applyProtectedDACL) — the function will quietly rewrite the
// DACL, and the "DACL still contains an explicit DENY for
// BUILTIN\Guests" assertion turns red with the "hardening silently
// dropped an explicit DENY ACE" diagnostic. After the fix — a refusal,
// the DACL untouched.
func TestIAMT315_RefusesExplicitDenyOnFile(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("IAMT-315 ACL check is Windows-only (GetNamedSecurityInfo/DACL semantics); here %s", runtime.GOOS)
	}
	requireWritableLockedFiles(t)

	path := filepath.Join(t.TempDir(), "hostkey-like")
	if err := os.WriteFile(path, []byte("seed bytes for IAMT-315"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	const guestsSID = "S-1-5-32-546"
	const denyMask = 0x1F01FF // FILE_ALL_ACCESS — same as full control
	if err := hardenGatewayFileACL(path, false, nil); err != nil {
		t.Fatalf("hardenGatewayFileACL(seed): %v", err)
	}
	attachExplicitDenyACE(t, path, guestsSID, denyMask)
	relaxACLOnCleanup(t, path)

	err := hardenGatewayFileACL(path, false, nil)
	if err == nil {
		t.Fatalf("IAMT-315: hardenGatewayFileACL on a file with an explicit ACCESS_DENIED for BUILTIN\\Guests must refuse (got nil err) — the hardening silently dropped an explicit DENY ACE")
	}
	var fdr *winkeys.ForeignDenyRefusalError
	if !errors.As(err, &fdr) {
		t.Fatalf("IAMT-315: refusal must be *winkeys.ForeignDenyRefusalError so the CLI can route it through deniedErrf; got %T: %v", err, err)
	}
	if fdr.Path != path {
		t.Errorf("IAMT-315: refusal.Path = %q, want %q", fdr.Path, path)
	}
	if len(fdr.Denies) != 1 {
		t.Fatalf("IAMT-315: refusal.Denies has %d entries, want 1 (one explicit DENY for Guests)", len(fdr.Denies))
	}
	if fdr.Denies[0].SID != guestsSID {
		t.Errorf("IAMT-315: refusal.Denies[0].SID = %q, want %q", fdr.Denies[0].SID, guestsSID)
	}
	if fdr.Denies[0].Mask != denyMask {
		t.Errorf("IAMT-315: refusal.Denies[0].Mask = %#x, want %#x", fdr.Denies[0].Mask, denyMask)
	}
	// The error message names the principal (resolved or as SID) and
	// the access mask; the test asserts both pieces are present so the
	// operator gets a useful refusal without opening the file's
	// properties dialog.
	msg := err.Error()
	if !strings.Contains(msg, guestsSID) && !strings.Contains(msg, "Guests") {
		t.Errorf("IAMT-315: refusal message must name the principal (SID or friendly); got %q", msg)
	}
	if !strings.Contains(msg, "0x1f01ff") && !strings.Contains(msg, "FILE_ALL_ACCESS") {
		t.Errorf("IAMT-315: refusal message must show the access mask; got %q", msg)
	}
	if !strings.Contains(msg, "--replace-acl") {
		t.Errorf("IAMT-315: refusal message must hint at the --replace-acl opt-in; got %q", msg)
	}

	// The DACL must be UNCHANGED after the refusal: the explicit DENY
	// for Guests is still there. If this assertion goes red, the
	// function silently dropped the foreign ACE.
	if !hasExplicitDenyFor(t, path, guestsSID) {
		t.Errorf("IAMT-315: hardening silently dropped an explicit DENY ACE — DACL of %s no longer carries the explicit ACCESS_DENIED for BUILTIN\\Guests", path)
	}
}

// TestIAMT315_ReplaceACLProceedsAndListsRemoved — the same scenario,
// but with replaceACL=true: hardening must proceed, printing the
// operator the list of removed ACEs (one line per ACE, name/SID +
// mask). After the call the file sits under the protected DACL (three
// trustees for the gateway), and the explicit DENY on it is gone.
//
// Canary: treat replaceACL=true as "refuse anyway" (or drop the
// report printout) — the "err == nil and the file under the protected
// DACL" assertion turns red, or the "report contains the line about
// BUILTIN\Guests" one does.
func TestIAMT315_ReplaceACLProceedsAndListsRemoved(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("IAMT-315 ACL check is Windows-only; here %s", runtime.GOOS)
	}
	requireWritableLockedFiles(t)

	path := filepath.Join(t.TempDir(), "hostkey-like")
	if err := os.WriteFile(path, []byte("seed bytes for IAMT-315"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	const guestsSID = "S-1-5-32-546"
	const denyMask = 0x1F01FF
	if err := hardenGatewayFileACL(path, false, nil); err != nil {
		t.Fatalf("hardenGatewayFileACL(seed): %v", err)
	}
	attachExplicitDenyACE(t, path, guestsSID, denyMask)
	relaxACLOnCleanup(t, path)

	// Direct-helper test: the production install path threads s.out
	// down (NOT os.Stderr — see reportGatewayForeignDeny), but this
	// test calls hardenGatewayFileACL with the standalone helper,
	// so it passes os.Stderr itself and uses captureStderr to read
	// it. The shape of the message is unchanged; only the writer
	// is supplied explicitly.
	var runErr error
	captured := captureStderr(t, func() {
		runErr = hardenGatewayFileACL(path, true, os.Stderr)
	})
	if runErr != nil {
		t.Fatalf("IAMT-315: hardenGatewayFileACL(replaceACL=true) on a file with an explicit DENY for Guests must proceed (got refusal: %v)", runErr)
	}

	// File's DACL is the protected three-trustee DACL (SYSTEM,
	// Administrators, NT SERVICE\iamtunnel-gateway). The DENY is gone.
	if hasExplicitDenyFor(t, path, guestsSID) {
		t.Errorf("IAMT-315: --replace-acl proceeded but the explicit DENY for BUILTIN\\Guests is still on %s", path)
	}
	assertGatewayDirDACL(t, "file under --replace-acl", path, false)

	// The report names the dropped ACE — either with the friendly
	// name or the SID string. LookupAccountSid for S-1-5-32-546 returns
	// "BUILTIN\Guests" on every Windows machine; the test allows
	// either form so a misconfigured account database does not flake
	// the suite. The mask appears as the documented FILE_ALL_ACCESS
	// name or as hex. The report goes to os.Stderr (production has
	// exactly one path: there is no package-level reporter variable
	// to redirect it through).
	if !strings.Contains(captured, guestsSID) && !strings.Contains(captured, "Guests") {
		t.Errorf("IAMT-315: --replace-acl report must name the principal (SID or friendly); got %q", captured)
	}
	if !strings.Contains(captured, "0x1f01ff") && !strings.Contains(captured, "FILE_ALL_ACCESS") {
		t.Errorf("IAMT-315: --replace-acl report must show the mask; got %q", captured)
	}
}

// TestIAMT315_InheritedDenyDoesNotTriggerRefusal — a DENY a file
// received through inheritance from its parent is not an operator's
// decision about THIS object. We place an explicit DENY on the parent
// directory with (OI)(CI) and create a file; the child file receives
// the DENY carrying the INHERITED_ACE flag. hardenFile must proceed
// (CheckForeignExplicitDeny finds zero — inherited ACEs are skipped).
//
// Canary: drop the aceFlags&aceInheritedFlag check (i.e. count an
// inherited DENY as foreign) — the "hardenGatewayFileACL returned
// nil" assertion turns red (hardening would have refused), or
// "assertGatewayDirDACL did not find the three trustees" does (an
// inherited DENY would have stayed on the file after the refusal).
func TestIAMT315_InheritedDenyDoesNotTriggerRefusal(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("IAMT-315 ACL check is Windows-only; here %s", runtime.GOOS)
	}
	requireWritableLockedFiles(t)

	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatalf("MkdirAll(%s): %v", parent, err)
	}
	relaxACLOnCleanup(t, parent)

	const guestsSID = "S-1-5-32-546"
	const denyMask = 0x1F01FF
	const oici = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	sid, err := windows.StringToSid(guestsSID)
	if err != nil {
		t.Fatalf("StringToSid: %v", err)
	}
	sd, err := windows.BuildSecurityDescriptor(
		nil, nil,
		[]windows.EXPLICIT_ACCESS{{
			AccessPermissions: windows.ACCESS_MASK(denyMask),
			AccessMode:        windows.DENY_ACCESS,
			Inheritance:       oici,
			Trustee: windows.TRUSTEE{
				MultipleTrustee:          nil,
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_USER,
				TrusteeValue:             windows.TrusteeValueFromSID(sid),
			},
		}},
		nil, nil,
	)
	if err != nil {
		t.Fatalf("BuildSecurityDescriptor(parent DENY): %v", err)
	}
	sdBytes := readSDBytes(t, sd)
	daclOff := readU32(sdBytes, 16)
	if daclOff == 0 {
		t.Fatalf("BuildSecurityDescriptor(parent) returned no DACL")
	}
	parentDACL := (*windows.ACL)(unsafeAdd(unsafe.Pointer(sd), uintptr(daclOff)))
	if err := windows.SetNamedSecurityInfo(
		parent,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil,
		parentDACL,
		nil,
	); err != nil {
		t.Fatalf("SetNamedSecurityInfo(parent DENY): %v", err)
	}

	child := filepath.Join(parent, "child-file")
	if err := os.WriteFile(child, []byte("seed"), 0o600); err != nil {
		t.Fatalf("write child: %v", err)
	}
	relaxACLOnCleanup(t, child)

	// Precondition: child inherited the DENY for Guests with
	// INHERITED_ACE set.
	if !hasInheritedDenyFor(t, child, guestsSID) {
		t.Fatalf("IAMT-315 precondition: child %s must inherit a DENY for BUILTIN\\Guests (INHERITED_ACE set) — parent setup failed", child)
	}

	if err := hardenGatewayFileACL(child, false, nil); err != nil {
		t.Fatalf("IAMT-315: hardenGatewayFileACL on a child file with an INHERITED DENY must NOT refuse (inherited ACEs are not the operator's local decision); got %v", err)
	}
	// File is under the protected three-trustee DACL; the inherited
	// DENY is no longer present (SE_DACL_PROTECTED + the rewrite).
	assertGatewayDirDACL(t, "child after hardening", child, false)
}

// TestIAMT315_OrdinaryPathProducesSameDACL — on a fresh file without
// foreign ACEs hardening yields exactly the DACL IAMT-257 pinned for
// the three trustees (an idempotence + regression canary): protected,
// exactly three ACEs, nothing inherited.
//
// Canary: flip CheckForeignExplicitDeny so that it refuses on an
// empty DACL — "err != nil" turns red here.
func TestIAMT315_OrdinaryPathProducesSameDACL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("IAMT-315 ACL check is Windows-only; here %s", runtime.GOOS)
	}
	requireWritableLockedFiles(t)

	path := filepath.Join(t.TempDir(), "fresh")
	if err := os.WriteFile(path, []byte("seed"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	relaxACLOnCleanup(t, path)

	if err := hardenGatewayFileACL(path, false, nil); err != nil {
		t.Fatalf("IAMT-315 ordinary path: hardenGatewayFileACL: %v", err)
	}
	assertGatewayDirDACL(t, "IAMT-315 ordinary path", path, false)
}

// TestIAMT315_InstallCLIThreadsReplaceACLThrough — the install CLI
// really threads --replace-acl through setupGatewayService into the
// hardenDir seam. Without that the operator cannot reinstall after
// placing a DENY on the directory.
//
// Canary: drop the fs.has("replace-acl") hand-off from
// cmdGatewayInstallOrRun, or forget to thread replaceACL into
// setupGatewayService — the rec.replaceACLSeen comparison with
// {true} turns red.
func TestIAMT315_InstallCLIThreadsReplaceACLThrough(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("IAMT-315 install CLI test is Windows-only; here %s", runtime.GOOS)
	}
	rec := withFakeGatewayService(t)
	_, errs, code := drive(t,
		"gateway", "install",
		"--public-host", "gw.example.test",
		"--replace-acl",
		"--data-dir", t.TempDir(),
	)
	if code != exitOK {
		t.Fatalf("gateway install --replace-acl: code=%d errs=%q, want exitOK", code, errs)
	}
	// IAMT-315 round 3 (rebase onto integr_1_1, c430629) put
	// hardenExeDir ahead of hardenDir in setupGatewayService; the seam
	// now records replaceACL once per call, so a single install
	// produces two entries. Both must be true under --replace-acl:
	// the binary's DACL is dropped before the data dir's (IAMT-312
	// hardening first, IAMT-257/IAMT-315 second). Anything else is a
	// contract break.
	if len(rec.replaceACLSeen) != 2 || !rec.replaceACLSeen[0] || !rec.replaceACLSeen[1] {
		t.Fatalf("IAMT-315: --replace-acl must reach the seam's hardenExeDir (entry 0) and hardenDir (entry 1) as replaceACL=true; rec.replaceACLSeen=%v", rec.replaceACLSeen)
	}
	rec2 := withFakeGatewayService(t)
	_, errs2, code2 := drive(t,
		"gateway", "install",
		"--public-host", "gw.example.test",
		"--data-dir", t.TempDir(),
	)
	if code2 != exitOK {
		t.Fatalf("gateway install (no --replace-acl): code=%d errs=%q, want exitOK", code2, errs2)
	}
	if len(rec2.replaceACLSeen) != 2 || rec2.replaceACLSeen[0] || rec2.replaceACLSeen[1] {
		t.Fatalf("IAMT-315: omit --replace-acl → seam must see replaceACL=false on BOTH entries; rec.replaceACLSeen=%v", rec2.replaceACLSeen)
	}
}

// TestIAMT315_InstallRefusesAndReturnsExit4 — full install path with
// a foreign DENY on the directory: install refuses, the message names
// the principal and the mask, and the process exits with exitDenied (4)
// — the same code the non-admin refusal already uses. Without the
// --replace-acl flag the install sequence does NOT proceed past the
// ACL step: the recorder sees only the two hardening calls (hardenExe
// first, harden second — IAMT-315 round 3 reordered them, since
// IAMT-312 hardening of the binary is part of the IAMT-315 contract
// too) and nothing after — no createService, no startService, no
// "service was installed under ...".
//
// Canary: return nil from hardenGatewayDirACL on a foreign DENY
// (i.e. forget IAMT-315 in the production seam) — the rec.order
// comparison with []string{"harden"} and/or the exit code turn red
// (it becomes 0, not 4).
func TestIAMT315_InstallRefusesAndReturnsExit4(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("IAMT-315 install CLI test is Windows-only; here %s", runtime.GOOS)
	}
	rec := withFakeGatewayService(t)
	dir := t.TempDir()
	rec.hardenResult = &winkeys.ForeignDenyRefusalError{
		Path: dir,
		Denies: []winkeys.ForeignDenyACE{{
			SID:  "S-1-5-32-546",
			Name: `BUILTIN\Guests`,
			Mask: 0x1F01FF,
		}},
	}
	_, errs, code := drive(t,
		"gateway", "install",
		"--public-host", "gw.example.test",
		"--data-dir", dir,
	)
	if code != exitDenied {
		t.Fatalf("IAMT-315: install must exit %d on a foreign explicit DENY; got code=%d errs=%q", exitDenied, code, errs)
	}
	if !strings.Contains(errs, "refusing to overwrite") {
		t.Errorf("IAMT-315: refusal must use the standard message; got %q", errs)
	}
	if !strings.Contains(errs, "BUILTIN\\Guests") && !strings.Contains(errs, "S-1-5-32-546") {
		t.Errorf("IAMT-315: refusal must name the principal; got %q", errs)
	}
	if !strings.Contains(errs, "--replace-acl") {
		t.Errorf("IAMT-315: refusal must hint at --replace-acl; got %q", errs)
	}
	if !reflect.DeepEqual(rec.order, []string{"hardenExe", "harden"}) {
		t.Errorf("IAMT-315: after refusal the sequence must stop at hardenExe + harden; got %v", rec.order)
	}
}

// TestIAMT315_InstallPreflightRefusesBeforeSecretCreation — the
// IAMT-315 preflight in runGatewayInstall must refuse BEFORE the data
// dir is created (MkdirAll), BEFORE the host key is generated, BEFORE
// the bootstrap token is written, and BEFORE the bootstrap reference
// is printed. The lesson of IAMT-308 round 7 (live Mac install
// already printed the bootstrap reference before its reachability
// refusal fired, leaving a working, printable secret behind for an
// install that had already failed) applies here too: refusal after
// secret creation is no refusal.
//
// Canary: drop the preflightGatewayACL call from runGatewayInstall
// (i.e. move the IAMT-315 check back into hardenExeDir/hardenDir
// inside setupGatewayService, as it was before the merge with the
// integration branch) — the "no hostkey" assertion turns red: the
// hostkey file sits under the already-created data directory, and
// MkdirAll and loadOrGenerateSigner had time to run before
// setupGatewayService.
//
// Canary: keep the preflight but ignore replaceACL — on a foreign
// DENY without --replace-acl install must still run the preflight and
// refuse before setupGatewayService starts with --replace-acl=true;
// see TestIAMT315_InstallRefusesAndReturnsExit4.
func TestIAMT315_InstallPreflightRefusesBeforeSecretCreation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("IAMT-315 install CLI test is Windows-only; here %s", runtime.GOOS)
	}
	requireWritableLockedFiles(t)
	rec := withFakeGatewayService(t)

	// Pre-create the data dir with the protected three-trustee DACL
	// (so the dir exists and is "well-formed" except for the foreign
	// DENY we attach on top). On a real machine this is the state
	// after a previous install: the canonical DACL is in place, but
	// the operator has since added an explicit DENY for some other
	// principal.
	dir := t.TempDir()
	if err := hardenGatewayDirACL(dir, false, nil); err != nil {
		t.Fatalf("seed: hardenGatewayDirACL: %v", err)
	}
	appendExplicitDenyACE(t, dir, "S-1-5-32-546", 0x1F01FF)
	relaxACLOnCleanup(t, dir)

	out, errs, code := drive(t,
		"gateway", "install",
		"--public-host", "gw.example.test",
		"--data-dir", dir,
	)
	if code != exitDenied {
		t.Fatalf("IAMT-315: install with foreign DENY must exit %d (preflight before any secret creation); got code=%d errs=%q out=%q", exitDenied, code, errs, out)
	}
	if !strings.Contains(errs, "refusing to overwrite") {
		t.Errorf("IAMT-315: refusal must name what it found; got %q", errs)
	}

	// No secret was created: no host key, no bootstrap token, no
	// state.json. The directory itself still exists (it was ours to
	// start with), but no install-time artifact landed inside it.
	if _, err := os.Stat(filepath.Join(dir, "hostkey")); err == nil {
		t.Errorf("IAMT-315: preflight must refuse BEFORE loadOrGenerateSigner — hostkey was created under %s despite the refusal", dir)
	} else if !os.IsNotExist(err) {
		t.Errorf("IAMT-315: hostkey stat: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "bootstrap-token")); err == nil {
		t.Errorf("IAMT-315: preflight must refuse BEFORE ensureBootstrapToken — bootstrap-token was written under %s despite the refusal", dir)
	} else if !os.IsNotExist(err) {
		t.Errorf("IAMT-315: bootstrap-token stat: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err == nil {
		t.Errorf("IAMT-315: preflight must refuse BEFORE writeBootstrapPending — state.json was written under %s despite the refusal", dir)
	} else if !os.IsNotExist(err) {
		t.Errorf("IAMT-315: state.json stat: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "enrol-hmac.key")); err == nil {
		t.Errorf("IAMT-315: preflight must refuse BEFORE state.Open — enrol-hmac.key was created under %s despite the refusal", dir)
	} else if !os.IsNotExist(err) {
		t.Errorf("IAMT-315: enrol-hmac.key stat: %v", err)
	}

	// No reference printed: the bootstrap-reference line is the only
	// stdout content that names the secret material. It must NOT
	// appear — that was the live-bug pattern IAMT-308 round 7 fixed.
	if strings.Contains(out, "bootstrap reference") {
		t.Errorf("IAMT-315: preflight must refuse BEFORE the bootstrap reference is printed; out=%q", out)
	}
	if strings.Contains(out, "directory") && strings.Contains(out, "host key ready") {
		t.Errorf("IAMT-315: preflight must refuse BEFORE the 'directory X and host key ready' line; out=%q", out)
	}

	// No service half reached. setupGatewayService is the only seam
	// that touches the SCM; a refusal in preflight means its recorder
	// never sees a single call.
	if len(rec.order) != 0 {
		t.Errorf("IAMT-315: preflight must refuse BEFORE setupGatewayService is called; the seam saw %v", rec.order)
	}
}

// TestIAMT315_InstallPreflightReplaceACLProceedsAndCreates — the same
// setup as TestIAMT315_InstallPreflightRefusesBeforeSecretCreation,
// but with --replace-acl. Preflight sees the foreign DENY, prints the
// list, proceeds; the install runs to completion and the host key,
// bootstrap token and state.json all exist. The point of this test is
// that replaceACL's "report and proceed" still runs to completion —
// the user paid for it by name.
//
// Stream choice for the dropped-ACE line: it is a success-side
// audit ("here is what I cleaned up to make install succeed"), so
// runGatewayInstall threads s.out (stdout) into the report writer
// — the same stream the rest of the install narrative ("directory
// X and host key ready", "bootstrap reference", "service X installed
// under …") already uses. errs is empty of the dropped-ACE line.
// That choice is the assertion target here: the line must appear on
// out, NOT on errs, so the in-process CLI driver that every other
// test in this package uses (drive()) can both capture it and confirm
// the production writer plumbing does not reach for os.Stderr (the
// round-6 regression canary).
//
// Canary: under --replace-acl install refuses in the preflight (i.e.
// replaceACL was not threaded through) — the "no hostkey" assertion
// turns red (no hostkey because install failed, not because there
// never was one).
// A second canary lives in the stream choice itself: revert to
// os.Stderr (or move the printout to errs) — the "out must contain
// the dropped-ACE line" assertion below goes red.
func TestIAMT315_InstallPreflightReplaceACLProceedsAndCreates(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("IAMT-315 install CLI test is Windows-only; here %s", runtime.GOOS)
	}
	requireWritableLockedFiles(t)
	withFakeGatewayService(t)

	dir := t.TempDir()
	if err := hardenGatewayDirACL(dir, false, nil); err != nil {
		t.Fatalf("seed: hardenGatewayDirACL: %v", err)
	}
	appendExplicitDenyACE(t, dir, "S-1-5-32-546", 0x1F01FF)
	relaxACLOnCleanup(t, dir)

	out, errs, code := drive(t,
		"gateway", "install",
		"--public-host", "gw.example.test",
		"--replace-acl",
		"--data-dir", dir,
	)
	if code != exitOK {
		t.Fatalf("IAMT-315: --replace-acl must proceed and complete install; got code=%d errs=%q out=%q", code, errs, out)
	}
	// The dropped-ACE line goes to stdout (same stream as the rest
	// of the install narrative; see the type's docstring for the
	// stream-choice rationale). The line names the principal, either
	// as the resolved friendly name BUILTIN\Guests or as the raw
	// SID S-1-5-32-546 (LookupAccountSid for S-1-5-32-546 returns
	// "BUILTIN\Guests" on every Windows machine; the test allows
	// either form so a misconfigured account database does not flake
	// the suite). The "must NOT appear on errs" side of the
	// assertion is the round-6 canary — errs is the CLI's error
	// stream (intended for refusals and environment errors), and
	// capturing the dropped-ACE report there would mean the writer
	// is back on os.Stderr (or somewhere reachable by other tests'
	// captureStderr swap), bypassing the CLI's own plumbing.
	if !strings.Contains(out, "BUILTIN\\Guests") && !strings.Contains(out, "S-1-5-32-546") {
		t.Errorf("IAMT-315: --replace-acl must report what was dropped on stdout (same stream as the install narrative); got out=%q errs=%q", out, errs)
	}
	if strings.Contains(errs, "BUILTIN\\Guests") || strings.Contains(errs, "S-1-5-32-546") {
		t.Errorf("IAMT-315: dropped-ACE line must NOT appear on errs (the CLI's error stream); the in-process CLI driver should capture it via s.out, not os.Stderr; got out=%q errs=%q", out, errs)
	}
	// ReplaceACL took over: host key, bootstrap token, state.json all
	// exist. The reference line was printed.
	if _, err := os.Stat(filepath.Join(dir, "hostkey")); err != nil {
		t.Errorf("IAMT-315: --replace-acl must create hostkey; stat: %v", err)
	}
	if !strings.Contains(out, "bootstrap reference") {
		t.Errorf("IAMT-315: --replace-acl install must print the bootstrap reference; out=%q", out)
	}
}

// ---- byte-level helpers local to iamt315 (kept here so this file
// compiles without depending on iamt213's package-private copies).

func readSDBytes(t *testing.T, sd *windows.SECURITY_DESCRIPTOR) []byte {
	t.Helper()
	const sdHeader = 20
	buf := make([]byte, sdHeader)
	src := unsafe.Slice((*byte)(unsafe.Pointer(sd)), sdHeader)
	copy(buf, src)
	return buf
}

func readU16(ptr unsafe.Pointer, off int) uint16 {
	b := unsafe.Add(ptr, off)
	return uint16(*(*uint8)(b)) | uint16(*(*uint8)(unsafe.Add(b, 1)))<<8
}

func readU32(buf []byte, off int) uint32 {
	return uint32(buf[off]) | uint32(buf[off+1])<<8 | uint32(buf[off+2])<<16 | uint32(buf[off+3])<<24
}

func unsafeAdd(ptr unsafe.Pointer, off uintptr) unsafe.Pointer {
	return unsafe.Add(ptr, off)
}
