//go:build windows

package main

// iamt258_windows_harden_children_test.go — the code-review round
// (blocker 2): the production hardenDir in the Windows half of install
// no longer only puts a protected DACL on the directory itself — it
// walks the existing files inside (hostkey/state.json/bootstrap-token/
// enrol-hmac.key/state.lock, everything runGatewayInstall managed to
// create BEFORE the service half) and applies a protected DACL with
// three trustees to them (SYSTEM, Administrators,
// NT SERVICE\iamtunnel-gateway).
//
// Without this walk the service under NT SERVICE\iamtunnel-gateway
// would have no ACE on hostkey/state.json and would crash-loop on the
// first read (a review finding, confirmed by the maintainer).

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// daclProtectedForTest is the winkeys DACLProtected re-export: iamt213
// uses the same helper. The package-internal wrapper exists so this
// file stays readable on its own.
func daclProtectedForTest(path string) (bool, error) {
	return winkeys.DACLProtected(path)
}

// openForWrite opens path with mode, creating it if absent.
func openForWrite(path string, mode uint32) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fs.FileMode(mode))
	if err != nil {
		return nil, err
	}
	return f, nil
}

// mkdirAll creates dir if absent (mode is advisory; Windows uses
// inherited ACL — the prod hardenDir DACL applies AFTER the create).
func mkdirAll(path string, mode uint32) error {
	return os.MkdirAll(path, fs.FileMode(mode))
}

// readServiceSIDACEforTest walks the DACL of path and reports whether
// it contains an ACCESS_ALLOWED ACE for the per-service SID. The
// shape of an ACE on disk (sid string + flags + mask) is captured in
// aceInfo, defined next to readDACLFull in iamt213; we re-use both.
func readServiceSIDACEforTest(t *testing.T, path string) (aces []aceInfo, found bool) {
	t.Helper()
	all := readDACLFull(t, path)
	want := serviceAccountSIDStringForTest()
	for _, a := range all {
		if a.allow && strings.EqualFold(a.sid, want) {
			found = true
		}
	}
	return all, found
}

// detectAccessDenied flags the typical non-admin failure: windows
// returns ERROR_ACCESS_DENIED for SetNamedSecurityInfo when the
// process lacks WRITE_DAC on the target. The iamt213 helpers use
// requireWritableLockedFiles for this; we do the same check inline.
func detectAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	var errno windows.Errno
	if errors.As(err, &errno) {
		return errno == windows.ERROR_ACCESS_DENIED
	}
	return strings.Contains(strings.ToLower(err.Error()), "access is denied")
}

// _ = unsafe keeps the unsafe import live for tests that may grow to
// walk ACL bytes directly (iamt213's readDACLFull is the only caller;
// keeping the import here documents that this file is the gateway-
// half counterpart of the winkeys-side lockdown tests).
var _ = unsafe.Pointer(nil)

// realHardenDir runs the production hardenDir sequence — directory DACL
// + walk-and-heal-existing-files — without the production SCM panic
// guard. Used only by TestIAMT258_HardenDirHealsExistingFiles below:
// the recorder pattern that backs every other IAMT-258 test is fine for
// sequence assertions, but this one needs the real syscall behaviour
// to verify the (OI)(CI) ACE actually lands on the existing files.
//
// The implementation is a direct mirror of the prod seam: walkDir the
// data directory, file variant for regular files, directory variant
// for subdirectories. Same SE_DACL_PROTECTED wrapper, same three
// trustees, same file-all-access mask. replaceACL is false here — the
// test's directory has no foreign explicit DENY ACE, so the IAMT-315
// check has nothing to refuse on.
func realHardenDir(t *testing.T, dir string) error {
	t.Helper()
	// R2-CX F-12: the production walk is a function now
	// (hardenGatewayDataTree), so the test runs it rather than a copy
	// of it that would stay green whatever the product did.
	return hardenGatewayDataTree(dir, false, nil)
}

// TestIAMT258_HardenDirHealsExistingFiles — canary: after install,
// hostkey and state.json sit under a protected DACL with three
// trustees (SYSTEM, Administrators, NT SERVICE\iamtunnel-gateway); the
// old hardenDir (only applyGatewayProtectedACL on the directory
// itself) would have left the files with an inherited DACL, and the
// service would have seen EACCES.
//
// Canary: switch the production hardenDir back to the bare
// hardenGatewayDirACL(dir) without the walk — the test turns red with
// the concrete name of the file where a service SID was expected and
// is missing.
//
// Under an ordinary user hardenDir fails at SetNamedSecurityInfo
// (admin rights are required); under an admin (the Windows test runner
// per RUNBOOK) it goes through. The test skips on non-windows and
// under non-admin.
func TestIAMT258_HardenDirHealsExistingFiles(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("the code-review heal-children check runs on the maintainer's Windows runner; here %s", runtime.GOOS)
	}

	// Pre-create the secret files the install CLI writes BEFORE
	// setupGatewayService runs (gateway.go:283 — loadOrGenerateSigner,
	// gateway.go:421 — ensureBootstrapToken, gateway.go:321 —
	// writeBootstrapPending). Without the heal walk the prod
	// hardenDir would have left each of them under the parent's
	// inherited DACL — exactly the pre-failure mode.
	dir := t.TempDir()
	files := []string{"hostkey", "state.json", "bootstrap-token", "enrol-hmac.key"}
	for _, name := range files {
		if err := writeFileForTest(filepath.Join(dir, name), []byte("seed"), 0o600); err != nil {
			t.Fatalf("pre-create %s: %v", name, err)
		}
	}
	// Subdir + file inside: walk should hit them too (recordings
	// style subdirectory).
	subDir := filepath.Join(dir, "recordings")
	if err := mkdirForTest(subDir, 0o700); err != nil {
		t.Fatalf("pre-create recordings: %v", err)
	}
	if err := writeFileForTest(filepath.Join(subDir, "x.log"), []byte("seed"), 0o600); err != nil {
		t.Fatalf("pre-create recordings/x.log: %v", err)
	}

	if err := realHardenDir(t, dir); err != nil {
		// Non-admin (test runner without elevated console): SetNamedSecurityInfo
		// returns ERROR_ACCESS_DENIED. That is the norm in some
		// CI environments; skip with a self-explaining name.
		if detectAccessDenied(err) {
			t.Skipf("the code-review heal-children check needs an elevated console on the Windows runner: %v", err)
		}
		t.Fatalf("realHardenDir(%s): %v", dir, err)
	}
	// Grant the test process full control on the dir + children
	// before t.TempDir cleanup — iamt213's same pattern. The
	// product's locked DACL with NT SERVICE\iamtunnel-gateway
	// would otherwise prevent os.RemoveAll on the tempdir.
	relaxACLOnCleanup(t, dir)

	// Each pre-existing file must carry the protected DACL with
	// THREE trustees (SYSTEM, Administrators, and the per-service
	// SID). winkeys.DACLProtected reports the SE_DACL_PROTECTED
	// bit; readDACLFull (defined in iamt213) enumerates the ACEs.
	for _, name := range files {
		path := filepath.Join(dir, name)
		prot, err := daclProtectedForTest(path)
		if err != nil {
			t.Errorf("%s: DACLProtected: %v", name, err)
			continue
		}
		if !prot {
			t.Errorf("%s: DACL not protected after hardenDir — the heal-children walk did not go through (the old implementation left the files under an inherited DACL)", name)
			continue
		}
		aces, ok := readServiceSIDACEforTest(t, path)
		if !ok {
			t.Errorf("%s: protected DACL without an ACE for the service SID %s; trustees=%v — the service under NT SERVICE\\iamtunnel-gateway will not read the file on first start",
				name, serviceAccountSIDStringForTest(), aces)
		}
	}
	// File in subdirectory: also expected.
	path := filepath.Join(dir, "recordings", "x.log")
	prot, err := daclProtectedForTest(path)
	if err != nil {
		t.Errorf("recordings/x.log: DACLProtected: %v", err)
	} else if !prot {
		t.Errorf("recordings/x.log: DACL not protected after hardenDir (the walk must enter subdirectories)")
	} else if _, ok := readServiceSIDACEforTest(t, path); !ok {
		t.Errorf("recordings/x.log: protected DACL without an ACE for the service SID")
	}
	// Subdirectory: directory variant — (OI)(CI) inheritance on every ACE.
	path = filepath.Join(dir, "recordings")
	prot, err = daclProtectedForTest(path)
	if err != nil {
		t.Errorf("recordings/: DACLProtected: %v", err)
	} else if !prot {
		t.Errorf("recordings/: DACL not protected")
	} else if aces, ok := readServiceSIDACEforTest(t, path); !ok {
		t.Errorf("recordings/: protected DACL without an ACE for the service SID; trustees=%v", aces)
	} else {
		// every ACE on the directory must carry (OI)(CI).
		for _, a := range aces {
			if !a.allow {
				continue
			}
			if a.inheritFlags&testOICI != testOICI {
				t.Errorf("recordings/: ACE for %s without (OI)(CI), flags=%#x — the subdirectory would create children under an inherited DACL", a.sid, a.inheritFlags)
			}
		}
	}
	// Sanity: the file-variant ACE on a regular file must NOT carry
	// (OI)(CI) — inheritance on a file is meaningless and the
	// canonicalization rule winkeys documents (IAMT-213) would
	// produce a different on-disk shape if we passed (OI)(CI).
	if aces := readDACLFull(t, filepath.Join(dir, "hostkey")); len(aces) > 0 {
		for _, a := range aces {
			if !a.allow {
				continue
			}
			if a.inheritFlags&testOICI != 0 {
				t.Errorf("hostkey: the ACE for %s carries (OI)(CI) — the file variant must be without inheritance (got flags %#x)", a.sid, a.inheritFlags)
			}
		}
	}
}

// ---- local thin wrappers around iamt213 helpers so this file stays
// self-contained: every other test in the package shares the helpers
// defined there (readDACLFull, aceInfo, testOICI, testFileAllAccess,
// testGenericAll, daclProtectedForTest is just winkeys.DACLProtected).
// The ones below are package-internal thin aliases that exist purely so
// this file's tests read as standalone code.

func writeFileForTest(path string, data []byte, mode uint32) error {
	f, err := openForWrite(path, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func mkdirForTest(path string, mode uint32) error { return mkdirAll(path, mode) }

// serviceAccountSIDStringForTest returns the per-service SID as a
// canonical "S-1-5-80-…" string. Built by the same SHA-1 algorithm
// serviceAccountSID uses; the helper's caller-side shape (a string)
// is the only difference — production uses *windows.SID, tests want
// a string for EqualFold in readDACLFull's aceInfo.
func serviceAccountSIDStringForTest() string {
	sid, err := serviceAccountSID(gatewayServiceName)
	if err != nil {
		return ""
	}
	if sid == nil {
		return ""
	}
	return sid.String()
}
