//go:build windows

// iamt333_f19_exe_acl_windows_test.go — Finding 19 of the review report
// (IAMT-333): applyGatewayExeACL — the four-trustee lockdown of the
// binary's directory and of the binary itself — checked DENY entries and
// wrote the owner BY PATH with a DACL (CheckForeignExplicitDeny, then
// SetNamedSecurityInfo), whereas the data side, since R2-CX F-12, opens
// without following a reparse point and locks through a single handle
// (winkeys.LockObject). SetNamedSecurityInfo follows reparse points: a
// junction on the binary directory's path redirects the whole lockdown —
// the owner included — to whatever the junction names, and by then that
// name may mean something else. The contract is the data side's
// (LockObject): a path that is itself a link is refused; the lockdown is
// not written through it.

package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// TestIAMT333_F19_AnExeDirectoryThatIsALinkIsRefused — a binary
// directory that is itself a junction is refused, and its target stays
// exactly as it was found: no Administrators owner, no protected DACL
// through the link.
func TestIAMT333_F19_AnExeDirectoryThatIsALinkIsRefused(t *testing.T) {
	target := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "iamtunnel")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J could not make a junction here: %v: %s", err, out)
	}

	if err := hardenGatewayExeDirACL(link, false, nil); err == nil {
		t.Fatal("an exe directory that is a junction was locked through it")
	} else {
		var lp *winkeys.LinkedPathRefusalError
		if !errors.As(err, &lp) {
			t.Errorf("refused, but not as a linked path: %v", err)
		}
	}
	r2cxF12Untouched(t, "exe", target)
}

// TestIAMT333_F19_AnExeFileThatIsALinkIsRefused — the same for the
// binary itself (a file link is a symlink, which not every host may
// allow): hardenGatewayExeFileACL refuses on a link path and writes
// nothing on the other side of the link.
func TestIAMT333_F19_AnExeFileThatIsALinkIsRefused(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "iamtunnel.exe")
	if err := os.WriteFile(exe, []byte("not really an exe"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "iamtunnel.exe")
	if err := os.Symlink(exe, link); err != nil {
		t.Skipf("this host does not grant symlink creation, so a linked exe cannot be planted here (%v)", err)
	}

	if err := hardenGatewayExeFileACL(link, false, nil); err == nil {
		t.Fatal("an exe file that is a link was locked through it")
	} else {
		var lp *winkeys.LinkedPathRefusalError
		if !errors.As(err, &lp) {
			t.Errorf("refused, but not as a linked path: %v", err)
		}
	}
	r2cxF12Untouched(t, "exe file", exe)
}

// TestIAMT333_F19_ALinkedBinaryDirectoryRefusesInstallAsDenied — the
// refusal reaches the operator as an operator decision (code 4), not as
// an environment failure (code 3): the same class as the data directory
// refusal (R2-CX F-12). The hardenExeDir seam here is the real
// hardening function, wrapped as production; hardenDir is a stub — this
// test is not about the data directory.
func TestIAMT333_F19_ALinkedBinaryDirectoryRefusesInstallAsDenied(t *testing.T) {
	real := t.TempDir()
	if err := os.Mkdir(filepath.Join(real, "iamtunnel"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "iamtunnel")
	r2cxJunction(t, link, real)
	setup := windowsServiceSetup{
		hardenExeDir: func(dir, exePath string, replaceACL bool, report io.Writer) error {
			return hardenGatewayExeDirACL(dir, replaceACL, report)
		},
		hardenDir: func(string, bool, io.Writer) (func(), error) { return func() {}, nil },
	}
	_, err := hardenGatewayDirs(setup, gatewayServiceSpec{}, link, real, false, nil)
	var ce *cliError
	if !errors.As(err, &ce) || ce.code != exitDenied {
		t.Fatalf("install's answer to a linked binary directory = %v, want the denied class (exit %d)", err, exitDenied)
	}
}
