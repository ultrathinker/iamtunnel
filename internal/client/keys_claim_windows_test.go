//go:build windows

package client

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

// protectClaimedKey is the Windows half of the winner's shape in
// TestM9cLoserWaitsForAKeyStillBeingWritten: it gives the claimed file
// the access list createKeyIfAbsent gives it — protected, naming this
// account — through icacls, which is the tool checkKeyFilePerms' refusal
// names. Test-only on purpose: the test must run against the tree the
// defect lived in, so it may not call the product's own helper (that
// name does not exist there).
func protectClaimedKey(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("read this account's SID: %v", err)
	}
	out, err := exec.Command("icacls", path, "/inheritance:r", "/grant:r", "*"+user.User.Sid.String()+":F").CombinedOutput()
	if err != nil {
		t.Fatalf("protect the claimed key file: %v (%s)", err, out)
	}
}
