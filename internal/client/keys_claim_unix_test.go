//go:build !windows

package client

import "testing"

// protectClaimedKey is the Unix half of the winner's shape in
// TestM9cLoserWaitsForAKeyStillBeingWritten: datafile.Create makes the
// key 0600 and there is nothing to add — the Unix check the loser runs is
// the mode check in keys_perms_unix.go, and 0600 is what it wants.
//
// The Windows half is a real access-list change (keys_claim_windows_test.go):
// there the file a plain create leaves behind is not protected at all,
// and the loser's check refuses it.
func protectClaimedKey(t *testing.T, _ string) {
	t.Helper()
}
