package acl

// goleak_test.go: IAMT-314. See internal/sshx/goleak_test.go for why the
// check is wired per package rather than once over ./....
//
// acl has exactly one place that starts a goroutine: runNotes (acl.go),
// which delivers each revocation notification in its own goroutine so
// that Revoke and SweepExpired never block on a subscriber. Those
// goroutines are expected to return as soon as the subscriber's callback
// does, and every callback in this package's tests returns. If one ever
// does not, the gateway's one-second sweep is quietly accumulating
// goroutines behind a slow session owner - which is a real bug and
// exactly what this check should say out loud.
//
// No ignores in this package.
//
// LEAK CANARY (make the edit, run, revert): in acl_test.go, in
// TestRevokeKillsActiveSession, replace the onRevoke passed to mustOpen
//
//	func(r DenyReason) { killed <- r }
//
// with one that never returns
//
//	func(r DenyReason) { killed <- r; select {} }
//
// The Revoke under test then leaves a delivery goroutine parked forever
// and this package goes red on
//
//	github.com/ultrathinker/iamtunnel/internal/gateway/acl.runNotes.func1
//
// - acl's own goroutine, named in the failure.

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
