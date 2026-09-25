package state_test

// goleak_test.go: IAMT-314. See internal/sshx/goleak_test.go for why the
// check is wired per package rather than once over ./....
//
// state starts no background goroutine of its own: the store is a file,
// a lock and a mutex, and every goroutine in these tests is a worker the
// test itself starts and joins through a sync.WaitGroup. That is
// precisely why it is worth wiring - the check costs nothing today and
// the first future sweeper, watcher or async fsync that forgets its stop
// path lands red on state, not on whichever package ran last.
//
// TestMain lives in the external test package (state_test), which is
// where the bulk of these tests are; the in-package files
// (filelock_*_export_test.go) share the same test binary and are covered
// by it.
//
// No ignores in this package.
//
// LEAK CANARY (make the edit, run, revert): in hardening_test.go, in the
// helper goroutine that closes the reader
//
//	go func() {
//		time.Sleep(40 * time.Millisecond)
//		_ = reader.Close()
//		close(closed)
//	}()
//
// change the sleep to time.Hour. The goroutine then outlives the suite
// and this package goes red on that test's own closure, with time.Sleep
// on top of the reported stack.

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
