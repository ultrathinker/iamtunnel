package events_test

// goleak_test.go: IAMT-314. See internal/sshx/goleak_test.go for why the
// check is wired per package rather than once over ./....
//
// events starts no background goroutine of its own: Append is a locked
// write plus an fsync, and the concurrency tests here start their own
// workers and join them through a sync.WaitGroup. As with state, the
// value is forward-looking - the journal is an obvious place for a
// future async flusher or rotation timer, and this file makes the first
// one that forgets its stop path land red here.
//
// No ignores in this package.
//
// LEAK CANARY (make the edit, run, revert): in events_test.go, in the
// concurrent-append test, add one line before the workers are started
//
//	go func() { select {} }() // IAMT-314 canary
//
// and this package goes red naming that closure in events_test.go. A
// package with no background goroutines has nothing more realistic to
// offer as a canary, which is itself the finding: there is nothing here
// today that can leak, and this file is what keeps it that way.

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
