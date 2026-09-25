package winkeys

// goleak_test.go: IAMT-314. See internal/sshx/goleak_test.go for why the
// check is wired per package rather than once over ./....
//
// winkeys starts no goroutine in-process: the file sink is a locked
// read-modify-write over the key file, and the doorwatch is a separate
// process (doorwatch_unix.go spawns "server doorwatch"), so the tests
// that exercise it drive real child processes and helper binaries, not
// goroutines. What is left in-process is the watcher plumbing the child
// itself runs, and that plumbing is what the one ignore below is about.
//
// THE ONE IGNORE, and why it is allowed to outlive the tests
//
// On Linux, when pidfd_open is unavailable (kernels before 5.3, or a
// seccomp profile that refuses it), newParentWatcher falls back to
// getppidWatcher, which arms PR_SET_PDEATHSIG and routes the resulting
// SIGTERM through signal.Notify (doorwatch_linux.go). The first
// signal.Notify anywhere in a process makes the Go runtime start its
// signal dispatch goroutine, and that goroutine is permanent by
// construction: signal.Stop unregisters the channel but never stops the
// dispatcher, and there is no API that does. It belongs to the Go
// runtime, not to this product; it holds nothing of ours, and no
// product goroutine is hidden behind it, because it is matched by the
// top frame alone.
//
// This is the only ignore in this package and it names exactly those two
// runtime entry points. It deliberately does NOT cover doorwatch, the
// file sink, or anything else of ours: those are product goroutines that
// are required to finish, and ignoring one would make this file
// decorative. If a run reports a leak whose top frame is anything other
// than the two below, it is real - report it, do not widen this list.
//
// LEAK CANARY (make the edit, run, revert): in doors_test.go, inside the
// two-writer test that ends with the pair of "<-done" receives, add one
// line just before the two "go func()" launches
//
//	go func() { select {} }() // IAMT-314 canary
//
// and this package goes red naming that closure in doors_test.go. A
// package whose only background work runs in child processes has nothing
// more realistic to offer, which is itself the point: there is nothing
// here today that can leak a goroutine, and this file is what keeps it
// that way.

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// The Go runtime's signal dispatcher, started by the
		// signal.Notify in doorwatch_linux.go's PDEATHSIG fallback and
		// unstoppable by design. Both frames are listed because which
		// one is on top depends on where the dispatcher happens to be
		// parked when the snapshot is taken.
		goleak.IgnoreTopFunction("os/signal.loop"),
		goleak.IgnoreTopFunction("os/signal.signal_recv"),
	)
}
