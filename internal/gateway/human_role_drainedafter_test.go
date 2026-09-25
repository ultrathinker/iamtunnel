package gateway

// human_role_drainedafter_test.go is a deterministic, non-network canary
// for drainedAfter (human_role.go, added while building the exec
// client): a wrapped Stream must not report the underlying stream's own
// io.EOF to core.Bridge until a separate "drained" signal has also fired.
//
// Why this exists: internal/client's own end-to-end exec test
// (execrun_test.go, TestExecRunsOverExecOnlyGrantWithoutTouchingInteractiveSetup)
// failed intermittently — about one run in three — with a nil ExitStatus
// on an otherwise clean command. The root cause: core.Bridge calls
// human.CloseWrite() the instant its own target -> human copy sees EOF,
// which (SSH's channel EOF being directional but not per stream type)
// flips golang.org/x/crypto/ssh's shared sentEOF flag for BOTH the
// channel's regular data and its extended data (stderr) — racing this
// file's own separate stderr-forwarder goroutine, whose next
// WriteExtended then silently gets io.EOF and force-closes the session.
// See drainedAfter's own doc comment in human_role.go for the full
// account.
//
// Canary: TestDrainedAfterHoldsEOFUntilDrained. Broken on purpose during
// development by commenting out the "<-d.drained" wait inside
// drainedAfter.Read (restoring exactly the pre-fix behavior — EOF passed
// straight through): the test went red on its own "Read returned before
// drained closed" assertion within the first 50ms select, not on setup.
// Reverted from this file's own saved copy of human_role.go, not `git
// checkout`.

import (
	"io"
	"testing"
	"time"
)

// fakeEOFStream is the minimal core.Stream a drainedAfter test needs: a
// Read that returns io.EOF immediately, and Write/Close/CloseWrite that do
// nothing, exercising exactly the one behavior drainedAfter changes.
type fakeEOFStream struct{}

func (fakeEOFStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (fakeEOFStream) Write(p []byte) (int, error) { return len(p), nil }
func (fakeEOFStream) Close() error                { return nil }
func (fakeEOFStream) CloseWrite() error           { return nil }

func TestDrainedAfterHoldsEOFUntilDrained(t *testing.T) {
	drained := make(chan struct{})
	d := drainedAfter{Stream: fakeEOFStream{}, drained: drained}

	readReturned := make(chan error, 1)
	go func() {
		_, err := d.Read(make([]byte, 1))
		readReturned <- err
	}()

	// The underlying stream is already at EOF the instant Read is called;
	// if drainedAfter reported that straight through, readReturned would
	// already be closed well before this deadline. It must not be: the
	// wrapper's whole point is holding EOF back until drained fires.
	select {
	case err := <-readReturned:
		t.Fatalf("Read returned before drained closed (err=%v) — EOF was not held back, the wrapper is not doing its job", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(drained)

	select {
	case err := <-readReturned:
		if err != io.EOF {
			t.Fatalf("Read err = %v after drained closed, want io.EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read never returned after drained closed — drainedAfter hung instead of forwarding the EOF")
	}
}

// TestDrainedAfterPassesThroughNonEOFReadsImmediately guards the other
// half of the contract: only the terminal, EOF-signaling Read may be
// delayed. An ordinary data Read (or any non-EOF error) must return at
// once, so this wrapper adds no latency to a session's actual output.
func TestDrainedAfterPassesThroughNonEOFReadsImmediately(t *testing.T) {
	d := drainedAfter{Stream: constReadStream{data: []byte("hello")}, drained: make(chan struct{})} // never closed
	buf := make([]byte, 5)
	n, err := d.Read(buf)
	if err != nil {
		t.Fatalf("Read err = %v, want nil for an ordinary data read", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("Read = %q, want %q", buf[:n], "hello")
	}
}

type constReadStream struct{ data []byte }

func (c constReadStream) Read(p []byte) (int, error) { return copy(p, c.data), nil }
func (constReadStream) Write(p []byte) (int, error)  { return len(p), nil }
func (constReadStream) Close() error                 { return nil }
func (constReadStream) CloseWrite() error            { return nil }
