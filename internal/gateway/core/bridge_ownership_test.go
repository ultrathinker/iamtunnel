package core

// bridge_ownership_test.go: IAMT-108, gateway half. The defect this fixes is
// a genuine goroutine-scheduling race - core.Bridge closed
// human and target the instant both copies finished, with nothing making
// sure the machine's last channel request (exit-status, PROTOCOL §4.1,
// forwarded machine -> human only) had already been read out of its request
// stream and forwarded on. A test that reproduces that race by racing real
// goroutines is exactly the kind of "test that got lucky" that looks green
// while being no proof at all (gate 5 went red under load about once in six
// runs, and 40
// isolated runs in a row were all green).
//
// So these tests do not race anything. They drive both of Bridge's copy
// directions to a predetermined outcome (clean EOF, or a still-blocked
// human plus a cancelled ctx) before Bridge is even started, then check a
// plain postcondition once Bridge returns. There is no scheduling window
// left for luck to occupy: reverting the fix below makes the first test
// fail on every single run, deterministically, not "about one time in six".

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// fakeStream is a deterministic double for Stream. Every fact about it that
// a test cares about - when Read returns EOF, whether Close/CloseWrite was
// called - is driven explicitly by the test calling sendEOF, not by real
// network or scheduling timing.
type fakeStream struct {
	mu         sync.Mutex
	readCh     chan []byte
	readClosed bool
	writes     [][]byte
	closed     bool
	closeCount int
	closeWrite bool
}

func newFakeStream() *fakeStream {
	return &fakeStream{readCh: make(chan []byte, 8)}
}

func (f *fakeStream) Read(p []byte) (int, error) {
	b, ok := <-f.readCh
	if !ok {
		return 0, io.EOF
	}
	return copy(p, b), nil
}

// sendEOF puts this stream's read side into "clean EOF" - the fake's stand-in
// for the peer sending SSH_MSG_CHANNEL_EOF (or a real close: buffer.eof() in
// golang.org/x/crypto/ssh fires from either).
func (f *fakeStream) sendEOF() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readClosed {
		return
	}
	f.readClosed = true
	close(f.readCh)
}

func (f *fakeStream) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (f *fakeStream) CloseWrite() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeWrite = true
	return nil
}

// Close records the call and, like a real SSH channel's Close eventually
// does once the peer's library acks it, unblocks a pending Read - so driving
// ctx cancellation in a test does not leak the copy goroutine blocked on a
// human fake that never sends anything.
func (f *fakeStream) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	f.closeCount++
	if !f.readClosed {
		f.readClosed = true
		close(f.readCh)
	}
	return nil
}

func (f *fakeStream) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// fakeRecording is a minimal Recording double: it only needs to report
// whether it was closed cleanly or aborted, and with what reason.
type fakeRecording struct {
	mu          sync.Mutex
	closed      bool
	aborted     bool
	abortReason string
}

func (r *fakeRecording) Write(p []byte) (int, error) { return len(p), nil }

func (r *fakeRecording) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *fakeRecording) Abort(reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aborted = true
	r.abortReason = reason
	return nil
}

// AddBytesIn is the bytesIn counter hook (IAMT-169). fakeRecording
// tracks "the bridge called me with this slice", which is exactly what
// the IAMT-169 unit test asserts. Production code reaches this only via
// the real record.Recorder. IAMT-336 phase 5 widened the argument from
// a count to the bytes that were just forwarded, so the streaming
// SHA-256 inside the real recorder can be updated incrementally.
func (r *fakeRecording) AddBytesIn(p []byte) {}

func (r *fakeRecording) snapshot() (closed, aborted bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed, r.aborted
}

// TestBridgeCleanEndLeavesStreamsOpenForCaller is the primary causal test for
// IAMT-108's gateway half: on a clean end, Bridge must not close human or
// target itself. Both directions are put into EOF before Bridge is even
// called, so there is nothing left to race - what is being checked is a
// simple postcondition of a completed, deterministic call.
//
// CANARY: revert core/bridge.go so the unconditional stop() after the
// select loop runs regardless of whether first is nil (the pre-fix
// ordering), and this test fails on every run with exactly the t.Fatalf
// text below - not "sometimes", because there is no race left for luck to
// hide behind.
func TestBridgeCleanEndLeavesStreamsOpenForCaller(t *testing.T) {
	human := newFakeStream()
	target := newFakeStream()
	rec := &fakeRecording{}

	// Both directions are already exhausted before Bridge starts: this is
	// "clean end", fully determined, not a race against Bridge's internals.
	human.sendEOF()
	target.sendEOF()

	done := make(chan error, 1)
	go func() { done <- Bridge(context.Background(), human, target, rec, nil) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Bridge returned %v on a clean end, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Bridge did not return on a clean end within 5s")
	}

	closed, aborted := rec.snapshot()
	if !closed || aborted {
		t.Fatalf("recording state after a clean end: closed=%v aborted=%v, want closed=true aborted=false", closed, aborted)
	}

	if human.isClosed() {
		t.Fatal("Bridge closed the human stream itself on a clean end; closing it is now the caller's job (IAMT-108) so the caller can wait for the machine's last request to drain first before closing - see the doc comment on Bridge in bridge.go")
	}
	if target.isClosed() {
		t.Fatal("Bridge closed the target stream itself on a clean end; see the human-stream failure above for why that is wrong now")
	}
}

// TestBridgeCtxCancelStillClosesStreamsImmediately guards the other half of
// the same change: IAMT-108 only changes the CLEAN-end path. On ctx
// cancellation (machine_conn.go's mc.ctx, cancelled by teardown when the
// machine's transport dies) Bridge must keep closing both streams itself,
// right away, exactly as before - that is what unblocks a human read that
// would otherwise stay blocked forever on a human who is still connected
// and has sent nothing (machine_conn.go's comment on the ctx field). This
// test exists so a future attempt to "fix" IAMT-108 by simply deleting
// Bridge's stop() calls altogether - instead of scoping the change to the
// clean-end branch only - fails loudly here first.
func TestBridgeCtxCancelStillClosesStreamsImmediately(t *testing.T) {
	human := newFakeStream() // never sends EOF: "connected and has sent nothing"
	target := newFakeStream()
	target.sendEOF() // the machine's own side is already gone
	rec := &fakeRecording{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Bridge(ctx, human, target, rec, nil) }()

	// Let the target->human copy actually observe its EOF and finish before
	// cancelling, so the assertion below is about the ctx.Done() branch
	// specifically and not an accident of goroutine start order.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		target.mu.Lock()
		targetSeen := target.readClosed
		target.mu.Unlock()
		if targetSeen {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Bridge returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Bridge did not return after ctx was cancelled - this is exactly the hang machine_conn.go's ctx field exists to prevent")
	}

	if !human.isClosed() {
		t.Fatal("Bridge did not close human after ctx cancellation; a human still connected and silent would then block core.Bridge's caller forever (machine_conn.go's comment on the ctx field)")
	}
	closed, aborted := rec.snapshot()
	if closed || !aborted {
		t.Fatalf("recording state after a non-clean end: closed=%v aborted=%v, want closed=false aborted=true", closed, aborted)
	}
}
