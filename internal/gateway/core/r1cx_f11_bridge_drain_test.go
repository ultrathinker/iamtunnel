package core

// F-11 (round-1 review, 24.09.2026): Bridge's select loop waits for
// exactly two results, but once ctx is cancelled the ctx.Done case stays
// ready forever - both iterations can pick it, and Bridge returns while one
// or both copy goroutines are still inside their io.Copy. stop() closes the
// streams, which unblocks a real read eventually; "eventually" is not
// "before Bridge returned": the caller's teardown and rec.Close can then
// run against a copy goroutine that is still writing to rec or reading the
// streams. The promise goleak_test.go in the gateway package records -
// "core.Bridge's two copy goroutines: joined inside Bridge before it
// returns" - was true of the error and clean paths only.
//
// This test parks both copies inside Read and cancels the ctx, then asks
// the only question that matters: when Bridge returned, had both copies
// actually finished? Before the fix the answer is no on every single run -
// the reads are still parked, nothing has unblocked them, so nobody had to
// rely on scheduling luck to catch the early return.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// f23parkStream is a Stream whose Read parks until the shared release
// channel closes, and never unblocks from Close: the copy goroutines stand
// exactly where the finding lives - blocked in Read - and only the test
// decides when they may finish. readsOut counts the Reads that returned.
type f23parkStream struct {
	parked   chan struct{}
	parkOnce sync.Once
	release  <-chan struct{}
	readsOut *atomic.Int32
}

func (s *f23parkStream) Read(p []byte) (int, error) {
	s.parkOnce.Do(func() { close(s.parked) })
	<-s.release
	s.readsOut.Add(1)
	return 0, errors.New("f23: read released")
}

func (s *f23parkStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *f23parkStream) Close() error                { return nil }
func (s *f23parkStream) CloseWrite() error           { return nil }

func TestR1CX_F11_BridgeReturnsOnlyAfterBothCopiesHaveFinished(t *testing.T) {
	var readsOut atomic.Int32
	release := make(chan struct{})
	human := &f23parkStream{parked: make(chan struct{}), release: release, readsOut: &readsOut}
	target := &f23parkStream{parked: make(chan struct{}), release: release, readsOut: &readsOut}

	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		err      error
		finished int32
	}
	out := make(chan outcome, 1)
	go func() {
		err := Bridge(ctx, human, target, &fakeRecording{}, nil)
		out <- outcome{err: err, finished: readsOut.Load()}
	}()

	// Both copies parked inside Read - the exact shape of the scenario:
	// two blocked copies and a cancelled context.
	<-human.parked
	<-target.parked
	cancel()

	// The reads unblock no later than this, in either world: before the fix
	// Bridge returned long before it; after the fix Bridge is already
	// draining at this point, and this release is what lets the copies end
	// and the drain complete. It starts only after the cancel, so no copy
	// result can ever arrive before the ctx.Done case has been taken once -
	// under load the 500ms must not race the parking above.
	time.AfterFunc(500*time.Millisecond, func() { close(release) })

	res := <-out
	if res.finished != 2 {
		t.Fatalf("Bridge returned while %d of its 2 copy goroutines were still inside their reads: the select loop answered the already-ready ctx.Done twice instead of waiting the copies out, and the caller's teardown can now race a copy that is still running (F-11)", 2-res.finished)
	}
	if res.err == nil {
		t.Fatal("a cancelled bridge reported a clean end")
	}
}
