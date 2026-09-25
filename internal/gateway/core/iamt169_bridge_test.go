package core

// IAMT-169 unit canaries for core/bridge.go.
//
// SPEC: with IAMT-169 the bridge must count bytesIn (human -> machine)
// and surface them in recordings.list as BytesIn. The input is NOT
// recorded (PROTOCOL §8): the counting goes through AddBytesIn on
// Recording, not through Write.
//
// Canaries:
//   - TestIAMT169_Bridge_CountsHumanToMachine_Only — counting happens only
//     in the human -> target direction; the reverse flow (target -> human)
//     is NOT summed into bytesIn, it goes through the recording.
//   - TestIAMT169_Bridge_AddBytesIn_Nil_NoPanic — a Recording implementation
//     whose AddBytesIn is an empty-bodied method remains valid for
//     the bridge (interface/smoke check on test-suite completeness).
//
// Both sides of the bridge here are fakeStream (bridge_ownership_test.go):
// a deterministic double of Stream where EOF/data are fed explicitly by the
// test, not by a scheduler race through io.Pipe. This is the same pattern
// that already closed IAMT-108 (bridge_ownership_test.go) — a real
// network/pipe hang cannot happen here by construction: fakeStream's Read
// either receives a buffer from a channel, or the channel is closed and
// Read returns EOF immediately.
//
// Bridge waits under a deadline — a select with a timer and t.Fatal: if
// this guarantee ever breaks (say, someone reintroduces a pipe pair
// without a matched EOF), the test goes red on its own instead of hanging.

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

// countingRecording — a Recording that accumulates BytesIn separately on
// top of BytesOut (via Write). This mirrors the production Recorder's
// format, and the unit canary checks that the bridge calls AddBytesIn
// exactly as many times and with exactly the bytes the bridge sees in
// io.Copy.
// IAMT-336 phase 5 widened the argument from a count to the bytes that
// were just forwarded, so a streaming SHA-256 of stdin can be updated
// incrementally without buffering.
type countingRecording struct {
	written []byte
	mu      sync.Mutex

	bytesOut         int64
	bytesInReported  int64
	addBytesInCalled int
	stdinCollected   []byte
}

func (r *countingRecording) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.written = append(r.written, p...)
	r.bytesOut += int64(len(p))
	return len(p), nil
}

func (r *countingRecording) Close() error { return nil }
func (r *countingRecording) Abort(string) error {
	return nil
}
func (r *countingRecording) AddBytesIn(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addBytesInCalled++
	r.bytesInReported += int64(len(p))
	r.stdinCollected = append(r.stdinCollected, p...)
}

func TestIAMT169_Bridge_CountsHumanToMachine_Only(t *testing.T) {
	human := newFakeStream()
	target := newFakeStream()
	rec := &countingRecording{}

	// human "types" exactly one chunk, "hello", then EOF (peer sent
	// SSH_MSG_CHANNEL_EOF). target's own output is already EOF too, so the
	// target->human copy finishes immediately with zero bytes and bytesOut
	// must stay 0 - only the human->target direction is exercised.
	human.readCh <- []byte("hello")
	human.sendEOF()
	target.sendEOF()

	done := make(chan error, 1)
	go func() { done <- Bridge(context.Background(), human, target, rec, nil) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Bridge: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Bridge did not return within 5s on a clean end with both sides already at EOF")
	}

	target.mu.Lock()
	gotWrites := append([][]byte(nil), target.writes...)
	target.mu.Unlock()
	var got []byte
	for _, w := range gotWrites {
		got = append(got, w...)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("target did not receive the human bytes; got %q", got)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.bytesInReported != 5 {
		t.Fatalf("bytesIn: expected 5 (\"hello\" via human->target), got %d", rec.bytesInReported)
	}
	if rec.bytesOut != 0 {
		t.Fatalf("bytesOut: this test has no reverse flow, got %d (smuggled through AddBytesIn? then Bridge breaks the direction)", rec.bytesOut)
	}
	if rec.addBytesInCalled == 0 {
		t.Fatalf("Bridge never called AddBytesIn — the human->machine counter does not work")
	}
}
