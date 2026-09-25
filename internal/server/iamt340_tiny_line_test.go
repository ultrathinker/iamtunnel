package server

// iamt340_tiny_line_test.go - a control line too small for any answer is
// a refusal here, not a one-byte question there.
//
// the review of IAMT-340 found the original clamp raising the
// ceiling to 1 when the configured ControlLineMax left no room after the
// reserve. One byte is the smallest LEGAL limit, so the request looked
// correct - but legality of the REQUEST was never the constraint. The
// gateway answers a one-byte tail with a well-formed line whose envelope
// alone is far over such a limit, this machine's own reader refuses it,
// and a control line that cannot be read tears down the channel, the
// door and the tunnel. Somebody glancing at a live session would have
// disconnected his own machine from the gateway.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestIAMT340_ALineTooSmallForAnyAnswerIsRefusedWithoutTouchingTheWire.
//
// Canary: put the old clamp back in Tail (replace the
// `return TailAnswer{}, ErrTailLineTooSmall` branch with `ceiling = 1`)
// and this goes red twice over - once on the error, which becomes a
// timeout instead, and once on the wire, which now carries a question
// the machine could not survive the answer to.
func TestIAMT340_ALineTooSmallForAnyAnswerIsRefusedWithoutTouchingTheWire(t *testing.T) {
	// Exactly the reserve: the envelope and the answer skeleton fill the
	// whole line and not one byte of body fits. It is set before the
	// machine is dialled, because Config is read by the serve goroutine
	// from then on and writing to it afterwards is a race - which is
	// what the first version of this test did.
	f := newTailFixtureWith(t, func(c *Config) { c.ControlLineMax = TailLineReserve })

	if got := tailChunkMaxFor(TailLineReserve); got != 0 {
		t.Fatalf("tailChunkMaxFor(%d) = %d, want 0 - the test's own premise is wrong", TailLineReserve, got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := f.m.Tail(ctx, TailRequest{SessionID: "1-alice-pc1", Offset: 0, Limit: TailChunkMax})
	if !errors.Is(err, ErrTailLineTooSmall) {
		t.Fatalf("Tail returned %v, want ErrTailLineTooSmall - a configuration that cannot carry any answer must be refused here, where it costs a feature, not there, where it costs the tunnel", err)
	}

	// And nothing was written. This is the half that matters: the error
	// alone would be satisfied by a machine that asked anyway and then
	// complained about its own question.
	select {
	case line, ok := <-f.lines:
		if ok {
			t.Fatalf("the machine put %q on the control channel - a question whose answer cannot be read must never leave this side", line)
		}
	case <-time.After(300 * time.Millisecond):
	}
}
