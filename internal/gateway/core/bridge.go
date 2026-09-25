package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Recording is the minimal contract of the already reviewed recording package.
// New recording objects are created by the caller before Bridge is called; this
// makes it structurally impossible for a byte to be proxied before a recording
// exists. Abort is used for every non-clean end.
//
// AddBytesIn is the human -> machine counter hook (PROTOCOL §8: input is
// never recorded, only counted and, since IAMT-336 phase 5, hashed).
// Implementations that do not surface a counter (test doubles such as
// probeRec) may leave it no-op; the bridge still records bytesOut via
// Write. The argument is the slice of bytes that were just forwarded
// to target, so an incremental SHA-256 can be updated without buffering
// (SPEC §6.5: a 47 KB image today, a 4 GB file tomorrow — the hash
// must not depend on size).
type Recording interface {
	Write([]byte) (int, error)
	Close() error
	Abort(reason string) error
	AddBytesIn(p []byte)
}

// Stream is an SSH channel (or the fake peer used by tests). CloseWrite is kept
// separate because EOF is directional in SSH.
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	CloseWrite() error
}

// Bridge copies a human SSH channel and a nested target channel. Target output is
// committed to rec before it can reach the human. Any recording fault or transport
// break closes both streams immediately and aborts the recording, so there is no
// unrecorded tail of a session.
//
// Closing on a clean end is the caller's job, not Bridge's (IAMT-108): the
// machine's last channel request (PROTOCOL §4.1's exit-status, forwarded
// machine -> human only) travels on a request stream this function never
// sees, drained by a goroutine the caller owns, and that goroutine may still
// be forwarding it after both copies below finish cleanly. Bridge closing
// human/target itself at that point would race that forward against the
// very channel it needs, which is exactly the defect this comment exists to
// prevent a future edit from reintroducing. So on a clean end (both copies
// finished, ctx not cancelled) Bridge leaves human and target open and lets
// the caller close them once it has done whatever draining a clean end
// still requires. On any non-clean end - a copy error, or ctx cancelled -
// Bridge keeps closing both streams itself, immediately, for the reason it
// always did: to unblock a peer that would otherwise stay blocked reading
// forever (see internal/gateway/machine_conn.go's comment on the ctx field
// for why ctx is part of this call's contract at all).
//
// targetDrained, if non-nil, is closed the instant the target -> human copy
// below returns, on either the clean or the error branch - i.e. every byte
// the machine sent, and only those bytes, have been committed to rec and
// forwarded to human. A caller has no other way to observe that instant:
// Bridge itself does not return until human -> target *also* ends, and nothing
// requires the human side to ever end on its own (IAMT-306 - a plain SSH exec
// client is not obliged to close its own stdin once the remote process it
// asked for has exited; many well-behaved clients wait for the server to
// close first). A caller that wants to force that close - once it has also
// drained whatever else must precede it, such as the exit-status request -
// needs to know the target side is genuinely finished first, or it would
// close human out from under Bridge's own still-in-flight write of the last
// chunk.
func Bridge(ctx context.Context, human, target Stream, rec Recording, targetDrained chan<- struct{}) error {
	if human == nil || target == nil || rec == nil {
		return errors.New("core: bridge requires streams and recording")
	}

	var once sync.Once
	stop := func() { once.Do(func() { _ = human.Close(); _ = target.Close() }) }
	type result struct {
		err           error
		targetToHuman bool
	}
	done := make(chan result, 2)

	go func() {
		defer func() {
			if p := recover(); p != nil {
				stop()
				done <- result{err: copyPanicked("human -> machine", p)}
			}
		}()
		// Counter wrapper: io.Copy forwards the bytes successfully
		// accepted by human -> target to the Recording so it can update
		// its bytesIn counter (PROTOCOL §6 / §8) and, since IAMT-336
		// phase 5, its streaming SHA-256 of stdin (SPEC §6.5). The
		// Recording never stores the bytes — PROTOCOL §8 forbids
		// recording stdin — it only updates its hash state and a counter.
		cw := &countWriter{w: target, onRead: rec.AddBytesIn}
		_, err := io.Copy(cw, human)
		if err == nil || errors.Is(err, io.EOF) {
			_ = target.CloseWrite()
			done <- result{}
			return
		}
		stop()
		done <- result{err: err}
	}()
	go func() {
		drained := false
		markDrained := func() {
			if targetDrained != nil && !drained {
				drained = true
				close(targetDrained)
			}
		}
		defer func() {
			if p := recover(); p != nil {
				stop()
				markDrained()
				done <- result{err: copyPanicked("machine -> human", p), targetToHuman: true}
			}
		}()
		// io.MultiWriter intentionally cannot be used: it may write the human
		// before discovering a partial recorder write. recordingWriter performs
		// the durable step first for every chunk.
		_, err := io.Copy(recordingWriter{rec: rec, dst: human}, target)
		if err == nil || errors.Is(err, io.EOF) {
			_ = human.CloseWrite()
			markDrained()
			done <- result{targetToHuman: true}
			return
		}
		stop()
		markDrained()
		done <- result{err: err, targetToHuman: true}
	}()

	var first error
	// draining is the ctx-cancellation path's second half (F-11, round-1
	// review 24.09.2026). The loop must receive TWO results, but after the
	// first ctx.Done the context's channel stays ready for good, so a
	// second select could answer it again - and a ctx.Done is not a result:
	// Bridge would return with a copy goroutine still inside its io.Copy,
	// and the caller's teardown and rec.Close would race a copy that is
	// still writing to rec. Once one ctx.Done has been taken, the wait
	// counts results only: stop() has closed both streams, so both copies
	// end, and Bridge returns only when both actually have - the promise
	// the gateway package's goleak_test.go records for this function.
	draining := false
	for received := 0; received < 2; {
		if draining {
			r := <-done
			received++
			if r.err != nil && first == nil {
				first = r.err
			}
			continue
		}
		select {
		case r := <-done:
			received++
			if r.err != nil && first == nil {
				first = r.err
			}
		case <-ctx.Done():
			stop()
			if first == nil {
				first = ctx.Err()
			}
			draining = true
		}
	}
	if first != nil {
		// stop() has already run on every path that can set first (both copy
		// goroutines' error branches and the ctx.Done() case above all call
		// it before first is set) - this call is only a safety net for a
		// future path that sets first without closing first, and sync.Once
		// makes it free otherwise.
		stop()
		_ = rec.Abort(first.Error())
		return first
	}
	// Clean end: finalize the recording now, but leave human and target
	// open - see the doc comment above for why closing them is the
	// caller's job here (IAMT-108).
	return rec.Close()
}

// copyPanicked turns a panic inside one direction of the bridge into that
// direction's error (IAMT-441). The recording runs inside these copies - it
// parses every chunk the machine prints - so a fault in it is within reach
// of anyone with a shell on the machine, and an unrecovered panic in any
// goroutine ends the whole gateway process, every other session included.
// Recovered, it ends this one session the way any other copy error does:
// both streams closed, the recording aborted with the panic as the reason,
// targetDrained closed so nobody waits on it forever.
func copyPanicked(direction string, p any) error {
	return fmt.Errorf("core: the %s copy panicked: %v", direction, p)
}

type recordingWriter struct {
	rec Recording
	dst io.Writer
}

func (w recordingWriter) Write(p []byte) (int, error) {
	n, err := w.rec.Write(p)
	if err != nil {
		return n, err
	}
	if n != len(p) {
		return n, io.ErrShortWrite
	}
	return w.dst.Write(p)
}

// countWriter pairs a downstream io.Writer with an optional callback
// invoked with the slice of bytes that were just accepted by Write, so a
// partial Write is not over-counted. The Recording sees the bytes too:
// since IAMT-336 phase 5 the bridge forwards them so an incremental
// SHA-256 of stdin can be maintained without buffering (SPEC §6.5).
// The Recording never stores the bytes — PROTOCOL §8 forbids recording
// stdin — it only updates its hash state and a counter.
type countWriter struct {
	w      io.Writer
	onRead func(p []byte)
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 && c.onRead != nil {
		c.onRead(p[:n])
	}
	return n, err
}
