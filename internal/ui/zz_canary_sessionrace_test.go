package ui

// The maintainer's canary: drawing a session and tail-fetching it must
// not touch one terminal emulator without a shared lock. The same
// disease the maintainer caught on 19.09.2026 in live_watch.go (fixed
// in d129a8d), but in a different tab -- Session -- the one they watch
// on the VM.
//
// The rendezvous of both goroutines here is real: the canary does not
// merely run them side by side and hope for the detector, it HOLDS
// s.mu from the test and watches the product's critical section
// block. That gives a deterministic red signal on either side -- the
// detector catches both symmetric regressions (dropping the lock from
// the reader and from the writer) -- which the existing watchrace
// canary does not do, because it relies on -race alone.

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// sessionRaceVT is a fixed, known VT we drop into the view: a single line
// of text in history, so layoutSessionTerminal has something stable to
// lay out before the goroutine under test runs.
func sessionRaceVT(t *testing.T) *record.VT {
	t.Helper()
	vt := record.NewVT(80, 24)
	vt.Write([]byte("BASE-LINE-IN-HISTORY\r\n"))
	vt.Write([]byte("BASE-LINE-ON-SCREEN"))
	return vt
}

// sessionRaceFrame builds a Frame whose Session tab is set up for the
// race canary: a tail action that never returns until cancelled (so the
// goroutine is parked inside pollLoop), and one view that already has
// bytes in it.
func sessionRaceFrame(t *testing.T) (*Frame, string) {
	t.Helper()
	f := newBareFrame(t)
	const id = "sess-canary"
	f.sessionUI.mu.Lock()
	v := f.sessionUI.getView(id)
	v.vt = sessionRaceVT(t)
	f.sessionUI.selectedID = id
	f.sessionUI.mu.Unlock()

	// Park one writer inside pollLoop: a tail action that blocks until
	// the test cancels it. The frame's own pollCancel will be enough to
	// unblock it, because the goroutine waits on ctx.Done().
	f.cfg.Actions.SessionTail = func(ctx context.Context, req SessionTailReq) (SessionTailResp, error) {
		<-ctx.Done()
		return SessionTailResp{}, ctx.Err()
	}
	return f, id
}

// TestCanary_SessionLayoutAcquiresTheLock.
//
// Canary: remove uiState.mu.Lock() / Unlock() in layoutSessionTerminal
// -- the test goes red below, because the operation did not block on
// the busy lock.
//
// The existing canary for live_watch does not do this: it runs the
// goroutines side by side and relies on -race. We need a
// deterministic signal -- the maintainer arrived here only after
// -race had let them down.
func TestCanary_SessionLayoutAcquiresTheLock(t *testing.T) {
	f, id := sessionRaceFrame(t)

	// Hold s.mu from the test. Any path that claims to read under it must
	// block here until we release it; the layout function runs on this
	// goroutine for the duration of the call.
	f.sessionUI.mu.Lock()
	holdingForTest := make(chan struct{})
	releaseForTest := make(chan struct{})
	go func() {
		close(holdingForTest)
		<-releaseForTest
		f.sessionUI.mu.Unlock()
	}()
	<-holdingForTest

	// Now call the layout. If it tries to lock s.mu first, it BLOCKS and
	// the timer below catches it. If it forgets the lock and reads the VT
	// directly, it returns immediately and the assertion fires.
	gtx := newTestLayoutContext(900, 600)
	layoutDone := make(chan struct{})
	go func() {
		// The Session tab calls layoutSessionTerminal only after a
		// non-empty session list is selected, so we drive the same path
		// the tab would: select the session, then layout.
		_ = f.layoutSessionTerminal(gtx, id)
		close(layoutDone)
	}()

	select {
	case <-layoutDone:
		close(releaseForTest)
		t.Fatal("layoutSessionTerminal returned while s.mu is held by the test -- the reader no longer takes the lock before touching the VT")
	case <-time.After(50 * time.Millisecond):
		// Blocked, as it must be when the lock is held.
	}

	close(releaseForTest)
	<-layoutDone
}

// TestCanary_SessionForwardFetchAcquiresTheLock.
//
// Canary: remove the locking in applyForwardFetch (or drop it from the
// writer) -- the test goes red, because the writer did not block on
// the busy lock. Paired with the reader one.
//
// The idea is the same: hold s.mu from the test and make sure
// applyForwardFetch waits for its release. This path writes
// v.remainder, v.offset, v.headOffset, v.total, v.live -- all of them
// must change under the lock.
func TestCanary_SessionForwardFetchAcquiresTheLock(t *testing.T) {
	f, id := sessionRaceFrame(t)

	// Get the view under the lock so the goroutine we are about to start
	// can call applyForwardFetch with a stable *sessionView without
	// racing with the layout on s.views.
	f.sessionUI.mu.Lock()
	v := f.sessionUI.getView(id)
	f.sessionUI.mu.Unlock()

	// Re-acquire s.mu from the test and hold it from a side goroutine.
	// Any path that claims to take it inside applyForwardFetch must block
	// here; the call returns synchronously only when the lock was
	// forgotten.
	f.sessionUI.mu.Lock()
	holdingForTest := make(chan struct{})
	releaseForTest := make(chan struct{})
	go func() {
		close(holdingForTest)
		<-releaseForTest
		f.sessionUI.mu.Unlock()
	}()
	<-holdingForTest

	// Build a small chunk: one output event, in asciicast format, so
	// ParseCast has something to swallow. The header is the same one
	// the live fixture produces.
	chunk := []byte("{\"version\":2,\"width\":80,\"height\":24}\n" +
		"[0.1,\"o\",\"ADDED-BY-WRITER\\r\\n\"]\n")

	fetchDone := make(chan struct{})
	go func() {
		_ = f.sessionUI.applyForwardFetch(v, SessionTailResp{
			ID:    id,
			Total: 4096,
			Live:  true,
			Data:  chunk,
		})
		close(fetchDone)
	}()

	select {
	case <-fetchDone:
		close(releaseForTest)
		t.Fatal("applyForwardFetch returned while s.mu is held by the test -- the writer no longer takes the lock before writing the view's fields")
	case <-time.After(50 * time.Millisecond):
		// Blocked, as it must be when the lock is held.
	}

	close(releaseForTest)
	<-fetchDone
}

// TestCanary_SessionLayoutAndForwardFetchMeet -- both
// goroutines work together in a single run: the reader draws while
// the writer tail-fetches.
//
// The sessionAuditReads and sessionAuditWrites counters live in
// export_test.go, not in the product type sessionView (REMARKS-round2
// §1). They are incremented through auditHook inside the critical
// sections, and the test checks that both sides really went through
// s.mu.
func TestCanary_SessionLayoutAndForwardFetchMeet(t *testing.T) {
	f, id := sessionRaceFrame(t)

	ResetSessionAuditCounts()
	EnableSessionAudit(f)
	readsBefore, writesBefore := SessionAuditCounts()

	// A tail action that produces a small chunk each call. It returns
	// synchronously so the writer goroutine iterates fast and the
	// reader is almost certain to interleave.
	var calls int32
	f.cfg.Actions.SessionTail = func(ctx context.Context, req SessionTailReq) (SessionTailResp, error) {
		atomic.AddInt32(&calls, 1)
		// Cap the burst so the test stays bounded on slow CI.
		if atomic.LoadInt32(&calls) > 64 {
			<-ctx.Done()
			return SessionTailResp{}, ctx.Err()
		}
		chunk := []byte("[0.1,\"o\",\"x\\r\\n\"]\n")
		if req.Offset == 0 {
			chunk = append([]byte("{\"version\":2,\"width\":80,\"height\":24}\n"), chunk...)
		}
		return SessionTailResp{
			ID:     req.ID,
			Offset: uint64(int64(req.Offset) + int64(len(chunk))),
			Total:  uint64(int64(req.Offset) + int64(len(chunk)) + 16*1024),
			Live:   true,
			Data:   chunk,
		}, nil
	}

	// Drive the writer directly: applyForwardFetch is the section that
	// writes under s.mu. Calling it in a tight loop with a parallel
	// layout is what surfaces the race the live canary was meant to
	// catch.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 64; i++ {
			select {
			case <-stop:
				return
			default:
			}
			f.sessionUI.mu.Lock()
			vv := f.sessionUI.getView(id)
			f.sessionUI.mu.Unlock()
			_ = f.sessionUI.applyForwardFetch(vv, SessionTailResp{
				ID:    id,
				Total: 16 * 1024,
				Live:  true,
				Data:  []byte("[0.1,\"o\",\"y\\r\\n\"]\n"),
			})
		}
	}()

	gtx := newTestLayoutContext(900, 600)
	for i := 0; i < 32; i++ {
		_ = f.layoutSessionTerminal(gtx, id)
	}
	close(stop)
	<-done

	readsAfter, writesAfter := SessionAuditCounts()
	if writesAfter <= writesBefore {
		t.Fatalf("audit: not a single write under the lock was recorded under applyForwardFetch (before %d, after %d) -- either the lock was dropped or the counter forgotten",
			writesBefore, writesAfter)
	}
	if readsAfter <= readsBefore {
		t.Fatalf("audit: not a single read under the lock was recorded under layoutSessionTerminal (before %d, after %d) -- either the lock was dropped or the counter forgotten",
			readsBefore, readsAfter)
	}
}

// TestCanary_SessionCompositeReadTearsFrame -- a canary on
// the composite-read defect (REMARKS-round2 §1):
// reading HistoryTotal, Screen, Cursor and History without holding the
// single uiState.mu lock, under concurrent writes, assembles the frame
// from different moments in time.
// If the reader drops the lock before reading the VT while the writer
// clears/trims the terminal history through applyForwardFetch /
// extendBackward, numHistory and the actually drawn history lines
// diverge (for example numHistory > 0 while the history lines come
// back empty because of the shift/trim).
//
// The canary fails from the defect itself: if the lock is removed in
// layoutSessionTerminal before touching the VT (or in
// applyForwardFetch), then under a concurrent writer trimming the
// history the frame goes inconsistent: index < numHistory draws an
// empty line.
func TestCanary_SessionCompositeReadTearsFrame(t *testing.T) {
	f, id := sessionRaceFrame(t)

	// Fill the initial VT with history lines (50 lines so that ~26 fall
	// into history).
	f.sessionUI.mu.Lock()
	v := f.sessionUI.getView(id)
	v.termList.ScrollToEnd = false
	v.termList.Position.First = 0
	vt := record.NewVT(80, 24)
	for i := 0; i < 50; i++ {
		vt.Write([]byte(fmt.Sprintf("HIST-LINE-%02d\r\n", i)))
	}
	v.vt = vt
	f.sessionUI.mu.Unlock()

	var linesChecked int
	var tornFrameErr error
	var errOnce sync.Once

	// renderHook checks the frame's consistency:
	// if index < numHistory, the line MUST be a non-empty history line.
	// Under the defect (composite read without a single lock) a
	// concurrent history reset between HistoryTotal and History makes
	// the history shorter than numHistory, and for indices
	// index < numHistory an empty line is returned.
	SetSessionRenderHook(f, func(index int, numHistory int, line record.Line) {
		linesChecked++
		if index < numHistory && line.Text == "" {
			errOnce.Do(func() {
				tornFrameErr = fmt.Errorf("torn frame: index %d < numHistory %d, but an empty line was drawn (the VT history changed concurrently without a single lock)", index, numHistory)
			})
		}
	})

	// interleaveHook is called right after HistoryTotal() is read.
	// If the reader holds uiState.mu (the fix, in place):
	// the writer's attempt to take s.mu fails (TryLock false),
	// and the history trim CANNOT happen in the middle of frame
	// assembly.
	// If the reader dropped the lock (the defect):
	// the writer takes s.mu, trims the VT to 2 lines,
	// and the reader's subsequent v.vt.History() read yields a torn
	// frame!
	SetSessionInterleaveHook(f, func() {
		if f.sessionUI.mu.TryLock() {
			v.vt = record.NewVT(80, 24)
			v.vt.Write([]byte("SHORT-0\r\nSHORT-1\r\n"))
			f.sessionUI.mu.Unlock()
		}
	})

	// Run the frame assembly.
	gtx := newTestLayoutContext(900, 600)
	_ = f.layoutSessionTerminal(gtx, id)

	if linesChecked == 0 {
		t.Fatal("the test checked not a single drawn line")
	}
	if tornFrameErr != nil {
		t.Fatalf("the composite-read defect reproduced: %v", tornFrameErr)
	}
}
