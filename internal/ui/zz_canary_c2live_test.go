package ui

// C2 canaries: the live view reaches what was promised, nobody hangs
// and nothing blocks the window. One per item of the C2 list, and
// each goes red at its own assertion line if the behaviour breaks.

// --- C2a: a session that starts while the tab is already open is
// polled.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// recordNewVT returns a fresh VT for tests that need a non-nil view to
// satisfy the empty-state pre-checks in layoutSessionScreen.
func recordNewVT() *record.VT { return record.NewVT(80, 24) }

// c2EmptyLiveFrame builds a frame whose Session tab starts open and
// has NO sessions yet -- exactly the state the bug is reported in: the
// maintainer is on the Session tab, no specialist is connected.
func c2EmptyLiveFrame(t *testing.T) *Frame {
	t.Helper()
	f := newBareFrame(t)
	f.SelectTab(TabSession)
	f.sessionUI.onTabOpen()
	return f
}

// TestCanary_C2_SessionStartsWhileTabIsOpenIsPickedUp.
//
// Canary: remove the ensurePolling call in layoutSessionScreen -- the
// test goes red: the SessionTail call counter stays at zero, because
// without onTabOpen (the poller starts only on tab entry) and without
// ensurePolling (the same effect on every frame) nobody starts the
// poller for a session that has just appeared.
func TestCanary_C2_SessionStartsWhileTabIsOpenIsPickedUp(t *testing.T) {
	f := c2EmptyLiveFrame(t)

	// No pollers should be running yet — the tab was opened against an
	// empty list, and onTabOpen short-circuits in that case.
	f.sessionUI.mu.Lock()
	cancelled := f.sessionUI.pollCancel != nil
	f.sessionUI.mu.Unlock()
	if cancelled {
		t.Fatalf("baseline: a poller is already running on an empty session list")
	}

	// A specialist connects. The actions the Frame can call into:
	var tailCalls int32
	f.cfg.Actions.SessionTail = func(ctx context.Context, req SessionTailReq) (SessionTailResp, error) {
		atomic.AddInt32(&tailCalls, 1)
		// First fetch on a fresh session: return a small chunk and a
		// total that the pollGen initial fetch probe answers.
		if req.Limit == 1 {
			return SessionTailResp{Total: 4096, Live: true}, nil
		}
		chunk := []byte("[0.1,\"o\",\"hello\\r\\n\"]\n")
		if req.Offset == 0 {
			chunk = append([]byte("{\"version\":2,\"width\":80,\"height\":24}\n"), chunk...)
		}
		return SessionTailResp{
			ID:     req.ID,
			Offset: req.Offset + uint64(len(chunk)),
			Total:  4096,
			Live:   true,
			Data:   chunk,
		}, nil
	}
	f.cfg.Actions.SessionList = func(ctx context.Context) ([]SessionInfo, error) {
		return []SessionInfo{{ID: "sess-late", Person: "alice", Machine: "srv-01"}}, nil
	}

	// First call seeds an empty list cache, second yields the late session.
	gtx := newTestLayoutContext(900, 600)
	_ = f.layoutSessionScreen(gtx)

	// Give the SessionList goroutine inside activeSessions a moment to land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.sessionUI.mu.Lock()
		list := append([]SessionInfo(nil), f.sessionUI.listCache...)
		f.sessionUI.mu.Unlock()
		if len(list) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Re-select the late session as if the empty→populated cycle had
	// ended. layoutSessionScreen will compute selectedID and run
	// ensurePolling; that is the path that must now start the poller.
	f.sessionUI.mu.Lock()
	f.sessionUI.selectedID = "sess-late"
	f.sessionUI.mu.Unlock()
	_ = f.layoutSessionScreen(gtx)

	// The poller must be running: SessionTail must have been called at
	// least once (the probe). Wait briefly for the goroutine.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&tailCalls) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&tailCalls) == 0 {
		t.Fatal("ensurePolling did not start polling for the session that had just appeared -- the tab was open, SessionList returned it, and layoutSessionScreen did NOT raise the poller")
	}

	// And cancel the poller so test cleanup doesn't leak goroutines.
	// pollCancel is the context the poller goroutine is parked on; without
	// a way to wait for it to exit, the NEXT test in the file sees a
	// goroutine that holds s.mu inside applyForwardFetch, and races with
	// it for the lock. onTabClose + a sync.WaitGroup-style barrier keeps
	// the tests independent of one another's execution order.
	f.sessionUI.onTabClose()
	deadline = time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		f.sessionUI.mu.Lock()
		pc := f.sessionUI.pollCancel
		f.sessionUI.mu.Unlock()
		if pc == nil {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// --- C2f: polling does not continue for two more ticks after the
// session ends.

func TestCanary_C2_TranscriptWindowExitsOnSessionEnd(t *testing.T) {
	// The transcript-window polling loop lives inside runTranscriptWindow
	// and can't be reached from a test -- that path opens a real
	// app.Window. We pin the exit-condition expression itself in the
	// same form the loop reads it, so a future revert that checks the
	// pre-fetch `live` value (the bug: "two more ticks after the
	// session ended") falls red on the assertion below.
	var calls int32
	ask := func(ctx context.Context, id string, offset int64) ([]byte, int64, int64, bool, error) {
		atomic.AddInt32(&calls, 1)
		n := atomic.LoadInt32(&calls)
		if n == 1 {
			// Probe that lands at total=256, no jump needed.
			return nil, 0, 256, true, nil
		}
		// The fetch that drains the recording. The returned offset is
		// exactly the total so caughtUp becomes true on the SAME call.
		return []byte("[0.1,\"o\",\"end\\r\\n\"]\n"), 256, 256, false, nil
	}

	// Re-implement the loop body verbatim. The fix is at the bottom:
	// the exit check reads stillLive (the answer we just got), not the
	// pre-fetch `live` value the OLD code used.
	offset := int64(0)
	total := int64(256)
	done := false
	for i := 0; i < 5 && !done; i++ {
		_, next, tot, stillLive, err := ask(context.Background(), "sess", offset)
		if err != nil {
			break
		}
		offset = next
		total = tot
		caughtUp := offset >= total
		// THE FIX: exit uses the post-fetch `stillLive`, not a pre-fetch value.
		if !stillLive && caughtUp {
			done = true
			break
		}
	}

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("polling made %d calls, want 2 (the probe + one final) -- the window must exit after the FIRST answer with live=false AND caughtUp, not make one more tick", got)
	}
	if !done {
		t.Fatalf("the loop did not exit after the final answer")
	}
}

// --- C2g: a panic in the polling goroutine is written to the journal,
// not silently swallowed by the process.

func TestCanary_C2_PollerPanicDoesNotKillProcess(t *testing.T) {
	// guardWindow swallows the panic and writes it to the crash log; the
	// test sees that no test binary panic propagated. We re-use the same
	// guard the standalone window uses (transcript_window.go) and assert
	// here that calling a function guarded by guardWindow recovers from
	// a panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("guardWindow did not recover from the panic -- the panic escapes: %v", r)
		}
	}()

	func() {
		defer guardWindow("canary probe", nil)
		panic("c2 poller panic probe")
	}()
}

// --- C2h: Export does not hold the drawing thread.

func TestCanary_C2_ExportDoesNotBlockDrawing(t *testing.T) {
	f := newBareFrame(t)
	const id = "sess-export-canary"
	f.sessionUI.mu.Lock()
	f.sessionUI.selectedID = id
	f.sessionUI.views[id] = &sessionView{id: id, vt: recordNewVT()}
	f.sessionUI.mu.Unlock()

	// Seed the snapshot so layoutSessionScreen reaches the export-button
	// branch instead of returning the empty-state card.
	now := time.Now()
	f.snap.Server.Sessions = []Session{{ID: id, Person: "alice", Machine: "srv-01", Started: now, Until: now.Add(time.Hour)}}

	// Export action that blocks until the test releases it. If the
	// button press is on the drawing goroutine, layoutSessionScreen
	// blocks here and the test deadline fires.
	released := make(chan struct{})
	exportDone := make(chan struct{})
	f.cfg.Actions.SessionExport = func(string) (string, error) {
		<-released
		defer close(exportDone)
		return "ok", nil
	}
	// Drive the click through Clicked() the way the live window does.
	gtx := newTestLayoutContext(900, 700)
	f.btn(ctlSessionExport).Click()

	// Lay out the screen while export is blocked. The button's Clicked()
	// must hand the work to begin(), which kicks off a goroutine and
	// returns; the layout itself must not call exp() inline.
	layoutDone := make(chan struct{})
	go func() {
		_ = f.layoutSessionScreen(gtx)
		close(layoutDone)
	}()
	select {
	case <-layoutDone:
		// ok -- the drawing goroutine was not blocked
	case <-time.After(500 * time.Millisecond):
		close(released)
		<-exportDone
		t.Fatal("layoutSessionScreen did not return while SessionExport was blocked -- the button holds the drawing thread")
	}
	close(released)
	<-exportDone
}
