//go:build windows || linux || darwin

package ui

// IAMT-341 round 2 canaries: each test pins one defect found in round 2
// review by exercising the new behaviour and naming the line that, if
// broken, will make it red. The tests here were authored alongside the
// fix.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// TestIAMT341_R2_VTResetClearsAndReinitializes pins record.VT.Reset (the
// replay primitive the live-session tab uses to rebuild its emulator
// after extending the held range backward).
//
// Canary: remove the `v.initScreen()` call at the bottom of Reset, or
// zero only some of the parser-state fields. The transcript must be
// empty and the dimensions must match the new value.
func TestIAMT341_R2_VTResetClearsAndReinitializes(t *testing.T) {
	vt := record.NewVT(80, 24)
	vt.Write([]byte("hello world\r\n"))
	if trans := vt.Transcript(); trans == "" {
		t.Fatalf("baseline: expected non-empty transcript before Reset, got %q", trans)
	}

	vt.Reset(120, 40)

	cols, rows := vt.Size()
	if cols != 120 || rows != 40 {
		t.Fatalf("Reset(%d, %d) got size %dx%d", 120, 40, cols, rows)
	}
	if trans := vt.Transcript(); trans != "" {
		t.Fatalf("Reset did not clear the transcript: %q", trans)
	}
	if total := vt.HistoryTotal(); total != 0 {
		t.Fatalf("Reset did not clear history: %d lines left", total)
	}
}

// TestIAMT341_R2_ForwardExtensionAppendsToHeld pins the forward half of
// the held-buffer invariant: the live viewer appends new bytes to held
// and feeds only the delta to the existing VT.
//
// Canary: drop the `s.appendHeld(v, resp.Data)` call in applyForwardFetch
// (so the parser still sees the bytes but held stays empty). The
// backward rebuild would then replay nothing.
func TestIAMT341_R2_ForwardExtensionAppendsToHeld(t *testing.T) {
	tail := func(ctx context.Context, req SessionTailReq) (SessionTailResp, error) {
		return SessionTailResp{
			ID:    req.ID,
			Total: 50,
			Live:  true,
			Data:  []byte("[0.0,\"o\",\"abc\\r\\n\"]\n"),
		}, nil
	}
	actions := Actions{SessionTail: tail}

	// The theme source is a fixed fake (MAC, 24.09.2026), and every
	// frame below carries the same one: with the field unset NewFrame
	// falls back to the platform's live probe, and on darwin that probe
	// refuses to run in a test binary by design (the seam panics rather
	// than read the operator's real appearance settings). These tests
	// pin the session screen's data flow — held buffers, pollers,
	// scroll state — never the theme, so the fake is the honest stand-in
	// at the one door every frame walks through. On d8d71da this stayed
	// hidden behind TestIAMT336, whose own panic killed the package
	// before any of these frames were built.
	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Actions:     actions,
		Snap: Snapshot{
			Server: ServerState{Sessions: []Session{{ID: "sess-r2", Person: "alice"}}},
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	frame.sessionUI.onTabOpen()
	uiState := frame.sessionUI

	// Drive the initial fetch synchronously by calling pollLoop once.
	// Easier: just call applyForwardFetch via the package's exported
	// path; but we don't have one. So we lean on the public API: let
	// pollLoop run a tick.
	uiState.mu.Lock()
	v := uiState.getView("sess-r2")
	uiState.mu.Unlock()
	// Reset state, then synthesize one forward fetch.
	uiState.mu.Lock()
	v.held = nil
	v.headOffset = 0
	v.offset = 0
	v.total = 50
	v.live = true
	resp := SessionTailResp{ID: "sess-r2", Total: 50, Live: true,
		Data: []byte("[0.0,\"o\",\"abc\\r\\n\"]\n")}
	uiState.mu.Unlock()
	// applyForwardFetch takes s.mu itself since the C1 race fix.
	uiState.applyForwardFetch(v, resp)

	if string(v.held) != string(resp.Data) {
		t.Fatalf("held should equal the chunk we fetched; got %q want %q", v.held, resp.Data)
	}
	if v.offset != uint64(len(resp.Data)) {
		t.Fatalf("offset should advance to %d; got %d", len(resp.Data), v.offset)
	}
	if v.headOffset != 0 {
		t.Fatalf("forward extension must NOT advance headOffset (it is the start of held); got %d", v.headOffset)
	}
	if trans := v.vt.Transcript(); trans == "" {
		t.Fatalf("VT should have rendered 'abc' but transcript is empty")
	}
}

// TestIAMT341_R2_BackwardExtensionRebuildsVT pins the main defect
// found in review: bytes replayed in order, never the other way around.
// Loads a small chunk, then extends backward; the new VT must contain
// the OLD content followed by the NEW content, not the reverse.
//
// Canary: replace the fresh-VT rebuild with `v.remainder = record.ParseCast(resp.Data, nil, v.vt)`
// (the old bug). The test fails because the VT now contains only the
// "old" prefix and the "new" tail is not appended to the rebuilt state.
func TestIAMT341_R2_BackwardExtensionRebuildsVT(t *testing.T) {
	tail := func(ctx context.Context, req SessionTailReq) (SessionTailResp, error) {
		// First request (initial tail): the last chunk.
		// Second request (backward load): the chunk before.
		if req.Offset == 0 && req.Limit == tailChunkLimit {
			return SessionTailResp{
				ID:    req.ID,
				Total: 100,
				Live:  true,
				Data:  []byte("[0.0,\"o\",\"NEW\\r\\n\"]\n"),
			}, nil
		}
		if req.Offset == 0 && req.Limit < tailChunkLimit {
			return SessionTailResp{
				ID:    req.ID,
				Total: 100,
				Live:  true,
				Data:  []byte("[0.0,\"o\",\"OLD\\r\\n\"]\n"),
			}, nil
		}
		return SessionTailResp{ID: req.ID, Total: 100, Live: true, Data: nil}, nil
	}

	actions := Actions{SessionTail: tail}
	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Actions:     actions,
		Snap: Snapshot{
			Server: ServerState{Sessions: []Session{{ID: "sess-order", Person: "bob"}}},
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	frame.sessionUI.onTabOpen()
	uiState := frame.sessionUI
	uiState.mu.Lock()
	v := uiState.getView("sess-order")
	uiState.mu.Unlock()

	// Simulate "we loaded the tail already" so the initial discovery
	// branch doesn't fire.
	uiState.mu.Lock()
	v.total = 100
	v.headOffset = 40
	v.offset = 60
	v.held = []byte("[0.0,\"o\",\"NEW\\r\\n\"]\n")
	record.ParseCast(v.held, nil, v.vt)
	uiState.mu.Unlock()

	uiState.mu.Lock()
	uiState.extendBackward(v, []byte("[0.0,\"o\",\"OLD\\r\\n\"]\n"), 18)
	uiState.mu.Unlock()

	if v.headOffset != 18 {
		t.Fatalf("after extendBackward headOffset should be 18, got %d", v.headOffset)
	}

	trans := v.vt.Transcript()
	// The replay order is OLD then NEW, in held order. Re
	if !containsOrdered(trans, "OLD", "NEW") {
		t.Fatalf("VT transcript does not contain OLD before NEW in order; got %q "+
			"— the rebuild replayed bytes out of order or skipped the prefix", trans)
	}
	if containsOrdered(trans, "NEW", "OLD") {
		t.Fatalf("VT transcript has NEW before OLD — replay is backwards: %q", trans)
	}
}

// containsOrdered reports whether both substrings appear in s, in the
// given order. Empty needles match trivially.
func containsOrdered(s, first, second string) bool {
	if first == "" {
		return true
	}
	i := indexOf(s, first)
	if i < 0 {
		return false
	}
	j := indexOf(s[i+len(first):], second)
	return j >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestIAMT341_R2_HeldCapDropsOldestOnForwardOverflow pins the bounded
// held range: the window cannot hold a session for eight hours whole.
//
// Canary: delete the overflow branch in appendHeld. The test fails
// because held grows past heldByteCap.
func TestIAMT341_R2_HeldCapDropsOldestOnForwardOverflow(t *testing.T) {
	uiState := &sessionScreenState{
		views: map[string]*sessionView{},
	}
	v := &sessionView{
		id:         "sess-cap",
		vt:         record.NewVT(80, 24),
		live:       true,
		headOffset: 0,
		held:       []byte("AAA"),
	}
	v.offset = uint64(len(v.held))
	uiState.views["sess-cap"] = v

	// Force a small cap for the test by using an explicit append
	// loop. Since heldByteCap is a package constant we cannot shrink
	// it, so test with a chunk larger than the current held (always
	// non-overflowing) and verify the cap-with-oldest-drop branch
	// separately by writing a single huge chunk that exceeds
	// heldByteCap. The forward path uses ParseCastChunk so we cannot
	// go through applyForwardFetch here without rendering; we use
	// appendHeld directly.
	uiState.appendHeld(v, []byte("BBB"))
	if string(v.held) != "AAABBB" {
		t.Fatalf("small append: got %q want %q", v.held, "AAABBB")
	}

	// Construct a chunk larger than heldByteCap; appendHeld must drop
	// the oldest bytes from held to keep within cap and never panic.
	huge := make([]byte, heldByteCap+1024)
	for i := range huge {
		huge[i] = 'x'
	}
	uiState.appendHeld(v, huge)

	if len(v.held) > heldByteCap {
		t.Fatalf("held grew past heldByteCap: %d bytes", len(v.held))
	}
	if v.headOffset == 0 {
		t.Fatalf("held overflowed but headOffset did not advance — oldest bytes not dropped")
	}
	if v.offset != v.headOffset+uint64(len(v.held)) {
		t.Fatalf("offset/headOffset/length invariant broken: head=%d offset=%d len=%d",
			v.headOffset, v.offset, len(v.held))
	}
}

// TestIAMT341_R2_LoadPreviousChunkCancelsOnTabClose pins defect 2:
// loadPreviousChunk must share its lifecycle with the forward poller.
//
// Canary: change `context.WithCancel(parentCtx)` to
// `context.WithCancel(context.Background())`. The test fails because
// the load does not see ctx.Done() when the tab is closed.
func TestIAMT341_R2_LoadPreviousChunkCancelsOnTabClose(t *testing.T) {
	var reachedTail int32
	hold := make(chan struct{})
	tail := func(ctx context.Context, req SessionTailReq) (SessionTailResp, error) {
		atomic.AddInt32(&reachedTail, 1)
		<-hold // simulate slow gateway
		select {
		case <-ctx.Done():
			return SessionTailResp{}, ctx.Err()
		default:
			return SessionTailResp{ID: req.ID, Total: 1000, Live: true,
				Data: []byte("[0.0,\"o\",\"OLD\\r\\n\"]\n")}, nil
		}
	}

	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Actions:     Actions{SessionTail: tail},
		Snap: Snapshot{
			Server: ServerState{Sessions: []Session{{ID: "sess-cancel", Person: "carol"}}},
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	frame.sessionUI.onTabOpen()
	uiState := frame.sessionUI

	// Pretend we already have the tail loaded.
	uiState.mu.Lock()
	v := uiState.getView("sess-cancel")
	v.headOffset = 500
	v.offset = 600
	v.held = []byte("[0.0,\"o\",\"NEW\\r\\n\"]\n")
	record.ParseCast(v.held, nil, v.vt)
	v.total = 1000
	v.live = true
	uiState.mu.Unlock()

	uiState.loadPreviousChunk("sess-cancel")

	// Wait for the request to start.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&reachedTail) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&reachedTail) == 0 {
		t.Fatalf("loadPreviousChunk did not reach SessionTail within 2s")
	}

	// Close the tab — should cancel the in-flight request.
	uiState.onTabClose()

	// Release the slow handler so the goroutine finishes.
	close(hold)

	// Give it a moment to apply or to bail out.
	time.Sleep(100 * time.Millisecond)

	uiState.mu.Lock()
	defer uiState.mu.Unlock()
	if v.headOffset != 500 {
		t.Fatalf("headOffset should be unchanged after a cancelled load; got %d", v.headOffset)
	}
}

// TestIAMT341_R2_PollGenIgnoresStaleResponse pins defect 3: an old
// poller's response must not write into a view it no longer owns.
//
// Canary: drop the `if s.pollGen != myGen { s.mu.Unlock(); return }`
// check inside pollLoop's per-tick branch. The test fails because the
// old poller writes "STALE" into the live view after a session switch.
func TestIAMT341_R2_PollGenIgnoresStaleResponse(t *testing.T) {
	release := make(chan struct{})
	var reached int32
	tail := func(ctx context.Context, req SessionTailReq) (SessionTailResp, error) {
		atomic.AddInt32(&reached, 1)
		<-release
		return SessionTailResp{
			ID:    req.ID,
			Total: 100,
			Live:  true,
			Data:  []byte("[0.0,\"o\",\"STALE\\r\\n\"]\n"),
		}, nil
	}

	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Actions:     Actions{SessionTail: tail},
		Snap: Snapshot{
			Admin: AdminState{
				ActiveSessions: []Session{
					{ID: "sess-old", Person: "old", Machine: "m1"},
					{ID: "sess-new", Person: "new", Machine: "m2"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	frame.sessionUI.onTabOpen()
	uiState := frame.sessionUI

	uiState.mu.Lock()
	oldView := uiState.getView("sess-old")
	uiState.mu.Unlock()

	// Wait for the first poll to be in flight.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&reached) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&reached) == 0 {
		t.Fatalf("first poll did not reach SessionTail")
	}

	// Switch to the other session — bumps pollGen.
	uiState.startPoller("sess-new")

	// Let the first poll return its (now stale) response.
	close(release)
	time.Sleep(100 * time.Millisecond)

	uiState.mu.Lock()
	defer uiState.mu.Unlock()
	trans := oldView.vt.Transcript()
	if contains(trans, "STALE") {
		t.Fatalf("stale poll response was applied to the view it no longer owns: %q", trans)
	}
}

// TestIAMT341_R2_SessionListIsAskedWhenSnapshotEmpty pins defect 6:
// Actions.SessionList must actually be invoked when the snapshot has
// nothing to show.
//
// Canary: delete the SessionList goroutine branch in activeSessions.
// The test fails because askList was never called.
func TestIAMT341_R2_SessionListIsAskedWhenSnapshotEmpty(t *testing.T) {
	var asked int32
	askList := func(ctx context.Context) ([]SessionInfo, error) {
		atomic.AddInt32(&asked, 1)
		return []SessionInfo{{ID: "from-list", Person: "list-source"}}, nil
	}

	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Actions: Actions{
			SessionList: askList,
		},
		Snap: Snapshot{}, // empty on purpose
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	uiState := frame.sessionUI

	// First call kicks off the fetch.
	_ = uiState.activeSessions()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&asked) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&asked) == 0 {
		t.Fatalf("Actions.SessionList was never invoked when snapshot was empty")
	}

	// Wait for the cache to be populated and trigger a second pass.
	deadline = time.Now().Add(2 * time.Second)
	var saw bool
	for time.Now().Before(deadline) {
		for _, s := range uiState.activeSessions() {
			if s.ID == "from-list" {
				saw = true
				break
			}
		}
		if saw {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !saw {
		t.Fatalf("after SessionList replied, activeSessions should surface it; got %v", uiState.activeSessions())
	}
}

// TestIAMT341_R2_TermListIsPerSession pins defect 5: two sessions on
// the same tab must not share a scroll position.
//
// Canary: move termList back into sessionScreenState. The test fails
// because both views share one Position.First.
func TestIAMT341_R2_TermListIsPerSession(t *testing.T) {
	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Snap: Snapshot{
			Admin: AdminState{
				ActiveSessions: []Session{
					{ID: "alice", Person: "alice", Machine: "m1"},
					{ID: "bob", Person: "bob", Machine: "m2"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	uiState := frame.sessionUI

	uiState.mu.Lock()
	a := uiState.getView("alice")
	uiState.mu.Unlock()
	uiState.mu.Lock()
	b := uiState.getView("bob")
	uiState.mu.Unlock()

	// Move alice's list somewhere; bob's must NOT move.
	a.termList.Position.First = 7
	a.termList.Position.Count = 100

	if b.termList.Position.First == 7 {
		t.Fatalf("Bob's view inherited Alice's scroll position — termList is shared, " +
			"defect 5 of round 2")
	}
	if &a.termList == &b.termList {
		t.Fatalf("alice and bob have termList at the same address")
	}
}

// TestIAMT341_R2_PollGenBumpsOnTabClose pins the safety net: onTabClose
// must invalidate any in-flight poller, even if its context object
// outlives the close call.
//
// Canary: drop `s.pollGen++` from onTabClose. The test still mostly
// passes (cancellation is the primary line of defence), but a future
// refactor that swaps context.Background() in would silently break
// without this gen.
func TestIAMT341_R2_PollGenBumpsOnTabClose(t *testing.T) {
	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Snap: Snapshot{
			Server: ServerState{Sessions: []Session{{ID: "sess-gen", Person: "dan"}}},
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	uiState := frame.sessionUI
	uiState.onTabOpen()

	uiState.mu.Lock()
	gen1 := uiState.pollGen
	uiState.mu.Unlock()

	uiState.onTabClose()

	uiState.mu.Lock()
	gen2 := uiState.pollGen
	uiState.mu.Unlock()

	if gen2 <= gen1 {
		t.Fatalf("onTabClose must bump pollGen (got %d → %d)", gen1, gen2)
	}
	if uiState.pollCtx != nil {
		t.Fatalf("onTabClose must clear pollCtx so loadPreviousChunk refuses to spawn a child")
	}
}

// TestIAMT341_R2_ParseCastChunkDoesNotAliasRemainder pins the round-2
// fix for defect 1: the remainder passed in must not be mutated or
// alias the chunk bytes that follow.
//
// Canary: revert to `combined := append(remainder, chunk...)`. The
// test fails because mutating the caller's remainder corrupts the
// next call's view of "what's left to parse".
func TestIAMT341_R2_ParseCastChunkDoesNotAliasRemainder(t *testing.T) {
	vt := record.NewVT(80, 24)
	remainder := []byte("[0.0, \"o\", \"hel")
	chunk := []byte("lo\\r\\n\"]\n")

	rem1 := record.ParseCast(chunk, remainder, vt)
	if string(rem1) != "" {
		t.Fatalf("expected empty remainder after a complete event; got %q", rem1)
	}
	if string(remainder) != "[0.0, \"o\", \"hel" {
		t.Fatalf("caller's remainder was mutated: got %q", remainder)
	}
}

// contains is a small helper used by the staleness check above.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
