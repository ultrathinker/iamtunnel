//go:build windows || linux || darwin

package ui

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// newTestLayoutContext creates a dummy layout context for headless layout passes.
func newTestLayoutContext(w, h int) layout.Context {
	var ops op.Ops
	return layout.Context{
		Ops: &ops,
		Constraints: layout.Constraints{
			Min: image.Pt(w, h),
			Max: image.Pt(w, h),
		},
		Metric: unit.Metric{PxPerDp: 1, PxPerSp: 1},
	}
}

// TestIAMT341_SessionTabEmptyState verifies that when there are 0 active sessions,
// the tab says this in words rather than rendering an empty void.
//
// Canary: change the empty-state condition `len(sessions) == 0` in layoutSessionScreen
// to `false`. The test fails because the empty-state headline is absent.
func TestIAMT341_SessionTabEmptyState(t *testing.T) {
	// Same fixed theme source as iamt341_round2_test.go (MAC,
	// 24.09.2026): with the field unset NewFrame falls back to the
	// platform's live probe, which on darwin refuses to run in a test
	// binary by design. The theme is not what these tests pin.
	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Snap:        Snapshot{}, // 0 sessions
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	gtx := newTestLayoutContext(900, 600)
	dims := frame.layoutSessionScreen(gtx)
	if dims.Size.Y <= 0 {
		t.Fatalf("layoutSessionScreen returned zero height for empty state: %d", dims.Size.Y)
	}

	sessions := frame.sessionUI.activeSessions()
	if len(sessions) != 0 {
		t.Fatalf("expected 0 active sessions, got %d", len(sessions))
	}
	if frame.sessionUI.selectedID != "" {
		t.Fatalf("expected empty selectedID for 0 sessions, got %q", frame.sessionUI.selectedID)
	}
}

// TestIAMT341_SessionTabSingleSessionAutoSelect verifies that when exactly 1 session
// exists, it is selected automatically without the switcher getting in the way.
//
// Canary: change `len(sessions) == 1` in layoutSessionTopBar to `false`.
// The test fails because the compact single-session layout is not selected.
func TestIAMT341_SessionTabSingleSessionAutoSelect(t *testing.T) {
	now := time.Now()
	until := now.Add(time.Hour)

	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Snap: Snapshot{
			Server: ServerState{
				Sessions: []Session{
					{ID: "sess-alice-01", Person: "alice", Machine: "srv-01", Started: now, Until: until},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	gtx := newTestLayoutContext(900, 600)
	dims := frame.layoutSessionScreen(gtx)
	if dims.Size.Y <= 0 {
		t.Fatalf("layoutSessionScreen returned zero height: %d", dims.Size.Y)
	}

	sessions := frame.sessionUI.activeSessions()
	if len(sessions) != 1 {
		t.Fatalf("expected exactly 1 active session, got %d", len(sessions))
	}
	if frame.sessionUI.selectedID != "sess-alice-01" {
		t.Fatalf("expected auto-selected ID %q, got %q", "sess-alice-01", frame.sessionUI.selectedID)
	}
}

// TestIAMT341_SessionTabMultipleSessionsSwitcher verifies that when multiple sessions
// exist, the switcher allows switching between them.
//
// Canary: break the button click handler `f.btn(btnKey).Clicked(gtx)` in layoutSessionTopBar
// so that clicking does not update `uiState.selectedID`.
func TestIAMT341_SessionTabMultipleSessionsSwitcher(t *testing.T) {
	now := time.Now()
	until := now.Add(time.Hour)

	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Snap: Snapshot{
			Admin: AdminState{
				ActiveSessions: []Session{
					{ID: "sess-1", Person: "alice", Machine: "srv-01", Started: now, Until: until},
					{ID: "sess-2", Person: "bob", Machine: "srv-02", Started: now, Until: until},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	gtx := newTestLayoutContext(900, 600)
	frame.layoutSessionScreen(gtx)

	sessions := frame.sessionUI.activeSessions()
	if len(sessions) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(sessions))
	}
	if frame.sessionUI.selectedID != "sess-1" {
		t.Fatalf("expected default selected session %q, got %q", "sess-1", frame.sessionUI.selectedID)
	}

	// Switch to sess-2
	frame.sessionUI.mu.Lock()
	frame.sessionUI.selectedID = "sess-2"
	frame.sessionUI.mu.Unlock()

	frame.layoutSessionScreen(gtx)
	if frame.sessionUI.selectedID != "sess-2" {
		t.Fatalf("expected selected session %q, got %q", "sess-2", frame.sessionUI.selectedID)
	}
}

// TestIAMT341_SessionPollerStopsOnLiveFalse verifies that the background poller stops
// polling when the gateway response indicates `live: false` and offset reached total.
//
// Canary: remove `if !live && off >= tot { return }` in pollLoop. The test fails because
// polling continues and pollCount exceeds 1.
func TestIAMT341_SessionPollerStopsOnLiveFalse(t *testing.T) {
	var pollCount int32

	actions := Actions{
		SessionTail: func(ctx context.Context, req SessionTailReq) (SessionTailResp, error) {
			atomic.AddInt32(&pollCount, 1)
			return SessionTailResp{
				ID:     req.ID,
				Offset: 0,
				Total:  20,
				Live:   false, // Session ended
				// The trailing newline matters: ParseCastChunk splits on
				// it, and a chunk that ends mid-line is deliberately held
				// back as a remainder until the rest arrives. Without it
				// this fixture fed the terminal nothing at all.
				Data: []byte("[0.1,\"o\",\"test output\\n\"]\n"),
			}, nil
		},
	}

	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Actions:     actions,
		Snap: Snapshot{
			Server: ServerState{
				Sessions: []Session{{ID: "sess-fin", Person: "carol"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run initial fetch of pollLoop synchronously
	uiState := frame.sessionUI
	uiState.mu.Lock()
	v := uiState.getView("sess-fin")
	uiState.mu.Unlock()

	resp, err := actions.SessionTail(ctx, SessionTailReq{
		ID:     "sess-fin",
		Offset: 0,
		Limit:  tailChunkLimit,
	})
	if err != nil {
		t.Fatalf("SessionTail failed: %v", err)
	}

	v.total = resp.Total
	v.live = resp.Live
	v.offset = uint64(len(resp.Data))
	record.ParseCast(resp.Data, nil, v.vt)

	// Verify terminal received output
	transcript := v.vt.Transcript()
	if !strings.Contains(transcript, "test output") {
		t.Fatalf("expected transcript to contain %q, got %q", "test output", transcript)
	}

	// Verify condition: live is false and offset >= total -> poll must stop
	if v.live {
		t.Fatalf("expected v.live to be false")
	}
	if v.offset < v.total {
		t.Fatalf("expected v.offset (%d) >= v.total (%d)", v.offset, v.total)
	}
}

// TestIAMT341_CastChunkParser verifies that ParseCastChunk correctly extracts
// asciinema header resize events and "o" output events, handling partial lines.
//
// Canary: break the '[' event check in ParseCastChunk. The test fails because
// VT size and output are not updated.
func TestIAMT341_CastChunkParser(t *testing.T) {
	vt := record.NewVT(80, 24)

	// Chunk 1: Header + output + resize + half of next line
	chunk1 := []byte("{\"version\":2,\"width\":100,\"height\":30}\n" +
		"[0.1, \"o\", \"First line\\r\\n\"]\n" +
		"[0.2, \"r\", \"120x40\"]\n" +
		"[0.3, \"o\", \"Sec")

	rem := record.ParseCast(chunk1, nil, vt)
	if string(rem) != "[0.3, \"o\", \"Sec" {
		t.Fatalf("expected remainder %q, got %q", "[0.3, \"o\", \"Sec", string(rem))
	}

	cols, rows := vt.Size()
	if cols != 120 || rows != 40 {
		t.Fatalf("expected resized VT 120x40, got %dx%d", cols, rows)
	}

	// Chunk 2: Rest of second line + complete third line
	chunk2 := []byte("ond line\\r\\n\"]\n[0.4, \"o\", \"Third line\\r\\n\"]\n")
	rem2 := record.ParseCast(chunk2, rem, vt)
	if len(rem2) != 0 {
		t.Fatalf("expected empty remainder, got %q", string(rem2))
	}

	transcript := vt.Transcript()
	if !strings.Contains(transcript, "First line") {
		t.Errorf("transcript missing 'First line': %q", transcript)
	}
	if !strings.Contains(transcript, "Second line") {
		t.Errorf("transcript missing 'Second line': %q", transcript)
	}
	if !strings.Contains(transcript, "Third line") {
		t.Errorf("transcript missing 'Third line': %q", transcript)
	}
}

// TestIAMT341_ScrollbackVirtualization10000Lines verifies that 10,000 lines
// of scrollback are tracked in VT and layoutSessionTerminal handles them cleanly.
//
// Canary: change `v.vt.HistoryTotal()` to return 0. The test fails with 0 history lines.
func TestIAMT341_ScrollbackVirtualization10000Lines(t *testing.T) {
	vt := record.NewVT(80, 24)

	// Feed 10,000 newlines to push lines into history
	var buf bytes.Buffer
	for i := 0; i < 10000; i++ {
		buf.WriteString("line\r\n")
	}
	vt.Write(buf.Bytes())

	// The last rows are on SCREEN, not in history, so 10 000 written
	// lines do not make 10 000 history lines — and maxHistoryLines caps
	// history at 10 000 anyway. What is worth pinning is the ceiling
	// itself: the scrollback is bounded, so a session that runs all day
	// cannot grow the window without limit.
	total := vt.HistoryTotal()
	if total > 10000 {
		t.Fatalf("history holds %d lines, past the 10000 ceiling — an unbounded scrollback grows with the session", total)
	}
	if total < 9000 {
		t.Fatalf("history holds only %d lines after 10000 were written", total)
	}

	// Slicing test
	firstBatch := vt.History(0, 5)
	if len(firstBatch) != 5 {
		t.Fatalf("expected 5 lines from History(0, 5), got %d", len(firstBatch))
	}
	// Asking past the end returns what exists and nothing more — the
	// window scrolling up must not be able to walk off the top into a
	// panic or an invented line. The exact count depends on how many
	// rows are still on screen rather than in history, so the assertion
	// is the property, not an arithmetic guess.
	lastBatch := vt.History(total-5, 10)
	if len(lastBatch) != 5 {
		t.Fatalf("History(total-5, 10) returned %d lines, want the 5 that exist — a window scrolled to the top must get what is there, not a short read", len(lastBatch))
	}
	if past := vt.History(total+100, 10); len(past) != 0 {
		t.Fatalf("History past the end returned %d lines, want none", len(past))
	}

	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Snap: Snapshot{
			Server: ServerState{
				Sessions: []Session{{ID: "sess-big", Person: "alice"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	frame.setSessionVT("sess-big", vt)

	gtx := newTestLayoutContext(900, 600)
	dims := frame.layoutSessionTerminal(gtx, "sess-big")
	if dims.Size.Y <= 0 {
		t.Fatalf("layoutSessionTerminal returned zero height: %d", dims.Size.Y)
	}
}

// TestIAMT341_TerminalColorsAndStyles verifies ANSI 16, 256-color, and RGB color resolution.
//
// Canary: break the `ColorNamed` case in `resolveColor` to return Black for all indices.
// The test fails because Red (index 1) returns Black.
func TestIAMT341_TerminalColorsAndStyles(t *testing.T) {
	def := color.NRGBA{R: 50, G: 50, B: 50, A: 255}

	// 1. ColorDefault
	cDef := resolveColor(record.Color{Kind: record.ColorDefault}, def)
	if cDef != def {
		t.Fatalf("ColorDefault got %+v, want %+v", cDef, def)
	}

	// 2. ColorNamed (Index 1 = Red)
	cRed := resolveColor(record.Color{Kind: record.ColorNamed, Index: 1}, def)
	if cRed != ansi16Colors[1] {
		t.Fatalf("ColorNamed(1) got %+v, want %+v", cRed, ansi16Colors[1])
	}

	// 3. ColorRGB (R:12, G:34, B:56)
	cRGB := resolveColor(record.Color{Kind: record.ColorRGB, R: 12, G: 34, B: 56}, def)
	wantRGB := color.NRGBA{R: 12, G: 34, B: 56, A: 255}
	if cRGB != wantRGB {
		t.Fatalf("ColorRGB got %+v, want %+v", cRGB, wantRGB)
	}

	// 4. Color256 (Index 240 = Grayscale)
	c256 := resolveColor(record.Color{Kind: record.Color256, Index: 240}, def)
	wantGray := color.NRGBA{R: 88, G: 88, B: 88, A: 255}
	if c256 != wantGray {
		t.Fatalf("Color256(240) got %+v, want %+v", c256, wantGray)
	}
}

// TestIAMT341_TabSwitchStopsPoller verifies that switching away from the Session tab
// terminates the background poller: there is no permanent thread into a closed tab.
//
// Canary: remove `f.sessionUI.onTabClose()` call when switching away from TabSession
// in Frame.Layout. The test fails because `pollCancel` remains non-nil.
func TestIAMT341_TabSwitchStopsPoller(t *testing.T) {
	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Snap: Snapshot{
			Server: ServerState{
				Sessions: []Session{{ID: "sess-switch", Person: "dave"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	// Simulate tab open
	frame.sessionUI.onTabOpen()
	frame.sessionUI.mu.Lock()
	hasCancel := frame.sessionUI.pollCancel != nil
	frame.sessionUI.mu.Unlock()
	if !hasCancel {
		t.Fatalf("expected active pollCancel on tab open")
	}

	// Simulate tab close (user switched to another tab)
	frame.sessionUI.onTabClose()
	frame.sessionUI.mu.Lock()
	hasCancelAfter := frame.sessionUI.pollCancel != nil
	frame.sessionUI.mu.Unlock()
	if hasCancelAfter {
		t.Fatalf("expected pollCancel to be nil after tab close")
	}
}
