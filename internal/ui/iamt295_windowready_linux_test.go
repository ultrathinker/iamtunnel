//go:build linux

package ui

// iamt295_windowready_linux_test.go — IAMT-295, round 3 (round 4 added
// the submit ordering): the two things the Linux restart handover needs
// from the frame — the OnWindowReady one-shot (the ready line may only
// ever mean a frame SUBMITTED to the window system, so a display the
// root session cannot reach reads as a child that exited without the
// line), and the restart action's error path resetting its restarting
// flag, so a failed or abandoned attempt leaves the button alive.
//
// Nothing here opens a real window: a FrameEvent is fabricated with
// app.NewContext, the same headless shape gio's own widget tests use,
// and NewFrame's theme probe is pinned to a seam that answers nothing —
// a test binary never launches gsettings/kreadconfig.
//
// Run on the Linux host: go test -count=1 ./internal/ui/

import (
	"errors"
	"image"
	"testing"
	"time"

	"gioui.org/app"
	"gioui.org/op"
)

// silentTheme keeps NewFrame off the desktop: the default theme source
// asks gsettings/kreadconfig through probeExec, and no test binary
// launches a program.
func silentTheme(t *testing.T) {
	t.Helper()
	orig := probeExec
	probeExec = func(string, ...string) ([]byte, error) {
		return nil, errors.New("tests launch nothing")
	}
	t.Cleanup(func() { probeExec = orig })
}

// drawFrame lays one full frame out into a throwaway ops list — no
// window, no main loop. Layout alone no longer acknowledges a window
// (that is drawSubmittedFrame's job, with the submission); this helper
// is for tests that only need the frame drawn, not the handover.
func drawFrame(t *testing.T, f *Frame) {
	t.Helper()
	var ops op.Ops
	gtx := app.NewContext(&ops, app.FrameEvent{
		Size:  image.Pt(800, 600),
		Frame: func(*op.Ops) {},
	})
	f.Layout(gtx)
}

// TestIAMT295_ReadyFiresOnlyAfterTheFrameIsSubmitted pins the ordering
// the round-4 review demanded: the callback does NOT fire when Layout
// returns — its operations are built, but nobody has handed them to the
// window system yet, and a submission can still fail or meet a
// DestroyEvent in that gap. It fires once frameSubmit (the FrameEvent's
// own e.Frame call) has returned, in the window loop
// (drawSubmittedFrame), exactly once across frames.
//
// Canary: move the firing back into Frame.Layout (the round-3 shape,
// `defer f.windowReady()`). The recorded order flips and this test goes
// red with:
//
//	after one frame event the order was [ready submit], want [submit
//	ready] — Layout returning is not a window: the ops were built, but
//	the window system has not even seen them, and a ready line sent
//	then can confirm a handover whose frame is never shown
func TestIAMT295_ReadyFiresOnlyAfterTheFrameIsSubmitted(t *testing.T) {
	silentTheme(t)
	fired := 0
	var order []string
	f, err := NewFrame(FrameConfig{
		Enrolled: true,
		OnWindowReady: func() {
			fired++
			order = append(order, "ready")
		},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	if fired != 0 {
		t.Fatal("OnWindowReady fired before any frame — a window that never came up would announce itself")
	}

	// The fabricated event's Frame hook records "submit": through the
	// production seam body (frameSubmit → e.Frame) it is exactly the step
	// that hands the operations to the window system.
	var ops op.Ops
	e := app.FrameEvent{
		Size:  image.Pt(800, 600),
		Frame: func(*op.Ops) { order = append(order, "submit") },
	}
	f.drawSubmittedFrame(e, &ops)

	if len(order) != 2 || order[0] != "submit" || order[1] != "ready" {
		t.Fatalf("after one frame event the order was %v, want [submit ready] — Layout returning is not a window: the ops were built, but the window system has not even seen them, and a ready line sent then can confirm a handover whose frame is never shown", order)
	}

	f.drawSubmittedFrame(e, &ops)
	f.drawSubmittedFrame(e, &ops)
	if fired != 1 {
		t.Fatalf("OnWindowReady fired %d time(s) after 3 submitted frames, want exactly 1 — the ready line is a one-shot birth certificate, not a per-frame heartbeat", fired)
	}
}

// TestIAMT295_RestartErrorResetsTheButton pins the recovery path: the
// restart action runs OFF the drawing goroutine (frame.go), and any
// error it returns — a declined dialog, a timed-out wait — resets
// restarting and is said under the Server Start control, so the button
// works again. A stuck flag would be the hung-pkexec finding: one
// failure and the action is dead for the window's whole life.
//
// Canary: forget the `f.restarting = false` on the error path in
// frame.go. This test goes red with:
//
//	the failed restart left restarting=true — one failure must not kill
//	the button for the window's whole life
func TestIAMT295_RestartErrorResetsTheButton(t *testing.T) {
	silentTheme(t)
	started := make(chan struct{}, 4)
	f, err := NewFrame(FrameConfig{Enrolled: true})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	f.cfg.Actions.RestartAsAdmin = func() error {
		started <- struct{}{}
		return errors.New("pkexec did not answer within 5m0s")
	}

	btn := f.btn(ctlRestartAdmin)
	btn.Click()
	drawFrame(t, f)
	select {
	case <-started:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("the first press never started the restart action")
	}
	// The action's goroutine has its answer and must reset the flag;
	// wait for that to land before pressing again.
	deadline := time.Now().Add(200 * time.Millisecond)
	for {
		f.mu.Lock()
		stuck := f.restarting
		f.mu.Unlock()
		if !stuck {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the failed restart left restarting=true — one failure must not kill the button for the window's whole life")
		}
		time.Sleep(2 * time.Millisecond)
	}

	btn.Click()
	drawFrame(t, f)
	select {
	case <-started:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("the second press never started the action again — a failed restart must reset the restarting flag, or one failure kills the button for the window's whole life")
	}
}
