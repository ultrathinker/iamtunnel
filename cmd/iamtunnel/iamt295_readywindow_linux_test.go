//go:build linux && !nogui

package main

// iamt295_readywindow_linux_test.go — IAMT-295, round 3: the canary for
// the "confirmed too early" finding. runGUI must hand the restart
// handover to the frame's OnWindowReady and must NOT announce before the
// window exists; a window that never comes up (root without a usable
// Wayland/X display is the realistic case) must read, in the original,
// as pkexec exiting without the ready line — an error, the original
// window stays.
//
// This is the one test that reaches the window launcher itself, through
// the linuxUIRun seam — and therefore the one that imports internal/ui
// (gioui.org/app rides along, which is why it does not live in
// iamt254_gui_linux_test.go: a GOOS=linux CGO_ENABLED=0 cross type-check
// cannot load that chain; the Linux VM, CGO_ENABLED=1, can).
//
// Run on the Linux host: go test -count=1 ./cmd/iamtunnel/

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// TestIAMT295_ReadyLineOnlyAfterTheWindowIsUp pins the wiring: the
// marker is the window's FIRST FRAME, not a promise made before
// ui.Run, and a failed window start fails loudly on the child's stderr
// (which the original captures into its error message).
//
// Canary: move the announce back in front of the window launcher (the
// round-2 shape, gui_linux.go calling announceElevatedSession() before
// linuxUIRun). This test goes red with:
//
//	the ready line went out with no window at all ("iamtunnel: elevated
//	session ready" / "") — the marker must be the window's first frame,
//	not a promise made before ui.Run
func TestIAMT295_ReadyLineOnlyAfterTheWindowIsUp(t *testing.T) {
	t.Run("a window that never came up announces nothing", func(t *testing.T) {
		seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
		seamSwap(t, &linuxStdoutIsTTY, func() bool { return false })
		seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
		r := armAnnounce(t)
		seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
			if cfg.OnWindowReady == nil {
				t.Error("runGUI handed the frame no OnWindowReady — the handover could never be confirmed")
			}
			return errors.New("cannot open display")
		})

		var errs bytes.Buffer
		s := &streams{
			in:   strings.NewReader(""),
			out:  &bytes.Buffer{},
			errs: &errs,
			env:  testsupport.PlatformDataEnv(t),
		}
		if code := runGUI(s); code != exitInternal {
			t.Fatalf("runGUI after a window failure = %d, want %d", code, exitInternal)
		}
		if !strings.Contains(errs.String(), "could not start the window") {
			t.Fatalf("a failed window start must say so on stderr, got: %q", errs.String())
		}
		if r.announcedAnywhere() {
			t.Fatalf("the ready line went out with no window at all (%q) — the marker must be the window's first frame, not a promise made before ui.Run", r.marker)
		}
	})

	t.Run("the window's first frame is the announce", func(t *testing.T) {
		seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
		seamSwap(t, &linuxStdoutIsTTY, func() bool { return false })
		seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
		r := armAnnounce(t)
		seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
			if cfg.OnWindowReady == nil {
				t.Error("runGUI handed the frame no OnWindowReady — the handover could never be confirmed")
				return errors.New("no hook")
			}
			cfg.OnWindowReady() // the frame came up: the hook fires
			return errors.New("closed")
		})

		s := &streams{
			in:   strings.NewReader(""),
			out:  &bytes.Buffer{},
			errs: &bytes.Buffer{},
			env:  testsupport.PlatformDataEnv(t),
		}
		runGUI(s)

		if r.marker != elevatedReadyLine+"\n" {
			t.Fatalf("the frame's OnWindowReady fired, yet the marker did not go out on the saved pipe (%q)", r.marker)
		}
	})
}
