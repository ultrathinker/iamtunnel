//go:build linux && !nogui

package main

// iamt309_softwaregl_linux_test.go — IAMT-309: a live run on a real
// graphical session (GNOME/Xorg, a VirtualBox VM with no 3D
// acceleration) showed iamtunnel opening a window that was entirely
// black — not one pixel of interface — with stdout and stderr both
// completely empty, the process alive, and no way for a person to act
// on it. The same binary on the same display drew every screen
// correctly the moment LIBGL_ALWAYS_SOFTWARE=1 was set by hand.
// ensureSoftwareGL (gui_linux.go) makes that fix automatic and makes
// the console say which rendering path it took — never silent, in
// either direction.
//
// Round 4 (F-GUI-1) tried to decide from evidence instead of forcing
// unconditionally — a working DRM render node (/dev/dri/renderD*) — to
// avoid a performance regression on real hardware. Round 5's live run on
// the very VM this item was filed for proved that evidence unreliable:
// its render node exists while its hardware GL is not actually usable,
// so the heuristic (a) left the original black window exactly where it
// started and (b) made softwareGLActive report "hardware" wrongly,
// which silently defeated the elevated-display refusal too (it never
// got to look at Wayland or XAUTHORITY). ensureSoftwareGL/softwareGLActive
// are back to forcing/assuming software unconditionally, absent an
// explicit LIBGL_ALWAYS_SOFTWARE either way — see gui_linux.go's own
// comment for the full reasoning.
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

// setenvCall records one linuxSetenv invocation.
type setenvCall struct{ key, value string }

// TestIAMT309_EnsureSoftwareGLForcesItByDefault pins the default path: an
// environment with no LIBGL_ALWAYS_SOFTWARE at all gets it set to "1"
// before anything else, and the console says so.
//
// Canary: drop the linuxSetenv call (or stop checking its error) from
// ensureSoftwareGL. This test goes red on:
//
//	ensureSoftwareGL did not force software rendering — a display with
//	no working hardware OpenGL will open a silent black window again
//	(IAMT-309)
func TestIAMT309_EnsureSoftwareGLForcesItByDefault(t *testing.T) {
	var calls []setenvCall
	seamSwap(t, &linuxSetenv, func(key, value string) error {
		calls = append(calls, setenvCall{key, value})
		return nil
	})

	var errs bytes.Buffer
	s := &streams{errs: &errs, env: map[string]string{}}

	ensureSoftwareGL(s)

	if len(calls) != 1 || calls[0] != (setenvCall{"LIBGL_ALWAYS_SOFTWARE", "1"}) {
		t.Fatalf("ensureSoftwareGL did not force software rendering — a display with no working hardware OpenGL will open a silent black window again (IAMT-309); linuxSetenv calls = %v", calls)
	}
	if !strings.Contains(errs.String(), "forcing software OpenGL rendering") || !strings.Contains(errs.String(), "LIBGL_ALWAYS_SOFTWARE=1") {
		t.Fatalf("ensureSoftwareGL forced software rendering silently — stderr = %q, want it to say so", errs.String())
	}
}

// TestIAMT309_EnsureSoftwareGLRespectsAnExplicitSetting pins the escape
// hatch: a person who already set LIBGL_ALWAYS_SOFTWARE (to force it, or
// to "0"/"false" to test hardware GL on purpose) is left alone — this is
// a default, not an override.
//
// Canary: drop the "already set" guard and always call linuxSetenv. This
// test goes red with:
//
//	ensureSoftwareGL overrode an explicitly set LIBGL_ALWAYS_SOFTWARE=0 —
//	a person testing hardware OpenGL on purpose would never see it run
func TestIAMT309_EnsureSoftwareGLRespectsAnExplicitSetting(t *testing.T) {
	var calls []setenvCall
	seamSwap(t, &linuxSetenv, func(key, value string) error {
		calls = append(calls, setenvCall{key, value})
		return nil
	})

	var errs bytes.Buffer
	s := &streams{errs: &errs, env: map[string]string{"LIBGL_ALWAYS_SOFTWARE": "0"}}

	ensureSoftwareGL(s)

	if len(calls) != 0 {
		t.Fatalf("ensureSoftwareGL overrode an explicitly set LIBGL_ALWAYS_SOFTWARE=0 — a person testing hardware OpenGL on purpose would never see it run; calls = %v", calls)
	}
	if errs.String() != "" {
		t.Fatalf("ensureSoftwareGL wrote %q to stderr although the setting was already explicit — nothing to announce", errs.String())
	}
}

// TestIAMT309_EnsureSoftwareGLReportsASetenvFailure pins the failure
// path: a setenv that itself fails must say so — never claim success —
// so a black window is at least accompanied by a reason on the console.
//
// Canary: swallow linuxSetenv's error. This test goes red with:
//
//	ensureSoftwareGL swallowed a setenv failure — stderr carried no
//	explanation for why the window may still open black
func TestIAMT309_EnsureSoftwareGLReportsASetenvFailure(t *testing.T) {
	seamSwap(t, &linuxSetenv, func(string, string) error { return errors.New("read-only environment") })

	var errs bytes.Buffer
	s := &streams{errs: &errs, env: map[string]string{}}

	ensureSoftwareGL(s)

	if !strings.Contains(errs.String(), "could not force software OpenGL rendering") || !strings.Contains(errs.String(), "read-only environment") {
		t.Fatalf("ensureSoftwareGL swallowed a setenv failure — stderr carried no explanation for why the window may still open black; got %q", errs.String())
	}
	if strings.Contains(errs.String(), "forcing software OpenGL rendering") {
		t.Fatalf("ensureSoftwareGL claimed success (%q) after linuxSetenv failed", errs.String())
	}
}

// TestIAMT309_RunGUIForcesSoftwareGLBeforeTheWindow proves the wiring,
// not just the function in isolation: runGUI must call ensureSoftwareGL
// before it ever reaches the window launcher, so a display with no
// hardware OpenGL never gets as far as a black or blank window.
//
// Canary: remove the ensureSoftwareGL call from runGUI (gui_linux.go).
// This test goes red with:
//
//	runGUI never forced software OpenGL rendering — a display with no
//	working hardware OpenGL reaches the window unprotected (IAMT-309)
func TestIAMT309_RunGUIForcesSoftwareGLBeforeTheWindow(t *testing.T) {
	var calls []setenvCall
	seamSwap(t, &linuxSetenv, func(key, value string) error {
		calls = append(calls, setenvCall{key, value})
		return nil
	})
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		return errors.New("window launcher not reached in this test")
	})

	var errs bytes.Buffer
	s := &streams{
		in:   strings.NewReader(""),
		out:  &bytes.Buffer{},
		errs: &errs,
		env:  testsupport.PlatformDataEnv(t),
	}
	runGUI(s)

	if len(calls) != 1 || calls[0] != (setenvCall{"LIBGL_ALWAYS_SOFTWARE", "1"}) {
		t.Fatalf("runGUI never forced software OpenGL rendering — a display with no working hardware OpenGL reaches the window unprotected (IAMT-309); linuxSetenv calls = %v", calls)
	}
	if !strings.Contains(errs.String(), "forcing software OpenGL rendering") {
		t.Fatalf("runGUI's stderr did not report the forced rendering path, got: %q", errs.String())
	}
}

// TestFGUI1_EnsureSoftwareGLAlwaysForcesRegardlessOfLocalHardware is
// round 5's canary for the reverted decision (review round 21 accepted
// round 4's render-node heuristic as "conservative"; a live run on the
// actual VM this item was filed for then showed it forces the wrong way
// — a render node present, hardware GL not usable, the window solid
// black again): with no explicit override, ensureSoftwareGL must force
// software UNCONDITIONALLY, never deferring to any local-hardware
// evidence.
//
// Canary: reintroduce a render-node (or any other local-hardware) check
// that can skip the setenv call. This test goes red on:
//
//	ensureSoftwareGL did not force software rendering unconditionally —
//	a live run proved a present render node is not proof of usable
//	hardware GL (round 4/F-GUI-1 reverted, round 5)
func TestFGUI1_EnsureSoftwareGLAlwaysForcesRegardlessOfLocalHardware(t *testing.T) {
	var calls []setenvCall
	seamSwap(t, &linuxSetenv, func(key, value string) error {
		calls = append(calls, setenvCall{key, value})
		return nil
	})

	var errs bytes.Buffer
	s := &streams{errs: &errs, env: map[string]string{}}

	ensureSoftwareGL(s)

	if len(calls) != 1 || calls[0] != (setenvCall{"LIBGL_ALWAYS_SOFTWARE", "1"}) {
		t.Fatalf("ensureSoftwareGL did not force software rendering unconditionally — a live run proved a present render node is not proof of usable hardware GL (round 4/F-GUI-1 reverted, round 5); linuxSetenv calls = %v", calls)
	}
}

// TestFGUI1_SoftwareGLActiveIsTrueByDefaultRegardlessOfLocalHardware
// pins softwareGLActive against the same reverted decision: it must
// agree with ensureSoftwareGL's own unconditional default, or the
// elevated-display refusal (which gates on softwareGLActive) can again
// be silently skipped by a wrong "hardware" guess — exactly how round
// 4's heuristic defeated LIVE FINDING 2 in round 5's report.
//
// Canary: make softwareGLActive consult any local-hardware signal when
// LIBGL_ALWAYS_SOFTWARE is unset. This test goes red on:
//
//	softwareGLActive(unset) = false — must default to true regardless
//	of local hardware, or the elevated refusal can be silently skipped
//	again (round 5)
func TestFGUI1_SoftwareGLActiveIsTrueByDefaultRegardlessOfLocalHardware(t *testing.T) {
	s := &streams{env: map[string]string{}}
	if got := softwareGLActive(s); !got {
		t.Fatalf("softwareGLActive(unset) = %v, want true — must default to true regardless of local hardware, or the elevated refusal can be silently skipped again (round 5)", got)
	}
}
