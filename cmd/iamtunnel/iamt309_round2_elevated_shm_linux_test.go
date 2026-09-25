//go:build linux && !nogui

package main

// iamt309_round2_elevated_shm_linux_test.go — IAMT-309 round 2: the
// SAME binary started as root on the SAME display
// ("sudo -E DISPLAY=:1 XAUTHORITY=/run/user/1000/gdm/Xauthority
// ./iamtunnel", or the elevated pkexec relaunch reaching the identical
// DISPLAY/XAUTHORITY) drew a fully TRANSPARENT window — the desktop
// showing straight through the frame, not one interface element — while
// stderr carried "MESA: error: Failed to attach to x11 shm" and the very
// next line was "iamtunnel: elevated session ready". The cause: a root
// client authenticated with another user's Xauthority cookie is denied
// MIT-SHM by that user's X server, and Mesa's forced software rasterizer
// (IAMT-309 round 1's own ensureSoftwareGL) needs MIT-SHM to hand the X
// server a frame at all — a precondition that never applies to
// hardware-accelerated GL (DRI3/GBM buffer sharing, no X11 shared memory
// involved), so this refuses ONLY the specific combination that broke:
// elevated, software-rendered, a foreign display.
//
// Run on the Linux host: go test -count=1 ./cmd/iamtunnel/

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// TestIAMT309Round2_XauthorityOwnerUIDRealImplementation exercises the
// real (unseamed) filesystem check, not just the fakes the other tests
// install: a file this test process itself created reports back its own
// uid, and a missing path or an unset variable both report ok=false
// rather than a false uid.
func TestIAMT309Round2_XauthorityOwnerUIDRealImplementation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Xauthority")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seeding fixture: %v", err)
	}

	uid, ok := linuxXauthorityOwnerUID(map[string]string{"XAUTHORITY": path})
	if !ok {
		t.Fatal("linuxXauthorityOwnerUID could not stat a file this test process just created")
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("linuxXauthorityOwnerUID = %d, want the test process's own uid %d", uid, os.Getuid())
	}

	if _, ok := linuxXauthorityOwnerUID(map[string]string{"XAUTHORITY": filepath.Join(dir, "missing")}); ok {
		t.Fatal("linuxXauthorityOwnerUID reported ok=true for a file that does not exist")
	}
	if _, ok := linuxXauthorityOwnerUID(map[string]string{}); ok {
		t.Fatal("linuxXauthorityOwnerUID reported ok=true with no XAUTHORITY set at all")
	}
}

// TestIAMT309Round2_SoftwareGLActive pins the pure predicate in
// isolation: unset or truthy LIBGL_ALWAYS_SOFTWARE reads as active (the
// default since ensureSoftwareGL), an explicit falsy value reads as an
// opt-out.
func TestIAMT309Round2_SoftwareGLActive(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"unset — ensureSoftwareGL will force it", map[string]string{}, true},
		{"explicitly 1", map[string]string{"LIBGL_ALWAYS_SOFTWARE": "1"}, true},
		{"explicitly 0 — opted out", map[string]string{"LIBGL_ALWAYS_SOFTWARE": "0"}, false},
		{"explicitly false — opted out", map[string]string{"LIBGL_ALWAYS_SOFTWARE": "false"}, false},
		{"some other truthy spelling", map[string]string{"LIBGL_ALWAYS_SOFTWARE": "yes"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &streams{env: tc.env}
			if got := softwareGLActive(s); got != tc.want {
				t.Fatalf("softwareGLActive(%v) = %v, want %v", tc.env, got, tc.want)
			}
		})
	}
}

// TestIAMT309Round2_ElevatedDisplayIsForeign pins the XAUTHORITY-owner
// check against the three cases that matter: a foreign owner, a root
// owner (a genuine root desktop session), and no XAUTHORITY at all
// (Gio's own window open fails on its own — nothing for this check to
// add).
func TestIAMT309Round2_ElevatedDisplayIsForeign(t *testing.T) {
	cases := []struct {
		name string
		uid  uint32
		ok   bool
		want bool
	}{
		{"foreign owner (uid 1000) — the live-run shape", 1000, true, true},
		{"root's own Xauthority — a genuine root session", 0, true, false},
		{"no XAUTHORITY / unstattable — nothing to add", 0, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seamSwap(t, &linuxXauthorityOwnerUID, func(map[string]string) (uint32, bool) { return tc.uid, tc.ok })
			if got := elevatedDisplayIsForeign(map[string]string{"XAUTHORITY": "/run/user/1000/gdm/Xauthority"}); got != tc.want {
				t.Fatalf("elevatedDisplayIsForeign() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIAMT309Round2_RunGUIRefusesElevatedForeignSoftwareDisplay is THE
// canary the ticket asked for: the exact broken combination must refuse
// before any window exists, with a non-zero exit and no ready line ever
// possible (OnWindowReady is never even wired — linuxUIRun must not be
// reached at all).
//
// Canary: drop the round-2 guard from runGUI (gui_linux.go). This test
// goes red on:
//
//	runGUI reached the window launcher on an elevated+software+foreign
//	display — the exact combination a live run found draws a fully
//	transparent window while still printing "elevated session ready"
//	(IAMT-309 round 2)
func TestIAMT309Round2_RunGUIRefusesElevatedForeignSoftwareDisplay(t *testing.T) {
	seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
	seamSwap(t, &linuxXauthorityOwnerUID, func(map[string]string) (uint32, bool) { return 1000, true })
	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	reached := false
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		reached = true
		return errors.New("must not be reached")
	})

	env := testsupport.PlatformDataEnv(t)
	env["XAUTHORITY"] = "/run/user/1000/gdm/Xauthority"
	env["DISPLAY"] = ":1"
	var errs bytes.Buffer
	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &errs, env: env}

	code := run([]string{}, s)

	if reached {
		t.Fatalf("runGUI reached the window launcher on an elevated+software+foreign display — the exact combination a live run found draws a fully transparent window while still printing %q (IAMT-309 round 2)", elevatedReadyLine)
	}
	if code != exitDenied {
		t.Fatalf("runGUI on an elevated+software+foreign display = exit %d, want exitDenied (%d)", code, exitDenied)
	}
	if !strings.Contains(errs.String(), "cannot draw its window") || !strings.Contains(errs.String(), "MIT-SHM") {
		t.Fatalf("refusal stderr = %q, want it to name the display it cannot draw on and MIT-SHM", errs.String())
	}
	if strings.Contains(errs.String(), elevatedReadyLine) {
		t.Fatalf("refusal stderr carried the ready line (%q) — a window that was never opened must never be announced as ready", errs.String())
	}
}

// TestIAMT309Round2_RunGUIProceedsWhenSoftwareGLIsOptedOut proves the
// refusal is scoped to the software-rendering path, not to every
// elevated+foreign-display launch: a person who explicitly asked for
// hardware GL (LIBGL_ALWAYS_SOFTWARE=0) is presumably on a machine where
// DRI3/GBM buffer sharing works, which does not hit the MIT-SHM wall —
// the elevated relaunch must keep working there exactly as it always
// has.
//
// Canary: widen the guard to ignore softwareGLActive. This test goes red
// on "runGUI refused an elevated relaunch that opted out of software
// rendering".
func TestIAMT309Round2_RunGUIProceedsWhenSoftwareGLIsOptedOut(t *testing.T) {
	seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
	seamSwap(t, &linuxXauthorityOwnerUID, func(map[string]string) (uint32, bool) { return 1000, true })
	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	reached := false
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		reached = true
		return errors.New("stop here — the test only checks that the launcher was reached")
	})

	env := testsupport.PlatformDataEnv(t)
	env["XAUTHORITY"] = "/run/user/1000/gdm/Xauthority"
	env["DISPLAY"] = ":1"
	env["LIBGL_ALWAYS_SOFTWARE"] = "0"
	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &bytes.Buffer{}, env: env}

	run([]string{}, s)

	if !reached {
		t.Fatal("runGUI refused an elevated relaunch that opted out of software rendering — the MIT-SHM finding does not apply to a hardware-accelerated GL path")
	}
}

// TestIAMT309Round2_RunGUIProceedsOnAGenuineRootSession proves the other
// half of the scoping: a real root desktop login (its own Xauthority,
// uid 0) is not the broken case and must not be refused.
func TestIAMT309Round2_RunGUIProceedsOnAGenuineRootSession(t *testing.T) {
	seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
	seamSwap(t, &linuxXauthorityOwnerUID, func(map[string]string) (uint32, bool) { return 0, true })
	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	reached := false
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		reached = true
		return errors.New("stop here — the test only checks that the launcher was reached")
	})

	env := testsupport.PlatformDataEnv(t)
	env["XAUTHORITY"] = "/root/.Xauthority"
	env["DISPLAY"] = ":1"
	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &bytes.Buffer{}, env: env}

	run([]string{}, s)

	if !reached {
		t.Fatal("runGUI refused a genuine root desktop session (its own Xauthority) — this is not the MIT-SHM finding's case")
	}
}

// TestFGUI3_GioWillUseX11 pins the backend predicate in isolation
// (review round 20, MEDIUM; narrowed by F-GUI-5, round 21): DISPLAY
// absent means Gio has no X11 fallback to reach at all, and Wayland only
// wins when its socket is ACTUALLY reachable by this process — a merely
// present WAYLAND_DISPLAY is not enough (gioui.org/app's Unix newWindow
// falls back to X11 the instant that connect attempt fails).
func TestFGUI3_GioWillUseX11(t *testing.T) {
	reachable := func(ok bool) func(string) (io.Closer, error) {
		return func(string) (io.Closer, error) {
			if ok {
				return nopCloser{}, nil
			}
			return nil, errors.New("connection refused")
		}
	}
	cases := []struct {
		name       string
		env        map[string]string
		socketOK   bool
		wantSocket bool // whether linuxDialUnix should even be reached
		want       bool
	}{
		{"plain X11 — DISPLAY set, no Wayland env at all", map[string]string{"DISPLAY": ":1"}, true, false, true},
		{"no DISPLAY at all", map[string]string{}, true, false, false},
		{"no DISPLAY, only Wayland env — DISPLAY absent short-circuits before any dial", map[string]string{"WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}, true, false, false},
		{"both set, socket actually reachable — Wayland wins", map[string]string{"DISPLAY": ":1", "WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}, true, true, false},
		{"both set, socket stale/inaccessible — falls back to X11 (F-GUI-5)", map[string]string{"DISPLAY": ":1", "WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}, false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialed := false
			seamSwap(t, &linuxDialUnix, func(path string) (io.Closer, error) {
				dialed = true
				return reachable(tc.socketOK)(path)
			})
			if got := linuxGioWillUseX11(tc.env); got != tc.want {
				t.Fatalf("linuxGioWillUseX11(%v) = %v, want %v", tc.env, got, tc.want)
			}
			if dialed != tc.wantSocket {
				t.Fatalf("linuxDialUnix called = %v, want %v", dialed, tc.wantSocket)
			}
		})
	}
}

// TestFGUI3_RunGUIDoesNotRefuseAWorkingWaylandSession is F-GUI-3's
// canary, updated for F-GUI-5's stricter check: the exact
// elevated+software+non-root-XAUTHORITY combination that IS refused
// under plain X11 (TestIAMT309Round2_RunGUIRefusesElevated...) must NOT
// be refused when Wayland's socket is ACTUALLY reachable — a working
// Wayland/XWayland session (or a legitimate root/kiosk desktop carrying
// a stray XAUTHORITY) must not be rejected on the XAUTHORITY file's uid
// alone.
func TestFGUI3_RunGUIDoesNotRefuseAWorkingWaylandSession(t *testing.T) {
	seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
	seamSwap(t, &linuxXauthorityOwnerUID, func(map[string]string) (uint32, bool) { return 1000, true })
	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	seamSwap(t, &linuxDialUnix, func(string) (io.Closer, error) { return nopCloser{}, nil })
	reached := false
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		reached = true
		return errors.New("stop here — the test only checks that the launcher was reached")
	})

	env := testsupport.PlatformDataEnv(t)
	env["XAUTHORITY"] = "/run/user/1000/gdm/Xauthority"
	env["DISPLAY"] = ":1" // XWayland compatibility — still present, but Wayland wins
	env["WAYLAND_DISPLAY"] = "wayland-0"
	env["XDG_RUNTIME_DIR"] = "/run/user/1000"
	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &bytes.Buffer{}, env: env}

	run([]string{}, s)

	if !reached {
		t.Fatal("runGUI refused an elevated session whose Wayland socket is actually reachable — the XAUTHORITY file's uid is not proof of the X11 backend (F-GUI-3)")
	}
}

// TestFGUI5_RunGUIRefusesWhenWaylandSocketIsUnreachable is F-GUI-5's
// canary (review round 21, MEDIUM, confirmed): sudo -E/pkexec can
// leave WAYLAND_DISPLAY and XDG_RUNTIME_DIR set in the elevated
// process's environment while root cannot actually reach a socket
// scoped to the original user's session — Gio's own Wayland attempt
// would fail there and fall back to X11, reproducing the exact
// software-GL/MIT-SHM transparent-or-black window this refusal exists
// to prevent. The env-var-only predicate (F-GUI-3, round 20) read this
// as "Wayland wins" and skipped the refusal; the real connect attempt
// must not.
//
// Canary: revert linuxGioWillUseX11 to checking WAYLAND_DISPLAY's mere
// presence (the round-20 shape). This test goes red on:
//
//	runGUI reached the window launcher with a stale/inaccessible
//	WAYLAND_DISPLAY — Gio would have fallen back to X11 into the exact
//	MIT-SHM failure this refusal exists for (F-GUI-5)
func TestFGUI5_RunGUIRefusesWhenWaylandSocketIsUnreachable(t *testing.T) {
	seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
	seamSwap(t, &linuxXauthorityOwnerUID, func(map[string]string) (uint32, bool) { return 1000, true })
	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	seamSwap(t, &linuxDialUnix, func(string) (io.Closer, error) { return nil, errors.New("connection refused") })
	reached := false
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		reached = true
		return errors.New("must not be reached")
	})

	env := testsupport.PlatformDataEnv(t)
	env["XAUTHORITY"] = "/run/user/1000/gdm/Xauthority"
	env["DISPLAY"] = ":1"
	env["WAYLAND_DISPLAY"] = "wayland-0"
	env["XDG_RUNTIME_DIR"] = "/run/user/1000"
	var errs bytes.Buffer
	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &errs, env: env}

	code := run([]string{}, s)

	if reached {
		t.Fatalf("runGUI reached the window launcher with a stale/inaccessible WAYLAND_DISPLAY — Gio would have fallen back to X11 into the exact MIT-SHM failure this refusal exists for (F-GUI-5)")
	}
	if code != exitDenied {
		t.Fatalf("exit code = %d, want exitDenied (%d)", code, exitDenied)
	}
	if strings.Contains(errs.String(), elevatedReadyLine) {
		t.Fatalf("stderr carried the ready line (%q) on a path that ends in an unusable window", errs.String())
	}
}

// TestFGUI1Round5_RunGUIRefusesTheExactLiveReproduction is round 5's
// canary: the literal live shape a real run hit on a Linux test VM —
// "sudo -n DISPLAY=:1 XAUTHORITY=/run/user/1000/gdm/Xauthority
// <binary>" — root, DISPLAY set, a foreign XAUTHORITY, and
// XDG_RUNTIME_DIR simply absent (sudo -n, unlike sudo -E, does not
// inherit it), so Wayland has nowhere to even look. Round 4's
// render-node heuristic made softwareGLActive report "hardware" on this
// exact VM (its render node exists), which short-circuited the whole
// elevated guard BEFORE it ever reached linuxGioWillUseX11 or
// elevatedDisplayIsForeign — no refusal, "iamtunnel: elevated session
// ready" printed anyway, and the process left running. This test
// reproduces the shape without seaming softwareGLActive's own decision
// (it must reach its real, now-unconditional default).
//
// Canary: reintroduce any local-hardware check that can make
// softwareGLActive report false when LIBGL_ALWAYS_SOFTWARE is unset
// (round 4's shape). This test goes red on:
//
//	runGUI reached the window launcher on the exact live-reproduction
//	shape (root, DISPLAY set, foreign XAUTHORITY, no XDG_RUNTIME_DIR) —
//	this is precisely the case the refusal exists to catch (round 5)
func TestFGUI1Round5_RunGUIRefusesTheExactLiveReproduction(t *testing.T) {
	seamSwap(t, &linuxIsElevated, func() (bool, error) { return true, nil })
	seamSwap(t, &linuxXauthorityOwnerUID, func(map[string]string) (uint32, bool) { return 1000, true })
	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	dialed := false
	seamSwap(t, &linuxDialUnix, func(string) (io.Closer, error) {
		dialed = true
		return nil, errors.New("connection refused")
	})
	reached := false
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		reached = true
		return errors.New("must not be reached")
	})

	env := testsupport.PlatformDataEnv(t)
	env["XAUTHORITY"] = "/run/user/1000/gdm/Xauthority"
	env["DISPLAY"] = ":1"
	// The live shape: sudo -n (no -E) never inherited these at all.
	delete(env, "XDG_RUNTIME_DIR")
	delete(env, "WAYLAND_DISPLAY")
	// LIBGL_ALWAYS_SOFTWARE is deliberately left unset too: the whole
	// point is that softwareGLActive's own unconditional default must
	// carry the guard, with no local-hardware seam propping it up.
	var errs bytes.Buffer
	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &errs, env: env}

	code := run([]string{}, s)

	if reached {
		t.Fatalf("runGUI reached the window launcher on the exact live-reproduction shape (root, DISPLAY set, foreign XAUTHORITY, no XDG_RUNTIME_DIR) — this is precisely the case the refusal exists to catch (round 5)")
	}
	if code != exitDenied {
		t.Fatalf("exit code = %d, want exitDenied (%d)", code, exitDenied)
	}
	if strings.Contains(errs.String(), elevatedReadyLine) {
		t.Fatalf("stderr carried the ready line (%q) on a path that ends in an unusable window", errs.String())
	}
	if dialed {
		t.Fatalf("linuxDialUnix was called with no XDG_RUNTIME_DIR at all — there is nowhere to even look, the same way wl_display_connect itself has nowhere to look")
	}
}

// nopCloser is the smallest io.Closer a fake linuxDialUnix can return
// for a "socket reachable" case.
type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// TestIAMT309Round2_GUITabEnvSelectsTheInitialTab pins the live-check
// hook this round asked for: a deterministic, click-free way to reach
// a given tab. IAMTUNNEL_GUI_TAB is read once, verbatim, into
// FrameConfig.InitialTab (the same field shot_windows.go already uses
// for the offscreen shot) — unset leaves NewFrame's own default choice
// untouched.
func TestIAMT309Round2_GUITabEnvSelectsTheInitialTab(t *testing.T) {
	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	var gotTab string
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		gotTab = cfg.InitialTab
		return errors.New("stop here — the test only checks InitialTab")
	})

	env := testsupport.PlatformDataEnv(t)
	env["IAMTUNNEL_GUI_TAB"] = "Admin"
	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &bytes.Buffer{}, env: env}

	run([]string{}, s)

	if gotTab != "Admin" {
		t.Fatalf("cfg.InitialTab = %q, want %q — IAMTUNNEL_GUI_TAB was not wired through", gotTab, "Admin")
	}
}

// TestIAMT309Round2_GUITabEnvUnsetLeavesTheDefault proves the hook is
// inert when absent: an ordinary launch (no IAMTUNNEL_GUI_TAB in the
// environment) must not force any particular tab.
func TestIAMT309Round2_GUITabEnvUnsetLeavesTheDefault(t *testing.T) {
	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	var gotTab string
	sawTab := false
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		gotTab, sawTab = cfg.InitialTab, true
		return errors.New("stop here — the test only checks InitialTab")
	})

	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &bytes.Buffer{}, env: testsupport.PlatformDataEnv(t)}

	run([]string{}, s)

	if !sawTab {
		t.Fatal("linuxUIRun was never reached")
	}
	if gotTab != "" {
		t.Fatalf("cfg.InitialTab = %q, want \"\" (NewFrame's own default) when IAMTUNNEL_GUI_TAB is unset", gotTab)
	}
}
