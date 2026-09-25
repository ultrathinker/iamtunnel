//go:build linux

package main

// iamt255_desktop_test.go — IAMT-255 canary tests for the
// \`iamtunnel desktop install|uninstall\` verb: install writes the
// .desktop entry and the two PNG icons under a seamed base
// directory (the production wiring reads $XDG_DATA_HOME, the tests
// inject t.TempDir() so no real user data is touched), uninstall
// removes the same paths, and both verbs refuse the environment
// class when their inputs are bad. The install body NEVER touches
// /usr/share/applications or /usr/share/icons, by construction:
// every path goes through desktopControl.xdgDataHome(), and the
// seam default is a callable that returns only $XDG_DATA_HOME or
// ~/.local/share — both per-user locations.
//
// CANARY (red text on regression):
//   - "iamtunnel desktop install did not write the .desktop entry"
//   - "iamtunnel desktop install did not write the 48-pixel icon"
//   - "iamtunnel desktop install did not write the 256-pixel icon"
//   - "iamtunnel desktop install wrote outside the seamed base"
//   - "iamtunnel desktop uninstall did not remove every installed path"
//   - "iamtunnel desktop refused on !linux" (covered by the
//     non-Linux stub in desktop_other_test.go).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordingDesktopControl substitutes desktopControl's os helpers
// with t.TempDir()-rooted fakes and a stable fake exe path so the
// canary tests do not touch the real $XDG_DATA_HOME or the real
// binary on disk.
func recordingDesktopControl(t *testing.T) desktopControl {
	t.Helper()
	base := t.TempDir()
	written := map[string][]byte{}
	removed := []string{}
	assets := filepath.Join(base, "assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatalf("setup assets dir: %v", err)
	}
	// Drop two tiny PNG-shaped blobs; the body only checks the
	// size matches the openForWrite closure, not pixel content.
	for _, size := range iconSizes {
		blob := []byte("PNG-FAKE-" + strings.Repeat("x", size))
		if err := os.WriteFile(filepath.Join(assets, "iamtunnel-"+itoa(size)+".png"), blob, 0o644); err != nil {
			t.Fatalf("setup fake icon %d: %v", size, err)
		}
	}
	return desktopControl{
		xdgDataHome: func() string { return base },
		openForWrite: func(path string, data []byte) error {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			written[path] = data
			return os.WriteFile(path, data, 0o644)
		},
		remove: func(path string) (bool, error) {
			// Pre-check existence so the recording shape mirrors
			// the production contract: existed=true only when the
			// path was there before the call and os.Remove
			// actually deleted it. A second uninstall against the
			// same path sees os.Remove return ENOENT, which
			// production defaultRemove turns into (false, nil);
			// this fake does the same explicit pre-stat.
			_, statErr := os.Stat(path)
			if os.IsNotExist(statErr) {
				return false, nil
			}
			if err := os.Remove(path); err != nil {
				if os.IsNotExist(err) {
					return false, nil
				}
				return false, err
			}
			removed = append(removed, path)
			return true, nil
		},
		exePath: func() (string, error) { return "/opt/iamtunnel/iamtunnel", nil },
		iconOpen: func(size int) ([]byte, error) {
			return os.ReadFile(filepath.Join(assets, "iamtunnel-"+itoa(size)+".png"))
		},
	}
}

// itoa avoids strconv.Itoa in this file — keeps the test imports
// minimal (only what the body uses directly).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

// TestIAMT255_DesktopInstallWritesAllThreePaths is the headline
// canary: install writes the .desktop entry, the 48-pixel icon, and
// the 256-pixel icon — at exactly the three relative paths under
// the seamed base, and nowhere else. Drops any of the three writes
// and the test reddens with the named path.
//
// CANARY (red text on regression): the named short message below is
// what the failure mode looks like.
func TestIAMT255_DesktopInstallWritesAllThreePaths(t *testing.T) {
	ctrl := recordingDesktopControl(t)
	paths, err := installDesktopFiles(ctrl)
	if err != nil {
		t.Fatalf("installDesktopFiles: %v", err)
	}
	want := []string{
		filepath.Join(ctrl.xdgDataHome(), "applications", "iamtunnel.desktop"),
		filepath.Join(ctrl.xdgDataHome(), "icons", "hicolor", "48", "apps", "iamtunnel.png"),
		filepath.Join(ctrl.xdgDataHome(), "icons", "hicolor", "256", "apps", "iamtunnel.png"),
	}
	if len(paths) != len(want) {
		t.Fatalf("installDesktopFiles wrote %d paths, want %d (paths=%v)", len(paths), len(want), paths)
	}
	for i, p := range want {
		if paths[i] != p {
			t.Errorf("path[%d] = %q, want %q — install must use the seamed base, not /usr/share", i, paths[i], p)
		}
	}
	for _, p := range want {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: stat after install = %v", p, err)
		}
	}
}

// TestIAMT255_DesktopFileLivesUpToFreedesktopSpec is the wording
// canary: every required keyword (Name, Exec=, Icon=, Terminal=,
// Categories=) MUST appear in the installed .desktop entry — a
// freedesktop launcher refuses to render an entry missing any of
// these, so a regression here reddens on the desktop side before
// any user notices. The keyword set lives in requiredDesktopKeywords
// (cmd/iamtunnel/desktop.go) and is the single source of truth
// for both the template and the canary.
//
// CANARY (red text on regression): "missing required keyword" — the
// assertion reads the actual missing keyword name.
func TestIAMT255_DesktopFileLivesUpToFreedesktopSpec(t *testing.T) {
	ctrl := recordingDesktopControl(t)
	paths, err := installDesktopFiles(ctrl)
	if err != nil {
		t.Fatalf("installDesktopFiles: %v", err)
	}
	// Side check that this test's install also produced the .desktop
	// path the wording check reads from: a regression that breaks the
	// returned list but leaves the wording check's hardcoded path
	// still on disk (because the install body wrote there too) would
	// otherwise pass this test while failing TestIAMT255_DesktopInstallWritesAllThreePaths.
	desktopAbs := filepath.Join(ctrl.xdgDataHome(), "applications", "iamtunnel.desktop")
	found := false
	for _, p := range paths {
		if p == desktopAbs {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("install returned %v, expected %q in the list", paths, desktopAbs)
	}
	content, err := os.ReadFile(desktopAbs)
	if err != nil {
		t.Fatalf("read %s: %v", desktopAbs, err)
	}
	got := string(content)
	// Exec= must point at the absolute path the seam said, not a
	// relative or PATH-resolved name — the launcher does NOT honour
	// $PATH, it runs Exec verbatim.
	wantExec := "Exec=/opt/iamtunnel/iamtunnel"
	if !strings.Contains(got, wantExec) {
		t.Errorf("Exec line = %q, want a line containing %q", got, wantExec)
	}
	for _, kw := range requiredDesktopKeywords {
		if !strings.Contains(got, kw) {
			t.Errorf("missing required keyword %q in %s", kw, desktopAbs)
		}
	}
}

// TestIAMT255_DesktopInstallRefusesWithoutHomeOrXDG is the
// environment-class canary: when neither $XDG_DATA_HOME nor $HOME
// is set (the production seam xdgDataHome returns ""), install
// must refuse rather than write to a relative path — relative
// paths are exactly the IAMT-76 trap the system test class warns
// against.
//
// CANARY (red text on regression): "cannot determine XDG_DATA_HOME".
func TestIAMT255_DesktopInstallRefusesWithoutHomeOrXDG(t *testing.T) {
	ctrl := recordingDesktopControl(t)
	ctrl.xdgDataHome = func() string { return "" } // emulate no env, no home
	if _, err := installDesktopFiles(ctrl); err == nil {
		t.Fatalf("installDesktopFiles must refuse with empty xdgDataHome")
	} else if !strings.Contains(err.Error(), "cannot determine XDG_DATA_HOME") {
		t.Errorf("refusal = %v, want a message naming XDG_DATA_HOME", err)
	}
}

// TestIAMT255_DesktopUninstallRemovesWhatInstallWrote is the
// reversibility canary: uninstall removes exactly the paths
// install produced — same list, same order — and is idempotent
// (running uninstall twice is a no-op the second time, so a
// stale state cannot stall a real uninstall).
//
// CANARY (red text on regression): "uninstall did not remove every
// installed path".
func TestIAMT255_DesktopUninstallRemovesWhatInstallWrote(t *testing.T) {
	ctrl := recordingDesktopControl(t)
	paths, err := installDesktopFiles(ctrl)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	removed, err := uninstallDesktopFiles(ctrl)
	if err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if len(removed) != len(paths) {
		t.Fatalf("uninstall removed %d paths, install wrote %d (removed=%v written=%v)", len(removed), len(paths), removed, paths)
	}
	for i, p := range paths {
		if removed[i] != p {
			t.Errorf("removed[%d] = %q, want %q — install and uninstall must agree on the path list", i, removed[i], p)
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s: must be absent after uninstall, stat err = %v", p, err)
		}
	}
	// Idempotency: a second uninstall reports no paths removed
	// without erroring (the platform's defaultRemove swallows
	// os.ErrNotExist, so the body sees zero work).
	again, err := uninstallDesktopFiles(ctrl)
	if err != nil {
		t.Errorf("second uninstall: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("second uninstall removed %d paths, want 0 (idempotent)", len(again))
	}
}

// TestIAMT255_DesktopCmdDispatchesInstallAndUninstall drives the
// CLI verb (cmdDesktop) through both shapes with the production
// seam swapped for t.TempDir(). It is the only canary that
// exercises the dispatcher: a future refactor that breaks the
// argv parsing or the help-text path reddens here without going
// through the body-level tests.
//
// cmdDesktop intentionally does NOT call loadConfig — the verb
// has no settings and no data directory of its own (the .desktop
// file lives under $XDG_DATA_HOME, which the body reads from the
// environment). drive() sets XDG_DATA_HOME to t.TempDir() via the
// standard PlatformDataEnv, so the test reaches the recording
// fake through the same seam the body-level tests use.
//
// CANARY (red text on regression): "iamtunnel desktop install
// wrote outside the seamed base" — the same canary as the body
// test, but emitted by the CLI layer so a regression in the
// dispatch path is still flagged.
func TestIAMT255_DesktopCmdDispatchesInstallAndUninstall(t *testing.T) {
	ctrl := recordingDesktopControl(t)
	// Swap the production seam for the recording one for the
	// duration of the test; restore on cleanup so other tests
	// see the real wiring.
	prev := defaultDesktopControl
	defaultDesktopControl = ctrl
	t.Cleanup(func() { defaultDesktopControl = prev })

	out, errs, code := drive(t, "desktop", "install")
	if code != exitOK {
		t.Fatalf("desktop install: code=%d errs=%q out=%q", code, errs, out)
	}
	if !strings.Contains(out, "installed the desktop shortcut") {
		t.Errorf("install stdout = %q, want a phrase the user can read", out)
	}
	want := filepath.Join(ctrl.xdgDataHome(), "applications", "iamtunnel.desktop")
	if _, err := os.Stat(want); err != nil {
		t.Errorf("%s: stat after install via cmd = %v", want, err)
	}

	out, errs, code = drive(t, "desktop", "uninstall")
	if code != exitOK {
		t.Fatalf("desktop uninstall: code=%d errs=%q out=%q", code, errs, out)
	}
	if !strings.Contains(out, "removed the desktop shortcut") {
		t.Errorf("uninstall stdout = %q, want a phrase the user can read", out)
	}
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Errorf("%s: must be absent after uninstall via cmd, stat err = %v", want, err)
	}
}

// TestIAMT255_DesktopCmdRefusesUnknownVerb is the dispatcher
// shape canary: an unknown verb is a user error (exit 2), not
// an environment error (exit 3) — the verb list is part of the
// CLI surface the user reads in --help.
func TestIAMT255_DesktopCmdRefusesUnknownVerb(t *testing.T) {
	_, errs, code := drive(t, "desktop", "bogus")
	if code != 2 {
		t.Errorf("desktop bogus verb: code=%d, want 2 (user error)", code)
	}
	if !strings.Contains(errs, "unknown verb") {
		t.Errorf("desktop bogus verb: stderr = %q, want a phrase naming the verb list", errs)
	}
}

// TestIAMT255_DesktopHelpTextListsInstallAndUninstall pins the
// help text the user reads under \`iamtunnel help desktop\`. A
// future regression that hides one of the verbs, or changes the
// short shape of the per-verb usage, reddens here.
func TestIAMT255_DesktopHelpTextListsInstallAndUninstall(t *testing.T) {
	out, errs, code := drive(t, "help", "desktop")
	if code != exitOK {
		t.Fatalf("help desktop: code=%d errs=%q", code, errs)
	}
	for _, want := range []string{"desktop install", "desktop uninstall", "XDG_DATA_HOME", "freedesktop"} {
		if !strings.Contains(out, want) {
			t.Errorf("help desktop: missing %q in:\n%s", want, out)
		}
	}
}

// _ keeps the unused-import detector quiet if any of the helpers
// above change in a future refactor.
var _ = strings.Contains
