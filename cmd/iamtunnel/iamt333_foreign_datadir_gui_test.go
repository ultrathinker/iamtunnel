//go:build (windows || linux || darwin) && !nogui

package main

// The GUI wiring of the foreign-data-directory gate (IAMT-333, P1.6):
// the window's save action carries the same refusal as the CLI verb.
// This file is tagged to match gui_actions.go — under the nogui builds
// the gates vet, the window does not compile, so neither can a test that
// calls into it (IAMT-470's rule: vet compiles the test files, so a test
// that needs the window is tagged !nogui).

import (
	"strings"
	"testing"
)

// stubGUIElevation fixes what the no-streams callers (the window's action
// wrappers) see for elevation: the real check would consult the live token
// of the test process, which is not what these tests are about.
func stubGUIElevation(t *testing.T, elevated bool) {
	t.Helper()
	saved := foreignDirElevation
	foreignDirElevation = func() (bool, error) { return elevated, nil }
	t.Cleanup(func() { foreignDirElevation = saved })
}

func TestIAMT333_GUIActionRefusesToo(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, "owned by BUILTIN\\Users, and this console is elevated — "+
		"a directory somebody else owns can aim this command's writes at files of their choosing", nil)
	stubGUIElevation(t, true)

	_, err := guiSaveConnection(dir, connStr, "", false)
	if err == nil {
		t.Fatal("the window's save action must carry the same refusal as the CLI verb")
	}
	if !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "--accept-foreign-data-dir") {
		t.Errorf("the GUI refusal must name the directory and the escape flag: %v", err)
	}

	// The window has no flag to pass: a non-elevated window never sees the
	// refusal at all, which is the ordinary case for the GUI.
	stubGUIElevation(t, false)
	if _, err := guiSaveConnection(dir, connStr, "", false); err != nil {
		t.Fatalf("a non-elevated window must never see the refusal: %v", err)
	}
}
