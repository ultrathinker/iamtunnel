//go:build linux && !nogui

package main

// iamt256_fgui8_setup_tab_linux_test.go — F-GUI-8's end-to-end wiring
// check: runGUI must actually reach warnIfSetupTabUnreachable when
// "--tab=setup" is requested on a machine that turns out to be already
// enrolled, not just the unit-level check in
// iamt256_fgui8_setup_tab_test.go.
//
// Run on the Linux host: go test -count=1 ./cmd/iamtunnel/

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// TestFGUI8_RunGUIWarnsWhenTabSetupIsUnreachable pins the wiring.
//
// Canary: drop the warnIfSetupTabUnreachable call from runGUI
// (gui_linux.go). This test goes red on:
//
//	runGUI with --tab=setup on an already-enrolled machine said nothing
//	— the person asked for a screen that silently does not exist
//	(F-GUI-8)
func TestFGUI8_RunGUIWarnsWhenTabSetupIsUnreachable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "machine.id"), []byte("lin-ubu-vm\n"), 0o644); err != nil {
		t.Fatalf("seeding fixture: %v", err)
	}

	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	var gotTab string
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		gotTab = cfg.InitialTab
		return errors.New("stop here — the test only checks the diagnostic and InitialTab")
	})

	env := testsupport.PlatformDataEnv(t)
	env["IAMTUNNEL_DATA_DIR"] = dir
	var errs bytes.Buffer
	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &errs, env: env}

	run([]string{"--tab=setup"}, s)

	if !strings.Contains(errs.String(), "--tab=setup") || !strings.Contains(errs.String(), "already enrolled") {
		t.Fatalf("runGUI with --tab=setup on an already-enrolled machine said nothing — the person asked for a screen that silently does not exist (F-GUI-8); stderr = %q", errs.String())
	}
	// The flag still reaches FrameConfig verbatim — the fallback happens
	// inside NewFrame/Tabs.Show, not by main.go silently rewriting it.
	if gotTab != ui.TabSetUp {
		t.Fatalf("cfg.InitialTab = %q, want %q — main.go must not silently rewrite the requested tab itself", gotTab, ui.TabSetUp)
	}
}
