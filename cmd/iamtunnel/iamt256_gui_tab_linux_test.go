//go:build linux && !nogui

package main

// iamt256_gui_tab_linux_test.go — IAMT-256's Linux-only half: pinning
// guiTabNames (main.go, plain literals — main.go builds on every
// platform, including the ones gui_other.go stubs out, where
// internal/ui does not build at all) against internal/ui's own Tab*
// constants, and the end-to-end path from "--tab=server" on the command
// line through to FrameConfig.InitialTab, the same seam
// TestIAMT309Round2_GUITabEnvSelectsTheInitialTab already exercises for
// the environment-variable half of this wiring.
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

// TestIAMT256_GUITabNamesMatchUITabConstants pins guiTabNames' literal
// values against internal/ui's own exported Tab* constants, so
// the two lists (kept apart on purpose — see guiTabNames' own comment)
// cannot silently drift.
//
// Canary: rename a ui.TabXxx constant without updating guiTabNames. This
// test goes red on the corresponding mismatch.
func TestIAMT256_GUITabNamesMatchUITabConstants(t *testing.T) {
	// Was SIX entries, and said "one per internal/ui tab" while the
	// window had EIGHT (21.09.2026). The sentence was false the day
	// Session arrived and false again when History did, and because the
	// test only counted what was written here, it agreed with itself
	// every time. Guide and History spent that whole period unreachable
	// by name, which is what the owner ran into when he asked for a
	// picture of every screen.
	//
	// The list is now written out in full and checked against the tab
	// constants in BOTH directions, so a new tab shows up as a missing
	// entry rather than as nothing at all.
	want := map[string]string{
		"guide":    ui.TabGuide,
		"setup":    ui.TabSetUp,
		"client":   ui.TabClient,
		"server":   ui.TabServer,
		"gateway":  ui.TabGateway,
		"session":  ui.TabSession,
		"admin":    ui.TabAdmin,
		"history":  ui.TabHistory,
		"settings": ui.TabSettings,
	}
	for k, v := range want {
		if guiTabNames[k] != v {
			t.Errorf("guiTabNames[%q] = %q, want ui.Tab* constant %q", k, guiTabNames[k], v)
		}
	}
	for k := range guiTabNames {
		if _, ok := want[k]; !ok {
			t.Errorf("guiTabNames has %q, which this test does not know about", k)
		}
	}
	if len(guiTabNames) != len(want) {
		t.Errorf("guiTabNames has %d entries, want exactly %d (one per internal/ui tab)", len(guiTabNames), len(want))
	}
}

// TestIAMT256_TabFlagReachesFrameConfigInitialTab is the end-to-end
// canary: "--tab=server" on the command line must reach
// FrameConfig.InitialTab exactly the way IAMTUNNEL_GUI_TAB already does
// when set directly (round 2's live-check hook).
func TestIAMT256_TabFlagReachesFrameConfigInitialTab(t *testing.T) {
	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	var gotTab string
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		gotTab = cfg.InitialTab
		return errors.New("stop here — the test only checks InitialTab")
	})

	var errs bytes.Buffer
	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &errs, env: testsupport.PlatformDataEnv(t)}

	run([]string{"--tab=server"}, s)

	if gotTab != ui.TabServer {
		t.Fatalf("cfg.InitialTab = %q, want %q — \"--tab=server\" was not wired through to the window", gotTab, ui.TabServer)
	}
}
