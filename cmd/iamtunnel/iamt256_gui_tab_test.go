package main

// iamt256_gui_tab_test.go — IAMT-256: xdotool could not switch tabs on
// the live Ubuntu VM (only the hover highlight changed on click), so
// there was still no deterministic way to reach the Server screen for a
// live screenshot. --tab exposes FrameConfig.InitialTab (already used
// internally by shot_windows.go) as a validated CLI flag; it must not
// change any default behaviour when absent, and an unknown value must be
// refused with a clear error, on every platform — the parsing itself
// never opens a window (streams.openGUI is faked throughout).

import (
	"bytes"
	"strings"
	"testing"
)

// driveGUIFlags is driveGUI (main_test.go) with args instead of always
// nil, so --tab can be exercised without ever reaching a real window.
func driveGUIFlagsArgs(t *testing.T, args []string, openGUI func(*streams) int) (string, string, int, map[string]string) {
	t.Helper()
	var out, errs bytes.Buffer
	env := map[string]string{}
	s := &streams{
		in:      strings.NewReader(""),
		out:     &out,
		errs:    &errs,
		env:     env,
		openGUI: openGUI,
	}
	code := run(args, s)
	return out.String(), errs.String(), code, env
}

// TestIAMT256_TabFlagSelectsTheServerScreen pins the exact live-check
// use case: --tab=server reaches the launcher with IAMTUNNEL_GUI_TAB
// set to the canonical "Server" tab name.
func TestIAMT256_TabFlagSelectsTheServerScreen(t *testing.T) {
	reached := false
	_, errs, code, env := driveGUIFlagsArgs(t, []string{"--tab=server"}, func(s *streams) int {
		reached = true
		return 0
	})
	if !reached {
		t.Fatalf("--tab=server did not reach the GUI launcher; stderr=%q", errs)
	}
	if code != 0 {
		t.Fatalf("--tab=server exit code = %d, want 0", code)
	}
	if env["IAMTUNNEL_GUI_TAB"] != "Server" {
		t.Fatalf("IAMTUNNEL_GUI_TAB = %q, want %q", env["IAMTUNNEL_GUI_TAB"], "Server")
	}
}

// TestIAMT256_TabFlagAcceptsEveryDocumentedValue pins all five values
// the flag advertises, each mapping onto the exact tab header
// internal/ui.NewFrame expects.
func TestIAMT256_TabFlagAcceptsEveryDocumentedValue(t *testing.T) {
	cases := map[string]string{
		"setup":    "Set up",
		"client":   "Client",
		"server":   "Server",
		"admin":    "Admin",
		"settings": "Settings",
	}
	for raw, want := range cases {
		t.Run(raw, func(t *testing.T) {
			_, errs, code, env := driveGUIFlagsArgs(t, []string{"--tab=" + raw}, func(s *streams) int { return 0 })
			if code != 0 {
				t.Fatalf("--tab=%s exit code = %d, want 0; stderr=%q", raw, code, errs)
			}
			if env["IAMTUNNEL_GUI_TAB"] != want {
				t.Fatalf("--tab=%s → IAMTUNNEL_GUI_TAB = %q, want %q", raw, env["IAMTUNNEL_GUI_TAB"], want)
			}
		})
	}
}

// TestIAMT256_TabFlagIsCaseInsensitive proves "--tab=Server",
// "--tab=SERVER" etc. all work — the flag's own case, not just
// design.Tabs.Show's later EqualFold, should not surprise anyone typing
// it from a shell history.
func TestIAMT256_TabFlagIsCaseInsensitive(t *testing.T) {
	_, errs, code, env := driveGUIFlagsArgs(t, []string{"--tab=SERVER"}, func(s *streams) int { return 0 })
	if code != 0 {
		t.Fatalf("--tab=SERVER exit code = %d, want 0; stderr=%q", code, errs)
	}
	if env["IAMTUNNEL_GUI_TAB"] != "Server" {
		t.Fatalf("--tab=SERVER → IAMTUNNEL_GUI_TAB = %q, want %q", env["IAMTUNNEL_GUI_TAB"], "Server")
	}
}

// TestIAMT256_UnknownTabValueIsRefused is THE canary the ticket asked
// for: an unknown --tab value must be refused with a clear error, and
// must never reach the window launcher.
//
// Canary: drop the guiTabNames lookup and pass the raw flag value
// through unvalidated. This test goes red with:
//
//	--tab=bogus reached the GUI launcher instead of being refused
func TestIAMT256_UnknownTabValueIsRefused(t *testing.T) {
	reached := false
	_, errs, code, _ := driveGUIFlagsArgs(t, []string{"--tab=bogus"}, func(s *streams) int {
		reached = true
		return 0
	})
	if reached {
		t.Fatal("--tab=bogus reached the GUI launcher instead of being refused")
	}
	if code != exitUser {
		t.Fatalf("--tab=bogus exit code = %d, want exitUser (%d)", code, exitUser)
	}
	if !strings.Contains(errs, "unknown --tab value") || !strings.Contains(errs, "bogus") {
		t.Fatalf("refusal stderr = %q, want it to name the bad value", errs)
	}
	for _, want := range []string{"setup", "client", "server", "admin", "settings"} {
		if !strings.Contains(errs, want) {
			t.Fatalf("refusal stderr = %q, want it to list the allowed value %q", errs, want)
		}
	}
}

// TestIAMT256_AbsentTabFlagLeavesTheDefaultUntouched proves the flag
// changes nothing when it is not given: no IAMTUNNEL_GUI_TAB entry at
// all, exactly the ordinary no-arguments launch.
func TestIAMT256_AbsentTabFlagLeavesTheDefaultUntouched(t *testing.T) {
	reached := false
	var gotEnv map[string]string
	_, errs, code, env := driveGUIFlagsArgs(t, nil, func(s *streams) int {
		reached = true
		gotEnv = s.env
		return 0
	})
	if !reached {
		t.Fatalf("no-arguments launch did not reach the GUI launcher; stderr=%q", errs)
	}
	if code != 0 {
		t.Fatalf("no-arguments launch exit code = %d, want 0", code)
	}
	if _, set := env["IAMTUNNEL_GUI_TAB"]; set {
		t.Fatalf("IAMTUNNEL_GUI_TAB was set (%q) although --tab was never given — the absent flag must not change default behaviour", env["IAMTUNNEL_GUI_TAB"])
	}
	if _, set := gotEnv["IAMTUNNEL_GUI_TAB"]; set {
		t.Fatal("the launcher's own streams carried IAMTUNNEL_GUI_TAB although --tab was never given")
	}
}

// TestIAMT256_TabFlagRejectsAStrayPositionalArgument proves --tab does
// not quietly accept a trailing word after it — the GUI launch takes no
// positional arguments.
func TestIAMT256_TabFlagRejectsAStrayPositionalArgument(t *testing.T) {
	reached := false
	_, errs, code, _ := driveGUIFlagsArgs(t, []string{"--tab=server", "extra"}, func(s *streams) int {
		reached = true
		return 0
	})
	if reached {
		t.Fatalf("a stray positional argument after --tab reached the GUI launcher; stderr=%q", errs)
	}
	if code == 0 {
		t.Fatalf("a stray positional argument after --tab was accepted, exit code = %d", code)
	}
}

// TestIAMT256_TabFlagIsMentionedInHelp pins this round's finding:
// --tab was real and validated but undiscoverable, since
// runGUIWithFlags prints the unchanged usageText on --help. A check aid
// nobody can discover is half-useful.
//
// Canary: revert usageText to the pre-IAMT-256 line. This test goes red
// on: "usageText does not mention --tab".
func TestIAMT256_TabFlagIsMentionedInHelp(t *testing.T) {
	if !strings.Contains(usageText, "--tab") {
		t.Fatal("usageText does not mention --tab — a check aid nobody can discover is half-useful")
	}
}
