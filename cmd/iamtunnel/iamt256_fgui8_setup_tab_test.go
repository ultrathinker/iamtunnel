//go:build !nogui

package main

// iamt256_fgui8_setup_tab_test.go — F-GUI-8 (review round 25,
// LOW, confirmed): --tab=setup is accepted and validated by
// runGUIWithFlags regardless of enrolment state (the flag parser is
// platform-agnostic and has no notion of "enrolled"), but
// internal/ui.NewFrame never registers the Set up tab once the machine
// is enrolled, and design.Tabs.Show has no error signal for "this tab
// does not exist" — it silently falls back to the first registered tab.
// warnIfSetupTabUnreachable (gui_actions.go) says so honestly on stderr
// instead, right where "enrolled" is already known (before the Frame is
// ever built). This is a UX/documentation-accuracy fix, not a safety
// one: the elevated refusal (IAMT-309) already runs before this point
// regardless of which tab was requested.
//
// No internal/ui import here on purpose: "Set up" is ui.TabSetUp's own
// value, literal, so this test builds and runs on every platform
// without pulling gio's cgo dependency into a file that does not need
// it (the same discipline iamt254_gui_linux_test.go already applies).

import (
	"bytes"
	"strings"
	"testing"
)

// TestFGUI8_WarnsOnceWhenSetupIsUnreachable is the canary.
//
// Canary: drop the enrolled-and-requested-setup check from
// warnIfSetupTabUnreachable (always silent, the pre-fix shape). This
// test goes red on:
//
//	warnIfSetupTabUnreachable said nothing although --tab=setup was
//	requested on an already-enrolled machine (F-GUI-8)
func TestFGUI8_WarnsOnceWhenSetupIsUnreachable(t *testing.T) {
	var errs bytes.Buffer
	s := &streams{errs: &errs}

	warnIfSetupTabUnreachable(s, "Set up", true)

	if !strings.Contains(errs.String(), "--tab=setup") || !strings.Contains(errs.String(), "already enrolled") {
		t.Fatalf("warnIfSetupTabUnreachable said nothing although --tab=setup was requested on an already-enrolled machine (F-GUI-8); stderr = %q", errs.String())
	}
}

// TestFGUI8_SilentWhenSetupIsReachableOrNotRequested proves the check
// is scoped: an unenrolled machine (Set up genuinely exists) and any
// other --tab value (or none at all) must stay silent.
func TestFGUI8_SilentWhenSetupIsReachableOrNotRequested(t *testing.T) {
	cases := []struct {
		name       string
		initialTab string
		enrolled   bool
	}{
		{"setup requested, not yet enrolled — the tab genuinely exists", "Set up", false},
		{"enrolled, but a different tab requested", "Server", true},
		{"enrolled, no --tab at all", "", true},
		{"not enrolled, no --tab at all", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var errs bytes.Buffer
			s := &streams{errs: &errs}
			warnIfSetupTabUnreachable(s, tc.initialTab, tc.enrolled)
			if errs.String() != "" {
				t.Fatalf("warnIfSetupTabUnreachable wrote %q, want silence", errs.String())
			}
		})
	}
}
