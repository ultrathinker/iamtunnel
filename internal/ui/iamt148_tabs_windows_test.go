//go:build windows

package ui

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui/winfonts"
)

type iamt148ThemeSource struct{}

func (iamt148ThemeSource) IsDark() bool { return false }

// TestIAMT148_SetUpTabOnlyOnUnenrolledMachine locks both sides of SPEC §7.1:
// an enrolled frame has no Set up tab, while an unenrolled frame has it and
// opens on it. The mock resolver keeps the test independent of the host's
// font registry and confines its temporary files to t.TempDir().
func TestIAMT148_SetUpTabOnlyOnUnenrolledMachine(t *testing.T) {
	resolver := winfonts.NewMockResolver(map[string]string{}, t.TempDir())
	newFrame := func(enrolled bool) *Frame {
		t.Helper()
		frame, err := NewFrame(FrameConfig{
			Enrolled:    enrolled,
			ForceTheme:  ThemeLight,
			ThemeSource: iamt148ThemeSource{},
			resolver:    resolver,
		})
		if err != nil {
			t.Fatalf("NewFrame(enrolled=%v): %v", enrolled, err)
		}
		return frame
	}

	enrolled := newFrame(true)
	if enrolled.tabs.Has(TabSetUp) {
		t.Fatalf("enrolled frame contains %q tab; SPEC §7.1 permits Set up only before enrolment", TabSetUp)
	}
	if enrolled.CurrentTab() != TabClient {
		t.Fatalf("enrolled frame starts on %q, want %q", enrolled.CurrentTab(), TabClient)
	}
	enrolled.SelectTab(TabSetUp)
	if enrolled.CurrentTab() != TabClient {
		t.Fatalf("selecting absent %q changed enrolled frame to %q", TabSetUp, enrolled.CurrentTab())
	}

	unenrolled := newFrame(false)
	if !unenrolled.tabs.Has(TabSetUp) {
		t.Fatalf("unenrolled frame has no %q tab", TabSetUp)
	}
	if unenrolled.CurrentTab() != TabSetUp {
		t.Fatalf("unenrolled frame starts on %q, want %q", unenrolled.CurrentTab(), TabSetUp)
	}
	unenrolled.SelectTab(TabClient)
	unenrolled.SelectTab(TabSetUp)
	if unenrolled.CurrentTab() != TabSetUp {
		t.Fatalf("unenrolled frame could not return to %q after selecting another tab", TabSetUp)
	}
}
