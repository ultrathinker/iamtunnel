//go:build windows

package ui

// iamt400_shell_warning_windows_test.go — IAMT-400's own canary: a
// "shell" capability grant must carry a standing Warn-colored notice next
// to the New grant form, and an "exec" one (default or explicit) must
// not. Pixel verdict, not a state check, for the same reason
// TestRecordingWarningAlwaysOnClientScreen on the Client tab is one: the
// requirement is that a PERSON SEES it, and only a rendered frame can
// testify to that.

import (
	"image"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

func TestShellCapabilityWarningShowsOnlyForShell(t *testing.T) {
	for _, tc := range []struct {
		name       string
		capability string // "" leaves the box untouched (the exec default)
		wantWarn   bool
	}{
		{"untouched box (exec default)", "", false},
		{"exec typed explicitly", "exec", false},
		{"shell", "shell", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := NewFrame(FrameConfig{
				Enrolled:       false,
				InitialTab:     TabAdmin,
				HasAdminRights: false,
				StillFrame:     true,
				ForceTheme:     ThemeLight,
				Snap:           exampleSnapshot(),
			})
			if err != nil {
				t.Fatalf("NewFrame: %v", err)
			}
			f.SelectTab(TabAdmin)
			f.subTabs = map[string]string{TabAdmin: "Access"}
			// The warning has to be visible with the form open, which is
			// how an administrator actually meets it — pressing "New
			// grant" first is not part of what this canary tests.
			f.toggleForm(ctlAdminGrant)
			if tc.capability != "" {
				f.editor(ctlAdminGrant + "/capability").SetText(tc.capability)
			}

			img, err := renderFrameOffscreen(f, WindowWidth, WindowHeight)
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			warn := design.LightPalette().Warn
			region := image.Rect(0, 0, WindowWidth, WindowHeight)
			n := countColor(img, warn, region)
			got := n >= 50
			if got != tc.wantWarn {
				t.Errorf("capability=%q: %d warn-colored pixels (want shown=%v, got shown=%v) — "+
					"the standing notice must appear next to the field exactly when \"shell\" is picked, "+
					"and nowhere else, because every safety mode (log/warn/ask/block) does nothing on a shell grant",
					tc.capability, n, tc.wantWarn, got)
			}
		})
	}
}

// TestGrantCapabilityDefaultAndShellWarningLiveInOnePlace is the
// non-pixel half of the same canary: the exact word grantAccess sends to
// the gateway when the box is untouched, and the exact predicate the
// warning above is gated on, come from the same function
// (grantCapability) — not two copies of "== shell" that could drift.
func TestGrantCapabilityDefaultAndShellWarningLiveInOnePlace(t *testing.T) {
	f := newBareFrame(t)
	if got := f.grantCapability(); got != "exec" {
		t.Fatalf("grantCapability() on an untouched box = %q, want %q (IAMT-391/IAMT-400)", got, "exec")
	}
	f.editor(ctlAdminGrant + "/capability").SetText("shell")
	if got := f.grantCapability(); got != "shell" {
		t.Fatalf(`grantCapability() with "shell" typed = %q, want "shell"`, got)
	}
}
