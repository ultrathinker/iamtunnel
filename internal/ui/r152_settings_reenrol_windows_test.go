//go:build windows

package ui

import "testing"

// Gate 17 draws every tab from an unregistered frame, where Settings has
// no registration card. A registered machine's Settings carries the 1.52
// "register on another gateway" card, and must fit the default window
// too.
func TestR152_RegisteredSettingsFitsTheDefaultWindow(t *testing.T) {
	frame, err := NewFrame(FrameConfig{
		Enrolled:       true,
		InitialTab:     TabSettings,
		HasAdminRights: false,
		StillFrame:     true,
		ForceTheme:     ThemeLight,
		Snap:           exampleSnapshot(),
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	frame.SelectTab(TabSettings)
	img, err := renderFrameOffscreen(frame, WindowWidth, WindowHeight)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if thumb, _ := scrollbarPixels(t, img); thumb > 0 {
		t.Fatalf("a registered machine's Settings overflows the %dx%d window by %d scroll-thumb pixels", WindowWidth, WindowHeight, thumb)
	}
}
