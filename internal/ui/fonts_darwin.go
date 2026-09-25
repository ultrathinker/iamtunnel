//go:build darwin

package ui

import (
	"os"

	giofont "gioui.org/font"

	"github.com/ultrathinker/iamtunnel/internal/ui/macfonts"
)

// platformFonts resolves the faces the frame's shaper draws with (SPEC
// §7.1 preference lists). This is the macOS half of the seam: the
// resolver walks macOS's font directories (/System/Library/Fonts,
// /System/Library/Fonts/Supplemental, /Library/Fonts and ~/Library/Fonts
// — IAMT-262), and a missing font is a substitution, never a refusal: it
// falls back to the embedded gofont on its own.
//
// resolver, when non-nil, is a *macfonts.Resolver (tests inject a mock
// through FrameConfig.resolver); nil or anything else means the system
// search path for this person's home.
//
// Everything but the home lookup lives in macfonts.PlatformFonts, which
// internal/ui/macfonts' own tests cover on every platform the gates run
// on. This file is one of the two that genuinely need a Mac: package ui
// as a whole cannot be compiled without one (gioui.org/app needs cgo and
// Cocoa), so the darwin-only surface is kept as small as it can be — see
// the report's list of files that need a live mac build.
func platformFonts(resolver any) []giofont.FontFace {
	home, _ := os.UserHomeDir() // "" simply drops ~/Library/Fonts
	return macfonts.PlatformFonts(resolver, home)
}
