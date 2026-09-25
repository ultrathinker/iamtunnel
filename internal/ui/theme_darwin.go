//go:build darwin

package ui

import "github.com/ultrathinker/iamtunnel/internal/macos"

// ReadSystemThemeIsDark is the macOS probe for the dark palette:
// `defaults read -g AppleInterfaceStyle`, where the key's absence is
// macOS's own way of reporting Light (IAMT-262, the counterpart of
// theme_windows.go's registry read and theme_linux.go's $GTK_THEME
// stand-in).
//
// The probe and its parsing live in internal/macos.SystemThemeIsDark so
// that they are covered by tests on every platform the gates run on; this
// file only wires them to the frame's ThemeSource, which is the part that
// needs a Mac to compile at all (package ui pulls in gioui.org/app).
func ReadSystemThemeIsDark() bool {
	return macos.SystemThemeIsDark()
}

// defaultThemeSource is the production ThemeSource on macOS.
var defaultThemeSource ThemeSource = ThemeSourceFunc(ReadSystemThemeIsDark)
