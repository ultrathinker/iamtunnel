//go:build windows

package ui

import (
	"golang.org/x/sys/windows/registry"
)

const personalizeKeyPath = `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`

// ReadSystemThemeIsDark reads Windows registry to determine if dark mode is preferred for apps.
// AppsUseLightTheme == 1 -> Light theme (returns false)
// AppsUseLightTheme == 0 or key not found -> Dark theme (returns true)
func ReadSystemThemeIsDark() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, personalizeKeyPath, registry.READ)
	if err != nil {
		return true // default to dark
	}
	defer k.Close()

	val, _, err := k.GetIntegerValue("AppsUseLightTheme")
	if err != nil {
		return true // default to dark
	}

	return val == 0
}

// defaultThemeSource is the production ThemeSource on Windows: it reads
// the live Windows registry. (The ThemeSource seam itself is in theme.go,
// next to the frame that consumes it.)
var defaultThemeSource ThemeSource = ThemeSourceFunc(ReadSystemThemeIsDark)
