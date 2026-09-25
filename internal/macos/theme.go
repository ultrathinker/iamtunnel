package macos

import "strings"

// appleInterfaceStyleKey is the global preference macOS keeps the current
// appearance in. It is what System Settings → Appearance writes when the
// person picks Dark.
const appleInterfaceStyleKey = "AppleInterfaceStyle"

// SystemThemeIsDark reports whether macOS is in Dark Mode, by asking
// defaults(1) for the global AppleInterfaceStyle preference.
//
// The absence of the key is macOS's own way of saying "Light" — it does
// not write Light, it deletes the key — so defaults exits non-zero and
// prints "The domain/default pair of (kCFPreferencesAnyApplication,
// AppleInterfaceStyle) does not exist". That non-zero exit therefore must
// NOT be an error: it is the common case on a Mac that has never been
// switched to Dark. Anything else that makes the probe unanswerable
// (defaults missing, output we do not recognise) is also Light rather
// than Dark: a probe that cannot answer must not silently repaint the
// window in the palette the person did not choose — the same rule
// internal/server's launchctl probe follows for the same reason.
func SystemThemeIsDark() bool {
	out, err := outputFn(defaultsPath, "read", "-g", appleInterfaceStyleKey)
	return IsDarkFromDefaults(out, err)
}

// IsDarkFromDefaults is SystemThemeIsDark's decision, split out so it can
// be tested with a hand-built answer — no defaults(1) call, no Mac.
func IsDarkFromDefaults(out []byte, err error) bool {
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "dark")
}
