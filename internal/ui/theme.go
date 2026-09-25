//go:build windows || linux || darwin

package ui

// ThemeSource reports whether the dark palette should be used. Frame consults it
// on every CheckThemeSync call instead of reading the system theme directly,
// so tests can supply their own source instead of touching the real thing.
type ThemeSource interface {
	IsDark() bool
}

// ThemeSourceFunc adapts a plain func() bool to a ThemeSource.
type ThemeSourceFunc func() bool

// IsDark calls f.
func (f ThemeSourceFunc) IsDark() bool {
	return f()
}
