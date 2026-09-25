// Package macos carries the macOS integration the window and the server
// installation reach for that has no portable equivalent: the shell and
// AppleScript command lines that open a Terminal.app window (SPEC §3.1's
// "the session itself is a terminal"), the consent relaunch with
// administrator privileges that replaces Windows's UAC (SPEC §3.2), and
// the reading of the system appearance with defaults(1) (SPEC §7.1's
// theme, the macOS half of the seam whose Linux half is $GTK_THEME).
//
// Like internal/ui/macfonts this package is deliberately NOT build-tagged
// to darwin, and for the same reason: everything in it is string building
// plus one exec seam, and the macOS window itself cannot be built on the
// Linux or Windows gates host (gioui.org/app needs cgo and Cocoa), so a
// darwin tag would leave every line here — including the quoting that
// stands between a machine name and a shell — without a single test run
// outside a developer's Mac. Untagged, the quoting is proved by tests
// that hand hostile names to a real /bin/sh on the Unix gates host, and
// only the callers are macOS-only (internal/ui/theme_darwin.go and
// cmd/iamtunnel/gui_darwin.go).
//
// The seams below are the production OS calls: each panics under
// testing.Testing(), so a test that forgets to install a fake fails
// loudly instead of opening a real Terminal window or asking a real
// human for an administrator password (the same discipline as
// internal/server's launchctlFn and internal/winkeys' spawn seams).
package macos
