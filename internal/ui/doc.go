// Package ui hosts the GUI: the screens for Set up, Client, Server,
// Admin and Settings, plus shot and the palette selftest (SPEC §4.2,
// §7.1). It must contain no role logic — roles live in internal/{client,
// server,admin} and the GUI only calls them.
//
// The package builds on Windows, Linux and macOS (//go:build windows ||
// linux || darwin) and the window opens on all three; the two Unix builds
// are the sanctioned departures from CGO_ENABLED=0 (gio talks to
// X11/Wayland through cgo on Linux and to Cocoa on macOS). What stays
// genuinely Windows-only is small and tagged //go:build windows: the
// registry theme reader (theme_windows.go), the Windows half of the font
// seam (fonts_windows.go), the offscreen shot machinery (shot_windows.go
// — its example data is a Windows machine) and winfonts (registry font
// discovery).
//
// The other platforms have their own halves of the same two seams, and
// nothing else:
//
//   - Linux: theme_linux.go ($GTK_THEME as a stand-in) and
//     fonts_linux.go (Gio's embedded gofont). A real desktop theme and
//     fontconfig are IAMT-253, window actions are IAMT-254.
//   - macOS (IAMT-262): theme_darwin.go (defaults(1)'s
//     AppleInterfaceStyle) and fonts_darwin.go (macfonts, a directory
//     scan of the system font directories). Both are three-line wires:
//     the probes and the resolver live in internal/macos and
//     internal/ui/macfonts, which is portable code with no cgo in it, so
//     it is built, vetted and tested on every platform the gates cover —
//     the darwin-tagged files here can only be compiled on a Mac.
//
// Everything else — frame, screens, state, actions, and the whole design
// package — is platform-neutral Gio code all three platforms share
// verbatim. (SPEC §9 still says the ui package is absent from Linux
// builds; that line described 1.0 and epic 1.1 revises it — the proposed
// amendment is in the task report.)
package ui
