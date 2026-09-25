//go:build !linux

package main

// desktop_other.go — the !linux half of \`iamtunnel desktop
// install|uninstall\` (IAMT-255). Windows and macOS have no
// .desktop concept, and the cross-platform dispatcher in
// desktop.go is built so it does not need to know that fact —
// this file installs the platform bodies through the installFn /
// uninstallFn function pointers and refuses with the env-class
// error the operator reads (same exit class 3 as every other
// platform-specific refusal in this package). The real Linux
// implementation is in desktop_linux.go (//go:build linux).

import (
	"runtime"
)

// init wires installFn / uninstallFn to the !linux refusals. The
// function pointers are the only contract cmdDesktop depends on;
// keeping the !linux bodies out of desktop.go means staticcheck
// does not see dead code on darwin/windows (the seam struct, the
// .desktop template, the icon size list — all of those are
// desktop_linux.go's concern).
func init() {
	installFn = func() ([]string, error) {
		return nil, &desktopUnsupportedErr{host: runtime.GOOS}
	}
	uninstallFn = func() ([]string, error) {
		return nil, &desktopUnsupportedErr{host: runtime.GOOS}
	}
}

// desktopUnsupportedErr is the env-class error install / uninstall
// return on !linux: the operator reading the message sees exactly
// why the verb cannot run on this host and what the Linux-shaped
// alternative is (the launcher's own entry point — Start menu on
// Windows, launchd plist on macOS).
type desktopUnsupportedErr struct {
	host string
}

func (e *desktopUnsupportedErr) Error() string {
	return "iamtunnel desktop: the .desktop shortcut is a Linux / freedesktop concept (this host is " + e.host + "); on Windows and macOS the live GUI window's own entry points — Start menu, Services, launchd plist — are the platform-native paths the user already knows"
}
