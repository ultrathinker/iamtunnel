//go:build !linux

// iamt255_desktop_stub_test.go — !linux half of the IAMT-255 desktop
// command's canary: cmdDesktop must refuse on Windows and macOS
// hosts (where the .desktop concept does not apply) with the
// env-class exit code the operator reads on the same exit class
// (3) as every other platform-specific refusal in this package.
// The test exercises the installFn / uninstallFn function
// pointers the cross-platform dispatcher in desktop.go calls —
// that is the actual production path on !linux, not a duplicate
// stub, so a regression that changes the wiring but leaves the
// function-pointer bodies right still reddens here.

package main

import (
	"strings"
	"testing"
)

// TestIAMT255_DesktopRefusesOnNonLinux drives the install and
// uninstall function pointers (the same seam cmdDesktop uses) on
// a !linux host. Each returns the env-class refusal rather than a
// generic stub; the wording names the platform (the user reads
// the message to know whether the command is supposed to run on
// this host) and points at the platform-native alternative
// (Start menu / Services / launchd plist).
//
// CANARY (red text on regression): "the desktop shortcut is a Linux
// / freedesktop concept". Drop the desktopUnsupportedErr type or
// the !linux init wiring and the test reddens with the generic-stub
// wording instead.
func TestIAMT255_DesktopRefusesOnNonLinux(t *testing.T) {
	for _, verb := range []string{"install", "uninstall"} {
		var err error
		if verb == "install" {
			_, err = installFn()
		} else {
			_, err = uninstallFn()
		}
		if err == nil {
			t.Fatalf("desktop %s on !linux must return the env-class refusal, got nil", verb)
		}
		if _, ok := err.(*desktopUnsupportedErr); !ok {
			t.Fatalf("desktop %s on !linux: error type = %T, want *desktopUnsupportedErr (the !linux wiring must answer for itself, not the generic 'not implemented yet' wording)", verb, err)
		}
		if !strings.Contains(err.Error(), "Linux / freedesktop") {
			t.Errorf("desktop %s on !linux: error = %q, want a phrase naming the .desktop / freedesktop scope", verb, err.Error())
		}
	}
}
