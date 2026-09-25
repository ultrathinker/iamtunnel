package main

// desktop.go — the cross-platform dispatcher for \`iamtunnel desktop
// install|uninstall\` (IAMT-255). The verb is documented as a
// Linux / freedesktop.org concept — Windows and macOS have no
// .desktop notion and the operator reading the rejection text is
// pointed at the platform-native entry point (Start menu, Services,
// launchd plist) instead. The dispatcher itself is identical on
// every OS: parse, dispatch to the platform body, print one line.
//
// The platform bodies (desktop_linux.go and desktop_other.go) live
// behind a function-pointer seam — installFn / uninstallFn —
// initialised in each platform's init(). That way cmdDesktop does
// not have to know whether the seam struct (the desktopControl,
// defined in desktop_linux.go because nothing on !linux touches
// it) exists on the host at compile time; the only thing that has
// to exist on every host is the dispatcher and the two function
// pointers, which compile on every GOOS.
//
// cmdDesktop intentionally does NOT call loadConfig. The verb
// needs no settings, no data directory, no client/server identity
// — install writes to $XDG_DATA_HOME (or ~/.local/share), and
// uninstall removes the same paths. loadConfig would demand a
// config file even when the operator named none, refuse a named
// config file that does not exist (the established contract for
// every other command), and pull in server/client machinery the
// verb has no business with. The canary tests run with
// XDG_DATA_HOME pinned to t.TempDir() via the same PlatformDataEnv
// the other command tests use, so the verb stays isolated without
// loadConfig.

import (
	"fmt"
	"strings"
)

// installFn and uninstallFn are the per-platform bodies the
// dispatcher calls. Each platform's init() in desktop_linux.go or
// desktop_other.go installs the right implementation; the test
// binary on Linux installs the body that reads the recording fake
// for cmdDesktop's CLI dispatch canary. The variables are nil
// until init() runs — a missing init() would make cmdDesktop
// panic on the verb, which is the loud signal that platform
// wiring is incomplete.
var (
	installFn   func() ([]string, error)
	uninstallFn func() ([]string, error)
)

// cmdDesktop is the cross-platform dispatcher: parse
// install|uninstall, dispatch to the platform body through the
// function-pointer seam, print one line. The platform body lives
// in desktop_linux.go (real implementation, //go:build linux) and
// desktop_other.go (env-class refusal on Windows and macOS).
// cmdDesktop itself has no platform knowledge.
func cmdDesktop(s *streams, args []string) int {
	const path = "desktop"
	fs := newFlagSet(path, "install|uninstall")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(1); err != nil {
		return fail(s, err)
	}
	verb := fs.pos[0]
	switch verb {
	case "install":
		paths, err := installFn()
		if err != nil {
			return fail(s, err)
		}
		fmt.Fprintf(s.out, "iamtunnel %s: installed the desktop shortcut (paths: %s).\n", path, strings.Join(paths, ", "))
		return exitOK
	case "uninstall":
		paths, err := uninstallFn()
		if err != nil {
			return fail(s, err)
		}
		fmt.Fprintf(s.out, "iamtunnel %s: removed the desktop shortcut (paths: %s).\n", path, strings.Join(paths, ", "))
		return exitOK
	default:
		return fail(s, userErrf("iamtunnel %s: unknown verb %q — want \"install\" or \"uninstall\"", path, verb))
	}
}
