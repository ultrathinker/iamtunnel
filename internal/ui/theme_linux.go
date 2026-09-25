//go:build linux

package ui

import (
	"os"
	"os/exec"
	"strings"
)

// probeExec is the seam the theme probe reads desktop settings through:
// a tool name plus arguments in, its output out. Production points it
// at exec.Command(...).Output(); tests substitute a table, so no test
// binary ever launches gsettings, kreadconfig or anything else.
var probeExec = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// ReadSystemThemeIsDark asks the running desktop for its color scheme,
// in priority order (IAMT-253):
//
//  1. GNOME: gsettings get org.gnome.desktop.interface color-scheme —
//     the canonical key since GNOME 42; prefer-dark is dark,
//     prefer-light/default light. A value the probe does not recognize
//     is not an answer — the next probe tries.
//  2. KDE Plasma: kreadconfig5 --group General --key ColorScheme, then
//     kreadconfig6 the same way (5 first: Plasma 5 ships only the 5
//     binary, Plasma 6 only the 6 one — asking both in that order hits
//     whichever exists). The value is the scheme's display name, and
//     every scheme shipped with dark colors carries "dark" in that
//     name (BreezeDark, Breeze Dark, Adwaita-dark…), so the substring
//     decides — the same heuristic the $GTK_THEME stand-in used.
//  3. $GTK_THEME with "dark" in it — the per-application override the
//     IAMT-252 stand-in read, kept as the last word a desktop can say
//     without its settings tool.
//  4. Light. An unanswered probe means the session runs on something
//     the probes above do not cover (a bare window manager, a
//     container); light is the default scheme of the desktops named
//     above, so it is the default here too — unlike the Windows
//     registry reader, which defaults dark when its key is missing.
func ReadSystemThemeIsDark() bool {
	if out, err := probeExec("gsettings", "get", "org.gnome.desktop.interface", "color-scheme"); err == nil {
		switch scheme := strings.ToLower(strings.Trim(string(out), " \t\r\n'\"")); scheme {
		case "prefer-dark":
			return true
		case "prefer-light", "default", "":
			return false
		}
		// An unrecognized scheme value: not an answer, keep asking.
	}
	for _, tool := range []string{"kreadconfig5", "kreadconfig6"} {
		out, err := probeExec(tool, "--group", "General", "--key", "ColorScheme")
		if err != nil {
			continue // tool absent or failed: not an answer either
		}
		return strings.Contains(strings.ToLower(string(out)), "dark")
	}
	return strings.Contains(strings.ToLower(os.Getenv("GTK_THEME")), "dark")
}

// defaultThemeSource is the production ThemeSource on Linux.
var defaultThemeSource ThemeSource = ThemeSourceFunc(ReadSystemThemeIsDark)
