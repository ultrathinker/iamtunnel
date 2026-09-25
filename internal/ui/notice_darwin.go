//go:build darwin

package ui

// The macOS wording of the window's platform-specific sentences — see
// notice_windows.go for why they are per-platform at all (IAMT-262).
//
// All three name macOS's own levers (IAMT-264's words, so the window and
// the command line give the same instruction):
//
//   - the consent prompt is osascript's "with administrator privileges"
//     dialog (internal/macos.RelaunchAsAdmin), not UAC;
//   - the theme is the system appearance, read with defaults(1)
//     (theme_darwin.go, IAMT-262) — the same setting System Settings →
//     Appearance writes;
//   - sshd is the Remote Login switch, which is a checkbox in System
//     Settings before it is a launchd job.
const (
	restartAdminNotice = "Press Restart as administrator — macOS will ask for your permission."
	themeFollowsNotice = "The window follows the macOS light or dark setting on its own."
	sshdServiceNotice  = "Remote Login is not running — turn it on in System Settings → General → Sharing (Remote Login) before pressing Start (see the guide, When something went wrong)."
)
