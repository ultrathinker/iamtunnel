//go:build windows

package ui

// The window's platform-specific sentences. They used to sit inline in
// frame.go and screens.go, which was true only while the ui package
// itself was Windows-only: from IAMT-252 (linux) and IAMT-262 (macOS) the
// same files are compiled for all three platforms, and a shared file that
// tells a Mac user about "the Windows OpenSSH service" is simply wrong.
// The three sentences are the ones that name the system's own levers —
// which consent prompt appears, which setting the window follows, and how
// the sshd daemon is switched on — so each platform states its own, in
// the file that is already that platform's.
//
// Windows wording: unchanged from before the split, so the settings and
// server screens read exactly as they did (the offscreen shot renders
// these screens, and its golden text is not disturbed).
const (
	restartAdminNotice = "Press Restart as administrator — Windows will ask for consent."
	themeFollowsNotice = "The window follows the Windows light or dark setting on its own."
	sshdServiceNotice  = "The standard Windows OpenSSH service is not running — start the sshd service before pressing Start (see the guide, When something went wrong)."
)
