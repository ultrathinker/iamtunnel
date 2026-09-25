//go:build linux

package ui

// The Linux wording of the window's platform-specific sentences — see
// notice_windows.go for why they are per-platform at all (IAMT-262).
//
// Both levers named here are the ones the Linux work already
// established: the theme stands in as $GTK_THEME (theme_linux.go,
// IAMT-253), sshd is a systemd unit, and the restart-with-rights button
// IS wired since IAMT-254 (gui_linux.go's guiRestartAsAdminLinux relaunches
// through pkexec) — IAMT-313 found this notice still describing the
// pre-254 shape (refusing outright, naming a root shell as the only
// path) months after the feature it described stopped existing: the
// banner named a missing button that was, in fact, on screen
// (internal/ui/frame.go's layoutElevationNotice always renders it,
// enabled or not) and pointed at the worse of its own two remedies (a
// root-owned GUI on the person's own display is exactly the failure mode
// IAMT-309's second observation found).
//
// F-GUI-4 (review round 20): IAMT-313's first fix over-claimed —
// it promised the button would "refuse and say so" whenever "this
// machine has no pkexec/polkit installed", but guiRestartAsAdminLinux
// only ever checks that the pkexec EXECUTABLE resolves
// (linuxLookPath("pkexec")); it has no way to tell an installed pkexec
// with no working polkit authority or session agent from a healthy one
// — that case surfaces as pkexec's own words (or, if pkexec hangs
// waiting on an agent that will never answer, the bounded five-minute
// timeout — see pkexecConfirmTimeout), never the promised message. The
// wording is narrowed to exactly what the code verifies: pkexec's own
// presence. Gates 12-15 compare docs and code, so the banner names only
// the one case (guiRestartAsAdminLinux's own refusal, "pkexec is not
// installed — start iamtunnel from a root shell instead") it can
// actually promise.
//
// F-GUI-7 (review round 25): F-GUI-4 fixed the "missing pkexec"
// half but left the OTHER half over-claiming — the notice still stated,
// unconditionally, that "a polkit prompt (pkexec) will ask for consent"
// whenever rights are missing. guiRestartAsAdminLinux (:568-570, the
// same linuxLookPath("pkexec") check F-GUI-4 already relies on) verifies
// only that the executable resolves; it has no way to know whether a
// polkit authority or session agent is actually present, so a present-
// but-non-functional pkexec gives raw pkexec output or the bounded
// timeout, never the promised prompt. The wording now says only what
// was checked to write it: pkexec's presence is what the button
// verifies; whether a prompt actually appears depends on this machine's
// own polkit setup, which is out of the button's sight until it tries.
const (
	restartAdminNotice = "Press Restart as administrator — the button relaunches through pkexec. Whether that shows a polkit consent prompt depends on this machine's own polkit setup, which the button cannot confirm in advance; if pkexec itself is not installed, it refuses immediately and says so — start iamtunnel from a root shell in that case instead."
	themeFollowsNotice = "The window follows the desktop's light or dark setting where it can ($GTK_THEME) on its own."
	sshdServiceNotice  = "The standard OpenSSH service is not running — start it (\"sudo systemctl start ssh\") before pressing Start (see the guide, When something went wrong)."
)
