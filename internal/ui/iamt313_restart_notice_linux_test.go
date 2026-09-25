//go:build linux

package ui

// iamt313_restart_notice_linux_test.go — IAMT-313: the Linux rights
// banner told the truth about IAMT-254 only until the day pkexec relaunch
// was actually wired (gui_linux.go's guiRestartAsAdminLinux), and then
// kept saying the opposite for as long as nobody read it again: "that is
// not wired on Linux yet" next to the very button that already worked,
// telling the person to fall back to the worse of the two remedies (a
// root-owned GUI on their own display — IAMT-309's second observation).
// This pins the corrected text against both failure shapes.
//
// Run on the Linux host: go test -count=1 ./internal/ui/

import (
	"strings"
	"testing"
)

// TestIAMT313_RestartNoticeDoesNotClaimTheRelaunchIsMissing is the
// canary the ticket asked for: the banner text for a build that HAS the
// elevated relaunch must not claim the relaunch is missing.
//
// Canary: restore the pre-fix string ("that is not wired on Linux yet
// (IAMT-254); start iamtunnel from a root shell meanwhile"). This test
// goes red on:
//
//	restartAdminNotice still claims the Linux relaunch is missing (IAMT-313)
func TestIAMT313_RestartNoticeDoesNotClaimTheRelaunchIsMissing(t *testing.T) {
	for _, stale := range []string{"not wired", "IAMT-254", "meanwhile"} {
		if strings.Contains(restartAdminNotice, stale) {
			t.Fatalf("restartAdminNotice still claims the Linux relaunch is missing (IAMT-313): contains %q in %q", stale, restartAdminNotice)
		}
	}
}

// TestIAMT313_RestartNoticeNamesTheWiredMechanismAndTheRealFallback pins
// what the corrected text must say instead: the relaunch goes through
// pkexec/polkit, and the root-shell advice is conditioned on pkexec
// actually being absent — never given as blanket advice for a button
// that already works, which is worse advice than the button itself
// (IAMT-309's root+GUI failure mode).
//
// Canary: reword the notice to drop either the mechanism it actually
// uses or the condition around the root-shell fallback. This test goes
// red on the corresponding substring.
func TestIAMT313_RestartNoticeNamesTheWiredMechanismAndTheRealFallback(t *testing.T) {
	if !strings.Contains(restartAdminNotice, "pkexec") {
		t.Fatalf("restartAdminNotice = %q, want it to name pkexec — the mechanism the button actually uses since IAMT-254", restartAdminNotice)
	}
	if !strings.Contains(restartAdminNotice, "not installed") {
		t.Fatalf("restartAdminNotice = %q, want the root-shell advice conditioned on pkexec actually being absent, not given unconditionally", restartAdminNotice)
	}
	if !strings.Contains(restartAdminNotice, "root shell") {
		t.Fatalf("restartAdminNotice = %q, want it to still name the real remedy for a machine with no pkexec at all", restartAdminNotice)
	}
}

// TestFGUI4_RestartNoticeDoesNotOverclaimPolkitAgentDetection is F-GUI-4's
// canary (review round 20, LOW, confirmed): guiRestartAsAdminLinux
// only ever checks that the pkexec EXECUTABLE resolves
// (linuxLookPath("pkexec")) — it has no way to tell an installed pkexec
// with no working polkit authority/agent from a healthy one, so the
// banner must not promise it can. It may still promise the ONE case the
// code actually verifies: pkexec itself missing.
//
// Canary: restore wording that promises detecting "no ... polkit
// installed" as one combined, checked condition. This test goes red on:
//
//	restartAdminNotice promises detecting a missing polkit agent/authority
//	that guiRestartAsAdminLinux never checks (F-GUI-4)
func TestFGUI4_RestartNoticeDoesNotOverclaimPolkitAgentDetection(t *testing.T) {
	if strings.Contains(restartAdminNotice, "polkit installed") || strings.Contains(restartAdminNotice, "pkexec/polkit") {
		t.Fatalf("restartAdminNotice promises detecting a missing polkit agent/authority that guiRestartAsAdminLinux never checks (F-GUI-4): %q", restartAdminNotice)
	}
}

// TestFGUI7_RestartNoticeDoesNotPromiseAPromptWillAppear is F-GUI-7's
// canary (review round 25, LOW, confirmed): F-GUI-4 fixed the
// "missing pkexec" half but the notice still stated, unconditionally,
// that a polkit prompt WILL appear whenever rights are missing.
// guiRestartAsAdminLinux only ever verifies that pkexec resolves in
// PATH (linuxLookPath) — it cannot know whether a working polkit
// authority or session agent is present, so a present-but-broken
// pkexec gives raw pkexec output or the bounded timeout, never the
// promised prompt.
//
// Canary: restore unconditional wording ("will ask for consent") with
// no hedge about this machine's own polkit setup. This test goes red
// on:
//
//	restartAdminNotice still promises a polkit prompt will appear,
//	unconditionally — guiRestartAsAdminLinux only verifies pkexec's
//	presence, never a working polkit authority/agent (F-GUI-7)
func TestFGUI7_RestartNoticeDoesNotPromiseAPromptWillAppear(t *testing.T) {
	if strings.Contains(restartAdminNotice, "will ask for consent") {
		t.Fatalf("restartAdminNotice still promises a polkit prompt will appear, unconditionally — guiRestartAsAdminLinux only verifies pkexec's presence, never a working polkit authority/agent (F-GUI-7): %q", restartAdminNotice)
	}
	if !strings.Contains(restartAdminNotice, "cannot confirm") && !strings.Contains(restartAdminNotice, "depends on") {
		t.Fatalf("restartAdminNotice = %q, want it to hedge that whether a prompt appears depends on this machine's own polkit setup, which the button cannot confirm in advance", restartAdminNotice)
	}
}
