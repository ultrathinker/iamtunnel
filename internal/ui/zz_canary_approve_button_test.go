//go:build windows || linux || darwin

package ui

import (
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// The maintainer's canary for IAMT-394, the window side.
//
// The request went like this: "If you do it through the form, you can
// still press the other button, like run anyway. And the command goes
// through even after a refusal."
//
// Three things are checked here, each with its own assertion, because
// each breaks separately:
//  1. the approval id is taken from the DIAGNOSTIC field of the
//     answer, not scraped out of an English phrase that will be
//     reworded tomorrow;
//  2. an ask-mode refusal is painted as a refusal, not as a silent
//     success: without this, "nothing happened" would look exactly
//     like "everything went through";
//  3. the gateway's words are separated from the machine's bytes by
//     a prefix.
func TestCanary_IAMT394_ApprovalIDComesFromTheDiagnostic(t *testing.T) {
	const id = "apr-0123456789abcdef"
	notice := strings.Join([]string{
		"APPROVAL REQUIRED — this command was not run. Not a byte of it reached the machine.",
		"Reason (red): recursive forced deletion of '/var/lib/postgresql' outside temporary directories — data will be lost",
		`The gateway is in "ask" mode. Approve this exact command with "iamtunnel admin risk approve ` + id + `", then rerun it.`,
		"risk=red rule=rm-recursive-outside-temp action=ask approval-id=" + id + " E_APPROVAL_REQUIRED",
	}, "\n")

	if got := approvalIDIn(notice); got != id {
		t.Errorf("CANARY IAMT-394: approvalIDIn = %q, want %q -- without the id the \"Run anyway\" button has nothing to approve", got, id)
	}
	if got := approvalIDIn("APPROVAL REQUIRED — nothing ran.\nrisk=red action=block E_COMMAND_BLOCKED"); got != "" {
		t.Errorf("CANARY IAMT-394: an id was found where there is none: %q -- the button must appear only on a final refusal", got)
	}
}

func TestCanary_IAMT394_AskRefusalIsNotPaintedAsSuccess(t *testing.T) {
	const askNotice = "APPROVAL REQUIRED — this command was not run.\nrisk=red rule=x action=ask approval-id=apr-0123456789abcdef E_APPROVAL_REQUIRED"
	if got := classifyExecStderr(askNotice); got != design.BadKey {
		t.Errorf("CANARY IAMT-394: the ask-mode refusal is painted as %v, want a refusal (%v). "+
			"Green here would mean \"the command went through silently\" -- the worst possible reading of "+
			"the fact that it never ran at all", got, design.BadKey)
	}
}

func TestCanary_IAMT392_GatewayWordsAreSplitFromMachineBytes(t *testing.T) {
	stderr := strings.Join([]string{
		"[iamtunnel] WARNING — this command is classified red, and it is being run anyway.",
		"[iamtunnel] risk=red rule=x action=warn",
		"This session is recorded. Machine win-test-vm, until revoked.",
		"Remove-Item : Cannot find path 'C:\test' because it does not exist.",
	}, "\n")

	notice, rest := splitGatewayNotice(stderr)
	if strings.Contains(notice, "Remove-Item") || strings.Contains(notice, "recorded") {
		t.Errorf("CANARY IAMT-392: foreign bytes got into the gateway's words: %q", notice)
	}
	if !strings.HasPrefix(notice, "WARNING —") {
		t.Errorf("CANARY IAMT-392: the gateway's words do not start with the outcome: %q", notice)
	}
	if strings.Contains(notice, gatewayNoticePrefix) {
		t.Errorf("CANARY IAMT-392: the prefix stayed in the text meant for the window: %q", notice)
	}
	if !strings.Contains(rest, "Remove-Item") || !strings.Contains(rest, "recorded") {
		t.Errorf("CANARY IAMT-392: the machine's output was lost: %q", rest)
	}
	if strings.Contains(rest, "[iamtunnel]") {
		t.Errorf("CANARY IAMT-392: the gateway's words leaked into the machine's output: %q", rest)
	}
}
