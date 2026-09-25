//go:build windows || linux || darwin

package ui

// client_exec_test.go covers client_exec.go's own pure/deterministic
// logic: classifyExecStderr (reads the outcome word
// internal/gateway/human_role.go's riskWarning writes), isExecOnlyCaps
// (the machines.mine "caps" decision screens.go's row and Connect button
// both key off), and layoutClientExecRow's execOnly=false no-op guard —
// the path every shell-granted machine's row exercises every frame.
//
// Canary: TestClassifyExecStderrReadsGatewayMarkers. Broken on purpose
// during development (swapped the WarnKey/BadKey branches): the test
// went red on its own table-driven assertion line, not on setup.
// Reverted from this file's own saved copy of client_exec.go, not `git
// checkout`.

import (
	"context"
	"strings"
	"testing"

	"gioui.org/layout"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// execNotice mirrors what runClientExec actually hands
// classifyExecStderr: the output of splitGatewayNotice, i.e. every
// "[iamtunnel] " line internal/gateway/human_role.go's formatGatewayNotice
// wrote for pty=false (no ANSI colour, "\n" line endings, prefix already
// stripped), joined back with "\n" and nothing else — never the raw
// stderr blob a machine's own output shares the wire with. That split
// happens once, in runClientExec, before classifyExecStderr is ever
// called; a test that fed it a mixed banner-plus-prose blob directly (as
// this file did before review19) was testing an input classifyExecStderr
// never actually receives.
func execNotice(lines ...string) string {
	return strings.Join(lines, "\n")
}

func TestClassifyExecStderrReadsGatewayMarkers(t *testing.T) {
	// Every non-empty case below is the exact text (post-splitGatewayNotice)
	// one of internal/gateway/human_role.go's notice-writing functions
	// produces for pty=false — not hand-invented prose. review19 finding 4
	// found two of these five falling through to the default GoodKey:
	// the classifier's own fail-closed stop (riskClassifierFailureStop)
	// and its live "log" escape (riskClassifierFailureWarningWithAction).
	cases := []struct {
		name   string
		notice string
		want   design.ColorKey
	}{
		{"green, no gateway commentary at all", "", design.GoodKey},
		{
			"yellow, run-anyway warn (riskWarningWithClassifier, default case)",
			execNotice(
				"WARNING — this command is classified yellow, and it is being run anyway.",
				"Reason (yellow): the service is stopping",
				`The gateway is allowing this warning to proceed. An administrator can choose a stricter mode with "iamtunnel admin risk mode ask" or "block", or Admin → Live in the window.`,
				"risk=yellow rule=service-stop action=warn",
			),
			design.WarnKey,
		},
		{
			"yellow, classifier degraded with the live 'log' escape (riskClassifierFailureWarningWithAction) — review19 finding 4",
			execNotice(
				"WARNING — the external classifier is unavailable; this command is running without AI risk protection.",
				"Reason: dial tcp: i/o timeout",
				"risk=unavailable rule=external-classifier action=log classifier=ai external=unavailable",
			),
			design.WarnKey,
		},
		{
			"red, block (riskWarningWithClassifier, RiskActionBlock)",
			execNotice(
				"STOPPED — this command was not run. Not a byte of it reached the machine.",
				"Reason (red): data would be lost",
				`The gateway is in "block" mode. An administrator can change that: "iamtunnel admin risk mode warn", or Admin → Live in the window.`,
				"risk=red rule=rm-recursive-root action=block E_COMMAND_BLOCKED",
			),
			design.BadKey,
		},
		{
			"red, ask refusal (riskWarningWithClassifier, RiskActionAsk)",
			execNotice(
				"APPROVAL REQUIRED — this command was not run. Not a byte of it reached the machine.",
				"Reason (red): data would be lost",
				`The gateway is in "ask" mode. Approve this exact command with "iamtunnel admin risk approve apr-0123456789abcdef", then rerun it before the approval expires.`,
				"risk=red rule=rm-recursive-root action=ask approval-id=apr-0123456789abcdef E_APPROVAL_REQUIRED",
			),
			design.BadKey,
		},
		{
			"red, external classifier unavailable fail-closed stop (riskClassifierFailureStop) — review19 finding 4",
			execNotice(
				"STOPPED — this command was not run. Not a byte of it reached the machine.",
				"Reason: the external classifier service is unavailable; the request timed out after 800 ms",
				`To continue, set risk_classifier to "rules" or "both" in gateway configuration and restart, or explicitly disable protection with:`,
				"iamtunnel admin risk mode log",
				"iamtunnel admin risk mode warn",
				"Then retry the command.",
				"risk=unavailable rule=external-classifier action=fail-closed E_RISK_CLASSIFIER_UNAVAILABLE classifier=ai",
			),
			design.BadKey,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyExecStderr(tc.notice); got != tc.want {
				t.Errorf("classifyExecStderr(%q) = %v, want %v", tc.notice, got, tc.want)
			}
		})
	}
}

// TestClassifyExecStderrIgnoresTheMachinesOwnBytes proves the split, not
// just the classify: a raw stderr blob carrying the recording banner and
// a machine's own error text (neither one "[iamtunnel] "-prefixed) must
// classify green once run through splitGatewayNotice first, exactly the
// order runClientExec uses — this is the "green, only the recording
// banner" case the pre-review19 version of this file asserted directly
// against classifyExecStderr, which is not what happens in production.
func TestClassifyExecStderrIgnoresTheMachinesOwnBytes(t *testing.T) {
	stderr := "This session is recorded. Machine win01, until 2026-09-21T00:00:00Z.\r\n" +
		"Remove-Item : Cannot find path 'C:\\test' because it does not exist.\r\n"
	notice, _ := splitGatewayNotice(stderr)
	if got := classifyExecStderr(notice); got != design.GoodKey {
		t.Errorf("classifyExecStderr(splitGatewayNotice(%q)) = %v, want %v", stderr, got, design.GoodKey)
	}
}

// TestLayoutClientExecRowIsANoOpWhenNotExecOnly pins the one path every
// current caller reaches (screens.go's hook passes execOnly=false): the
// function must return immediately without touching the receiver, so a
// nil *Frame — the cheapest possible proof nothing else was touched — is
// safe to call it on.
func TestLayoutClientExecRowIsANoOpWhenNotExecOnly(t *testing.T) {
	var f *Frame
	got := f.layoutClientExecRow(layout.Context{}, "win01", false, nil)
	if got != (layout.Dimensions{}) {
		t.Errorf("layoutClientExecRow(execOnly=false) = %+v, want the zero value", got)
	}
}

// TestLayoutClientExecRowNeverCallsRunWhenExecOnlyIsFalse guards the same
// claim from the other side: even a run func that would panic or fail
// the test if invoked must never be reached while execOnly is false —
// today's only real caller's own condition.
func TestLayoutClientExecRowNeverCallsRunWhenExecOnlyIsFalse(t *testing.T) {
	var f *Frame
	run := func(ctx context.Context, machine, command string) ClientExecResult {
		t.Fatal("run was called although execOnly was false")
		return ClientExecResult{}
	}
	f.layoutClientExecRow(layout.Context{}, "win01", false, run)
}

// TestIsExecOnlyCaps pins the exact decision screens.go's row makes for
// every machine, every frame: hide Connect and draw the exec row only
// when caps is exactly ["exec"]. caps == nil — a gateway that has not
// started sending the field, or (today) simply had none to report — must
// read as false (offer Connect, PROTOCOL's pre-1.8 shape), not as a
// silently hidden control.
func TestIsExecOnlyCaps(t *testing.T) {
	cases := []struct {
		name string
		caps []string
		want bool
	}{
		{"exec-only", []string{"exec"}, true},
		{"shell", []string{"shell"}, false},
		{"nil (pre-1.8 gateway)", nil, false},
		{"empty slice", []string{}, false},
		{"both, however that got here", []string{"shell", "exec"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isExecOnlyCaps(tc.caps); got != tc.want {
				t.Errorf("isExecOnlyCaps(%v) = %v, want %v", tc.caps, got, tc.want)
			}
		})
	}
}
