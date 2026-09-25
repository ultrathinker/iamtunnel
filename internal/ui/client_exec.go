//go:build windows || linux || darwin

package ui

// client_exec.go: the exec-only grant's Client-tab window.
//
// A per-machine command field + Run button, shown ONLY for a machine
// whose grant is exec-only, with the gateway's risk verdict
// (green/yellow/red) drawn on the output, and the ordinary Connect
// button not even offered there. That needed one fact this window had
// nowhere at first: whether a given machine's grant is "shell" or "exec"
// (PROTOCOL §6's machines.mine schema carried no `caps` before 1.8).
// MachineAccess.Caps (state.go) and Actions.ClientExec (live.go) close
// that gap end to end, both additions-only next to files being actively
// rewritten elsewhere.
//
// This file itself still keeps layoutClientExecRow's execOnly/run as
// explicit parameters rather than reaching into Frame/Actions directly
// inside the render function — runClientExec below is the one place that
// bridges to f.cfg.Actions.ClientExec, so the render function stays
// testable with a bare *Frame (client_exec_test.go) the same way it was
// before the wire existed.
//
// screens.go's own hook — the one-line hook this row needs —
// now passes isExecOnlyCaps(m.Caps) and f.runClientExec.

import (
	"context"
	"strings"

	"gioui.org/layout"
	"gioui.org/unit"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// isExecOnlyCaps reports whether caps names exec and nothing else — the
// one question this row needs answered before deciding whether to
// draw at all (mirrors internal/client.Machine.ExecOnly(); this package
// never imports internal/client, so the check is repeated here on the
// window's own MachineAccess.Caps rather than shared). caps == nil (a
// gateway that has not yet started sending the field) reads as false:
// offer Connect, the same pre-1.8 behavior, rather than silently hiding
// a control a person may in fact be able to use.
func isExecOnlyCaps(caps []string) bool {
	return len(caps) == 1 && caps[0] == "exec"
}

// runClientExec adapts f.cfg.Actions.ClientExec — plain (stdout, stderr,
// error), the same undecorated shape AdminRiskCheck already returns —
// into layoutClientExecRow's own run signature, which always returns a
// ClientExecResult and never an error: a failed dial or a gateway
// refusal is exactly the kind of thing this row's own status line under
// the output box already shows other failures in, not a second,
// differently-shaped error path. The verdict color is decided here, by
// classifyExecStderr reading stderr alone — the action itself stays
// ignorant of window/color concerns.
func (f *Frame) runClientExec(ctx context.Context, machine, command string) ClientExecResult {
	action := f.cfg.Actions.ClientExec
	if action == nil {
		return ClientExecResult{Verdict: design.BadKey, Summary: noRuntime}
	}
	stdout, stderr, err := action(ctx, machine, command)
	if err != nil {
		return ClientExecResult{Verdict: design.BadKey, Summary: err.Error()}
	}
	notice, machineErr := splitGatewayNotice(stderr)
	output := stdout
	if machineErr != "" {
		if output != "" && !strings.HasSuffix(output, "\n") {
			output += "\n"
		}
		output += machineErr
	}
	verdict := classifyExecStderr(notice)
	summary := "Ran."
	if notice != "" {
		// The gateway's own words, verbatim, in the coloured slot. They
		// already state the outcome in a sentence (IAMT-395), so a
		// summary of our own on top of them would only say it twice.
		summary = notice
	}
	return ClientExecResult{Output: output, Verdict: verdict, Summary: summary, ApprovalID: approvalIDIn(notice)}
}

// approvalPrefix is how the gateway's "ask"-mode refusal names the one
// pending approval, inside the diagnostic line riskWarningWithApproval
// writes (IAMT-394).
const approvalPrefix = "approval-id="

// approvalIDIn picks the approval id out of the gateway's refusal.
//
// The id is read from the DIAGNOSTIC field rather than from the prose
// around it, and that is why the gateway puts it there: prose is meant
// to be rewritten, and a window that scraped an English sentence would
// break the next time somebody improved the sentence.
//
// An empty result is the ordinary case — every mode but "ask", and every
// command "ask" lets through — and means the row offers no second button.
func approvalIDIn(notice string) string {
	at := strings.Index(notice, approvalPrefix)
	if at < 0 {
		return ""
	}
	id := notice[at+len(approvalPrefix):]
	if cut := strings.IndexAny(id, " \t\r\n"); cut >= 0 {
		id = id[:cut]
	}
	return id
}

// gatewayNoticePrefix is what internal/gateway/human_role.go's
// riskWarning puts at the head of every line it writes.
const gatewayNoticePrefix = "[iamtunnel] "

// splitGatewayNotice separates the gateway's own lines from the
// machine's (IAMT-392).
//
// Both arrive on one stderr, and until this split the window drew them
// as one undifferentiated block in the neutral colour -- so a red
// command's warning looked exactly like a compiler's chatter, which is
// what the maintainer objected to on 20.09.2026: a warning that still
// lets the command through has to be shown in orange, while one that
// does not let it through has to be red.
//
// The prefix is the only reliable separator, which is why riskWarning
// repeats it on every line rather than once per notice. The prefix is
// dropped from the returned text: in the window the notice already
// stands apart by colour and position, and four repetitions of
// "[iamtunnel] " would be noise. The CLI, which has no colours, keeps
// them.
//
// Deliberately NOT treated as gateway words here: the recording banner
// ("This session is recorded. Machine X, until Y."). It carries no
// prefix -- PROTOCOL §5 fixes its bytes -- and it is not a verdict, so
// colouring it as one would cry wolf on every single command.
func splitGatewayNotice(stderr string) (notice, rest string) {
	if stderr == "" {
		return "", ""
	}
	var gw, machine []string
	for _, line := range strings.Split(stderr, "\n") {
		if trimmed := strings.TrimSuffix(line, "\r"); strings.HasPrefix(trimmed, gatewayNoticePrefix) {
			gw = append(gw, strings.TrimPrefix(trimmed, gatewayNoticePrefix))
			continue
		}
		machine = append(machine, line)
	}
	return strings.Join(gw, "\n"), strings.Trim(strings.Join(machine, "\n"), "\r\n")
}

// ClientExecResult is what one "client exec" run hands back to the
// window: the combined stdout+stderr text for the output box, the color
// the gateway's own verdict earns, and the one-line summary shown under
// the box.
type ClientExecResult struct {
	Output  string
	Verdict design.ColorKey
	Summary string

	// ApprovalID is set only when the gateway refused under "ask" mode
	// and is waiting for a person to say yes (IAMT-394). It is what the
	// row's second button approves, and it names exactly the command
	// that was refused.
	ApprovalID string
}

// classifyExecStderr reads the marker text internal/gateway/human_role.go's
// riskWarning already writes to the exec channel's stderr, and turns it
// into the window's three-color verdict — green silently,
// yellow with a warning, red with a stop and a reason — without this
// window keeping a second copy of the risk rules themselves. PROTOCOL is
// explicit that the classifier lives exactly once, on the gateway
// (risk.check classifies the line with the GATEWAY's rules, not with a
// copy of the rules inside the client binary, which after an update may
// drift apart) — this function reads the gateway's own words, it does not
// re-decide anything.
//
// review19 finding 4: this used to switch on the trailing diagnostic
// TAG (E_COMMAND_BLOCKED, E_APPROVAL_REQUIRED, action=warn), with an
// unrecognised tag falling through to the default case — GoodKey. Every
// one of the three times this class of bug hit (a stopped "ask" refusal,
// a mode button, and this notice) was the same shape: a new tag the
// switch had never heard of read as silent success. E_RISK_CLASSIFIER_UNAVAILABLE's
// "action=fail-closed" and the live-mode escape's "action=log" are two
// more tags nobody had listed here.
//
// The fix reads the OUTCOME WORD every notice starts with instead of the
// tag it ends with. riskWarning's own doc comment makes this a closed,
// three-word set by construction ("the outcome comes FIRST, in words,
// before any code or rule name"): a command either ran (WARNING, maybe
// with a caveat) or it did not (STOPPED, APPROVAL REQUIRED, or whatever a
// future fourth refusal is spelled) — there is no other truth to state.
// Checking the small "it still ran" word and defaulting everything else,
// known or not yet invented, to the stopped colour means a future new way
// to STOP a command needs no edit here at all, and a future new way to
// let one through with a caveat needs one — but forgetting that one now
// paints an annoying false red instead of the dangerous false green this
// review found three times running.
func classifyExecStderr(stderr string) design.ColorKey {
	if stderr == "" {
		return design.GoodKey
	}
	first := stderr
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if strings.HasPrefix(first, "WARNING") {
		return design.WarnKey
	}
	// ALLOWED is the one other outcome that is not a refusal: the command
	// was stopped for review and a person let it through, so it ran. It
	// is named explicitly rather than folded into the default because the
	// default here is RED on purpose -- three times in one day a new
	// gateway outcome fell into a silent green, and the rule that fixed
	// it was "anything the gateway says, that is not a warning, is a
	// refusal until proven otherwise". This is the proof.
	if strings.HasPrefix(first, "ALLOWED") {
		return design.GoodKey
	}
	return design.BadKey
}

// layoutClientExecRow renders one machine row's exec-only UI: the
// command field, the Run button, and — once something has run — the
// output box (design.CopyableBox, the same primitive IAMT-355's
// layoutHandOver already uses elsewhere on this screen) colored by the
// gateway's verdict.
//
// execOnly gates whether this row draws at all (screens.go's hook passes
// isExecOnlyCaps(m.Caps)); false makes it a no-op, touching neither gtx
// nor f, so a nil *Frame is safe to call this with for exactly that case
// (see client_exec_test.go, which still pins that path directly since it
// is what every shell-granted machine's row exercises every frame). run
// is the actual network call, injected rather than reached through
// f.cfg.Actions directly, so this render function stays testable without
// a live Frame — screens.go passes f.runClientExec.
func (f *Frame) layoutClientExecRow(gtx layout.Context, machine string, execOnly bool, run func(ctx context.Context, machine, command string) ClientExecResult) layout.Dimensions {
	if !execOnly {
		return layout.Dimensions{}
	}
	ctl := "client/exec/" + machine
	statusCtl := ctl + "/said"

	if run == nil {
		return design.Said(gtx, f.theme, f.sel(statusCtl),
			"This grant only runs commands, and this build has no runtime wired to send one.", design.BadKey)
	}

	launch := func(command string, approveFirst string) {
		f.beginGiving(statusCtl, "Running.", func() (give, text string, key design.ColorKey) {
			ctx := context.Background()
			if approveFirst != "" {
				approve := f.cfg.Actions.ClientRiskApprove
				if approve == nil {
					return "", noRuntime, design.BadKey
				}
				if err := approve(ctx, approveFirst); err != nil {
					f.setApproval(ctl, "")
					return "", "The gateway would not lift its refusal: " + err.Error(), design.BadKey
				}
			}
			res := run(ctx, machine, command)
			// Either the gateway named a new pending approval, or this
			// run settled the old one -- both cases are the same write.
			f.setApproval(ctl, res.ApprovalID)
			return res.Output, res.Summary, res.Verdict
		})
	}

	if f.submitted(gtx, ctl) || f.btn(ctl+"/run").Clicked(gtx) {
		command := strings.TrimSpace(f.editor(ctl).Text())
		if command == "" {
			f.say(statusCtl, "Type the command to run on this machine first.", design.BadKey)
		} else {
			launch(command, "")
		}
	}
	// "Run anyway" is deliberately not a confirm-twice control. The
	// gateway already stopped this command once and said why in the
	// block above the button; asking again would only teach the person
	// to click past both (IAMT-394).
	if pending := f.approvalOf(ctl); pending != "" && f.btn(ctl+"/approve").Clicked(gtx) {
		if command := strings.TrimSpace(f.editor(ctl).Text()); command != "" {
			launch(command, pending)
		}
	}

	said := f.saidUnder(statusCtl)
	word := "Run"
	if f.busy(statusCtl) {
		word = "Running…"
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "command",
				func(gtx layout.Context) layout.Dimensions {
					return design.TextBox(gtx, f.theme, f.editor(ctl), "cmd /c echo hello")
				},
				"runs exactly this, on "+machine+", through the exec-only grant — no shell, no other machine bytes")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.SecondaryButton(gtx, f.theme, f.btn(ctl+"/run"), word)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if f.approvalOf(ctl) == "" {
				return layout.Dimensions{}
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.PrimaryButton(gtx, f.theme, f.btn(ctl+"/approve"), "RUN ANYWAY")
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if said.give == "" && said.text == "" {
				return layout.Dimensions{}
			}
			// The gateway's verdict goes ABOVE the machine's output, in
			// the order the two were actually produced: the gateway
			// decides, says so, and only then are any machine bytes
			// possible at all. Under "block" there are none, and the
			// verdict is the whole answer (IAMT-392, IAMT-395).
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if said.text == "" {
						return layout.Dimensions{}
					}
					return design.Said(gtx, f.theme, f.sel(statusCtl+"/text"), said.text, said.key)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if said.give == "" {
						return layout.Dimensions{}
					}
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.CopyableBox(gtx, f.theme, f.sel(ctl+"/output"), said.give)
						}),
					)
				}),
			)
		}),
	)
}

// setApproval and approvalOf hold the one pending "ask"-mode approval a
// row is carrying (IAMT-394). Both take f.mu: the value is written from
// beginGiving's goroutine and read on the layout goroutine every frame.
//
// Writing "" is as meaningful as writing an id: a run that the gateway
// let through is exactly how a stale refusal stops being offered.
func (f *Frame) setApproval(ctl, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.approvals == nil {
		f.approvals = map[string]string{}
	}
	if id == "" {
		delete(f.approvals, ctl)
		return
	}
	f.approvals[ctl] = id
}

func (f *Frame) approvalOf(ctl string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.approvals[ctl]
}
