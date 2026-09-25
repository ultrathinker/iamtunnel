//go:build windows || linux || darwin

package ui

// The commands the gateway is holding, and the two words that settle one.
//
// Until 21.09.2026 a held command existed only as a sentence in the
// refusal the agent received, carrying an id to be copied into a terminal
// on some other screen. The maintainer met that the first time they asked an AI
// agent to copy a file, and the objection was exact: these prohibitions
// had to be decided outside the AI agent, and a prohibition should be
// one that can be agreed to right inside the program, after which it
// re-runs that same request.
//
// So the question comes to the person instead. The masthead says something is
// held whatever tab is open; this list says what, on the tab the machines
// are on; and the detail window says the whole of it, because a person
// deciding whether a command may run must see the command, not a summary
// of it.
//
// WHAT THIS IS AND IS NOT. Approving here is exactly as strong as
// approving from the terminal, and no stronger: an agent running on this
// machine with this key could call the same verb. Its value is that a
// person SEES each red command before it runs -- not that an agent is
// prevented from passing. A real wall needs a second key on a second
// machine, and that is a different piece of work.

import (
	"context"
	"strconv"
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/unit"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// heldCtl is one held command's control prefix, keyed by approval id so
// two rows never share a button or a status line.
func heldCtl(id string) string { return "client/held/" + id }

// shortCommand is the row's one-line form. The whole command lives in the
// detail window; a row that wrapped to four lines would bury the next
// request under the first one.
func shortCommand(cmd string) string {
	cmd = strings.TrimSpace(strings.ReplaceAll(cmd, "\n", " "))
	return clipStr(cmd, 64)
}

// heldLeft is how long the offer has, in words a glance can use. A person
// reading "expires 12:41:07Z" has to work out whether that is soon.
func heldLeft(expires time.Time, now time.Time) string {
	if expires.IsZero() {
		return ""
	}
	d := expires.Sub(now)
	if d <= 0 {
		return "lapsed"
	}
	if d < time.Minute {
		return strconv.Itoa(int(d.Seconds())) + "s left"
	}
	return strconv.Itoa(int(d.Minutes())) + "m left"
}

// heldDeciderShort names WHO stopped this, in the two or three words a
// list row has room for.
//
// The full sentence lives in the detail window, and that was where the
// maintainer could not find it: looking at the list they asked whether
// it was the AI or the program's own internal stopper. The reason text
// hints at it -- the
// classifier's reasons read differently from a rule's -- but hinting is
// not naming, and this is the first thing anyone wants to know, every
// time.
func heldDeciderShort(rule string) string {
	switch {
	case rule == "":
		return "the gateway"
	case strings.Contains(rule, "external"):
		return "AI classifier"
	default:
		return "rule " + rule
	}
}

// layoutHeldList draws the held commands, or nothing at all when there
// are none. Nothing, not "no held commands": an empty state here would be
// a permanent reminder of a thing that almost never happens.
func (f *Frame) layoutHeldList(gtx layout.Context) layout.Dimensions {
	held := f.snap.Client.Held
	if len(held) == 0 {
		return layout.Dimensions{}
	}
	now := time.Now()

	var children []layout.FlexChild
	children = append(children,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Status(gtx, f.theme,
				func(gtx layout.Context) layout.Dimensions {
					return design.Dot(gtx, f.theme, design.WarnKey, false)
				},
				func(gtx layout.Context) layout.Dimensions {
					return design.Deck(gtx, f.theme,
						"Stopped and waiting for you. Allow one and the agent's next attempt at "+
							"the same command goes through; refuse it and the attempt is settled.")
				})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
	)

	for i := range held {
		h := held[i]
		ctl := heldCtl(h.ApprovalID)
		if f.btn(ctl + "/allow").Clicked(gtx) {
			f.settleHeld(ctl, h.ApprovalID, true)
		}
		if f.btn(ctl + "/refuse").Clicked(gtx) {
			f.settleHeld(ctl, h.ApprovalID, false)
		}
		if f.btn(ctl + "/detail").Clicked(gtx) {
			f.openHeldWindow(h)
		}
		said := f.saidUnder(ctl)
		children = append(children,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.Fixed(gtx, f.theme,
									orDash(clipStr(h.Machine, 24))+"  "+shortCommand(h.Command))
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								// Who first, then why, then how long is
								// left: the order the questions are asked.
								line := "stopped by " + heldDeciderShort(h.Rule)
								if h.Reason != "" {
									line += " · " + h.Reason
								}
								if left := heldLeft(h.Expires, now); left != "" {
									line += " · " + left
								}
								return design.Hint(gtx, f.theme, line)
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.SecondaryButton(gtx, f.theme, f.btn(ctl+"/detail"), "Details")
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.GoodButton(gtx, f.theme, f.btn(ctl+"/allow"), "Allow")
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.BadButton(gtx, f.theme, f.btn(ctl+"/refuse"), "Refuse")
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Said(gtx, f.theme, f.sel(ctl+"/said"), clipStr(said.text, 300), said.key)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		)
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// settleHeld answers one held command, yes or no.
//
// Neither answer confirms twice. The person is looking at the command
// while they press, which is the confirmation; a second press would only
// train them to press twice. Refusing is safe by construction -- the
// command did not run -- and allowing is the decision they came here to
// make.
func (f *Frame) settleHeld(ctl, id string, allow bool) {
	stopCallingForAttention(f.mainHandle())
	word := "Allowing."
	if !allow {
		word = "Refusing."
	}
	f.begin(ctl, word, func() (string, design.ColorKey) {
		defer f.refreshHeld()
		ctx := context.Background()
		if allow {
			approve := f.cfg.Actions.ClientRiskApprove
			if approve == nil {
				return noRuntime, design.BadKey
			}
			if err := approve(ctx, id); err != nil {
				return err.Error(), design.BadKey
			}
			return "Allowed. The agent's next attempt at this exact command will go through.", design.GoodKey
		}
		deny := f.cfg.Actions.ClientRiskDeny
		if deny == nil {
			return noRuntime, design.BadKey
		}
		if err := deny(ctx, id); err != nil {
			return err.Error(), design.BadKey
		}
		return "Refused. The command stays stopped.", design.GoodKey
	})
}

// refreshHeld asks the gateway what is held now and writes it into the
// snapshot, so a settled request leaves the list at once rather than
// waiting for the next poll.
func (f *Frame) refreshHeld() {
	ask := f.cfg.Actions.ClientRiskPending
	if ask == nil {
		return
	}
	// A failed read is not evidence that nothing is held, so the list is
	// left exactly as it was rather than emptied. What the gateway the
	// window has since switched away from holds is not this screen's
	// either (R1-CX F-16).
	_ = f.forCurrentGateway(func(ctx context.Context) (func(*Snapshot), error) {
		held, err := ask(ctx)
		if err != nil {
			return nil, err
		}
		return func(s *Snapshot) { s.Client.Held = held }, nil
	})
}
