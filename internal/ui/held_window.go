//go:build windows || linux || darwin

package ui

// One held command, in full, in a window of its own.
//
// The row on the Client tab shortens the command to a line so a second
// request is not buried under the first. That is right for a list and
// wrong for a decision: the person is about to say whether this exact
// text may run on that machine, and a decision made on a truncated
// command is a decision about a different command.
//
// So the detail window shows the whole thing, selectable and copyable,
// together with what stopped it -- the rule's name when a rule stopped
// it, and the classifier's own words when the AI did. The maintainer
// asked for
// exactly that distinction: the reason may be described there, and it
// should say whether the AI refused it or something else did.
//
// The two answers are here as well as in the list. A person who opened
// this to read the command should not have to close it to act on what
// they read.

import (
	"context"
	"image"
	"strings"
	"sync"
	"testing"
	"time"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// heldStoppedBy turns a verdict's rule name into the sentence a person
// needs: WHO stopped this.
//
// The gateway names the external classifier "external-classifier" and its
// own rules by their rule id. That distinction is the first thing the
// maintainer asked to see, and with good reason -- a rule is a list somebody
// wrote once and can read, while the classifier is a judgement made about
// this command in this context, and the two deserve different amounts of
// trust in different directions.
func heldStoppedBy(rule string) string {
	switch {
	case rule == "":
		return "Stopped, without a rule named."
	case strings.Contains(rule, "external"):
		return "Stopped by the AI classifier, which judged this command in the context of the declared goal."
	default:
		return "Stopped by a built-in rule (" + rule + ") -- a pattern written into the gateway, not a judgement about this situation."
	}
}

func (f *Frame) openHeldWindow(h HeldCommand) {
	if testing.Testing() {
		panic("ui: openHeldWindow invoked in test binary; tests must never open a real window")
	}
	theme := f.windowTheme()
	approve := f.cfg.Actions.ClientRiskApprove
	deny := f.cfg.Actions.ClientRiskDeny
	after := f.refreshHeld
	go runHeldWindow(theme, h, approve, deny, after)
}

func runHeldWindow(
	theme *design.Theme,
	h HeldCommand,
	approve func(ctx context.Context, id string) error,
	deny func(ctx context.Context, id string) error,
	after func(),
) {
	defer guardWindow("held window", nil)

	w := new(app.Window)
	w.Option(
		app.Title("iamtunnel - held command on "+h.Machine),
		app.Size(unit.Dp(720), unit.Dp(520)),
	)

	// Centred by GIO, before the window is shown.
	//
	// This used to be a SetWindowPos of my own on the first view event,
	// and the maintainer watched the result: it first pops up on the
	// left and then moves to the centre. That is right, and the cause is in gio's
	// own order of operations -- os_windows.go configures and SHOWS the
	// window, and only then hands over the handle in a Win32ViewEvent.
	// Anything done from that event is by definition a move of a window
	// that is already on the screen.
	//
	// gio has system.ActionCenter for exactly this, and it computes the
	// same thing (the work area of the window's own monitor, so the
	// taskbar is not counted as room and a second screen is respected).
	// Performed before the first Event, it is queued as an initial action
	// and applied inside Configure -- the SetWindowPos that runs BEFORE
	// ShowWindow. No jump, no syscalls here, and no chance of the
	// deadlock the hand-rolled version had.
	w.Perform(system.ActionCenter)

	var ops op.Ops
	var allowBtn, refuseBtn, closeBtn widget.Clickable
	var cmdSel, noteSel widget.Selectable
	var list widget.List
	list.Axis = layout.Vertical

	var mu sync.Mutex
	note, noteKey := "", design.MutedKey
	busy, settled := false, false

	answer := func(allow bool) {
		mu.Lock()
		if busy || settled {
			mu.Unlock()
			return
		}
		busy = true
		note, noteKey = "Asking the gateway.", design.MutedKey
		mu.Unlock()

		go func() {
			ctx := context.Background()
			var err error
			switch {
			case allow && approve == nil, !allow && deny == nil:
				mu.Lock()
				note, noteKey, busy = noRuntime, design.BadKey, false
				mu.Unlock()
				w.Invalidate()
				return
			case allow:
				err = approve(ctx, h.ApprovalID)
			default:
				err = deny(ctx, h.ApprovalID)
			}
			mu.Lock()
			if err != nil {
				note, noteKey = err.Error(), design.BadKey
			} else {
				settled = true
				if allow {
					note, noteKey = "Allowed. The next attempt at this exact command goes through.", design.GoodKey
				} else {
					note, noteKey = "Refused. The command stays stopped.", design.GoodKey
				}
			}
			busy = false
			mu.Unlock()
			if err == nil && after != nil {
				after()
			}
			w.Invalidate()
		}()
	}

	// A window is closed by ASKING, never by walking away.
	//
	// The loop below returns only on DestroyEvent. Returning straight from a
	// button used to look equivalent and is not: gio's window is an
	// operating-system window with a message loop, and this goroutine is what
	// serves it. Walk away from the loop and the window stays on the screen
	// with nobody answering it -- which Windows reports, correctly, as "Not
	// Responding". The maintainer pressed Close on 21.09.2026 and got exactly that.
	//
	// system.ActionClose asks the window to go. The DestroyEvent that follows
	// is what ends the loop, and by then there is no window left to ignore.
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			return
		case app.ViewEvent:
			applyTitleBarTheme(viewHandle(e), theme.IsDark())
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			if closeBtn.Clicked(gtx) {
				w.Perform(system.ActionClose)
			}
			if allowBtn.Clicked(gtx) {
				answer(true)
			}
			if refuseBtn.Clicked(gtx) {
				answer(false)
			}
			mu.Lock()
			shownNote, shownKey, done := note, noteKey, settled
			mu.Unlock()

			paint.FillShape(gtx.Ops, theme.Color(design.PageKey),
				clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Op())
			layout.Inset{
				Top: unit.Dp(design.Gap), Bottom: unit.Dp(design.Gap),
				Left: unit.Dp(design.Gap), Right: unit.Dp(design.Gap),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Heading(gtx, theme, "Held on "+h.Machine)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Hint(gtx, theme, heldLeft(h.Expires, time.Now())+
							"  ·  "+h.ApprovalID)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Hint(gtx, theme, "this exact command would run")
					}),
					// The command takes the room and scrolls: it may be
					// long, and shortening it here would defeat the whole
					// reason this window exists.
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return design.PageScrollbar(theme, &list).Layout(gtx, 1,
							func(gtx layout.Context, _ int) layout.Dimensions {
								return layout.Inset{Right: unit.Dp(design.Gap)}.Layout(gtx,
									func(gtx layout.Context) layout.Dimensions {
										return design.CopyableBox(gtx, theme, &cmdSel, h.Command)
									})
							})
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Text(gtx, theme, heldStoppedBy(h.Rule))
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if h.Reason == "" {
							return layout.Dimensions{}
						}
						return design.Hint(gtx, theme, h.Reason)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Said(gtx, theme, &noteSel, shownNote, shownKey)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if done {
							// Settled: the two answers go away rather than
							// stay pressable. A second press could only
							// produce a confusing refusal from the gateway.
							return design.SecondaryButton(gtx, theme, &closeBtn, "Close")
						}
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return design.GoodButton(gtx, theme, &allowBtn, "Allow")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return design.BadButton(gtx, theme, &refuseBtn, "Refuse")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.SecondaryButton(gtx, theme, &closeBtn, "Close")
							}),
						)
					}),
				)
			})
			e.Frame(gtx.Ops)
		}
	}
}
