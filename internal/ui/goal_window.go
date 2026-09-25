//go:build windows || linux || darwin

package ui

// The goal for one machine, set from where the work happens.
//
// The goal has existed since IAMT-402, on the grant's row under Admin →
// Access. That is where it BELONGS -- a goal is a property of the grant,
// not of a screen -- but it is not where a person is standing when they
// need it. The maintainer put it plainly on 21.09.2026: the goal should
// be sayable -- something like "right
// now I am putting pictures on that desktop" -- from the list of machines
// about to be worked on, so the classifier stops refusing the obvious.
//
// So this is a second door onto the same room, not a second room. It sets
// the same goal on the same grant, through the same verb; close it and
// Admin → Access shows what was set here.
//
// WHO MAY SET IT. The same rule as the access mode, for the same reason:
// the goal is what a red command is judged against, so somebody who could
// widen their own goal could talk their way past the classifier --
// "anything goes, I am doing maintenance" -- and the safety would be
// theirs to switch off. A machine holding an administrator's key may set
// it; anyone else sees what it is and who to ask.

import (
	"image"
	"strings"
	"sync"
	"testing"

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

// goalOfMachine finds the goal claimed for this machine on the grant the
// signed-in person holds, together with the recent ones to choose from.
func (f *Frame) goalOfMachine(person, machine string) (goal string, recent []string) {
	for _, g := range f.snap.Admin.Grants {
		if g.Person == person && g.Machine == machine {
			return g.Goal, g.RecentGoals
		}
	}
	return "", nil
}

func (f *Frame) openGoalWindow(machine string) {
	if testing.Testing() {
		panic("ui: openGoalWindow invoked in test binary; tests must never open a real window")
	}
	f.mu.Lock()
	id := f.snap.Admin.ThisMachine
	f.mu.Unlock()

	admin := ""
	if id != nil {
		admin = id.Person
	}
	goal, recent := f.goalOfMachine(admin, machine)
	go runGoalWindow(f.windowTheme(), machine, admin, goal, recent,
		f.cfg.Actions.AdminGrantGoal, f.refreshAdminLists)
}

func runGoalWindow(
	theme *design.Theme,
	machine, adminPerson, goal string,
	recent []string,
	set func(person, machine, goal string) (string, error),
	after func(),
) {
	defer guardWindow("goal window", nil)

	w := new(app.Window)
	w.Option(
		app.Title("iamtunnel - goal for "+machine),
		app.Size(unit.Dp(660), unit.Dp(520)),
	)
	w.Perform(system.ActionCenter)

	var ops op.Ops
	var claimBtn, closeBtn widget.Clickable
	var goalSel, noteSel widget.Selectable
	// page scrolls the whole upper half; body is the inner scroller of
	// the claimed-goal box, which keeps its own bounded height.
	var page, body widget.List
	page.Axis = layout.Vertical
	body.Axis = layout.Vertical
	box := new(widget.Editor)
	// The box opens EMPTY, every time, even when a goal is already
	// claimed. The maintainer chose that over an expiry: a deadline is a
	// guess, while resetting to empty guarantees one cannot accidentally
	// keep working under yesterday's goal. Pre-filling it here would
	// quietly undo that decision in a
	// second place.
	var picks []*widget.Clickable
	for range recent {
		picks = append(picks, new(widget.Clickable))
	}

	var mu sync.Mutex
	note, noteKey := "", design.MutedKey
	busy := false
	current := goal

	claim := func(text string) {
		text = strings.TrimSpace(text)
		if text == "" {
			mu.Lock()
			note, noteKey = "Say what this access is for, then claim it.", design.BadKey
			mu.Unlock()
			return
		}
		mu.Lock()
		if busy || set == nil || adminPerson == "" {
			mu.Unlock()
			return
		}
		busy = true
		note, noteKey = "Claiming.", design.MutedKey
		mu.Unlock()

		go func() {
			msg, err := set(adminPerson, machine, text)
			mu.Lock()
			if err != nil {
				note, noteKey = err.Error(), design.BadKey
			} else {
				current = text
				note, noteKey = msg, design.GoodKey
				if note == "" {
					note = "Claimed. Commands on this machine are judged against it from now on."
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
			if claimBtn.Clicked(gtx) {
				claim(box.Text())
			}
			for i := range picks {
				if picks[i].Clicked(gtx) {
					// Chosen, not applied: the maintainer asked for the list
					// so it would not have to be retyped, and for the choice
					// to stay deliberate. It fills the box; claiming is
					// still a press.
					box.SetText(recent[i])
				}
			}
			mu.Lock()
			shownGoal, shownNote, shownKey, shownBusy := current, note, noteKey, busy
			mu.Unlock()

			paint.FillShape(gtx.Ops, theme.Color(design.PageKey),
				clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Op())
			layout.Inset{
				Top: unit.Dp(design.Gap), Bottom: unit.Dp(design.Gap),
				Left: unit.Dp(design.Gap), Right: unit.Dp(design.Gap),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				// EVERYTHING above the actions scrolls; the actions do
				// not. The maintainer asked for exactly that, and the reason
				// is the twenty remembered goals: as a rigid block under
				// the form they would push Claim and Close off the bottom
				// of the window, and a person with a long history could
				// not reach the button the window exists for.
				//
				// There is no paging here and none is needed: the gateway
				// keeps at most MaxGoalHistory (20) goals per grant, so
				// "the rest" does not exist. Adding a pager would be a
				// control over data that cannot arrive.
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return design.PageScrollbar(theme, &page).Layout(gtx, 1,
							func(gtx layout.Context, _ int) layout.Dimensions {
								return layout.Inset{Right: unit.Dp(design.Gap)}.Layout(gtx,
									func(gtx layout.Context) layout.Dimensions {
										return goalBody(gtx, theme, machine, adminPerson,
											shownGoal, shownNote, shownKey, recent, picks, box,
											&goalSel, &noteSel, &body)
									})
							})
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						word := "CLAIM THIS GOAL"
						if shownBusy {
							word = "CLAIMING..."
						}
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								if adminPerson == "" {
									return layout.Dimensions{}
								}
								return design.PrimaryButton(gtx, theme, &claimBtn, word)
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

// goalBody is everything the goal window scrolls: what the classifier is
// told today, what happened last, the field for a new purpose, and the
// purposes used before.
//
// It is one widget rather than a handful of closures in the loop because
// it now lives inside a scrolling list, and a list item that reaches back
// into the loop's locals for half its content is a list item that reads
// differently from what it draws.
func goalBody(
	gtx layout.Context,
	th *design.Theme,
	machine, adminPerson, goal, note string,
	noteKey design.ColorKey,
	recent []string,
	picks []*widget.Clickable,
	box *widget.Editor,
	goalSel, noteSel *widget.Selectable,
	inner *widget.List,
) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Heading(gtx, th, "What this access to "+machine+" is for")
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Text(gtx, th,
				"The AI classifier reads every command against this. Say what you are doing and the "+
					"obvious parts of it stop being refused; leave it empty and each command is judged "+
					"alone, with no idea why it was asked for.")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, th, "claimed now")
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			text := goal
			if text == "" {
				text = "(nothing claimed — commands are judged with no context)"
			}
			// Bounded, and scrolling inside its own bound: a goal is
			// prose and can be long, and letting it push the field for
			// the next one off the page would be the same defect the
			// remembered list has.
			gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(120))
			return design.PageScrollbar(th, inner).Layout(gtx, 1,
				func(gtx layout.Context, _ int) layout.Dimensions {
					return layout.Inset{Right: unit.Dp(design.Gap)}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							return design.CopyableBox(gtx, th, goalSel, text)
						})
				})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, th, noteSel, note, noteKey)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if adminPerson == "" {
				return design.Hint(gtx, th,
					"Only an administrator of this gateway can set the goal, and this machine holds no "+
						"administrator key. Ask whoever gave you this access. That is deliberate: a goal is "+
						"what a red command is judged against, so somebody who could widen their own goal "+
						"could talk their way past the classifier.")
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Field(gtx, th, "new goal",
						func(gtx layout.Context) layout.Dimensions {
							return design.TextBox(gtx, th, box,
								"what are you doing on this machine right now?")
						},
						"empty every time this opens, on purpose — a goal from yesterday is worse than none")
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if len(recent) == 0 {
						return layout.Dimensions{}
					}
					var kids []layout.FlexChild
					kids = append(kids,
						layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.Hint(gtx, th, "used before — press one to fill the box")
						}),
					)
					for i := range recent {
						i := i
						kids = append(kids,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.SecondaryButton(gtx, th, picks[i], clipStr(recent[i], 48))
							}),
							layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
						)
					}
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
				}),
			)
		}),
	)
}
