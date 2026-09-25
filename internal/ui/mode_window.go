//go:build windows || linux || darwin

package ui

// What this grant lets you do, what it is FOR, and who may change
// either (21.09.2026).
//
// The maintainer's idea, looking at a machine row that showed "until revoked"
// and the reachability of sshd but never said which of the two modes the
// access was: name the mode, and let a click on it open something where
// the mode can be changed.
//
// Half of that is a plain gap and is now filled: the row says "exec only"
// or "full shell" in words.
//
// The other half needed a line drawn through it. This window is opened
// from the CLIENT tab -- the screen of the person ENTERING -- and if the
// one entering could widen their own access, the narrow mode would
// protect nobody. The whole reason exec-only exists is that the thing
// holding the grant is increasingly an AI agent, and the first thing a
// capable agent does when it meets a wall is look for the gate in it.
//
// So the window shows the change only to a machine that ALSO carries an
// administrator's identity on that gateway, and the request travels as an
// administrator's, signed with that key. The gateway grades it by the key
// and would refuse it whatever this window believed. A client without
// that key is not shown a disabled button -- it is told in a sentence who
// can do this instead, because a greyed-out control invites hunting for
// the way to un-grey it.
//
// THE GOAL, added the same evening on the maintainer's word: it should
// be possible to change a machine's goal on this screen -- natural,
// given that the person is the administrator.
// The goal (SPEC IAMT-402) is what a context-aware classifier reads a
// command AGAINST, and it belongs to this exact person-machine pair --
// the same pair this window is already about. Until now it could only be
// claimed on the Admin tab, several screens away from the machine it
// governs and from the mode it is weighed together with. Two things that
// decide whether one command is allowed now sit in one window.
//
// It travels the same road and under the same rule as the mode: an
// administrator's key or nothing. And it keeps IAMT-402's own decision
// about the form -- the box always opens EMPTY, with the goal in force
// shown separately and only for reading, so nobody works under
// yesterday's goal by pressing Save on a box that helpfully pre-filled
// itself.

import (
	"context"
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

// capWord is the mode of a grant, in the words the window uses for it.
func capWord(caps []string) string {
	if isExecOnlyCaps(caps) {
		return "exec only"
	}
	return "full shell"
}

// goalSnapshot is what one fetch of the gateway's lists says about ONE
// grant's goal: the goal in force, this grant's own recent goals for the
// picker, and the classifier that is going to read it (or not).
type goalSnapshot struct {
	Goal       string
	Recent     []string
	Classifier string
	// Found reports the gateway listed this person-machine pair at all.
	// A window opened on a grant that has just been revoked elsewhere
	// must say so rather than draw an empty goal as if none had been
	// claimed.
	Found bool
}

// goalOf picks ONE grant's goal out of a whole fetch of the gateway's
// lists. It is separate from the drawing, and it is the only part of the
// goal block a test can hold: the window itself opens a real
// operating-system window and is never entered by one.
func goalOf(lists AdminLists, person, machine string) goalSnapshot {
	snap := goalSnapshot{Classifier: lists.RiskMode.Classifier}
	for _, g := range lists.Grants {
		if g.Person != person || g.Machine != machine {
			continue
		}
		snap.Goal, snap.Recent, snap.Found = g.Goal, g.RecentGoals, true
		break
	}
	return snap
}

// classifierIgnoresGoalWord reports whether a classifier by this name
// cannot use a claimed goal at all (SPEC IAMT-402 point 6): rules parse
// text, not context, so a goal reaches only an external classifier. An
// unknown word reads as "rules" — see classifierIgnoresGoal, which asks
// this same question of the Frame's own snapshot.
func classifierIgnoresGoalWord(name string) bool {
	switch name {
	case "ai", "both":
		return false
	default:
		return true
	}
}

// openModeWindow opens the window that explains one grant's mode and,
// for an administrator, changes it -- and the goal it is judged against.
func (f *Frame) openModeWindow(machine string, caps []string) {
	if testing.Testing() {
		panic("ui: openModeWindow invoked in test binary; tests must never open a real window")
	}
	f.mu.Lock()
	id := f.snap.Admin.ThisMachine
	f.mu.Unlock()

	admin := ""
	if id != nil {
		admin = id.Person
	}

	// The goal is fetched by the window itself, not read off the
	// Frame's snapshot: the Admin tab may never have been opened in
	// this run, and a goal shown from a snapshot that was never filled
	// would read as "none claimed" for a grant that has one.
	var loadGoal func() (goalSnapshot, error)
	if ask := f.cfg.Actions.AdminList; ask != nil && admin != "" {
		loadGoal = func() (goalSnapshot, error) {
			lists, err := ask(context.Background())
			if err != nil {
				return goalSnapshot{}, err
			}
			return goalOf(lists, admin, machine), nil
		}
	}
	var saveGoal func(goal string) (string, error)
	if claim := f.cfg.Actions.AdminGrantGoal; claim != nil && admin != "" {
		saveGoal = func(goal string) (string, error) { return claim(admin, machine, goal) }
	}
	// The Admin tab's own grants list is one fetch out of date the
	// moment a goal is claimed here -- IAMT-357's rule for every action
	// that changes what the gateway holds.
	afterGoal := func() {}
	if f.cfg.Actions.AdminList != nil {
		afterGoal = f.refreshAdminLists
	}

	// Its OWN theme -- see windowTheme in frame.go. This window is
	// where the maintainer met the shared-shaper crash on 21.09.2026.
	go runModeWindow(f.windowTheme(), machine, capWord(caps), admin,
		f.cfg.Actions.AdminSetGrantCaps, loadGoal, saveGoal, f.refreshMachines, afterGoal)
}

func runModeWindow(
	theme *design.Theme,
	machine, mode, adminPerson string,
	set func(person, machine, capability string) (string, error),
	loadGoal func() (goalSnapshot, error),
	saveGoal func(goal string) (string, error),
	afterChange func(),
	afterGoal func(),
) {
	defer guardWindow("mode window", nil)

	w := new(app.Window)
	w.Option(
		app.Title("iamtunnel - access to "+machine),
		app.Size(unit.Dp(720), unit.Dp(700)),
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
	var execBtn, shellBtn, closeBtn, goalBtn, goalOpenBtn widget.Clickable
	var sel, goalSel, goalNoteSel widget.Selectable
	var page widget.List
	page.Axis = layout.Vertical

	goalBox := new(widget.Editor)
	goalBox.SingleLine = true
	goalBox.Submit = true

	// The picker's per-option buttons. Keyed by the option's own text
	// rather than by its position: the list is refetched, and a button
	// that kept its place in a re-sorted list would carry the press of
	// one goal onto another. Touched only while drawing, so no lock.
	goalPicks := map[string]*widget.Clickable{}
	pickBtn := func(name string) *widget.Clickable {
		b, ok := goalPicks[name]
		if !ok {
			b = new(widget.Clickable)
			goalPicks[name] = b
		}
		return b
	}
	goalOpen := false

	// The gateway is asked on goroutines of their own, so everything
	// below is written there and read while drawing. A mutex, not bare
	// variables: the same shape the command window uses, and the one the
	// race detector insists on.
	var mu sync.Mutex
	note, noteKey := "", design.MutedKey
	busy := false
	goal := goalSnapshot{}
	goalNote, goalNoteKey := "", design.MutedKey
	goalBusy := false

	apply := func(capability string) {
		mu.Lock()
		if busy || set == nil || adminPerson == "" {
			mu.Unlock()
			return
		}
		busy = true
		note, noteKey = "Asking the gateway.", design.MutedKey
		mu.Unlock()

		go func() {
			msg, err := set(adminPerson, machine, capability)
			mu.Lock()
			if err != nil {
				note, noteKey = err.Error(), design.BadKey
			} else {
				note, noteKey = msg, design.GoodKey
				if capability == "exec" {
					mode = "exec only"
				} else {
					mode = "full shell"
				}
			}
			busy = false
			mu.Unlock()
			if err == nil && afterChange != nil {
				afterChange()
			}
			w.Invalidate()
		}()
	}

	// fetchGoal reads what the gateway holds for this grant right now.
	// Silent about its own failure on the FIRST read -- a window opened
	// on a gateway that cannot be reached already says so through
	// everything else on it -- and loud when a save asked for it.
	fetchGoal := func(loud bool) {
		if loadGoal == nil {
			return
		}
		go func() {
			snap, err := loadGoal()
			mu.Lock()
			if err != nil {
				if loud {
					goalNote, goalNoteKey = err.Error(), design.BadKey
				}
			} else {
				goal = snap
			}
			mu.Unlock()
			w.Invalidate()
		}()
	}

	claim := func() {
		text := strings.TrimSpace(goalBox.Text())
		mu.Lock()
		if goalBusy || saveGoal == nil || adminPerson == "" {
			mu.Unlock()
			return
		}
		if text == "" {
			goalNote, goalNoteKey = "Describe what this access is for before saving.", design.BadKey
			mu.Unlock()
			w.Invalidate()
			return
		}
		goalBusy = true
		goalNote, goalNoteKey = "Asking the gateway.", design.MutedKey
		mu.Unlock()

		go func() {
			msg, err := saveGoal(text)
			mu.Lock()
			if err != nil {
				goalNote, goalNoteKey = err.Error(), design.BadKey
			} else {
				goalNote, goalNoteKey = msg, design.GoodKey
			}
			goalBusy = false
			mu.Unlock()
			if err == nil {
				// The box is emptied by the claim that SUCCEEDED, so
				// what stands below is the goal the gateway now holds
				// and never a leftover draft of it.
				goalBox.SetText("")
				if afterGoal != nil {
					afterGoal()
				}
				fetchGoal(true)
			}
			w.Invalidate()
		}()
	}

	fetchGoal(false)

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
			mu.Lock()
			shownMode, shownNote, shownKey := mode, note, noteKey
			shownGoal := goal
			shownGoalNote, shownGoalNoteKey, shownGoalBusy := goalNote, goalNoteKey, goalBusy
			mu.Unlock()
			if closeBtn.Clicked(gtx) {
				w.Perform(system.ActionClose)
			}
			if execBtn.Clicked(gtx) {
				apply("exec")
			}
			if shellBtn.Clicked(gtx) {
				apply("shell")
			}
			if goalBtn.Clicked(gtx) {
				claim()
			}
			if goalOpenBtn.Clicked(gtx) {
				goalOpen = !goalOpen
			}
			for {
				ev, ok := goalBox.Update(gtx)
				if !ok {
					break
				}
				if _, isSubmit := ev.(widget.SubmitEvent); isSubmit {
					claim()
				}
			}

			paint.FillShape(gtx.Ops, theme.Color(design.PageKey),
				clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Op())

			saveWord := "SAVE GOAL"
			if shownGoalBusy {
				saveWord = "SAVING…"
			}

			sections := []layout.Widget{
				func(gtx layout.Context) layout.Dimensions {
					return design.Heading(gtx, theme, "Access to "+machine+": "+shownMode)
				},
				func(gtx layout.Context) layout.Dimensions {
					return design.Text(gtx, theme,
						"EXEC ONLY runs one command at a time and nothing else. There is no terminal, "+
							"so the gateway sees each command whole before the machine does and can weigh "+
							"it -- against the goal declared for this access -- and stop it.")
				},
				func(gtx layout.Context) layout.Dimensions {
					return design.Text(gtx, theme,
						"FULL SHELL opens a terminal. What travels then is keystrokes, not commands, so "+
							"nothing can be weighed and nothing can be stopped -- the safety modes do not "+
							"apply to it at all. Everything is still recorded.")
				},
				func(gtx layout.Context) layout.Dimensions {
					if adminPerson == "" {
						return design.Hint(gtx, theme,
							"Only an administrator of this gateway can change the mode or the goal, and "+
								"this machine holds no administrator key. Ask the person who gave you "+
								"this access. That is deliberate: if whoever holds a grant could widen "+
								"it, a narrow grant would mean nothing.")
					}
					return design.Hint(gtx, theme,
						"You hold an administrator key on this gateway as \""+adminPerson+"\", so you may "+
							"change both. Narrowing to exec closes any terminal open on this grant right now.")
				},
				func(gtx layout.Context) layout.Dimensions {
					return design.Said(gtx, theme, &sel, shownNote, shownKey)
				},
				func(gtx layout.Context) layout.Dimensions {
					if adminPerson == "" {
						return layout.Dimensions{}
					}
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return design.SecondaryButton(gtx, theme, &execBtn, "Make it exec only")
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return design.SecondaryButton(gtx, theme, &shellBtn, "Make it full shell")
						}),
					)
				},
			}

			// The goal block, for an administrator only. The client who
			// cannot change it is not shown a form they cannot use --
			// the sentence above already names who can.
			if adminPerson != "" {
				sections = append(sections,
					func(gtx layout.Context) layout.Dimensions {
						return design.Rule(gtx, theme)
					},
					func(gtx layout.Context) layout.Dimensions {
						return design.Heading(gtx, theme, "What this access is for")
					},
					func(gtx layout.Context) layout.Dimensions {
						return design.Text(gtx, theme,
							"The goal travels with this grant and is what a command is weighed AGAINST: "+
								"\"stop the site\" is routine work under a goal of reinstalling that site "+
								"and a red flag under one about copying a directory.")
					},
					func(gtx layout.Context) layout.Dimensions {
						switch {
						case loadGoal == nil:
							return design.Hint(gtx, theme, noRuntime)
						case shownGoal.Goal != "":
							return design.CopyableBox(gtx, theme, &goalSel, shownGoal.Goal)
						case shownGoal.Found:
							return design.Hint(gtx, theme,
								"No goal claimed for this grant yet.")
						default:
							return design.Hint(gtx, theme,
								"The goal in force appears here once the gateway has answered.")
						}
					},
					func(gtx layout.Context) layout.Dimensions {
						if !classifierIgnoresGoalWord(shownGoal.Classifier) {
							return layout.Dimensions{}
						}
						return design.Hint(gtx, theme,
							"No effect while the classifier is rules: rules read text, not context. "+
								"It matters once the classifier is ai or both.")
					},
					func(gtx layout.Context) layout.Dimensions {
						// The box opens empty and is filled by hand or
						// from this grant's own recent goals -- never
						// pre-filled with the goal in force (IAMT-402
						// point 4). Re-stating yesterday's goal is a
						// press; doing it by accident is not possible.
						dims, picked := design.ComboBox(gtx, theme, goalBox,
							"what is this access for right now?",
							&goalOpenBtn, goalOpen, shownGoal.Recent, pickBtn)
						if picked != "" {
							goalBox.SetText(picked)
							goalOpen = false
						}
						return dims
					},
					func(gtx layout.Context) layout.Dimensions {
						return design.PrimaryButton(gtx, theme, &goalBtn, saveWord)
					},
					func(gtx layout.Context) layout.Dimensions {
						if shownGoalNote == "" {
							return layout.Dimensions{}
						}
						return design.Said(gtx, theme, &goalNoteSel, shownGoalNote, shownGoalNoteKey)
					},
				)
			}

			sections = append(sections,
				func(gtx layout.Context) layout.Dimensions {
					return design.SecondaryButton(gtx, theme, &closeBtn, "Close")
				},
			)

			layout.Inset{
				Top: unit.Dp(design.Gap), Bottom: unit.Dp(design.Gap),
				Left: unit.Dp(design.Gap), Right: unit.Dp(design.Gap),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return design.PageScrollbar(theme, &page).Layout(gtx, len(sections),
					func(gtx layout.Context, i int) layout.Dimensions {
						return layout.Inset{
							Bottom: unit.Dp(design.Tight),
							Right:  unit.Dp(design.Gap),
						}.Layout(gtx, sections[i])
					})
			})
			e.Frame(gtx.Ops)
		}
	}
}
