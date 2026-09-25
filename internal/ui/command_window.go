//go:build windows || linux || darwin

package ui

// Commands to one machine, in a window of its own (21.09.2026).
//
// Until now the exec-only grant put a command box and a Run button INSIDE
// the machine's row on the Client tab. The maintainer took one look at
// what a
// second machine would imply and said so: the field did not say which
// machine it belonged to, and a second one would simply appear under it.
//
// That is describing a category error. A list is a list: every row says the
// same kind of thing about a different machine, and a row that grows a
// text box, a button and a screenful of output has stopped being a row.
//
// So the row gets a button, and the button opens this. It is the same
// shape as the transcript window (IAMT-366), and for the reason the maintainer
// gave then: what you OPERATE belongs on a tab, what you WATCH and work
// in wants a window -- resizable, maximisable, alive while you look
// elsewhere. The machine's name is in the title bar, so the question
// "which machine is this for" cannot be asked.
//
// Each window holds one machine and its own history. Opening two is how
// you work on two machines, which the row-shaped version could never
// honestly offer.

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

// commandRun is one command and everything that came back from it.
type commandRun struct {
	command string
	summary string
	key     design.ColorKey
	output  string

	// The selections keep this entry's text selectable across frames,
	// the same way the transcript window's note does: a Selectable
	// rebuilt every frame loses the selection the moment the mouse
	// moves. Output and verdict get their own, because a person copying
	// an error message should not have to lose the command above it.
	outSel widget.Selectable
	sumSel widget.Selectable
	cmdSel widget.Selectable
}

// commandWindow is one machine's command window.
type commandWindow struct {
	machine string

	mu sync.Mutex
	// history is oldest first; the list scrolls to the end, so the run
	// that just finished is the one on screen.
	history []*commandRun
	// approval is the gateway's pending approval id, set when the last
	// run was stopped by the "ask" safety mode and may still be let
	// through by hand.
	approval string
	busy     bool
}

// openCommandWindow opens the command window for one machine. Nothing is
// returned and nothing awaited: the window owns its goroutine and dies
// alone, exactly as the transcript window does.
func (f *Frame) openCommandWindow(machine string) {
	// The same guard the transcript window carries: this opens a REAL
	// operating-system window, and a test that reached it would not fail
	// -- it would hang the package's whole test run behind a window
	// nobody sees.
	if testing.Testing() {
		panic("ui: openCommandWindow invoked in test binary; tests must never open a real window")
	}
	// Its OWN theme -- see windowTheme in frame.go.
	go runCommandWindow(f.windowTheme(), machine, f.runClientExec, f.cfg.Actions.ClientRiskApprove)
}

func runCommandWindow(
	theme *design.Theme,
	machine string,
	run func(ctx context.Context, machine, command string) ClientExecResult,
	approve func(ctx context.Context, approvalID string) error,
) {
	// This window dies alone if it dies at all (IAMT-367): its panic is
	// written down with its stack, and the process keeps standing.
	defer guardWindow("command window", nil)

	cw := &commandWindow{machine: machine}

	w := new(app.Window)
	w.Option(
		app.Title("iamtunnel - command on "+machine),
		app.Size(unit.Dp(900), unit.Dp(620)),
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
	var list widget.List
	list.Axis = layout.Vertical
	list.ScrollToEnd = true
	box := new(widget.Editor)
	box.SingleLine = true
	box.Submit = true
	var runBtn, approveBtn widget.Clickable

	launch := func(command, approveFirst string) {
		cw.mu.Lock()
		if cw.busy {
			cw.mu.Unlock()
			return
		}
		cw.busy = true
		entry := &commandRun{command: command, summary: "Running...", key: design.MutedKey}
		cw.history = append(cw.history, entry)
		cw.mu.Unlock()
		w.Invalidate()

		go func() {
			ctx := context.Background()
			if approveFirst != "" {
				if approve == nil {
					cw.finish(entry, noRuntime, design.BadKey, "", "")
					w.Invalidate()
					return
				}
				if err := approve(ctx, approveFirst); err != nil {
					cw.finish(entry, "The gateway would not lift its refusal: "+err.Error(),
						design.BadKey, "", "")
					w.Invalidate()
					return
				}
			}
			res := run(ctx, machine, command)
			cw.finish(entry, res.Summary, res.Verdict, res.Output, res.ApprovalID)
			w.Invalidate()
		}()
	}

	submit := func() {
		command := strings.TrimSpace(box.Text())
		if command == "" {
			return
		}
		box.SetText("")
		launch(command, "")
	}

	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			return
		case app.ViewEvent:
			applyTitleBarTheme(viewHandle(e), theme.IsDark())
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			if runBtn.Clicked(gtx) {
				submit()
			}
			for {
				ev, ok := box.Update(gtx)
				if !ok {
					break
				}
				if _, isSubmit := ev.(widget.SubmitEvent); isSubmit {
					submit()
				}
			}
			cw.mu.Lock()
			pending := cw.approval
			last := ""
			if n := len(cw.history); n > 0 {
				last = cw.history[n-1].command
			}
			cw.mu.Unlock()
			// "Run anyway" is deliberately not a confirm-twice control.
			// The gateway already stopped this command once and said why
			// in the line above the button; asking again would only teach
			// the person to click past both (IAMT-394).
			if pending != "" && last != "" && approveBtn.Clicked(gtx) {
				cw.mu.Lock()
				cw.approval = ""
				cw.mu.Unlock()
				launch(last, pending)
			}
			cw.layout(gtx, theme, &list, box, &runBtn, &approveBtn)
			e.Frame(gtx.Ops)
		}
	}
}

// finish writes one run's answer back into the history.
func (cw *commandWindow) finish(entry *commandRun, summary string, key design.ColorKey, output, approval string) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	entry.summary, entry.key, entry.output = summary, key, output
	cw.approval = approval
	cw.busy = false
}

func (cw *commandWindow) layout(
	gtx layout.Context,
	th *design.Theme,
	list *widget.List,
	box *widget.Editor,
	runBtn, approveBtn *widget.Clickable,
) layout.Dimensions {
	cw.mu.Lock()
	history := make([]*commandRun, len(cw.history))
	copy(history, cw.history)
	pending := cw.approval
	busy := cw.busy
	cw.mu.Unlock()

	// The page's own background, painted first: a window that inherited
	// whatever the compositor had would flash white on a dark desktop.
	paint.FillShape(gtx.Ops, th.Color(design.PageKey),
		clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Op())

	word := "Run"
	if busy {
		word = "Running..."
	}

	return layout.Inset{
		Top: unit.Dp(design.Gap), Bottom: unit.Dp(design.Gap),
		Left: unit.Dp(design.Gap), Right: unit.Dp(design.Gap),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Heading(gtx, th, "Commands on "+cw.machine)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Hint(gtx, th,
					"each line runs exactly as typed, on "+cw.machine+", through the exec-only grant - "+
						"no shell, and nothing of this machine's own")
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
			// The history takes the room, and scrolls. The box stays put
			// at the bottom: a person runs one command after another, and
			// a box that drifted up the page with the output would have
			// to be hunted for every time.
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				if len(history) == 0 {
					return design.Text(gtx, th,
						"Nothing run yet. Type a command below and press Enter.")
				}
				return design.PageScrollbar(th, list).Layout(gtx, len(history),
					func(gtx layout.Context, i int) layout.Dimensions {
						// The same gutter the pages keep.
						return layout.Inset{Right: unit.Dp(design.Gap)}.Layout(gtx,
							func(gtx layout.Context) layout.Dimensions {
								return layoutCommandRun(gtx, th, history[i])
							})
					})
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if pending == "" {
					return layout.Dimensions{}
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.PrimaryButton(gtx, th, approveBtn, "RUN ANYWAY")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return design.TextBox(gtx, th, box, "cmd /c echo hello")
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.SecondaryButton(gtx, th, runBtn, word)
					}),
				)
			}),
		)
	})
}

// layoutCommandRun draws one entry: what was asked, what the gateway said
// about it, and what the machine sent back -- in that order, because that
// is the order they happen in. Under "block" there is no third part at
// all, and the gateway's line is the whole answer (IAMT-392, IAMT-395).
func layoutCommandRun(gtx layout.Context, th *design.Theme, r *commandRun) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, th, &r.cmdSel, "> "+r.command, design.MutedKey)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if r.summary == "" {
				return layout.Dimensions{}
			}
			return design.Said(gtx, th, &r.sumSel, r.summary, r.key)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if r.output == "" {
				return layout.Dimensions{}
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.CopyableBox(gtx, th, &r.outSel, r.output)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
	)
}
