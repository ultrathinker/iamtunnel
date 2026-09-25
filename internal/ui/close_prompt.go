//go:build windows || linux || darwin

package ui

// Closing the window does not close the door (21.09.2026).
//
// Asked for by the maintainer: when the server is running and the form
// is closed, the program should ask whether to stop the server as well.
//
// The two really are separate, and that is deliberate: the agent is meant
// to keep serving while nobody is looking at a window, which is the whole
// reason a machine can be entered at three in the morning. But "the
// window is shut" and "nobody can get in" look identical from the outside,
// and a person who closed the window believing the second is running a
// machine that is still reachable and does not know it.
//
// So the process asks. It cannot ask BEFORE the window goes -- gio's
// DestroyEvent is a notification, not a request, and there is nothing to
// veto -- so the question arrives as a small window of its own, and the
// process does not exit until it is answered. Closing that window without
// choosing leaves the agent running, because that is what the old
// behaviour did and silence must not change anything.

import (
	"image"
	"sync"

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

// serving reports whether this machine's agent is up: Start was pressed
// and the tunnel is either waiting for somebody or carrying somebody.
func (f *Frame) serving() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snap.Server.Running || f.snap.Server.Waiting
}

// askStopServerOnClose runs the little decision window. It returns once
// the person has chosen, having already stopped the agent if that is
// what they chose.
func (f *Frame) askStopServerOnClose() {
	stop := f.cfg.Actions.ServerStop
	// Its OWN theme -- see windowTheme in frame.go. The main window is
	// gone by now, but its goroutine may still be unwinding.
	theme := f.windowTheme()

	f.mu.Lock()
	sessions := len(f.snap.Server.Sessions)
	gatewayUp := f.snap.Gateway.Running
	f.mu.Unlock()

	w := new(app.Window)
	w.Option(
		app.Title("iamtunnel - the agent is still running"),
		app.Size(unit.Dp(560), unit.Dp(300)),
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

	var mu sync.Mutex
	var stopBtn, leaveBtn widget.Clickable
	var sel widget.Selectable
	var ops op.Ops
	note, noteKey := "", design.MutedKey
	busy := false

	question := "This window is closing, but the agent on this machine is still running: it stays " +
		"registered with the gateway and anybody holding a live grant can still enter."
	if sessions > 0 {
		question = "This window is closing, but somebody is inside this machine RIGHT NOW. " +
			"The agent keeps serving whether a window is open or not."
	}

	// AND THE GATEWAY, when this computer is one (22.09.2026).
	//
	// The maintainer asked whether this box should grow a "stop everything"
	// button covering the gateway as well, or whether the gateway stops
	// by itself. Neither: it is a service, it keeps running, and that is
	// the correct behaviour -- stopping a gateway cuts every live
	// session on every machine that meets through it, belonging to
	// people who have not closed anything. One keystroke on one laptop
	// should not do that to them, and a button here would make it the
	// easiest thing on the screen to do by accident.
	//
	// But the omission was real, and it is the very fault this box was
	// built to cure: "the window is shut" and "nobody can get in" look
	// identical from outside. So the gateway is NAMED, with the one
	// place that can stop it, and no button of its own.
	gatewayNote := ""
	if gatewayUp {
		gatewayNote = "The gateway on this computer keeps running too — it is a service, and other " +
			"people's sessions pass through it. Stopping it is on the Gateway tab, deliberately and " +
			"not in passing."
	}

	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			// Closed without choosing: leave it running, which is what
			// closing the window has always done.
			return
		case app.ViewEvent:
			applyTitleBarTheme(viewHandle(e), theme.IsDark())
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			mu.Lock()
			shownNote, shownKey, shownBusy := note, noteKey, busy
			mu.Unlock()
			if leaveBtn.Clicked(gtx) {
				w.Perform(system.ActionClose)
			}
			if stopBtn.Clicked(gtx) && !busy {
				if stop == nil {
					note, noteKey = noRuntime, design.BadKey
				} else {
					// Off the event loop. Stopping the agent talks to
					// another process and can take a moment, and a window
					// that stops answering while it waits is a window the
					// system paints over with "Not Responding" -- exactly
					// what the maintainer met when a button returned from this
					// loop instead of closing the window.
					busy = true
					note, noteKey = "Stopping.", design.MutedKey
					go func() {
						_, err := stop()
						mu.Lock()
						busy = false
						if err != nil {
							note, noteKey = err.Error(), design.BadKey
						} else {
							// Said, then gone: the person asked for it to
							// stop, and a window that lingered to be
							// thanked would be one more thing to close.
							note, noteKey = "Stopped.", design.GoodKey
						}
						mu.Unlock()
						if err == nil {
							w.Perform(system.ActionClose)
						}
						w.Invalidate()
					}()
				}
			}
			paint.FillShape(gtx.Ops, theme.Color(design.PageKey),
				clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Op())
			layout.Inset{
				Top: unit.Dp(design.Gap), Bottom: unit.Dp(design.Gap),
				Left: unit.Dp(design.Gap), Right: unit.Dp(design.Gap),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Heading(gtx, theme, "Stop the agent as well?")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Text(gtx, theme, question)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if gatewayNote == "" {
							return layout.Dimensions{}
						}
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.Text(gtx, theme, gatewayNote)
							}),
						)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Hint(gtx, theme,
							"Leaving it running is the normal thing: it is how a machine can be entered "+
								"while nobody is at it. Stop it only if you meant to shut the door.")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Said(gtx, theme, &sel, shownNote, shownKey)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						word := "STOP THE AGENT"
						if shownBusy {
							word = "STOPPING..."
						}
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return design.SecondaryButton(gtx, theme, &leaveBtn, "Leave it running")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return design.PrimaryButton(gtx, theme, &stopBtn, word)
							}),
						)
					}),
				)
			})
			e.Frame(gtx.Ops)
		}
	}
}
