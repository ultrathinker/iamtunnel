//go:build windows || linux || darwin

package ui

// The live window (IAMT-157). Until now this file was a blank import
// that only proved the Gio dependency resolves in a CGO_ENABLED=0
// Windows build; the frame, the five screens and the offscreen shot were
// all there, and nothing opened a window with them in it. Since
// IAMT-252 the same code builds and opens the window on Linux too —
// the one place the project departs from CGO_ENABLED=0 on purpose
// (gio talks to X11/Wayland through cgo there).
//
// Size and title come from umtunnel's MainWindow.cs (940x760, the title
// in lower case, the masthead on the canvas in capitals) so a person who
// used the old program recognises this one.

import (
	"fmt"
	"os"
	"runtime/debug"
	"testing"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/op"
	"gioui.org/unit"
)

// The window's own furniture, value for value from umtunnel's
// MainWindow.cs (Title = "umtunnel"; Width = 940; Height = 760). The
// title bar is the operating system's and says the program's name in
// lower case; the word in capitals at the top of the canvas is the
// masthead, drawn by Frame.Layout, and is a different thing.
const (
	WindowTitle  = "iamtunnel"
	WindowWidth  = 940
	WindowHeight = 760
)

// Run opens the window and hands it the frame built from cfg. updates,
// if non-nil, is read for as long as the window lives; every value it
// yields is merged into the frame through ApplyLiveUpdate (IAMT-182:
// this is how a caller feeds the window state it learns about AFTER the
// window was built — a session started through the gateway, not through
// a button in this window — without Run handing back the *Frame itself,
// which would be a second, ad-hoc way to reach it alongside FrameConfig;
// see verify_iamt66_test.go's closed method-set guard).
//
// It is a LiveUpdate and not a Snapshot (21.09.2026). The channel used
// to carry the whole window state, which the poll behind it could not
// produce — so cmd/iamtunnel kept a shadow copy of everything and every
// tick redrew it over what the window had learned for itself. See
// live_update.go for what that cost.
//
// It returns an error ONLY for a failure that happens before any window
// exists — a frame that could not be built. Once the window is up, Run
// does not return at all: app.Main() blocks for the rest of the
// process's life by design (gioui.org/app: the platform main loop
// never finishes), so the exit code of a normal, successful close is
// handed to the operating system from inside the window's own goroutine
// when the DestroyEvent arrives. That is the one place in this program
// where a path does not travel back through main.go's exit-code
// machinery, and it is not a choice: there is no "afterwards" here to
// travel back through.
//
// The corollary callers rely on (and staticcheck SA4023 verified —
// IAMT-187): Run NEVER returns a nil error. Every return is a pre-window
// failure, so the caller reports it and exits without comparing against
// nil.
func Run(cfg FrameConfig, updates <-chan LiveUpdate) error {
	// The same belt-and-braces guard internal/server/run_windows.go uses
	// for defaultCheckSSHDService: Run opens a real OS window and then
	// blocks forever (app.Main() never returns on Windows), so an
	// un-mocked call from inside a test binary would not fail the test —
	// it would hang the whole package's test run. cmd/iamtunnel's own
	// seam (streams.openGUI) is supposed to keep every test from ever
	// reaching here at all; this panic is what fires if some other,
	// future caller forgets that seam.
	if testing.Testing() {
		panic("ui: Run invoked in test binary; tests must never open a real window")
	}

	w := new(app.Window)
	w.Option(
		app.Title(WindowTitle),
		app.Size(unit.Dp(WindowWidth), unit.Dp(WindowHeight)),
	)
	// Centred by GIO, before the window is shown.
	//
	// This used to be a SetWindowPos of my own on the first view event,
	// and the maintainer watched the result: the window appeared at the
	// system's default place and then slid to the middle. The cause is
	// gio's own order -- os_windows.go configures and SHOWS the window,
	// and only afterwards hands the handle over in a Win32ViewEvent, so
	// anything done from that event necessarily moves a window that is
	// already on screen.
	//
	// system.ActionCenter performed before the first Event is queued as
	// an initial action and applied inside Configure, in the SetWindowPos
	// that runs BEFORE ShowWindow. It centres on the work area of the
	// window's own monitor, which is what the hand-rolled version did the
	// long way round -- and without the deadlock that version could cause.
	w.Perform(system.ActionCenter)

	// The way a finished background operation asks to be seen. It is
	// wired before the frame is built so the frame never holds a half-set
	// runtime: a press that completes in the first millisecond still gets
	// its repaint.
	cfg.Actions.Repaint = w.Invalidate

	frame, err := NewFrame(cfg)
	if err != nil {
		return err
	}

	if updates != nil {
		go func() {
			for u := range updates {
				frame.ApplyLiveUpdate(u)
			}
		}()
	}

	go func() {
		// The main window's panic is written down before the process
		// goes (IAMT-367). It is NOT survived: this goroutine owns the
		// only frame there is, and a window that carried on after an
		// unknown failure in its own layout would be showing state
		// nobody can vouch for. What changes is that the crash leaves
		// a note instead of vanishing without one.
		defer func() {
			if r := recover(); r != nil {
				note := recordPanic("main window", r, debug.Stack())
				fmt.Fprintf(os.Stderr, "iamtunnel: the window crashed: %v\n", r)
				if note != "" {
					fmt.Fprintf(os.Stderr, "iamtunnel: details written to %s\n", note)
				}
				os.Exit(2)
			}
		}()
		var ops op.Ops
		for {
			switch e := w.Event().(type) {
			case app.DestroyEvent:
				if e.Err != nil {
					fmt.Fprintf(os.Stderr, "iamtunnel: the window closed with an error: %v\n", e.Err)
					os.Exit(1)
				}
				// Closing the window is not closing the door: the agent
				// keeps serving. If it is up, say so and offer to stop it
				// before the process goes (close_prompt.go). A window that
				// closed with an error skips the question -- something is
				// already wrong, and the fastest honest thing is to go.
				if frame.serving() {
					frame.askStopServerOnClose()
				}
				os.Exit(0)
			case app.ViewEvent:
				// The caption is the system's to draw, and it draws it
				// light unless told (IAMT-362). This is the one moment
				// the window handle is offered, so it is where the
				// telling happens.
				applyTitleBarTheme(viewHandle(e), frame.IsDark())
				frame.setWindowHandle(viewHandle(e))
			case app.FrameEvent:
				frame.drawSubmittedFrame(e, &ops)
			}
		}
	}()

	app.Main()
	// Unreachable on Windows and Linux; kept so the signature is honest
	// on any platform where app.Main() one day does return.
	return nil
}

// frameSubmit is the one place a finished frame is handed to the window
// system: the production body is the FrameEvent's own Frame call — the
// step that actually submits the operations. A seam, so the restart
// handover's ordering canary can watch the exact step the ready callback
// must follow without a real window.
var frameSubmit = func(e app.FrameEvent, ops *op.Ops) { e.Frame(ops) }

// drawSubmittedFrame is the window loop's frame path for one FrameEvent:
// lay the frame out, then SUBMIT the operations (frameSubmit — e.Frame,
// the hand-off to the window system), and only then acknowledge the
// frame (windowReady). The order is the point: a Layout that returned
// has merely built the operations — nothing has been shown, and a
// submission can still fail or meet a DestroyEvent in the gap. Gio
// acknowledges no actual composition (there is no "the compositor showed
// it" callback), so the submitted frame is the strongest "the window is
// up" signal there is, and the Linux restart handover's ready line waits
// for exactly it (OnWindowReady). Runs on the window loop's goroutine
// (the UI goroutine).
func (f *Frame) drawSubmittedFrame(e app.FrameEvent, ops *op.Ops) {
	gtx := app.NewContext(ops, e)
	f.Layout(gtx)
	frameSubmit(e, ops)
	f.windowReady()
}
