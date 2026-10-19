//go:build windows || linux || darwin

package ui

// OpenSSH Server before START (1.52).
//
// On 29.09.2026 the owner registered a production server that had never
// had OpenSSH Server installed, pressed START, and was told so by one
// line of small red text: "sshd service check failed: sshd service not
// found". The door this program opens IS an SSH login, so without the
// service nothing can work, and the window could have known before the
// press: asking Windows for a service's status needs no rights. Now it
// asks every few seconds, the fact row says what it found, and START
// on a machine without a running sshd opens a window that says so in
// large type and offers to fix it.

import (
	"image"
	"sync"
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

// The values of ServerState.SshdState. "" means the window does not know
// (not Windows, or the query failed): then nothing is added to what the
// running agent reports.
const (
	SshdMissing = "missing"
	SshdStopped = "stopped"
	SshdRunning = "running"
)

// sshdReady says whether START may go ahead as far as OpenSSH Server is
// concerned. When the window knows the service is missing or stopped it
// opens the prompt instead and answers false.
func (f *Frame) sshdReady() bool {
	state := f.snap.Server.SshdState
	if state != SshdMissing && state != SshdStopped {
		return true
	}
	go openSSHDPrompt(f, f.windowTheme(), state) // theme taken on the UI goroutine (V-06)
	return false
}

// openSSHDPrompt is askPrepareSSHD behind a seam, so a test can see the
// prompt asked for without a real window opening.
var openSSHDPrompt = (*Frame).askPrepareSSHD

// askPrepareSSHD is the prompt itself: what is wrong, in a heading, and
// one button that installs and starts the service.
func (f *Frame) askPrepareSSHD(theme *design.Theme, state string) {
	if !claimPopup("sshd") {
		return
	}
	defer releasePopup("sshd")

	lead, heading := "OpenSSH Server", "Not installed"
	yesWord := "Install and start OpenSSH Server"
	if state == SshdStopped {
		heading = "Not running"
		yesWord = "Start OpenSSH Server"
	}
	body := sshdPromptBody(state)
	hasRights := f.cfg.HasAdminRights

	w := new(app.Window)
	w.Option(
		app.Title("iamtunnel - OpenSSH Server needed"),
		app.Size(unit.Dp(sshdPromptWidth), unit.Dp(sshdPromptHeight)),
	)
	w.Perform(system.ActionCenter)

	var ops op.Ops
	var yesBtn, noBtn widget.Clickable
	var mu sync.Mutex
	note, noteKey := "", design.MutedKey
	var sel widget.Selectable

	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			return
		case app.ViewEvent:
			applyTitleBarTheme(viewHandle(e), theme.IsDark())
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			if noBtn.Clicked(gtx) {
				w.Perform(system.ActionClose)
			}
			if yesBtn.Clicked(gtx) {
				switch {
				case f.cfg.Actions.ServerPrepareSSHD == nil:
					mu.Lock()
					note, noteKey = noRuntime, design.BadKey
					mu.Unlock()
				case !hasRights:
					// Installing a Windows component needs the rights
					// this copy lacks: the same offer every other
					// action makes, and this prompt steps aside.
					what := "Installing OpenSSH Server"
					if state == SshdStopped {
						what = "Starting OpenSSH Server"
					}
					go f.askRestartAsAdmin(theme, what)
					w.Perform(system.ActionClose)
				default:
					f.prepareSSHD(state)
					w.Perform(system.ActionClose)
				}
			}
			mu.Lock()
			shownNote, shownKey := note, noteKey
			mu.Unlock()
			paint.FillShape(gtx.Ops, theme.Color(design.PageKey),
				clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Op())
			layoutSSHDPrompt(gtx, theme, sshdPromptView{
				lead: lead, heading: heading, body: body, yesWord: yesWord,
				note: shownNote, noteKey: shownKey, sel: &sel, yes: &yesBtn, no: &noBtn,
			})
			e.Frame(gtx.Ops)
		}
	}
}

// sshdPromptBody is what the prompt tells the person, for a missing service
// and for a stopped one.
func sshdPromptBody(state string) string {
	if state == SshdStopped {
		return "A specialist enters this machine through Windows' own OpenSSH Server (the \"sshd\" service). " +
			"It is installed but stopped, so START cannot open the door.\n\n" +
			"Start it now? It is also set to start with Windows."
	}
	return "A specialist enters this machine through Windows' own OpenSSH Server (the \"sshd\" service), " +
		"and this machine does not have it, so START cannot open the door.\n\n" +
		"Install it now? Windows downloads the component itself; it takes a minute or two. " +
		"The service is then started and set to start with Windows."
}

// sshdPromptSize is the prompt window's size in dp. It is a constant, not a
// literal in Option, so the test that measures the drawing can hold the
// content to the very window it is drawn in.
const (
	sshdPromptWidth  = 620
	sshdPromptHeight = 420
)

// sshdPromptView is everything the prompt draws.
type sshdPromptView struct {
	lead, heading, body, yesWord string
	note                         string
	noteKey                      design.ColorKey
	sel                          *widget.Selectable
	yes, no                      *widget.Clickable
}

// layoutSSHDPrompt draws the prompt: the big words, what they mean, the
// gateway's or the system's last answer, and the two buttons.
func layoutSSHDPrompt(gtx layout.Context, theme *design.Theme, v sshdPromptView) layout.Dimensions {
	return layout.UniformInset(unit.Dp(design.Gap)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.NewPoster(v.lead, v.heading, design.BadKey).Layout(gtx, theme)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Text(gtx, theme, v.body)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Said(gtx, theme, v.sel, v.note, v.noteKey)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return design.SecondaryButton(gtx, theme, v.no, "Not now")
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return design.PrimaryButton(gtx, theme, v.yes, v.yesWord)
					}),
				)
			}),
		)
	})
}

// prepareSSHD installs (when missing) and starts the service, reporting
// under START, and starts the machine agent once the service runs: the
// person pressed START, and the prompt was only a step on the way.
func (f *Frame) prepareSSHD(state string) {
	prepare := f.cfg.Actions.ServerPrepareSSHD
	working := "Installing OpenSSH Server — Windows downloads the component, this takes a minute or two…"
	if state == SshdStopped {
		working = "Starting OpenSSH Server…"
	}
	f.begin(ctlServerStart, working, func() (string, design.ColorKey) {
		msg, err := prepare()
		if err != nil {
			return err.Error(), design.BadKey
		}
		go f.startServerWhenIdle()
		return msg, design.GoodKey
	})
}

// startServerWhenIdle presses START on the person's behalf once the
// install's own report under the button has been written: both use the
// same control, and begin refuses a second action while one runs.
func (f *Frame) startServerWhenIdle() {
	for i := 0; i < 100; i++ {
		f.mu.Lock()
		busy := f.working[ctlServerStart]
		f.mu.Unlock()
		if !busy {
			f.startServer()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
