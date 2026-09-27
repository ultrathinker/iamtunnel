//go:build windows || linux || darwin

package ui

// The Server tab's setup section (1.49): the "old registration" block,
// drawn only when the registration really predates the enrolment anchor,
// and the autostart checkbox, off unless the person turns it on. See
// cmd/iamtunnel/gui_server_setup.go for the facts and the actions.

import (
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// layoutServerNoticeAndSetup draws the gateway's notice and the setup
// section as one page section, with a gap only between parts that exist.
func (f *Frame) layoutServerNoticeAndSetup(gtx layout.Context) layout.Dimensions {
	hasNotice := f.snap.Server.Notice != ""
	hasSetup := f.snap.Server.NeedsConfirm || f.snap.Server.AutostartKnown
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(f.layoutServerNotice),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if !hasNotice || !hasSetup {
				return layout.Dimensions{}
			}
			return layout.Spacer{Height: unit.Dp(design.Gap)}.Layout(gtx)
		}),
		layout.Rigid(f.layoutServerSetup),
	)
}

func (f *Frame) layoutServerSetup(gtx layout.Context) layout.Dimensions {
	s := f.snap.Server
	if !s.NeedsConfirm && !s.AutostartKnown {
		return layout.Dimensions{}
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if !s.NeedsConfirm {
				return layout.Dimensions{}
			}
			return layout.Inset{Bottom: unit.Dp(design.Gap)}.Layout(gtx, f.layoutConfirmSetup)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if !s.AutostartKnown {
				return layout.Dimensions{}
			}
			return f.layoutAutostart(gtx)
		}),
	)
}

// layoutConfirmSetup is the one-press answer to "the enrolment record has
// no anchor": the registration was made by an older version, and the
// elevated start refuses it until the setup is confirmed once.
func (f *Frame) layoutConfirmSetup(gtx layout.Context) layout.Dimensions {
	btn := f.btn(ctlServerConfirm)
	if btn.Clicked(gtx) && !f.busy(ctlServerConfirm) {
		if act := f.cfg.Actions.ServerConfirmSetup; act == nil {
			f.say(ctlServerConfirm, noRuntime, design.BadKey)
		} else if f.needsAdmin("Confirming this machine's setup") {
			f.begin(ctlServerConfirm, "Confirming…", func() (string, design.ColorKey) {
				msg, err := act()
				if err != nil {
					return err.Error(), design.BadKey
				}
				return msg, design.GoodKey
			})
		}
	}
	word := "Confirm setup"
	if f.busy(ctlServerConfirm) {
		word = "Confirming…"
	}
	said := f.saidUnder(ctlServerConfirm)
	return widget.Border{
		Color:        f.theme.Color(design.WarnKey),
		Width:        unit.Dp(1),
		CornerRadius: unit.Dp(design.Radius),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.UniformInset(unit.Dp(design.Pad)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return design.Text(gtx, f.theme,
								"This machine was set up by an older version of the program. "+
									"Confirm the setup once, and the agent can start.")
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.PrimaryButton(gtx, f.theme, btn, word)
						}),
					)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if said.text == "" {
						return layout.Dimensions{}
					}
					return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return f.saidFull(gtx, ctlServerConfirm, said.text, said.key, 240)
					})
				}),
			)
		})
	})
}

// layoutAutostart is the "start at sign-in" checkbox. It shows what Task
// Scheduler says, except while a press is on its way there.
func (f *Frame) layoutAutostart(gtx layout.Context) layout.Dimensions {
	s := f.snap.Server
	box := &f.autostartBox
	switch {
	case f.autostartPending == 1 && s.Autostart, f.autostartPending == 2 && !s.Autostart:
		f.autostartPending = 0
	case f.autostartPending != 0 && !f.busy(ctlServerAutostart) && f.saidUnder(ctlServerAutostart).key == design.BadKey:
		// The press failed: show what Task Scheduler really has.
		f.autostartPending = 0
	}
	if f.autostartPending == 0 && !f.busy(ctlServerAutostart) {
		box.Value = s.Autostart
	}
	if box.Update(gtx) {
		want := box.Value
		box.Value = !want // not until it has happened
		act := f.cfg.Actions.ServerAutostart
		switch {
		case f.busy(ctlServerAutostart):
		case act == nil:
			f.say(ctlServerAutostart, noRuntime, design.BadKey)
		case f.needsAdmin("Changing autostart"):
			box.Value = want
			f.autostartPending = 2
			working := "Turning autostart off…"
			if want {
				f.autostartPending = 1
				working = "Turning autostart on…"
			}
			f.begin(ctlServerAutostart, working, func() (string, design.ColorKey) {
				msg, err := act(want)
				if err != nil {
					return err.Error(), design.BadKey
				}
				return msg, design.GoodKey
			})
		}
	}
	said := f.saidUnder(ctlServerAutostart)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			cb := material.CheckBox(f.theme.Material, box, "Start the agent automatically when I sign in to Windows")
			cb.Color = f.theme.Color(design.InkKey)
			cb.IconColor = f.theme.Color(design.SpotKey)
			return cb.Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if said.text == "" {
				return design.Hint(gtx, f.theme,
					"Off by default: the agent runs when you press START, until you stop it or restart the computer.")
			}
			return f.saidFull(gtx, ctlServerAutostart, said.text, said.key, 240)
		}),
	)
}
