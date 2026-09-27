//go:build windows || linux || darwin

package ui

// Two small windows of their own (1.49), asked for by the maintainer
// after a live run on a Windows VM:
//
//   - A status line that does not fit is no longer simply cut. It ends
//     with "Show all", which opens the whole text in a window where it can
//     be read, selected and copied. The cut used to fall on the one part
//     that mattered: the remedy at the end of a refusal.
//   - An action that needs administrator rights, pressed in a window that
//     has none, no longer fails with a line under the button. It asks,
//     in a window of its own, whether to restart the program as
//     administrator, and does so on "Yes".
//
// gio has no modal dialogs; like the close prompt (close_prompt.go) each
// question is a small window of its own, centred before it is shown.

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
	"gioui.org/widget/material"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// openPopups keeps one window per kind: pressing "Show all" twice must not
// stack two copies of the same text.
var (
	openPopupsMu sync.Mutex
	openPopups   = map[string]bool{}
)

func claimPopup(kind string) bool {
	openPopupsMu.Lock()
	defer openPopupsMu.Unlock()
	if openPopups[kind] {
		return false
	}
	openPopups[kind] = true
	return true
}

func releasePopup(kind string) {
	openPopupsMu.Lock()
	delete(openPopups, kind)
	openPopupsMu.Unlock()
}

// saidFull draws a status line in full when it fits within limit
// characters, and otherwise its beginning followed by a "Show all" link
// that opens the whole text in a window of its own.
func (f *Frame) saidFull(gtx layout.Context, ctl, txt string, key design.ColorKey, limit int) layout.Dimensions {
	if len([]rune(txt)) <= limit {
		return design.Said(gtx, f.theme, f.sel(ctl+"/said"), txt, key)
	}
	link := f.btn(ctl + "/showall")
	if link.Clicked(gtx) {
		full := txt
		// The theme is taken here, on the UI goroutine: CheckThemeSync
		// replaces f.theme on this goroutine without f.mu (V-06).
		go f.showFullText(f.windowTheme(), "Full message", full)
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, f.theme, f.sel(ctl+"/said"), clipStr(txt, limit), key)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.CompactButton(gtx, f.theme, link, "Show all")
		}),
	)
}

// showFullText opens a window with the whole of a message: readable,
// selectable, and copyable with one press.
func (f *Frame) showFullText(theme *design.Theme, title, txt string) {
	if !claimPopup("fulltext") {
		return
	}
	defer releasePopup("fulltext")

	w := new(app.Window)
	w.Option(
		app.Title("iamtunnel - "+title),
		app.Size(unit.Dp(640), unit.Dp(420)),
	)
	w.Perform(system.ActionCenter)

	var ops op.Ops
	var copyBtn, closeBtn widget.Clickable
	var sel widget.Selectable
	list := widget.List{List: layout.List{Axis: layout.Vertical}}
	copied := false

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
			if copyBtn.Clicked(gtx) {
				copyToClipboard(gtx, txt)
				copied = true
			}
			paint.FillShape(gtx.Ops, theme.Color(design.PageKey),
				clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Op())
			layout.UniformInset(unit.Dp(design.Gap)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Heading(gtx, theme, title)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return material.List(theme.Material, &list).Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
							return design.Said(gtx, theme, &sel, txt, design.InkKey)
						})
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						word := "Copy"
						if copied {
							word = "Copied"
						}
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return design.SecondaryButton(gtx, theme, &copyBtn, word)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return design.PrimaryButton(gtx, theme, &closeBtn, "Close")
							}),
						)
					}),
				)
			})
			e.Frame(gtx.Ops)
		}
	}
}

// needsAdmin is the gate in front of every action that needs
// administrator rights. With rights it returns true and the caller goes
// on. Without them it opens the question window and returns false: the
// action does not run in this copy of the program.
func (f *Frame) needsAdmin(what string) bool {
	if f.cfg.HasAdminRights {
		return true
	}
	go f.askRestartAsAdmin(f.windowTheme(), what) // theme taken on the UI goroutine (V-06)
	return false
}

// askRestartAsAdmin asks whether to restart the program with
// administrator rights, and does it on "Yes".
func (f *Frame) askRestartAsAdmin(theme *design.Theme, what string) {
	if !claimPopup("admin") {
		return
	}
	defer releasePopup("admin")
	restart := f.cfg.Actions.RestartAsAdmin

	w := new(app.Window)
	w.Option(
		app.Title("iamtunnel - administrator rights needed"),
		app.Size(unit.Dp(560), unit.Dp(260)),
	)
	w.Perform(system.ActionCenter)

	var ops op.Ops
	var yesBtn, noBtn widget.Clickable
	var mu sync.Mutex
	note, noteKey := "", design.MutedKey
	var sel widget.Selectable

	body := what + " needs administrator rights, and this window is running without them. " +
		"Restart the program as administrator? Windows will ask for your consent."

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
				if restart == nil {
					mu.Lock()
					note, noteKey = noRuntime, design.BadKey
					mu.Unlock()
				} else {
					go func() {
						// On success the new copy has started and this
						// process exits inside restart; only a failure
						// comes back here.
						if err := restart(); err != nil {
							mu.Lock()
							note, noteKey = "Could not restart as administrator: "+err.Error(), design.BadKey
							mu.Unlock()
							w.Invalidate()
						}
					}()
				}
			}
			mu.Lock()
			shownNote, shownKey := note, noteKey
			mu.Unlock()
			paint.FillShape(gtx.Ops, theme.Color(design.PageKey),
				clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Op())
			layout.UniformInset(unit.Dp(design.Gap)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Heading(gtx, theme, "Administrator rights needed")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Text(gtx, theme, body)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Said(gtx, theme, &sel, shownNote, shownKey)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return design.SecondaryButton(gtx, theme, &noBtn, "No")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return design.PrimaryButton(gtx, theme, &yesBtn, "Yes, restart as administrator")
							}),
						)
					}),
				)
			})
			e.Frame(gtx.Ops)
		}
	}
}
