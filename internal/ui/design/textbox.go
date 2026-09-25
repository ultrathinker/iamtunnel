//go:build windows || linux || darwin

package design

// The one input control of the design (IAMT-149). Until now the design
// had buttons, rules, facts and a read-only CopyableBox but nothing a
// person could type into, even though the tokens for it
// (TextBoxMinHeight, TextBoxPadVertical) had been sitting unused in
// tokens.go since the design was ported.
//
// The shape was umtunnel's line under the words until IAMT-505
// (24.09.2026). The maintainer found those fields hard to see as fields --
// they looked like nothing but an underline, and the request was for them
// to look like ordinary text boxes framed on all four sides -- so a box is now framed on all
// four sides: a 1 dp LineKey frame that becomes a 2 dp SpotKey frame while
// the box holds the keyboard, square corners and no fill, the same frame
// the secondary buttons beside it wear. 6 dp of vertical and 8 dp of
// horizontal padding inside it, and the 30 dp floor under the whole thing.

import (
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// TextBox draws one editable field inside its frame. The caller owns the
// *widget.Editor and therefore owns its content and its options
// (SingleLine, MaxLen, Mask…): this function decides how a field LOOKS
// and nothing about what it accepts, so a screen that wants a one-line
// box and a screen that wants a wrapped block of pasted text both use
// the same picture.
//
// hint is the watermark shown while the box is empty — the same role as
// umtunnel's TextBox.Watermark.
func TextBox(gtx layout.Context, th *Theme, ed *widget.Editor, hint string) layout.Dimensions {
	// The focused box says so with its frame. Focus is read from the
	// input source the window attached, never stored here: a cached "is
	// focused" flag is a second copy of a fact the runtime already owns.
	focused := gtx.Source.Focused(ed)

	frameKey := LineKey
	frameDp := unit.Dp(TextBoxRule)
	if focused {
		frameKey = SpotKey
		frameDp = unit.Dp(TextBoxRuleFocused)
	}

	// The floor applies to the box as a whole, exactly as MinHeight does
	// on the control umtunnel styles.
	floor := gtx.Dp(unit.Dp(TextBoxMinHeight))

	// widget.Border draws over the edge of what it wraps, so the thicker
	// focused frame eats into the padding rather than growing the box: a
	// field that moves the rows under it when clicked is a field that
	// jumps.
	return widget.Border{
		Color:        th.Color(frameKey),
		Width:        frameDp,
		CornerRadius: unit.Dp(Radius),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		dims := layout.Inset{
			Top:    unit.Dp(TextBoxPadVertical),
			Bottom: unit.Dp(TextBoxPadVertical),
			Left:   unit.Dp(TextBoxPadHorizontal),
			Right:  unit.Dp(TextBoxPadHorizontal),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			e := material.Editor(th.Material, ed, hint)
			e.Font = th.MonoFont
			e.TextSize = BodySp
			e.Color = th.Color(InkKey)
			e.HintColor = th.Color(MutedKey)
			e.SelectionColor = th.Color(SurfaceKey)
			return e.Layout(gtx)
		})
		if dims.Size.Y < floor {
			dims.Size.Y = floor
		}
		// The frame spans the whole width it is given, as the rule under
		// the words did: a box sized to its words would change width as
		// they are typed.
		dims.Size.X = gtx.Constraints.Max.X
		return dims
	})
}

// Field is one labelled row of a form: the label in the same fixed
// FactsColumnWidth column the Facts table uses, the control in whatever
// is left, and the hint under the control (umtunnel's EnrolView.Row).
// Putting the label in the SAME column as the facts is the point: on a
// screen that both states facts and asks for one, the two must line up.
func Field(gtx layout.Context, th *Theme, label string, control layout.Widget, hint string) layout.Dimensions {
	return layout.Flex{
		Axis:      layout.Horizontal,
		Alignment: layout.Start,
	}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			colW := gtx.Dp(unit.Dp(FactsColumnWidth))
			gtxCol := gtx
			gtxCol.Constraints.Min.X = colW
			gtxCol.Constraints.Max.X = colW
			return layout.Inset{Top: unit.Dp(TextBoxPadVertical)}.Layout(gtxCol,
				func(gtx layout.Context) layout.Dimensions {
					return Hint(gtx, th, label)
				})
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Left: GapDp}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(control),
					layout.Rigid(layout.Spacer{Height: TightDp}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if hint == "" {
							return layout.Dimensions{}
						}
						return Hint(gtx, th, hint)
					}),
				)
			})
		}),
	)
}

// Said is a status line under a control: the words in the color of their
// KIND, never in a color (umtunnel's EnrolView.Say). The same sentence
// has to read on a light desktop and a dark one, so what is chosen here
// is the key — GoodKey, BadKey, MutedKey — and the palette decides the
// rest. An empty text draws nothing at all.
// It is SELECTABLE since 19.09.2026. These lines carry the one thing a
// person needs to pass on when something goes wrong -- the refusal, in
// the product's own words -- and until then they could only be
// photographed. The maintainer hit it on a fresh machine, with a denial that
// named a path that could not be retyped. A message nobody can quote is a
// message that arrives as "it says some error".
func Said(gtx layout.Context, th *Theme, sel *widget.Selectable, txt string, key ColorKey) layout.Dimensions {
	if txt == "" {
		return layout.Dimensions{}
	}
	return Status(gtx, th,
		func(gtx layout.Context) layout.Dimensions {
			return Dot(gtx, th, key, false)
		},
		func(gtx layout.Context) layout.Dimensions {
			if sel == nil {
				return Words(gtx, th, txt, SmallSp, key, th.MonoFont)
			}
			lbl := material.Label(th.Material, SmallSp, txt)
			lbl.Color = th.Color(key)
			lbl.Font = th.MonoFont
			lbl.SelectionColor = th.Color(SpotDimKey)
			lbl.State = sel
			return lbl.Layout(gtx)
		})
}
