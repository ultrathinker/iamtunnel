//go:build windows || linux || darwin

package design

// The three pieces every list-shaped screen is built from (IAMT-359).
//
// Until 19.09.2026 each screen invented its own arrangement, and the
// maintainer walked the product end to end and named what was wrong with all
// of them at once: the list is the thing you came for, the form that
// ADDS to it is not, and the form was permanently on screen above or
// below the list whether it was wanted or not. On the machines sub-tab
// the invitation that had already been used sat there for the rest of
// the session, and it was unclear why the add fields were on screen all
// the time.
//
// So: a heading with the one action on its right, the list, and nothing
// else until the action is pressed. Empty is a state the list draws
// itself, in its own words, rather than a blank space that reads as a
// broken screen.

import (
	"image"
	"strings"

	"gioui.org/f32"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// SectionHead is a section label with one control on its right: the
// "Add" that discloses the form belonging to that list.
//
// The word is the caller's, because it should name what is added -- "Add
// person", "Invite machine", "New grant" -- and never the generic "Add".
// A button that says what it makes needs no heading to explain it.
func SectionHead(gtx layout.Context, th *Theme, label string, btn *widget.Clickable, word string) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return Heading(gtx, th, label)
		}),
		layout.Rigid(layout.Spacer{Width: GapDp}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if btn == nil || word == "" {
				return layout.Dimensions{}
			}
			return SecondaryButton(gtx, th, btn, word)
		}),
	)
}

// Empty is what a list says when it holds nothing.
//
// It is not a blank area. A screen that draws nothing where a list
// belongs is indistinguishable from a screen that failed to load, and
// the maintainer met exactly that on every Admin sub-tab while the lists were
// never fetched at all. The sentence names what WILL be here and why
// there is none yet, so an empty list reads as an answer.
func Empty(gtx layout.Context, th *Theme, sentence string) layout.Dimensions {
	return layout.Inset{Top: TightDp, Bottom: TightDp}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			lbl := material.Label(th.Material, SmallSp, sentence)
			lbl.Color = th.Color(MutedKey)
			lbl.Font = th.MonoFont
			return lbl.Layout(gtx)
		})
}

// ComboBox is a text field that also offers what is already known: type
// a name, or press one (IAMT-359).
//
// It replaces the strip of words that used to sit UNDER the field. That
// strip was drawn in the same quiet small capitals as the captions
// beside it -- "RFC 3339, or leave empty", "shell is interactive" -- and
// the maintainer read it as a caption, which is what it looked like: no
// list was visible. A list of choices has to be told apart from prose that
// explains, and the only honest way is for the choices to look pressable.
//
// Typing stays possible on purpose. The gateway is the only party that
// knows every name, the window's copy can be a moment out of date, and a
// control that only offered its own copy would make a stale list into a
// wall.
//
// open toggles the panel; expanded says whether it is open now. The
// caller owns both, because which control is open is screen state and
// this package holds none.
func ComboBox(
	gtx layout.Context,
	th *Theme,
	ed *widget.Editor,
	hint string,
	open *widget.Clickable,
	expanded bool,
	options []string,
	optBtn func(string) *widget.Clickable,
) (dims layout.Dimensions, picked string) {
	current := strings.TrimSpace(ed.Text())

	children := []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return TextBox(gtx, th, ed, hint)
				}),
				layout.Rigid(layout.Spacer{Width: TightDp}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if len(options) == 0 || open == nil {
						return layout.Dimensions{}
					}
					// The arrow points the way the panel will move, so
					// the control says what pressing it does rather than
					// what state it is in.
					word := "▾"
					if expanded {
						word = "▴"
					}
					// SQUARE, not SecondaryButton. A secondary button
					// carries a minimum width meant for a word, and one
					// arrow inside it drew a wide empty box floating to
					// the right of the field -- on the History screen it
					// read as a second, unlabelled control rather than as
					// this field's own drop-down (21.09.2026).
					return SquareButton(gtx, th, open, word)
				}),
			)
		}),
	}

	if expanded && len(options) > 0 && optBtn != nil {
		children = append(children,
			layout.Rigid(layout.Spacer{Height: TightDp}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				var rows []layout.FlexChild
				for _, name := range options {
					name := name
					b := optBtn(name)
					if b.Clicked(gtx) {
						picked = name
					}
					rows = append(rows,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{Bottom: TightDp}.Layout(gtx,
								func(gtx layout.Context) layout.Dimensions {
									if name == current {
										return PrimaryButton(gtx, th, b, name)
									}
									return SecondaryButton(gtx, th, b, name)
								})
						}))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			}),
		)
	}

	dims = layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	return dims, picked
}

// Step is one box of the guide's flow chart (IAMT-359).
//
// The guide is a graph read downwards, because that is the shape of the
// thing it describes: a gateway is installed, then somebody becomes its
// administrator, then a machine registers, then access is granted, then
// somebody connects. Each step names the MACHINE it happens on first --
// the maintainer's own correction, made twice during the live
// walk-through: saying "double click" does not say on which machine.
type Step struct {
	// Number is the step's place in the order, drawn large and quiet.
	Number string
	// Where names the machine this step happens on, in capitals.
	Where string
	// What is the one sentence of what to do there.
	What string
	// How is the exact command or the exact path through the window --
	// monospaced, because it is meant to be retyped or followed
	// literally.
	How string
	// Here marks the step that happens on THIS machine. Exactly one step
	// carries it, and it is the reason the whole chart is worth drawing
	// rather than printing five sentences: a person looking at it learns
	// where they stand in a process that spans three computers.
	Here bool
	// Done marks a step already finished on this machine.
	Done bool
}

// StepBox draws one step. Its border is Spot when the step is HERE, a
// hairline otherwise, so the eye finds the current step before reading
// a word.
func StepBox(gtx layout.Context, th *Theme, s Step) layout.Dimensions {
	key := LineKey
	width := unit.Dp(1)
	if s.Here {
		key = SpotKey
		width = unit.Dp(2)
	}
	return widget.Border{
		Color:        th.Color(key),
		Width:        width,
		CornerRadius: unit.Dp(Radius),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: PadDp, Bottom: PadDp, Left: PadDp, Right: PadDp}.Layout(gtx,
			func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Start}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						lbl := material.Label(th.Material, HeadSp, s.Number)
						lbl.Color = th.Color(MutedKey)
						lbl.Font = th.BodyFont
						return lbl.Layout(gtx)
					}),
					layout.Rigid(layout.Spacer{Width: GapDp}.Layout),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								where := s.Where
								switch {
								case s.Here:
									where += "   ← you are here"
								case s.Done:
									where += "   ✓"
								}
								lbl := material.Label(th.Material, SmallSp, strings.ToUpper(where))
								k := MutedKey
								if s.Here {
									k = SpotKey
								} else if s.Done {
									k = GoodKey
								}
								lbl.Color = th.Color(k)
								lbl.Font = th.BodyFont
								return lbl.Layout(gtx)
							}),
							layout.Rigid(layout.Spacer{Height: TightDp}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return Deck(gtx, th, s.What)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if s.How == "" {
									return layout.Dimensions{}
								}
								return layout.Inset{Top: TightDp}.Layout(gtx,
									func(gtx layout.Context) layout.Dimensions {
										return Fixed(gtx, th, s.How)
									})
							}),
						)
					}),
				)
			})
	})
}

// StepArrow is the line between two steps: the graph's edge, drawn as a
// short vertical rule so the chart reads downwards even in one colour.
func StepArrow(gtx layout.Context, th *Theme) layout.Dimensions {
	h := gtx.Dp(unit.Dp(18))
	w := gtx.Dp(unit.Dp(2))
	x := gtx.Dp(unit.Dp(22))
	rect := image.Rect(x, 0, x+w, h)
	paint.FillShape(gtx.Ops, th.Color(LineKey), clip.Rect(rect).Op())
	return layout.Dimensions{Size: image.Pt(gtx.Constraints.Max.X, h)}
}

// Arrow draws a horizontal line with a head, pointing right or left, for
// the guide's picture of the three computers. It is a drawing, not a
// widget: nothing is clickable, and its only job is to say which way the
// connection is opened.
//
// Direction is the whole point of the picture. Every arrow in it points
// INTO the gateway, because both sides dial out and neither listens --
// that single fact is what lets this product reach a machine with no
// public address, behind a router nobody will reconfigure.
func Arrow(gtx layout.Context, th *Theme, rightwards bool) layout.Dimensions {
	w := gtx.Constraints.Max.X
	if w <= 0 {
		return layout.Dimensions{}
	}
	stroke := gtx.Dp(unit.Dp(1))
	if stroke < 1 {
		stroke = 1
	}
	head := gtx.Dp(unit.Dp(6))
	h := gtx.Dp(unit.Dp(16))
	mid := h / 2

	paint.FillShape(gtx.Ops, th.Color(LineKey),
		clip.Rect(image.Rect(0, mid-stroke/2, w, mid-stroke/2+stroke)).Op())

	var p clip.Path
	p.Begin(gtx.Ops)
	if rightwards {
		p.MoveTo(f32Pt(w, mid))
		p.LineTo(f32Pt(w-head, mid-head))
		p.LineTo(f32Pt(w-head, mid+head))
	} else {
		p.MoveTo(f32Pt(0, mid))
		p.LineTo(f32Pt(head, mid-head))
		p.LineTo(f32Pt(head, mid+head))
	}
	p.Close()
	paint.FillShape(gtx.Ops, th.Color(LineKey), clip.Outline{Path: p.End()}.Op())

	return layout.Dimensions{Size: image.Pt(w, h)}
}

func f32Pt(x, y int) f32.Point {
	return f32.Point{X: float32(x), Y: float32(y)}
}

// PlainBox frames one thing in the guide's picture: a hairline border and
// whatever the caller draws inside it. It is StepBox without the step --
// no number, no state, no colour -- because the picture says what the
// parts ARE, while the chart below it says what to DO.
func PlainBox(gtx layout.Context, th *Theme, inner layout.Widget) layout.Dimensions {
	return widget.Border{
		Color:        th.Color(LineKey),
		Width:        unit.Dp(1),
		CornerRadius: unit.Dp(Radius),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: PadDp, Bottom: PadDp, Left: PadDp, Right: PadDp}.Layout(gtx, inner)
	})
}
