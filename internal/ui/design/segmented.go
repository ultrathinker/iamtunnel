//go:build windows || linux || darwin

package design

// segmented.go — a segmented control: several mutually exclusive choices
// drawn as one strip of touching, bordered rectangles, the current one
// filled solid (SPEC §7.1, IAMT-393).
//
// Until 19.09.2026 a choice like this was three bare words side by side —
// "LOG   WARN   BLOCK" — with the current one only a little bolder than
// the other two. The maintainer's own words, on the live run that found
// it: there has to be a visual way to tell that the choices are
// pressable -- otherwise it is just three words standing next to each
// other. Prose that happens to react to a
// click still reads as prose: nothing about three words in a row says
// "control", and nothing about bold-versus-not says "this one, not those
// two". A bordered box says "press me" the way a caption never can, and a
// filled one says "already pressed" without asking the reader to compare
// font weights.
//
// This replaces PickStrip everywhere a screen offered a short row of
// mutually exclusive words with the live one marked only by weight: the
// safety mode strip on Admin/Live is the one the maintainer actually met, and
// it is the only caller left once the New grant card's own picks (SPEC
// IAMT-391) moved to the combo boxes person and machine already use —
// those are a different control answering a different question ("which
// of these already-known values, or type your own"), not this one
// ("which of these three states is live").
import (
	"image"
	"strings"

	giofont "gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// Segmented draws items edge to edge, each its own bordered box, and
// reports which one was pressed this frame ("" if none). The caller owns
// one *widget.Clickable per item, for the reason every other picker in
// this package does: the window keeps one strip per control across
// frames, and a widget that allocated its own would forget which item
// was current the moment the frame ended.
//
// active marks nothing when it matches no item, the same rule PickStrip
// followed: a caller with no current value must not have the strip lie
// about having one.
func Segmented(gtx layout.Context, th *Theme, items []string, active string, btn func(string) *widget.Clickable) (layout.Dimensions, string) {
	if len(items) == 0 {
		return layout.Dimensions{}, ""
	}
	pressed := ""
	children := make([]layout.FlexChild, 0, len(items))
	for _, it := range items {
		word := it
		on := strings.EqualFold(word, active)
		b := btn(word)
		if b.Clicked(gtx) {
			pressed = word
		}
		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return segment(gtx, th, b, word, on)
		}))
	}
	dims := layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
	return dims, pressed
}

// segment is one box of the strip: a hairline border everywhere, SpotKey
// on the current choice or under the pointer, filled solid when current —
// pressedShade darkens that fill under a held pointer exactly as
// PrimaryButton's does, so a segmented control being pressed reads the
// same as every other filled control in the design being pressed.
func segment(gtx layout.Context, th *Theme, b *widget.Clickable, word string, on bool) layout.Dimensions {
	return material.Clickable(gtx, b, func(gtx layout.Context) layout.Dimensions {
		// The fill has to be painted BEHIND the border and the word, and
		// its size is only known once they are laid out — the same
		// record-measure-paint-replay SecondaryButton uses.
		macro := op.Record(gtx.Ops)
		dims := segmentFace(gtx, th, b, word, on)
		face := macro.Stop()
		if on {
			bg := th.Color(SpotKey)
			if b.Pressed() {
				bg = pressedShade(bg)
			}
			paint.FillShape(gtx.Ops, bg, clip.Rect(image.Rectangle{Max: dims.Size}).Op())
		} else if b.Pressed() {
			paint.FillShape(gtx.Ops, th.Color(SunkenKey), clip.Rect(image.Rectangle{Max: dims.Size}).Op())
		}
		face.Add(gtx.Ops)
		return dims
	})
}

// segmentFace is the border and the word, without the fill only a current
// or held segment paints.
func segmentFace(gtx layout.Context, th *Theme, b *widget.Clickable, word string, on bool) layout.Dimensions {
	borderKey := LineKey
	if on || b.Hovered() || b.Pressed() {
		borderKey = SpotKey
	}
	return widget.Border{
		Color:        th.Color(borderKey),
		Width:        unit.Dp(1),
		CornerRadius: unit.Dp(Radius),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top:    unit.Dp(ButtonPadVertical),
			Bottom: unit.Dp(ButtonPadVertical),
			Left:   unit.Dp(ButtonPadHorizontal),
			Right:  unit.Dp(ButtonPadHorizontal),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			lbl := material.Label(th.Material, BodySp, strings.ToUpper(word))
			lbl.Font = th.BodyFont
			lbl.Alignment = text.Middle
			if on {
				lbl.Color = th.Color(OnSpotKey)
				lbl.Font.Weight = giofont.SemiBold
			} else {
				lbl.Color = th.Color(InkKey)
			}
			return lbl.Layout(gtx)
		})
	})
}
