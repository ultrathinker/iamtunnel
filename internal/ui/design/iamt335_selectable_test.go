//go:build windows || linux || darwin

package design

// IAMT-335 canary: after a typography piece renders its text, the
// label's selection state HOLDS that text — the property that makes a
// drawn string draggable and copyable the ordinary way. Said
// (textbox.go) and CopyableBox (pieces.go) have carried their own
// selection state since 19.09.2026; the plain pieces — Words, Text,
// Deck, Hint, Heading, Fixed, and every Facts row drawn through them —
// drew bare labels, and a bare gio label keeps no selection state at
// all: nothing can be dragged over, so there is nothing for Ctrl+C to
// take.
//
// The canary renders each piece and then reads back the selection
// state through the same lookup the pieces use. A label wired to its
// state writes the text into it at layout time (material.LabelStyle
// does SetText before drawing), so an empty Text() means the render
// drew a bare label again — the property this card asks for is gone.

import (
	"image"
	"testing"

	giofont "gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
)

func TestIAMT335_ARenderedLabelKeepsItsTextSelectable(t *testing.T) {
	th := NewTheme(LightPalette(), nil)

	const deckTxt = "the sentence under the headline"
	const hintTxt = "a small monospaced caption"
	const headingTxt = "a section label"
	const fixedTxt = "keys, output, lists"
	const textTxt = "ordinary running text"

	headingFont := th.BodyFont
	headingFont.Weight = giofont.SemiBold

	for _, tc := range []struct {
		name string
		draw func(gtx layout.Context) layout.Dimensions
		txt  string
		key  textKey
	}{
		{"Text", func(gtx layout.Context) layout.Dimensions { return Text(gtx, th, textTxt) },
			textTxt, textKey{txt: textTxt, size: BodySp, key: InkKey, font: th.BodyFont}},
		{"Deck", func(gtx layout.Context) layout.Dimensions { return Deck(gtx, th, deckTxt) },
			deckTxt, textKey{txt: deckTxt, size: HeadSp, key: InkKey, font: th.BodyFont}},
		{"Hint", func(gtx layout.Context) layout.Dimensions { return Hint(gtx, th, hintTxt) },
			hintTxt, textKey{txt: hintTxt, size: SmallSp, key: MutedKey, font: th.MonoFont}},
		{"Heading", func(gtx layout.Context) layout.Dimensions { return Heading(gtx, th, headingTxt) },
			"A SECTION LABEL", textKey{txt: "A SECTION LABEL", size: SmallSp, key: MutedKey, font: headingFont}},
		{"Fixed", func(gtx layout.Context) layout.Dimensions { return Fixed(gtx, th, fixedTxt) },
			fixedTxt, textKey{txt: fixedTxt, size: SmallSp, key: InkKey, font: th.MonoFont}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ops op.Ops
			gtx := layout.Context{
				Ops:         &ops,
				Constraints: layout.Constraints{Max: image.Pt(800, 600)},
				Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
			}
			tc.draw(gtx)
			sel := selectableFor(tc.key)
			if sel == nil {
				t.Fatalf("after rendering, the %s piece registered no selection state — the text cannot be selected or copied (IAMT-335)", tc.name)
			}
			if sel.Text() != tc.txt {
				t.Fatalf("after rendering, the %s label's selection state holds %q, want %q — the label drew with no selection state (IAMT-335)", tc.name, sel.Text(), tc.txt)
			}
		})
	}
}

// TestIAMT335_TheSelectionStateOutlivesTheFrame pins the property that
// makes selection USEFUL: the same label drawn again — next frame, after
// a tab switch — finds the same selection state, so a selection a person
// made survives the redraw instead of dying with the frame that drew it.
func TestIAMT335_TheSelectionStateOutlivesTheFrame(t *testing.T) {
	th := NewTheme(LightPalette(), nil)
	const txt = "the same caption drawn twice"
	key := textKey{txt: txt, size: SmallSp, key: MutedKey, font: th.MonoFont}

	draw := func() {
		var ops op.Ops
		gtx := layout.Context{
			Ops:         &ops,
			Constraints: layout.Constraints{Max: image.Pt(800, 600)},
			Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
		}
		Hint(gtx, th, txt)
	}
	draw()
	first := selectableFor(key)
	draw()
	second := selectableFor(key)
	if first == nil || first != second {
		t.Fatalf("two renders of the same caption produced two selection states — a selection would not survive the next frame (IAMT-335)")
	}
}
