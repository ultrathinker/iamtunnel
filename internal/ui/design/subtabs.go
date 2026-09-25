//go:build windows || linux || darwin

package design

// subtabs.go — the second row of tabs inside one tab (SPEC §7.1, 1.3).
//
// Why it exists. Until 1.3 a tab whose job had several independent parts
// simply stacked them down one page: the Admin tab was People, Machines,
// Grants, Grant access, Become an administrator, Pairing window, Add
// person and Enrol machine, in that order, one under the other. In the
// maintainer's live run the window ended after the fourth, there was no
// scrollbar (IAMT-334), and the entry point to the whole pairing flow was
// invisible. The verdict was not "add a scrollbar" but "if there are
// logical parts, separate them with tabs" — and that is right: a scrollbar
// makes a long page discoverable, it does not make eight unrelated
// operations legible.
//
// Why it is not Tabs. The main strip is the window's spine: Display-scale
// words, a 2 dp indicator, a hairline under it, and a promise that it
// never moves. A second strip drawn the same way competes with it and the
// eye stops knowing which level it is on. So this one is deliberately
// quieter — Small caps, no indicator bar, no rule underneath, active
// marked by ink and weight alone — and it is drawn INSIDE the page, above
// the page's own content, where it reads as belonging to the tab rather
// than to the window.

import (
	"image"
	"strings"

	giofont "gioui.org/font"
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

// SubTabGap is the horizontal space between two sub-tab words. Tighter
// than the main strip's Spacing: these belong to each other more closely
// than the five top-level tabs do.
const SubTabGap = 18

// SubTabStrip draws the second-level tab row and reports which word was
// pressed this frame, or "" if none.
//
// The caller owns the state — which sub-tab is active, and one Clickable
// per word — for the same reason the pages own their scroll position: the
// window has one of each per tab, they must survive every frame, and a
// widget that allocated them itself would forget the active sub-tab every
// time the person switched away and back.
//
// active that matches no item is not an error: the first item is drawn as
// active, which is what a freshly opened tab wants and what a renamed
// sub-tab degrades to.
func SubTabStrip(gtx layout.Context, th *Theme, items []string, active string, btn func(string) *widget.Clickable) (layout.Dimensions, string) {
	if len(items) == 0 {
		return layout.Dimensions{}, ""
	}
	if !containsFold(items, active) {
		active = items[0]
	}
	return wordStrip(gtx, th, items, active, btn)
}

// wordStrip is SubTabStrip's drawing: the words, the spacing, and exactly
// the one marked active — no substitution.
func wordStrip(gtx layout.Context, th *Theme, items []string, active string, btn func(string) *widget.Clickable) (layout.Dimensions, string) {
	pressed := ""
	for _, it := range items {
		if btn(it).Clicked(gtx) {
			pressed = it
		}
	}

	children := make([]layout.FlexChild, 0, len(items)*2)
	for i, it := range items {
		word := it
		on := strings.EqualFold(word, active)
		if i > 0 {
			children = append(children, layout.Rigid(layout.Spacer{Width: unit.Dp(SubTabGap)}.Layout))
		}
		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return btn(word).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return subTabWord(gtx, th, word, on)
			})
		}))
	}

	dims := layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, children...)
	return dims, pressed
}

// subTabWord is one word of the strip: small capitals, letterspaced by
// the same Heading treatment the page's section labels use, so a sub-tab
// reads as a heading that can be pressed rather than as a button.
func subTabWord(gtx layout.Context, th *Theme, word string, on bool) layout.Dimensions {
	lbl := material.Label(th.Material, SmallSp, strings.ToUpper(word))
	lbl.Font = th.BodyFont
	if on {
		lbl.Color = th.Color(InkKey)
		lbl.Font.Weight = giofont.SemiBold
	} else {
		lbl.Color = th.Color(MutedKey)
	}
	return lbl.Layout(gtx)
}

// SubTabPage is the whole page of a tab that has sub-tabs: the strip,
// then the active sub-tab's own sections, laid out by Page so the section
// spacing and the scrollbar behave exactly as on a tab without sub-tabs.
//
// The strip is PINNED — it never scrolls away. A sub-tab strip that
// scrolled out of view would be the original defect wearing a different
// hat: the way out of a page you are lost on must not itself be below the
// fold.
func SubTabPage(gtx layout.Context, th *Theme, list *widget.List, strip layout.Widget, sections ...layout.Widget) layout.Dimensions {
	all := make([]layout.Widget, 0, len(sections)+1)
	all = append(all, strip)
	all = append(all, sections...)
	return PinnedPage(gtx, th, list, 1, all...)
}

func containsFold(items []string, want string) bool {
	for _, it := range items {
		if strings.EqualFold(it, want) {
			return true
		}
	}
	return false
}

// SubTabHeight reports how tall the strip is for a given theme, so a
// caller that needs to reserve the space before drawing can do so. It
// lays the strip out into a discarded macro rather than returning a
// constant, for the same reason the masthead measures its button that
// way: a number copied into a second place rots.
func SubTabHeight(gtx layout.Context, th *Theme, items []string) int {
	if len(items) == 0 {
		return 0
	}
	var throwaway widget.Clickable
	dims, _ := SubTabStrip(gtx, th, items, items[0], func(string) *widget.Clickable { return &throwaway })
	return dims.Size.Y
}

var _ = image.Pt
