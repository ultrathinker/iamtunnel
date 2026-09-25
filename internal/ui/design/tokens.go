//go:build windows || linux || darwin

package design

import (
	"time"

	"gioui.org/unit"
)

// Telescope type scale, SPEC §7.1 and umtunnel's Design.cs.
// Five text sizes, exact values from Design.cs:
const (
	// Display is the state of the machine, and nothing else, ever.
	Display = 58.0
	// Title is the line above the headline, and a screen's own name.
	Title = 26.0
	// Head is the deck: the sentence or two under the headline that say what the state means.
	Head = 15.0
	// Body is ordinary running text.
	Body = 14.0
	// Small is captions, labels, and everything monospaced.
	Small = 11.5
)

// Telescope spacings, SPEC §7.1 and umtunnel's Design.cs.
// Five spacings, exact values from Design.cs:
const (
	// Tight spacing: inside a row, between rows.
	Tight = 5.0
	// Gap spacing: between elements, copyable padding.
	Gap = 10.0
	// Pad spacing: inside a block, card rule bottom margin.
	Pad = 16.0
	// Wide spacing: between sections, page vertical spacing.
	Wide = 30.0
	// Edge spacing: at the window's border, tab bar horizontal inset.
	Edge = 40.0

	// Radius is zero, and it is load-bearing. A rounded corner is a small
	// friendly gesture, and this design is not making one.
	Radius = 0.0
)

// Typed Sp units for type scale.
const (
	DisplaySp = unit.Sp(Display)
	TitleSp   = unit.Sp(Title)
	HeadSp    = unit.Sp(Head)
	BodySp    = unit.Sp(Body)
	SmallSp   = unit.Sp(Small)
)

// Typed Dp units for spacings.
const (
	TightDp = unit.Dp(Tight)
	GapDp   = unit.Dp(Gap)
	PadDp   = unit.Dp(Pad)
	WideDp  = unit.Dp(Wide)
	EdgeDp  = unit.Dp(Edge)
)

// Component-specific dimensions from Design.cs:
const (
	// DotSize is the width and height of the status dot (square, 9x9).
	DotSize = 9.0
	// DotStrokeHollow is the stroke thickness when the status dot is hollow.
	DotStrokeHollow = 1.5

	// TabSpacing is the horizontal spacing between tab headers.
	TabSpacing = 8.0
	// TabWordHeight is the fixed height of the cell holding a tab word.
	// The word itself is centered inside; the cell — not the font's
	// natural line — decides the tab strip's height, so a font
	// substitution never moves the window's furniture.
	TabWordHeight = 20.0
	// TabIndicatorHeight is the height of the active tab underline rule.
	TabIndicatorHeight = 2.0
	// TabIndicatorMargin is the top margin above the active tab underline rule.
	TabIndicatorMargin = 7.0
	// TabWordSize is the type size of a main tab's word. It is its own
	// token rather than Small, because the main tabs are the one piece of
	// furniture a person aims at with a mouse all day: they were set at
	// Small (11.5) with the rest of the small print until 21.09.2026,
	// when the maintainer asked for bigger letters on these main tabs.
	// The sub-tab strip stays at Small -- it is navigation WITHIN a
	// place, and the difference in size is what says which is which.
	TabWordSize = 13.0
	// TabPadX and TabPadY are the padding INSIDE a tab's hit area, around
	// its word. They are what the hover tint fills, and before they
	// existed the tint was the size of the letters: a grey rectangle
	// clamped to the word, which reads as a defect rather than as a
	// target. Padding gives the pointer something to land on and gives
	// the tint room to look deliberate.
	TabPadX = 12.0
	TabPadY = 6.0
	// TabLetterSpacing is the letter spacing factor for tab headers and headings.
	TabLetterSpacing = 1.2

	// FactsColumnWidth is the width of the label column in the Facts table ("210,*").
	FactsColumnWidth = 210.0

	// PosterSpacing is the vertical spacing between lead and word (-8).
	PosterSpacing = -8.0
	// PosterLineHeightRatio is the line height ratio for the Display word (1.06).
	PosterLineHeightRatio = 1.06

	// ButtonMinWidthPrimary is the minimum width for primary button (150).
	ButtonMinWidthPrimary = 150.0
	// ButtonMinWidthSecondary is the minimum width for secondary button (120).
	ButtonMinWidthSecondary = 120.0
	// ButtonPadHorizontal is the horizontal padding for buttons (22).
	ButtonPadHorizontal = 22.0
	// ButtonPadVertical is the vertical padding for buttons (10).
	ButtonPadVertical = 10.0

	// The three below are the same button at the proportions a LIST ROW
	// wants (21.09.2026). The maintainer looked at the Client tab, where one
	// machine's row carries four of them side by side, and said they are
	// too big — and they are: the standard button is sized to be the
	// thing you press on a page, and a row's controls are not that. They
	// are the row's own verbs, read after its name and its dates.
	//
	// Only the padding and the floor change. The border, the colours,
	// the radius and the text size are the standard button's, because a
	// row control that looked like a different KIND of button would say
	// something untrue about what pressing it does.
	//
	// ButtonMinWidthCompact is the minimum width for a row button (72).
	ButtonMinWidthCompact = 72.0
	// ButtonPadHorizontalCompact is its horizontal padding (10).
	ButtonPadHorizontalCompact = 10.0
	// ButtonPadVerticalCompact is its vertical padding (5).
	ButtonPadVerticalCompact = 5.0

	// TextBoxMinHeight is the minimum height of text boxes (30).
	TextBoxMinHeight = 30.0
	// TextBoxPadVertical is the vertical padding for text boxes (6), and
	// TextBoxPadHorizontal the room between the frame and the words (8).
	TextBoxPadVertical   = 6.0
	TextBoxPadHorizontal = 8.0
	// TextBoxRule is the thickness of an idle text box's frame (1), and
	// TextBoxRuleFocused the thickness while it holds the keyboard (2).
	// Until IAMT-505 (24.09.2026) this was umtunnel's line UNDER the words
	// only (BorderThickness 0,0,0,1); the maintainer asked for ordinary boxes,
	// framed on all four sides, and the frame now uses the same two
	// thicknesses and the same LineKey / SpotKey pair. No fill and no
	// corner radius — Radius is zero, as on the buttons beside them.
	TextBoxRule        = 1.0
	TextBoxRuleFocused = 2.0

	// PulseDuration is the period of the elevation notice pulse animation (1.5s).
	PulseDuration = 1500 * time.Millisecond
)
