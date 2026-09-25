//go:build windows || linux || darwin

package design

import (
	"image"
	"image/color"
	"math"
	"strings"
	"time"

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

// -------------------------------------------------------------------------
// Typography pieces (Design.cs lines 293-338)
// -------------------------------------------------------------------------

// Words renders text with the given size, color key, and font.
//
// The label carries a selection state (IAMT-335), so everything drawn
// through it — Text, Deck, Hint, Fixed, Facts rows — can be dragged
// over and copied the ordinary way, the same property Said and
// CopyableBox have carried for their own strings since 19.09.2026. The
// state comes from the package registry keyed by what shapes this
// label, so it is the SAME state the next frame finds.
func Words(gtx layout.Context, th *Theme, txt string, size unit.Sp, key ColorKey, f giofont.Font) layout.Dimensions {
	lbl := material.Label(th.Material, size, txt)
	lbl.Color = th.Color(key)
	lbl.Font = f
	lbl.SelectionColor = th.Color(SpotDimKey)
	lbl.State = selectableFor(textKey{txt: txt, size: size, key: key, font: f})
	return lbl.Layout(gtx)
}

// Text renders ordinary running text at Body size (14 sp, InkKey).
func Text(gtx layout.Context, th *Theme, txt string) layout.Dimensions {
	return Words(gtx, th, txt, BodySp, InkKey, th.BodyFont)
}

// Deck renders the sentence under the headline at Head size (15 sp, InkKey).
func Deck(gtx layout.Context, th *Theme, txt string) layout.Dimensions {
	return Words(gtx, th, txt, HeadSp, InkKey, th.BodyFont)
}

// Hint renders a small monospaced caption at Small size (11.5 sp, MutedKey).
func Hint(gtx layout.Context, th *Theme, txt string) layout.Dimensions {
	return Words(gtx, th, txt, SmallSp, MutedKey, th.MonoFont)
}

// Heading renders a section label in small capitals, letterspaced and quiet (11.5 sp, MutedKey).
// Selectable like every Words label (IAMT-335).
func Heading(gtx layout.Context, th *Theme, txt string) layout.Dimensions {
	upper := strings.ToUpper(txt)
	lbl := material.Label(th.Material, SmallSp, upper)
	lbl.Color = th.Color(MutedKey)
	lbl.Font = th.BodyFont
	lbl.Font.Weight = giofont.SemiBold
	lbl.SelectionColor = th.Color(SpotDimKey)
	lbl.State = selectableFor(textKey{txt: upper, size: SmallSp, key: MutedKey, font: lbl.Font})
	return lbl.Layout(gtx)
}

// Fixed renders text read character by character (keys, output, lists) in Mono at Small size (11.5 sp, InkKey).
func Fixed(gtx layout.Context, th *Theme, txt string) layout.Dimensions {
	return Words(gtx, th, txt, SmallSp, InkKey, th.MonoFont)
}

// -------------------------------------------------------------------------
// Poster: State headline at top of every screen (Design.cs lines 563-589)
// -------------------------------------------------------------------------

// Poster displays the headline poster: a quiet serif lead line (Title 26 sp, MutedKey),
// followed by one very large serif bold state phrase (Display 58 sp, Key or InkKey).
type Poster struct {
	Lead string
	Word string
	Key  ColorKey
}

// NewPoster creates a new Poster widget.
func NewPoster(lead, word string, key ...ColorKey) *Poster {
	k := InkKey
	if len(key) > 0 && key[0] != "" {
		k = key[0]
	}
	return &Poster{
		Lead: lead,
		Word: word,
		Key:  k,
	}
}

// Say updates the displayed state phrase and optional lead line.
func (p *Poster) Say(word string, key ColorKey, lead ...string) {
	p.Word = word
	p.Key = key
	if len(lead) > 0 && lead[0] != "" {
		p.Lead = lead[0]
	}
}

// Layout renders the Poster with tight negative spacing between lead and word.
func (p *Poster) Layout(gtx layout.Context, th *Theme) layout.Dimensions {
	k := p.Key
	if k == "" {
		k = InkKey
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Label(th.Material, TitleSp, p.Lead)
			lbl.Color = th.Color(MutedKey)
			lbl.Font = th.SerifFont
			return lbl.Layout(gtx)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(PosterSpacing)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			lbl := material.Label(th.Material, DisplaySp, p.Word)
			lbl.Color = th.Color(k)
			lbl.Font = th.SerifBoldFont
			lbl.LineHeight = DisplaySp * PosterLineHeightRatio
			return lbl.Layout(gtx)
		}),
	)
}

// -------------------------------------------------------------------------
// Rule: Hairline across the page (Design.cs lines 416-421)
// -------------------------------------------------------------------------

// Rule draws a 1 dp hairline across the available width using LineKey color.
func Rule(gtx layout.Context, th *Theme) layout.Dimensions {
	height := gtx.Dp(1)
	if height < 1 {
		height = 1
	}
	width := gtx.Constraints.Max.X
	rect := image.Rect(0, 0, width, height)
	paint.FillShape(gtx.Ops, th.Color(LineKey), clip.Rect(rect).Op())
	return layout.Dimensions{Size: image.Pt(width, height)}
}

// -------------------------------------------------------------------------
// Card: Section with heading label, hairline rule and body (Design.cs lines 390-412)
// -------------------------------------------------------------------------

// Card renders a section: a small capital label with optional right-aligned tools,
// a hairline rule under it with Tight top margin and Pad bottom margin, then the body.
type Card struct {
	Title string
	Tools layout.Widget
	Body  layout.Widget
}

// NewCard constructs a Card section.
func NewCard(title string, body layout.Widget, tools ...layout.Widget) Card {
	var tw layout.Widget
	if len(tools) > 0 {
		tw = tools[0]
	}
	return Card{
		Title: title,
		Body:  body,
		Tools: tw,
	}
}

// Layout renders the Card.
func (c Card) Layout(gtx layout.Context, th *Theme) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Header row: Heading on left, optional Tools on right
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{
				Axis:      layout.Horizontal,
				Alignment: layout.Middle,
			}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return Heading(gtx, th, c.Title)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if c.Tools != nil {
						return c.Tools(gtx)
					}
					return layout.Dimensions{}
				}),
			)
		}),
		// Hairline rule with Margin(0, Tight, 0, Pad)
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{
				Top:    TightDp,
				Bottom: PadDp,
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return Rule(gtx, th)
			})
		}),
		// Body
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if c.Body != nil {
				return c.Body(gtx)
			}
			return layout.Dimensions{}
		}),
	)
}

// -------------------------------------------------------------------------
// Dot: State as a square mark (Design.cs lines 492-506)
// -------------------------------------------------------------------------

// Dot renders a 9x9 dp square state mark (hollow or filled) with Gap (10 dp) right margin.
func Dot(gtx layout.Context, th *Theme, key ColorKey, hollow bool) layout.Dimensions {
	sizePx := gtx.Dp(unit.Dp(DotSize))
	gapPx := gtx.Dp(GapDp)
	c := th.Color(key)

	var strokePx float32 = 0
	if hollow {
		strokePx = float32(gtx.Dp(unit.Dp(DotStrokeHollow)))
		if strokePx < 1 {
			strokePx = 1
		}
	}

	rect := image.Rect(0, 0, sizePx, sizePx)
	if hollow {
		paint.FillShape(gtx.Ops, c, clip.Stroke{
			Path:  clip.Rect(rect).Path(),
			Width: strokePx,
		}.Op())
	} else {
		paint.FillShape(gtx.Ops, c, clip.Rect(rect).Op())
	}

	return layout.Dimensions{Size: image.Pt(sizePx+gapPx, sizePx)}
}

// Status combines a Dot mark and word widget on one baseline (Design.cs lines 527-534).
func Status(gtx layout.Context, th *Theme, dot layout.Widget, words layout.Widget) layout.Dimensions {
	return layout.Flex{
		Axis:      layout.Horizontal,
		Alignment: layout.Middle,
	}.Layout(gtx,
		layout.Rigid(dot),
		layout.Rigid(words),
	)
}

// -------------------------------------------------------------------------
// Facts: Table of captions with 210dp label column (Design.cs lines 453-484)
// -------------------------------------------------------------------------

// FactRow represents one row in a Facts table.
type FactRow struct {
	Label string
	Value string
	// Widget allows custom widget rendering if non-nil, otherwise Value string is used.
	Widget layout.Widget
}

// Fact creates a standard text FactRow.
func Fact(label, value string) FactRow {
	return FactRow{Label: label, Value: value}
}

// Facts renders a table of captions: 210 dp monospaced label column and value column beside it.
func Facts(gtx layout.Context, th *Theme, rows []FactRow) layout.Dimensions {
	var children []layout.FlexChild
	for _, row := range rows {
		r := row
		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{
				Axis:      layout.Horizontal,
				Alignment: layout.Start,
			}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					colW := gtx.Dp(unit.Dp(FactsColumnWidth))
					gtxCol := gtx
					gtxCol.Constraints.Min.X = colW
					gtxCol.Constraints.Max.X = colW
					return Hint(gtxCol, th, r.Label)
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					if r.Widget != nil {
						return r.Widget(gtx)
					}
					return Fixed(gtx, th, r.Value)
				}),
			)
		}))
		// Tight spacing between rows
		children = append(children, layout.Rigid(layout.Spacer{Height: TightDp}.Layout))
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// -------------------------------------------------------------------------
// Pulse: Slow pulse animation for elevation notice (Design.cs lines 718-748)
// -------------------------------------------------------------------------

// PulseOpacity computes the opacity value for a point in the 1.5s pulse cycle:
// - 0.00 to 0.70 (1.05s): opacity 1.0 (bright for most of a second and a half)
// - 0.70 to 0.85 (0.225s): dips linearly from 1.0 to 0.25
// - 0.85 to 1.00 (0.225s): rises linearly from 0.25 to 1.0
func PulseOpacity(elapsed time.Duration) float32 {
	const period = PulseDuration
	rem := elapsed % period
	phase := float32(rem) / float32(period)

	if phase <= 0.70 {
		return 1.0
	}
	if phase <= 0.85 {
		// Dip from 1.0 down to 0.25
		frac := (phase - 0.70) / (0.85 - 0.70)
		return 1.0 - 0.75*frac
	}
	// Rise from 0.25 back to 1.0
	frac := (phase - 0.85) / (1.0 - 0.85)
	return 0.25 + 0.75*frac
}

// SoftPulseDuration is the period of the masthead button's breathing
// (IAMT-336). Twice the notice pulse, because this mark lives in the
// window's chrome and is meant to be noticed once, not watched.
const SoftPulseDuration = 3 * time.Second

// SoftPulseOpacity is PulseOpacity's quiet twin, for the one control that
// pulses in the masthead rather than inside a page: the
// "Restart as administrator" button (SPEC §7.1, decision of 17.09.2026).
//
// Two differences, both deliberate. It never drops below 0.62, where the
// notice pulse dips to 0.25 — a chrome element that nearly vanishes reads
// as a rendering fault, not as an invitation. And it breathes on a smooth
// cosine over the whole period instead of holding bright and then
// blinking: a hold-then-blink cycle is an alarm, and this button is not an
// alarm. It says "there is something here you may want", and the person
// presses it if they want it.
func SoftPulseOpacity(elapsed time.Duration) float32 {
	const period = SoftPulseDuration
	const lo, hi = 0.62, 1.0
	phase := float64(elapsed%period) / float64(period)
	// cos runs 1 → -1 → 1 over the period; map it to hi → lo → hi.
	wave := (math.Cos(2*math.Pi*phase) + 1) / 2
	return float32(lo + (hi-lo)*wave)
}

// SoftPulseWidget applies SoftPulseOpacity to a widget. active=false
// renders it at full opacity and, unlike PulseWidget, that is the state
// the offscreen shot and the tests see: a still frame of a breathing
// control would otherwise be a different picture every run.
func SoftPulseWidget(gtx layout.Context, active bool, startTime time.Time, w layout.Widget) layout.Dimensions {
	if !active {
		return w(gtx)
	}
	gtx.Execute(op.InvalidateCmd{})
	op := paint.PushOpacity(gtx.Ops, SoftPulseOpacity(time.Since(startTime)))
	dims := w(gtx)
	op.Pop()
	return dims
}

// PulseWidget applies the 1.5-second pulse opacity animation to a widget.
// When active is false (e.g. on an inactive tab), it stops pulsing and renders at full 1.0 opacity.
func PulseWidget(gtx layout.Context, active bool, startTime time.Time, w layout.Widget) layout.Dimensions {
	if !active {
		return w(gtx)
	}

	elapsed := time.Since(startTime)
	opacity := PulseOpacity(elapsed)

	// Invalidate to drive continuous smooth 60fps animation
	gtx.Execute(op.InvalidateCmd{})

	// Apply alpha multiplier
	alpha := uint8(opacity * 255.0)
	paintOp := paint.PushOpacity(gtx.Ops, float32(alpha)/255.0)
	dims := w(gtx)
	paintOp.Pop()
	return dims
}

// -------------------------------------------------------------------------
// Tabs: Tab strip and frame (Design.cs lines 600-706)
// -------------------------------------------------------------------------

// TabItem represents one tab in the Tabs strip.
type TabItem struct {
	Header string
	Build  layout.Widget
	btn    widget.Clickable
}

// Tabs implements umtunnel's tab strip:
// - Small capitals with 2px underline rule under active tab
// - Horizontal Spacing 26 dp, horizontal padding Edge 40 dp
// - Hairline rule under the tab strip (LineKey)
// - Notice strip UNDER the tabs that does NOT push the tab strip around
// - Preserves tab contents once built
type Tabs struct {
	items         []TabItem
	current       string
	notice        layout.Widget
	noticeVisible bool
	Selected      func(header string)
}

// NewTabs creates a new Tabs component.
func NewTabs() *Tabs {
	return &Tabs{
		noticeVisible: true,
	}
}

// Add appends a tab with the given header and widget builder.
func (t *Tabs) Add(header string, build layout.Widget) {
	t.items = append(t.items, TabItem{
		Header: header,
		Build:  build,
	})
	if t.current == "" {
		t.current = header
	}
}

// Has reports whether a tab with the given header exists.
func (t *Tabs) Has(header string) bool {
	for _, item := range t.items {
		if strings.EqualFold(item.Header, header) {
			return true
		}
	}
	return false
}

// Current returns the header of the currently active tab.
func (t *Tabs) Current() string {
	return t.current
}

// Show sets the active tab by header name.
func (t *Tabs) Show(want string) {
	if len(t.items) == 0 {
		return
	}
	for _, item := range t.items {
		if strings.EqualFold(item.Header, want) {
			t.current = item.Header
			if t.Selected != nil {
				t.Selected(item.Header)
			}
			return
		}
	}
	// An unknown name must not MOVE anybody. Falling through to the
	// first tab was harmless only while the first tab happened to be the
	// one a person would already be on; when Guide took that place
	// (IAMT-359), asking for a tab that does not exist on this machine
	// started teleporting the window to the guide. Selecting nothing is
	// the honest answer to "show me a tab that is not here".
	//
	// The fall-through remains for the one case that needs it: nothing
	// is selected yet, and something has to be.
	for _, item := range t.items {
		if item.Header == t.current {
			return
		}
	}
	t.current = t.items[0].Header
	if t.Selected != nil {
		t.Selected(t.current)
	}
}

// Notice sets the widget displayed in the notice strip under the tabs.
func (t *Tabs) Notice(w layout.Widget) {
	t.notice = w
}

// NoticeVisible gets or sets whether the notice strip is visible.
func (t *Tabs) NoticeVisible() bool {
	return t.noticeVisible
}

// SetNoticeVisible sets visibility of the notice strip.
func (t *Tabs) SetNoticeVisible(v bool) {
	t.noticeVisible = v
}

// LayoutStrip renders only the tab strip (including underline hairline).
// The geometry (height) of this strip is invariant to tab selection and notice visibility.
func (t *Tabs) LayoutStrip(gtx layout.Context, th *Theme) layout.Dimensions {
	if len(t.items) == 0 {
		return layout.Dimensions{}
	}

	// Handle clicks
	for i := range t.items {
		if t.items[i].btn.Clicked(gtx) {
			t.Show(t.items[i].Header)
		}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// Tab buttons row with Edge (40 dp) padding
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// The strip gives back exactly the padding the first tab now
			// carries, so the first WORD still begins on the page's edge
			// line -- under the masthead's own first letter, where it has
			// always been. Padding a tab is a change to the target; it is
			// not licence to move the column everything else is aligned to.
			return layout.Inset{
				Left:  EdgeDp - unit.Dp(TabPadX),
				Right: EdgeDp - unit.Dp(TabPadX),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				var children []layout.FlexChild
				for i := range t.items {
					idx := i
					item := &t.items[idx]
					on := strings.EqualFold(item.Header, t.current)

					children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						// The word is laid out first into a recording, so the
						// underline can be exactly as wide as the word, and the
						// clickable can be sized to its content. Without the
						// explicit size, the hover layer inside material.Clickable
						// (a Stack with an Expanded child) stretches the tab
						// across the whole row and pushes every other tab off
						// the canvas.
						wordMacro := op.Record(gtx.Ops)
						wordDims := layoutTabWord(gtx, th, item.Header, on)
						wordCall := wordMacro.Stop()

						underline := func(gtx layout.Context) layout.Dimensions {
							return layout.Inset{
								Top: unit.Dp(TabIndicatorMargin),
							}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
								w := wordDims.Size.X
								h := gtx.Dp(unit.Dp(TabIndicatorHeight))
								if h < 2 {
									h = 2
								}
								rect := image.Rect(0, 0, w, h)
								if on {
									paint.FillShape(gtx.Ops, th.Color(InkKey), clip.Rect(rect).Op())
								} else {
									paint.FillShape(gtx.Ops, color.NRGBA{0, 0, 0, 0}, clip.Rect(rect).Op())
								}
								return layout.Dimensions{Size: image.Pt(w, h)}
							})
						}

						content := func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{
								Axis:      layout.Vertical,
								Alignment: layout.Middle,
							}.Layout(gtx,
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									// A fixed-height cell keeps the strip's
									// height independent of font metrics: the
									// substituted gofont must not move the
									// window's furniture.
									h := gtx.Dp(unit.Dp(TabWordHeight))
									y := (h - wordDims.Size.Y) / 2
									if y > 0 {
										trans := op.Offset(image.Pt(0, y)).Push(gtx.Ops)
										wordCall.Add(gtx.Ops)
										trans.Pop()
									} else {
										wordCall.Add(gtx.Ops)
									}
									return layout.Dimensions{Size: image.Pt(wordDims.Size.X, h)}
								}),
								layout.Rigid(underline),
							)
						}

						// The padded box is what the pointer hits and what
						// the hover tint fills -- see TabPadX/TabPadY. The
						// word and its underline sit inside it, so the
						// underline still measures the word and not the
						// padding.
						padded := func(gtx layout.Context) layout.Dimensions {
							// No padding under the word: the active tab's
							// underline must keep meeting the strip's
							// hairline, which is the design's own join
							// between "this tab" and "this page" and is
							// measured to the row by the invariant tests.
							// The tint gets its room above instead.
							return layout.Inset{
								Left:  unit.Dp(TabPadX),
								Right: unit.Dp(TabPadX),
								Top:   unit.Dp(TabPadY),
							}.Layout(gtx, content)
						}

						macro := op.Record(gtx.Ops)
						dims := padded(gtx)
						call := macro.Stop()

						sized := gtx
						sized.Constraints = layout.Constraints{
							Min: dims.Size,
							Max: dims.Size,
						}
						return material.Clickable(sized, &item.btn, func(gtx layout.Context) layout.Dimensions {
							call.Add(gtx.Ops)
							return dims
						})
					}))

					// Spacing = 26 dp between tabs
					if i < len(t.items)-1 {
						children = append(children, layout.Rigid(layout.Spacer{Width: unit.Dp(TabSpacing)}.Layout))
					}
				}
				return layout.Flex{
					Axis:      layout.Horizontal,
					Alignment: layout.End,
				}.Layout(gtx, children...)
			})
		}),
		// Hairline rule under the tabs bar (LineKey)
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return Rule(gtx, th)
		}),
	)
}

// layoutTabWord draws one tab word: TabWordSize uppercase; ink and
// semibold when the tab is active, muted and regular when not.
func layoutTabWord(gtx layout.Context, th *Theme, header string, on bool) layout.Dimensions {
	lbl := material.Label(th.Material, unit.Sp(TabWordSize), strings.ToUpper(header))
	if on {
		lbl.Color = th.Color(InkKey)
		lbl.Font.Weight = giofont.SemiBold
	} else {
		lbl.Color = th.Color(MutedKey)
		lbl.Font.Weight = giofont.Normal
	}
	lbl.Font.Typeface = th.BodyFont.Typeface
	return lbl.Layout(gtx)
}

// Layout renders the entire Tabs control: tab strip, notice strip under tabs, and active body.
func (t *Tabs) Layout(gtx layout.Context, th *Theme) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// 1. Tab strip (does not move)
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return t.LayoutStrip(gtx, th)
		}),
		// 2. Notice strip UNDER tabs (left aligned, Edge 40 dp inset)
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if t.noticeVisible && t.notice != nil {
				return layout.Inset{
					Top:   TightDp,
					Left:  EdgeDp,
					Right: EdgeDp,
				}.Layout(gtx, t.notice)
			}
			return layout.Dimensions{}
		}),
		// 3. Tab content body
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			for _, item := range t.items {
				if strings.EqualFold(item.Header, t.current) {
					if item.Build != nil {
						return item.Build(gtx)
					}
					break
				}
			}
			return layout.Dimensions{}
		}),
	)
}

// -------------------------------------------------------------------------
// Buttons & Form controls (Design.cs lines 226-289, 425-438)
// -------------------------------------------------------------------------

// pressedShade darkens a fill for the moment a button is held down
// (IAMT-364).
//
// gio's own button reacts to HOVER and to focus, and to nothing else: a
// button being held looks exactly like a button the pointer is merely
// resting on. The maintainer put it plainly -- pressing stop server
// gives the feeling that nothing is happening at all -- and that is
// describing a real absence, not a slow program. The work starts on the
// press; what was missing was the press SAYING so.
//
// A darker shade rather than a lighter one because every fill here is
// already a strong colour, and light-on-light vanishes on the accent
// this product uses most.
func pressedShade(c color.NRGBA) color.NRGBA {
	const keep = 78 // per cent of the original, i.e. 22% darker
	scale := func(v uint8) uint8 { return uint8(int(v) * keep / 100) }
	return color.NRGBA{R: scale(c.R), G: scale(c.G), B: scale(c.B), A: c.A}
}

// PrimaryButton renders the one primary button for a screen (solid SpotKey, OnSpotKey text, min width 150 dp, radius 0).
func PrimaryButton(gtx layout.Context, th *Theme, btn *widget.Clickable, txt string) layout.Dimensions {
	minW := gtx.Dp(unit.Dp(ButtonMinWidthPrimary))
	gtxBtn := gtx
	if gtxBtn.Constraints.Min.X < minW {
		gtxBtn.Constraints.Min.X = minW
	}

	b := material.Button(th.Material, btn, txt)
	b.Background = th.Color(SpotKey)
	if btn.Pressed() {
		b.Background = pressedShade(b.Background)
	}
	b.Color = th.Color(OnSpotKey)
	b.CornerRadius = unit.Dp(Radius)
	b.Inset = layout.Inset{
		Top:    unit.Dp(ButtonPadVertical),
		Bottom: unit.Dp(ButtonPadVertical),
		Left:   unit.Dp(ButtonPadHorizontal),
		Right:  unit.Dp(ButtonPadHorizontal),
	}
	b.TextSize = BodySp
	return b.Layout(gtxBtn)
}

// DangerButton renders the one destructive button of a screen (solid
// BadKey background, white-on-bad text, primary proportions, radius 0).
// Telescope keeps a single accent per screen: where a DangerButton is
// present, it — not PrimaryButton — is that accent, so the button that
// cuts everything off is unmissable.
func DangerButton(gtx layout.Context, th *Theme, btn *widget.Clickable, txt string) layout.Dimensions {
	minW := gtx.Dp(unit.Dp(ButtonMinWidthPrimary))
	gtxBtn := gtx
	if gtxBtn.Constraints.Min.X < minW {
		gtxBtn.Constraints.Min.X = minW
	}

	b := material.Button(th.Material, btn, txt)
	b.Background = th.Color(BadKey)
	if btn.Pressed() {
		b.Background = pressedShade(b.Background)
	}
	b.Color = rgb(0xFFFFFF)
	b.CornerRadius = unit.Dp(Radius)
	b.Inset = layout.Inset{
		Top:    unit.Dp(ButtonPadVertical),
		Bottom: unit.Dp(ButtonPadVertical),
		Left:   unit.Dp(ButtonPadHorizontal),
		Right:  unit.Dp(ButtonPadHorizontal),
	}
	b.TextSize = BodySp
	return b.Layout(gtxBtn)
}

// SecondaryButton renders a secondary button (clear background, LineKey 1dp border, InkKey text, min width 120 dp, radius 0).
func SecondaryButton(gtx layout.Context, th *Theme, btn *widget.Clickable, txt string) layout.Dimensions {
	minW := gtx.Dp(unit.Dp(ButtonMinWidthSecondary))
	gtxBtn := gtx
	if gtxBtn.Constraints.Min.X < minW {
		gtxBtn.Constraints.Min.X = minW
	}

	// An outline button has no fill to darken, so being held gives it
	// one, and the border takes the accent colour (IAMT-364). Hover
	// alone moves only the border, which keeps the two states apart:
	// "the pointer is here" and "you are pressing this".
	return material.Clickable(gtxBtn, btn, func(gtx layout.Context) layout.Dimensions {
		// The fill has to be painted BEHIND the border and the word, and
		// its size is only known once they have been laid out. So: record
		// them, paint under the recorded size, replay. Filling from the
		// incoming constraints instead would colour the minimum width,
		// not the button.
		macro := op.Record(gtx.Ops)
		dims := layoutSecondaryFace(gtx, th, btn, txt, ButtonPadHorizontal, ButtonPadVertical)
		face := macro.Stop()
		if btn.Pressed() {
			paint.FillShape(gtx.Ops, th.Color(SunkenKey),
				clip.Rect(image.Rectangle{Max: dims.Size}).Op())
		}
		face.Add(gtx.Ops)
		return dims
	})
}

// CompactButton is SecondaryButton at a list row's proportions (min
// width 72 dp, padding 10/5): the same border, colours, radius and text
// size, tighter box. See the compact tokens for why the row gets its own
// size and why nothing else about the button changes with it.
func CompactButton(gtx layout.Context, th *Theme, btn *widget.Clickable, txt string) layout.Dimensions {
	minW := gtx.Dp(unit.Dp(ButtonMinWidthCompact))
	gtxBtn := gtx
	if gtxBtn.Constraints.Min.X < minW {
		gtxBtn.Constraints.Min.X = minW
	}

	return material.Clickable(gtxBtn, btn, func(gtx layout.Context) layout.Dimensions {
		macro := op.Record(gtx.Ops)
		dims := layoutSecondaryFace(gtx, th, btn, txt,
			ButtonPadHorizontalCompact, ButtonPadVerticalCompact)
		face := macro.Stop()
		if btn.Pressed() {
			paint.FillShape(gtx.Ops, th.Color(SunkenKey),
				clip.Rect(image.Rectangle{Max: dims.Size}).Op())
		}
		face.Add(gtx.Ops)
		return dims
	})
}

// layoutSecondaryFace is the border and the word of a secondary button,
// without the fill that only a pressed one has. padH and padV are the
// only thing a compact row button changes about it.
func layoutSecondaryFace(gtx layout.Context, th *Theme, btn *widget.Clickable, txt string, padH, padV float32) layout.Dimensions {
	borderKey := LineKey
	if btn.Hovered() || btn.Pressed() {
		borderKey = SpotKey
	}
	return func() layout.Dimensions {
		return widget.Border{
			Color:        th.Color(borderKey),
			Width:        unit.Dp(1),
			CornerRadius: unit.Dp(Radius),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{
				Top:    unit.Dp(padV),
				Bottom: unit.Dp(padV),
				Left:   unit.Dp(padH),
				Right:  unit.Dp(padH),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Label(th.Material, BodySp, txt)
				lbl.Color = th.Color(InkKey)
				lbl.Alignment = text.Middle
				return lbl.Layout(gtx)
			})
		})
	}()
}

// AlertButton is a secondary button that carries a colour: the border
// and the word take the given key instead of the quiet line and ink.
//
// It exists for two jobs, and both are the same job: a control that says
// what it will do by its colour before it is read. The masthead's "held"
// notice takes Warn -- something is waiting -- and the two controls that
// settle one take Good and Bad, so "allow" and "refuse" are never
// confused by somebody moving fast, which is exactly how they will be
// used (the offer lapses in five minutes).
//
// The shape is deliberately the SAME as SecondaryButton: colour is the
// only difference, so these sit in a row with ordinary buttons without
// looking like a different species of control.
func AlertButton(gtx layout.Context, th *Theme, btn *widget.Clickable, txt string) layout.Dimensions {
	return alertButtonKeyed(gtx, th, btn, txt, WarnKey)
}

// GoodButton and BadButton are AlertButton in the two colours that answer
// a held command.
func GoodButton(gtx layout.Context, th *Theme, btn *widget.Clickable, txt string) layout.Dimensions {
	return alertButtonKeyed(gtx, th, btn, txt, GoodKey)
}

func BadButton(gtx layout.Context, th *Theme, btn *widget.Clickable, txt string) layout.Dimensions {
	return alertButtonKeyed(gtx, th, btn, txt, BadKey)
}

func alertButtonKeyed(gtx layout.Context, th *Theme, btn *widget.Clickable, txt string, key ColorKey) layout.Dimensions {
	minW := gtx.Dp(unit.Dp(ButtonMinWidthSecondary))
	gtxBtn := gtx
	if gtxBtn.Constraints.Min.X < minW {
		gtxBtn.Constraints.Min.X = minW
	}
	return material.Clickable(gtxBtn, btn, func(gtx layout.Context) layout.Dimensions {
		macro := op.Record(gtx.Ops)
		dims := widget.Border{
			Color:        th.Color(key),
			Width:        unit.Dp(1),
			CornerRadius: unit.Dp(Radius),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{
				Top:    unit.Dp(ButtonPadVertical),
				Bottom: unit.Dp(ButtonPadVertical),
				Left:   unit.Dp(ButtonPadHorizontal),
				Right:  unit.Dp(ButtonPadHorizontal),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				lbl := material.Label(th.Material, BodySp, txt)
				lbl.Color = th.Color(key)
				lbl.Alignment = text.Middle
				return lbl.Layout(gtx)
			})
		})
		face := macro.Stop()
		if btn.Pressed() || btn.Hovered() {
			paint.FillShape(gtx.Ops, th.Color(SunkenKey),
				clip.Rect(image.Rectangle{Max: dims.Size}).Op())
		}
		face.Add(gtx.Ops)
		return dims
	})
}

// CopyableBox renders a copyable monospaced text box with a hairline above and below (Design.cs lines 350-375).
//
// "Copyable" was a promise this box did not keep until 19.09.2026. It
// drew a plain label, and a plain gio label carries no selection state
// at all -- nothing can be dragged over, so there is nothing for Ctrl+C
// to take. The maintainer had a freshly minted enrol code on the screen and
// no way to get it off the screen: the one string that whole step
// exists to hand over.
//
// A selection state makes the text draggable and copyable the ordinary
// way. It does NOT replace a Copy button -- the two answer different
// people. Selecting is what someone reaches for who wants part of the
// line, or who trusts their own hands; the button is what someone
// reaches for who does not want to aim at a 90-character string. Every
// place that shows a string to take away now offers both.
//
// sel may be nil where the text is decoration rather than something to
// carry off; then the box behaves exactly as it did before.
func CopyableBox(gtx layout.Context, th *Theme, sel *widget.Selectable, txt string) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return Rule(gtx, th)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{
				Top:    GapDp,
				Bottom: GapDp,
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				if sel == nil {
					return Fixed(gtx, th, txt)
				}
				lbl := material.Label(th.Material, SmallSp, txt)
				lbl.Color = th.Color(InkKey)
				lbl.Font = th.MonoFont
				lbl.SelectionColor = th.Color(SpotDimKey)
				lbl.State = sel
				return lbl.Layout(gtx)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return Rule(gtx, th)
		}),
	)
}

// Page renders the standard Telescope page layout: Edge margin (40 dp), Wide top/bottom (30 dp),
// and Wide spacing between sections (Design.cs lines 538-551).
// list keeps the page's scroll position and its scrollbar's state; the
// caller owns one per page and per window.
func Page(gtx layout.Context, th *Theme, list *widget.List, sections ...layout.Widget) layout.Dimensions {
	return PinnedPage(gtx, th, list, 0, sections...)
}

// PageScrollbar is how a scrolling page says so (IAMT-334).
//
// Until this function the pages scrolled but drew nothing: a window too
// short for its content simply ended, and everything below the last
// visible card was undiscoverable — there was no mark on the screen from
// which a reader could learn that more existed. The Admin tab is where it
// cost us: its four 1.2 cards sit below "Grant access", and the maintainer,
// looking at a full-looking page, reasonably concluded the build was
// wrong. A control nobody can find is not a control.
//
// The bar is deliberately NOT an overlay. It takes its own strip on the
// right (material.Occupy), so it can never sit on top of a text box or a
// button at the page's right edge — on these pages the fields run the
// full width, and a floating bar would cover their ends.
//
// It draws itself only when the page actually overflows: gio's
// ScrollbarStyle returns empty dimensions for a range that covers the
// whole content, so a page that fits looks exactly as it did before. That
// is the "if it is needed" half of the rule, and it is the upstream
// implementation's own decision, not a condition re-derived here.
//
// The track is painted, not just the thumb. An empty groove is the part a
// reader sees BEFORE touching anything: the thumb alone says "you are
// here", while the groove says "there is somewhere else to be". That is
// precisely the information the Admin tab failed to give.
func PageScrollbar(th *Theme, list *widget.List) material.ListStyle {
	st := material.List(th.Material, list)
	st.AnchorStrategy = material.Occupy
	st.Track.Color = th.Color(LineKey)
	st.Indicator.Color = th.Color(MutedKey)
	st.Indicator.HoverColor = th.Color(InkKey)
	return st
}

// PinnedPage is Page whose first `pinned` sections stay fixed at the top
// while the rest scrolls (a page taller than the window scrolls instead of
// being cut off at the bottom edge). The client screen pins its poster and
// the recording notice, which must be on screen at every size and scroll
// position.
func PinnedPage(gtx layout.Context, th *Theme, list *widget.List, pinned int, sections ...layout.Widget) layout.Dimensions {
	if list == nil {
		list = &widget.List{List: layout.List{Axis: layout.Vertical}}
	}
	if list.Axis != layout.Vertical {
		// A page scrolls down, never sideways; a caller that handed us a
		// horizontal list would get a scrollbar along the bottom edge and
		// a page that reads nothing like the other four tabs.
		list.Axis = layout.Vertical
	}
	if pinned > len(sections) {
		pinned = len(sections)
	}
	withGap := func(w layout.Widget, gap unit.Dp) layout.Widget {
		return func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(w),
				layout.Rigid(layout.Spacer{Height: gap}.Layout))
		}
	}
	rest := sections[pinned:]
	// A bottom inset, symmetrical with the top one: the scrolling area --
	// and with it the scrollbar's groove -- stops short of the window's
	// bottom edge instead of running into it. It used to run into it,
	// with the bottom margin carried as the list's own last item, and the
	// maintainer's reading of that on 21.09 was that the page looked unfinished:
	// a groove that ends exactly on the frame reads as cut off rather than
	// as ended. The margin belongs to the page, not to its last card.
	return layout.Inset{
		Top:    WideDp,
		Bottom: WideDp,
		Left:   EdgeDp,
		Right:  EdgeDp,
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		children := make([]layout.FlexChild, 0, pinned+1)
		for _, s := range sections[:pinned] {
			children = append(children, layout.Rigid(withGap(s, WideDp)))
		}
		children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			// PageScrollbar, not list.Layout: the page draws the groove and
			// thumb that say it continues below the fold (IAMT-334).
			return PageScrollbar(th, list).Layout(gtx, len(rest), func(gtx layout.Context, i int) layout.Dimensions {
				// The section keeps the unbounded height the list offers
				// it (IAMT-387). Capping it at the visible height instead
				// made a section taller than the window report the
				// window's height: the list then had nothing left to
				// scroll to, and everything past the bottom edge -- on the
				// Join card, the button that does the joining -- was
				// unreachable at any scroll position. Nothing here grows
				// to fill the height it is offered; the one inner
				// scrolling panel (the Live transcript excerpt) bounds
				// itself explicitly.
				gap := WideDp
				if i == len(rest)-1 {
					// The page's own Bottom inset is the bottom margin
					// now, so the last card adds none of its own.
					gap = 0
				}
				// A gutter between the content and the scrollbar.
				//
				// material.Occupy gives the bar its own strip rather than
				// floating it over the page, which is what keeps it off
				// the right-hand end of every text box -- but it puts the
				// strip flush against the content, and a paragraph whose
				// last letter touches the groove reads as clipped. The
				// maintainer saw it the moment the guide grew a picture wide
				// enough to reach that edge.
				return layout.Inset{Right: GapDp}.Layout(gtx, withGap(rest[i], gap))
			})
		}))
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	})
}

// SquareButton is a compact button with no minimum width: a single short
// glyph in a box roughly as tall as it is wide.
//
// It exists because the CLIENT tab's machine row ran out of room
// (21.09.2026). Four word-buttons already sat there, and the maintainer wanted
// a fifth for settings -- a small square button at the end of the row.
// A fifth word would have pushed the row past the window on a narrow
// screen; a square one costs about a third of the width.
//
// The label is deliberately NOT a gear character. The window's font is
// whatever the system supplies, and a glyph outside the common ranges
// renders as an empty box on the machine that lacks it -- a control
// nobody can identify is worse than a plain one. Three dots are ordinary
// punctuation, present in every font, and already read as "more here".
func SquareButton(gtx layout.Context, th *Theme, btn *widget.Clickable, txt string) layout.Dimensions {
	return material.Clickable(gtx, btn, func(gtx layout.Context) layout.Dimensions {
		macro := op.Record(gtx.Ops)
		dims := layoutSecondaryFace(gtx, th, btn, txt,
			ButtonPadVerticalCompact, ButtonPadVerticalCompact)
		face := macro.Stop()
		if btn.Pressed() {
			paint.FillShape(gtx.Ops, th.Color(SunkenKey),
				clip.Rect(image.Rectangle{Max: dims.Size}).Op())
		}
		face.Add(gtx.Ops)
		return dims
	})
}
