//go:build windows || linux || darwin

package design

import (
	"image/color"

	giofont "gioui.org/font"
	"gioui.org/text"
	"gioui.org/widget/material"
)

// Theme combines the Telescope palette, typography fonts, and Gio material theme.
type Theme struct {
	Palette       Palette
	Shaper        *text.Shaper
	Material      *material.Theme
	SerifFont     giofont.Font
	SerifBoldFont giofont.Font
	MonoFont      giofont.Font
	BodyFont      giofont.Font
}

// NewTheme constructs a Telescope Theme with the specified palette and font shaper.
func NewTheme(pal Palette, shaper *text.Shaper) *Theme {
	mTh := material.NewTheme()
	if shaper != nil {
		mTh.Shaper = shaper
	}

	// Configure Material theme colors to match Telescope palette
	mTh.Palette.Bg = pal.Page
	mTh.Palette.Fg = pal.Ink
	mTh.Palette.ContrastBg = pal.Spot
	mTh.Palette.ContrastFg = pal.OnSpot

	return &Theme{
		Palette:  pal,
		Shaper:   shaper,
		Material: mTh,
		SerifFont: giofont.Font{
			Typeface: "Serif",
		},
		SerifBoldFont: giofont.Font{
			Typeface: "Serif",
			Weight:   giofont.Bold,
		},
		MonoFont: giofont.Font{
			Typeface: "Mono",
		},
		BodyFont: giofont.Font{
			Typeface: "Go",
		},
	}
}

// Color retrieves a color from the theme palette by key.
func (t *Theme) Color(key ColorKey) color.NRGBA {
	return t.Palette.Color(key)
}

// IsDark reports whether the theme variant is dark.
func (t *Theme) IsDark() bool {
	return t.Palette.IsDark
}
