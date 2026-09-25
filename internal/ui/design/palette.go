//go:build windows || linux || darwin

package design

import (
	"image/color"
)

// ColorKey represents a theme color key name, exactly matching umtunnel's Design.cs.
type ColorKey string

const (
	// Theme control keys (Design.cs lines 99-101)
	SunkenKey   ColorKey = "SystemControlBackgroundListLowBrush"
	AccentKey   ColorKey = "SystemControlHighlightAccentBrush"
	OnAccentKey ColorKey = "SystemControlForegroundChromeWhiteBrush"

	// Telescope palette keys (Design.cs lines 107-120)
	InkKey     ColorKey = "UmInkBrush"
	MutedKey   ColorKey = "UmMutedBrush"
	FaintKey   ColorKey = "UmFaintBrush"
	PageKey    ColorKey = "UmPageBrush"
	SurfaceKey ColorKey = "UmSurfaceBrush"
	LineKey    ColorKey = "UmLineBrush"
	ClearKey   ColorKey = "UmClearBrush"
	SpotKey    ColorKey = "UmSpotBrush"
	OnSpotKey  ColorKey = "UmOnSpotBrush"
	SpotDimKey ColorKey = "UmSpotDimBrush"
	GoodKey    ColorKey = "UmGoodBrush"
	WarnKey    ColorKey = "UmWarnBrush"
	BadKey     ColorKey = "UmBadBrush"
	BusyKey    ColorKey = "UmBusyBrush"
)

// paletteKeys is the full list of all 17 theme keys from Design.cs lines
// 122-127. It is deliberately unexported: an exported slice is a package
// variable any importer can rewrite, and this list decides what the
// palette selftest demands.
var paletteKeys = [...]string{
	string(SunkenKey), string(AccentKey), string(OnAccentKey),
	string(InkKey), string(MutedKey), string(FaintKey),
	string(PageKey), string(SurfaceKey), string(LineKey),
	string(ClearKey), string(SpotKey), string(OnSpotKey), string(SpotDimKey),
	string(GoodKey), string(WarnKey), string(BadKey), string(BusyKey),
}

// Palette holds the concrete RGBA values for one theme variant.
type Palette struct {
	IsDark bool

	Ink     color.NRGBA
	Muted   color.NRGBA
	Faint   color.NRGBA
	Page    color.NRGBA
	Surface color.NRGBA
	Line    color.NRGBA
	Clear   color.NRGBA
	Spot    color.NRGBA
	OnSpot  color.NRGBA
	SpotDim color.NRGBA
	Good    color.NRGBA
	Warn    color.NRGBA
	Bad     color.NRGBA
	Busy    color.NRGBA

	Sunken   color.NRGBA
	Accent   color.NRGBA
	OnAccent color.NRGBA
}

func rgb(val uint32) color.NRGBA {
	return color.NRGBA{
		R: byte(val >> 16),
		G: byte(val >> 8),
		B: byte(val),
		A: 0xFF,
	}
}

// LightPalette returns the Telescope light palette, values value-for-value from Design.cs lines 143-159.
func LightPalette() Palette {
	return Palette{
		IsDark:   false,
		Ink:      rgb(0x111111),
		Muted:    rgb(0x6E6E6E),
		Faint:    rgb(0x9A968D),
		Page:     rgb(0xFAF8F4), // off-white paper, not white
		Surface:  rgb(0xF0EDE5), // the few places something is lifted
		Line:     rgb(0xD5D2C9),
		Clear:    color.NRGBA{0, 0, 0, 0},
		Spot:     rgb(0xE8651A),
		OnSpot:   rgb(0xFFFFFF),
		SpotDim:  rgb(0xC8530F), // the same spot, pressed
		Good:     rgb(0x1F6B3A),
		Warn:     rgb(0x8A5200),
		Bad:      rgb(0xB3261E),
		Busy:     rgb(0x1A5FB4),
		Sunken:   rgb(0xF0EDE5),
		Accent:   rgb(0xE8651A),
		OnAccent: rgb(0xFFFFFF),
	}
}

// DarkPalette returns the Telescope dark palette, values value-for-value from Design.cs lines 160-176.
func DarkPalette() Palette {
	return Palette{
		IsDark:   true,
		Ink:      rgb(0xF0EDE3),
		Muted:    rgb(0x8C8C8C),
		Faint:    rgb(0x6A6A6A),
		Page:     rgb(0x111111),
		Surface:  rgb(0x1C1C1C),
		Line:     rgb(0x2C2C2C),
		Clear:    color.NRGBA{0, 0, 0, 0},
		Spot:     rgb(0xF48430),
		OnSpot:   rgb(0x17130A),
		SpotDim:  rgb(0xD86F20),
		Good:     rgb(0x5CD18E),
		Warn:     rgb(0xF0B43C),
		Bad:      rgb(0xFF7A6B),
		Busy:     rgb(0x79B8FF),
		Sunken:   rgb(0x1C1C1C),
		Accent:   rgb(0xF48430),
		OnAccent: rgb(0x17130A),
	}
}

// Color retrieves a color by its ColorKey.
func (p Palette) Color(key ColorKey) color.NRGBA {
	c, _ := p.ColorByName(string(key))
	return c
}

// ColorByName retrieves a color by its string key name.
func (p Palette) ColorByName(name string) (color.NRGBA, bool) {
	switch ColorKey(name) {
	case InkKey:
		return p.Ink, true
	case MutedKey:
		return p.Muted, true
	case FaintKey:
		return p.Faint, true
	case PageKey:
		return p.Page, true
	case SurfaceKey:
		return p.Surface, true
	case LineKey:
		return p.Line, true
	case ClearKey:
		return p.Clear, true
	case SpotKey:
		return p.Spot, true
	case OnSpotKey:
		return p.OnSpot, true
	case SpotDimKey:
		return p.SpotDim, true
	case GoodKey:
		return p.Good, true
	case WarnKey:
		return p.Warn, true
	case BadKey:
		return p.Bad, true
	case BusyKey:
		return p.Busy, true
	case SunkenKey:
		return p.Sunken, true
	case AccentKey:
		return p.Accent, true
	case OnAccentKey:
		return p.OnAccent, true
	default:
		return color.NRGBA{}, false
	}
}

// MissingKeys verifies every key in Keys is present in both Light and Dark palettes.
// Equivalent to Design.MissingKeys() in Design.cs lines 755-766.
func MissingKeys() []string {
	var missing []string
	variants := []struct {
		name string
		pal  Palette
	}{
		{"Light", LightPalette()},
		{"Dark", DarkPalette()},
	}

	for _, v := range variants {
		for _, key := range paletteKeys {
			if _, ok := v.pal.ColorByName(key); !ok {
				missing = append(missing, v.name+"/"+key)
			}
		}
	}
	return missing
}
