//go:build windows

package ui

import (
	giofont "gioui.org/font"

	"github.com/ultrathinker/iamtunnel/internal/ui/winfonts"
)

// platformFonts resolves the faces the frame's shaper draws with (SPEC
// §7.1 preference lists). This is the Windows half of the seam: the
// resolver walks the font registry, and a missing font is a substitution,
// never a refusal — it falls back to the embedded gofont on its own.
// resolver, when non-nil, is a *winfonts.Resolver (tests inject a mock
// through FrameConfig.resolver); nil or anything else means the system
// registry resolver.
func platformFonts(resolver any) []giofont.FontFace {
	r, ok := resolver.(*winfonts.Resolver)
	if !ok || r == nil {
		r = winfonts.NewResolver()
	}

	prefSerif := []string{"Sitka Display", "Sitka Text", "Cambria", "Georgia"}
	resSerif, err := r.ResolvePreference(prefSerif, "Serif")
	if err != nil {
		resSerif, _ = r.ResolvePreference(nil, "Serif")
	}

	prefMono := []string{"Cascadia Mono", "Consolas"}
	resMono, err := r.ResolvePreference(prefMono, "Mono")
	if err != nil {
		resMono, _ = r.ResolvePreference(nil, "Mono")
	}

	var allFaces []giofont.FontFace
	allFaces = append(allFaces, resSerif.Faces...)
	allFaces = append(allFaces, resMono.Faces...)
	return allFaces
}
