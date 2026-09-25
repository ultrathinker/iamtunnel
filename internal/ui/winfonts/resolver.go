//go:build windows

package winfonts

import (
	"fmt"
	"os"
	"strings"

	giofont "gioui.org/font"
	"gioui.org/font/gofont"
)

// FoundFontReport details a discovered font face for reporting and table printing.
type FoundFontReport struct {
	Name         string // Target name, e.g. "Cambria"
	MatchedName  string // Registry clean name, e.g. "Cambria & Cambria Math"
	FilePath     string // Absolute path to file
	IsCollection bool   // True if .ttc / multi-font collection
	FaceIndex    int    // Index inside collection
	Loaded       bool   // True if parsed and loaded successfully
	Err          error  // Any error during inspection or loading
}

// ResolvedFont represents a font face chosen by the resolver.
type ResolvedFont struct {
	RequestedName string             // Name from preference list, e.g. "Sitka Text"
	Family        string             // Actual family name, e.g. "Sitka Text" or "Go"
	FilePath      string             // File path or "(embedded gofont)"
	IsCollection  bool               // True if collection
	FaceIndex     int                // Collection index
	IsFallback    bool               // True if fell back to gofont
	Faces         []giofont.FontFace // Gio font faces ready for Shaper
}

// Resolver handles font discovery, preference resolution, and fallback.
type Resolver struct {
	RegistryReader RegistryReader
	FontsDir       string
}

// NewResolver creates a new Resolver using the system registry.
func NewResolver() *Resolver {
	reg := NewSystemRegistryReader()
	return &Resolver{
		RegistryReader: reg,
		FontsDir:       reg.FontsDir,
	}
}

// NewMockResolver creates a resolver with mock entries for testing.
func NewMockResolver(entries map[string]string, fontsDir string) *Resolver {
	return &Resolver{
		RegistryReader: &MockRegistryReader{
			Entries:  entries,
			FontsDir: fontsDir,
		},
		FontsDir: fontsDir,
	}
}

// MatchRegistryEntry finds a registry entry matching a target font name.
func MatchRegistryEntry(entries []RegistryFontEntry, target string) (*RegistryFontEntry, bool) {
	cleanTarget := strings.TrimSpace(strings.ToLower(target))

	// 1. Exact match against CleanName
	for i := range entries {
		if strings.ToLower(entries[i].CleanName) == cleanTarget {
			return &entries[i], true
		}
	}

	// 2. StartsWith match (e.g. "Sitka Text" in "Sitka Text (TrueType)", "Consolas" in "Consolas (TrueType)")
	for i := range entries {
		name := strings.ToLower(entries[i].CleanName)
		if strings.HasPrefix(name, cleanTarget) {
			// Ensure boundary word (e.g. "Sitka Text" vs "Sitka Text Italic" - prefer regular)
			rest := strings.TrimSpace(strings.TrimPrefix(name, cleanTarget))
			if rest == "" || rest == "regular" {
				return &entries[i], true
			}
		}
	}

	// 3. Multi-font entry check (e.g. "Cambria & Cambria Math")
	for i := range entries {
		name := strings.ToLower(entries[i].CleanName)
		parts := strings.Split(name, "&")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == cleanTarget {
				return &entries[i], true
			}
		}
	}

	// 4. Fallback contains match
	for i := range entries {
		name := strings.ToLower(entries[i].CleanName)
		if strings.Contains(name, cleanTarget) && !strings.Contains(name, "bold") && !strings.Contains(name, "italic") {
			return &entries[i], true
		}
	}

	return nil, false
}

// FindAllFonts searches the registry for each name in the targets list.
func (r *Resolver) FindAllFonts(targets []string) ([]FoundFontReport, error) {
	entries, err := r.RegistryReader.ReadFontValues()
	if err != nil {
		return nil, fmt.Errorf("failed reading registry: %w", err)
	}

	var reports []FoundFontReport
	for _, target := range targets {
		matched, found := MatchRegistryEntry(entries, target)
		if !found {
			reports = append(reports, FoundFontReport{
				Name:   target,
				Loaded: false,
				Err:    fmt.Errorf("not registered in Windows registry"),
			})
			continue
		}

		// Verify file exists
		if _, err := os.Stat(matched.FilePath); err != nil {
			reports = append(reports, FoundFontReport{
				Name:        target,
				MatchedName: matched.CleanName,
				FilePath:    matched.FilePath,
				Loaded:      false,
				Err:         fmt.Errorf("file not found on disk: %w", err),
			})
			continue
		}

		// Inspect with x/image/font/opentype
		insp, err := InspectFontFile(matched.FilePath)
		if err != nil {
			reports = append(reports, FoundFontReport{
				Name:        target,
				MatchedName: matched.CleanName,
				FilePath:    matched.FilePath,
				Loaded:      false,
				Err:         fmt.Errorf("inspection failed: %w", err),
			})
			continue
		}

		idx, _, _ := insp.FindFaceIndex(target)
		reports = append(reports, FoundFontReport{
			Name:         target,
			MatchedName:  matched.CleanName,
			FilePath:     matched.FilePath,
			IsCollection: insp.IsCollection,
			FaceIndex:    idx,
			Loaded:       true,
		})
	}

	return reports, nil
}

// ResolvePreference takes a list of candidate fonts in preference order,
// picks the first available one, loads it into Gio, or falls back to gofont.
func (r *Resolver) ResolvePreference(preferenceList []string, roleName string) (ResolvedFont, error) {
	entries, err := r.RegistryReader.ReadFontValues()
	if err != nil {
		// Log error and fallback to gofont
		return r.fallbackToGoFont(roleName, fmt.Errorf("cannot read registry: %w", err)), nil
	}

	for _, candidate := range preferenceList {
		matched, found := MatchRegistryEntry(entries, candidate)
		if !found {
			continue
		}

		if _, err := os.Stat(matched.FilePath); err != nil {
			continue
		}

		insp, err := InspectFontFile(matched.FilePath)
		if err != nil {
			continue
		}

		faceIdx, _, _ := insp.FindFaceIndex(candidate)
		gioFaces, err := LoadGioFontFaces(matched.FilePath, faceIdx, candidate, roleName)
		if err != nil {
			continue
		}

		return ResolvedFont{
			RequestedName: candidate,
			Family:        candidate,
			FilePath:      matched.FilePath,
			IsCollection:  insp.IsCollection,
			FaceIndex:     faceIdx,
			IsFallback:    false,
			Faces:         gioFaces,
		}, nil
	}

	// Fallback to gofont
	return r.fallbackToGoFont(roleName, nil), nil
}

func (r *Resolver) fallbackToGoFont(roleName string, cause error) ResolvedFont {
	baseFaces := gofont.Collection()
	var aliased []giofont.FontFace
	for _, f := range baseFaces {
		aliased = append(aliased, f)
		if roleName != "" {
			fRole := f
			fRole.Font.Typeface = giofont.Typeface(roleName)
			aliased = append(aliased, fRole)
		}
	}

	return ResolvedFont{
		RequestedName: "gofont (fallback)",
		Family:        "Go",
		FilePath:      "(embedded gofont)",
		IsCollection:  false,
		FaceIndex:     0,
		IsFallback:    true,
		Faces:         aliased,
	}
}
