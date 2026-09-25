//go:build windows

package winfonts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	giofont "gioui.org/font"
	gio_opentype "gioui.org/font/opentype"
	x_opentype "golang.org/x/image/font/opentype"
	"golang.org/x/image/font/sfnt"
)

// FaceMetadata holds inspected OpenType metadata for a single face.
type FaceMetadata struct {
	Index                int    // Index within collection (0 for single font)
	Family               string // NameIDFamily (1)
	Subfamily            string // NameIDSubfamily (2)
	FullName             string // NameIDFull (4)
	PostScriptName       string // NameIDPostScript (6)
	TypographicFamily    string // NameIDTypographicFamily (16)
	TypographicSubfamily string // NameIDTypographicSubfamily (17)
}

// FileFontInspection contains the result of parsing a font file with x/image/font/opentype.
type FileFontInspection struct {
	FilePath     string
	IsCollection bool
	NumFonts     int
	Faces        []FaceMetadata
}

// InspectFontFile parses a font file using golang.org/x/image/font/opentype & sfnt.
func InspectFontFile(filePath string) (*FileFontInspection, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read font file %s: %w", filePath, err)
	}
	return InspectFontBytes(data, filePath)
}

// InspectFontBytes inspects in-memory font bytes using x/image/font/opentype.
func InspectFontBytes(data []byte, filePath string) (*FileFontInspection, error) {
	res := &FileFontInspection{
		FilePath: filePath,
	}

	col, err := x_opentype.ParseCollection(data)
	if err == nil && col != nil && col.NumFonts() > 0 {
		res.NumFonts = col.NumFonts()
		res.IsCollection = (col.NumFonts() > 1) || strings.EqualFold(filepath.Ext(filePath), ".ttc")
		var buf sfnt.Buffer
		for i := 0; i < col.NumFonts(); i++ {
			f, err := col.Font(i)
			if err != nil {
				continue
			}
			fam, _ := f.Name(&buf, sfnt.NameIDFamily)
			sub, _ := f.Name(&buf, sfnt.NameIDSubfamily)
			full, _ := f.Name(&buf, sfnt.NameIDFull)
			post, _ := f.Name(&buf, sfnt.NameIDPostScript)
			typoFam, _ := f.Name(&buf, sfnt.NameIDTypographicFamily)
			typoSub, _ := f.Name(&buf, sfnt.NameIDTypographicSubfamily)

			res.Faces = append(res.Faces, FaceMetadata{
				Index:                i,
				Family:               fam,
				Subfamily:            sub,
				FullName:             full,
				PostScriptName:       post,
				TypographicFamily:    typoFam,
				TypographicSubfamily: typoSub,
			})
		}
		return res, nil
	}

	// Fallback to single font parse
	f, err := x_opentype.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse font: %w", err)
	}

	var buf sfnt.Buffer
	fam, _ := f.Name(&buf, sfnt.NameIDFamily)
	sub, _ := f.Name(&buf, sfnt.NameIDSubfamily)
	full, _ := f.Name(&buf, sfnt.NameIDFull)
	post, _ := f.Name(&buf, sfnt.NameIDPostScript)
	typoFam, _ := f.Name(&buf, sfnt.NameIDTypographicFamily)
	typoSub, _ := f.Name(&buf, sfnt.NameIDTypographicSubfamily)

	res.NumFonts = 1
	res.IsCollection = false
	res.Faces = append(res.Faces, FaceMetadata{
		Index:                0,
		Family:               fam,
		Subfamily:            sub,
		FullName:             full,
		PostScriptName:       post,
		TypographicFamily:    typoFam,
		TypographicSubfamily: typoSub,
	})

	return res, nil
}

// FindFaceIndex searches inspection metadata for a matching font name.
// Returns face index and matched metadata.
func (insp *FileFontInspection) FindFaceIndex(targetName string) (int, *FaceMetadata, bool) {
	cleanTarget := strings.TrimSpace(strings.ToLower(targetName))

	// 1. Exact match against Family, FullName, TypographicFamily
	for i := range insp.Faces {
		f := &insp.Faces[i]
		if strings.ToLower(f.Family) == cleanTarget ||
			strings.ToLower(f.FullName) == cleanTarget ||
			strings.ToLower(f.TypographicFamily) == cleanTarget {
			return f.Index, f, true
		}
	}

	// 2. Prefix / Contains match (e.g. "Cambria" in "Cambria & Cambria Math")
	for i := range insp.Faces {
		f := &insp.Faces[i]
		fLower := strings.ToLower(f.Family)
		if strings.HasPrefix(fLower, cleanTarget) || strings.Contains(fLower, cleanTarget) {
			return f.Index, f, true
		}
	}

	if len(insp.Faces) > 0 {
		// Default to index 0 if not explicitly matched
		return 0, &insp.Faces[0], false
	}
	return -1, nil, false
}

// LoadGioFontFaces loads font faces from file into Gio FontFace structures.
// It parses the file via gioui.org/font/opentype and aliases the typeface to aliasNames.
func LoadGioFontFaces(filePath string, faceIndex int, aliasNames ...string) ([]giofont.FontFace, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed reading font file %s: %w", filePath, err)
	}

	faces, err := gio_opentype.ParseCollection(data)
	if err != nil {
		return nil, fmt.Errorf("failed parsing font collection in %s: %w", filePath, err)
	}

	if len(faces) == 0 {
		return nil, fmt.Errorf("no faces found in %s", filePath)
	}

	if faceIndex < 0 || faceIndex >= len(faces) {
		faceIndex = 0
	}

	selected := faces[faceIndex]
	var result []giofont.FontFace

	// Keep original
	result = append(result, selected)

	// Add alias typefaces
	for _, alias := range aliasNames {
		alias = strings.TrimSpace(alias)
		if alias == "" || alias == string(selected.Font.Typeface) {
			continue
		}
		aliased := selected
		aliased.Font.Typeface = giofont.Typeface(alias)
		result = append(result, aliased)
	}

	return result, nil
}
