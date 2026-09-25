//go:build linux

package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	giofont "gioui.org/font"
	"gioui.org/font/gofont"
	gio_opentype "gioui.org/font/opentype"
)

// platformFonts resolves the faces the frame's shaper draws with (SPEC
// §7.1 preference lists, the Linux analog): font files are looked up
// where fontconfig's default configuration looks — the distribution's
// /usr/share/fonts and the user's ~/.local/share/fonts, recursively —
// and the first family from each role's preference list that is on disk
// is parsed with the very loader the Windows resolver uses
// (gioui.org/font/opentype, already a dependency — no fontconfig
// binding, no cgo beyond what gio itself needs; IAMT-253). A missing
// font is a substitution, never a refusal: when nothing matches — a
// minimal system, an unusual desktop — the role falls back to the
// embedded gofont, which carries the Cyrillic the screen is written in,
// the same substitution the Windows resolver reaches. resolver, when
// non-nil on Windows, is a *winfonts.Resolver; on Linux it carries
// nothing and is ignored.
func platformFonts(resolver any) []giofont.FontFace {
	files := collectFontFiles(fontRoots())
	var allFaces []giofont.FontFace
	allFaces = append(allFaces, linuxRoleFaces(files, serifPreferences, "Serif")...)
	allFaces = append(allFaces, linuxRoleFaces(files, monoPreferences, "Mono")...)
	return allFaces
}

// fontRoots are the directories searched for system fonts, in order:
// the distribution's fonts first, the user's own installs second. These
// are the two roots fontconfig's stock configuration scans on every
// mainstream desktop; the (XDG) variants fontconfig additionally knows
// are distro corners, and the preference lists below name families a
// desktop almost certainly ships. A variable, not a function, so the
// tests can point the search at a scratch directory.
var fontRoots = func() []string {
	roots := []string{"/usr/share/fonts"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, filepath.Join(home, ".local", "share", "fonts"))
	}
	return roots
}

// serifPreferences and monoPreferences are SPEC §7.1's explicit
// preference order, translated to what a Linux desktop ships: Noto
// first (GNOME's default since it replaced DejaVu), then DejaVu, then
// Liberation (the metric-compatible stand-in Fedora/RHEL install for
// MS compatibility). Every family listed exists in packages named
// fonts-noto-core / fonts-dejavu / fonts-liberation — the trio a bare
// desktop install brings in one way or another.
var (
	serifPreferences = []string{"Noto Serif", "DejaVu Serif", "Liberation Serif"}
	monoPreferences  = []string{"Noto Sans Mono", "DejaVu Sans Mono", "Liberation Mono"}
)

// fontFileExts are the file types gio's opentype loader parses. Matched
// case-insensitively: stray .TTF copies exist in the wild.
var fontFileExts = map[string]bool{".ttf": true, ".otf": true, ".ttc": true}

// collectFontFiles walks every root recursively and returns the font
// files it finds — roots in list order, each walked in lexical order,
// so the result is deterministic for a given filesystem. A root that
// does not exist (no user font dir) and subdirectories that cannot be
// read are skipped, not fatal: a permissions corner must not cost the
// whole search.
func collectFontFiles(roots []string) []string {
	var files []string
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable or missing: skip this entry
			}
			if d.IsDir() {
				return nil
			}
			if fontFileExts[strings.ToLower(filepath.Ext(path))] {
				files = append(files, path)
			}
			return nil
		})
	}
	return files
}

// foldFontName folds a font file's base name (or a family name) the way
// the two are spelled differently: "DejaVu Sans Mono" is shipped as
// DejaVuSansMono.ttf. Case and every separator go away, letters and
// digits stay folded to lower case.
func foldFontName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// pickFontFile picks the file for one preference family: its folded
// name must be a prefix of the file's folded base name (so "Noto Sans
// Mono" matches NotoSansMono-Regular.ttf but not NotoSerif anything).
// The plain face wins over Bold/Italic/Oblique copies — the frame asks
// the shaper for weights itself, and the aliased role should not
// default to a slanted or heavy face. Within one family the first plain
// file in collectFontFiles' deterministic order is the answer; with no
// plain copy at all, the first match is.
func pickFontFile(files []string, family string) (string, bool) {
	want := foldFontName(family)
	any := ""
	for _, f := range files {
		stem := foldFontName(filepath.Base(f))
		if !strings.HasPrefix(stem, want) {
			continue
		}
		plain := !strings.Contains(stem, "bold") &&
			!strings.Contains(stem, "italic") &&
			!strings.Contains(stem, "oblique")
		if plain {
			return f, true
		}
		if any == "" {
			any = f
		}
	}
	return any, any != ""
}

// loadFontFaces parses one font file and hands the same face back twice:
// under its own name and aliased under roleName — exactly what
// winfonts.LoadGioFontFaces does for a Windows file, with the same gio
// loader. The first face of a collection (.ttc) is taken; face metadata
// beyond that is not inspected — the role alias is what §7.1 resolves
// through, and the shaper picks styles from the face itself.
func loadFontFaces(path, roleName string) ([]giofont.FontFace, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading font file %s: %w", path, err)
	}
	faces, err := gio_opentype.ParseCollection(data)
	if err != nil {
		return nil, fmt.Errorf("failed parsing font file %s: %w", path, err)
	}
	if len(faces) == 0 {
		return nil, fmt.Errorf("no faces found in %s", path)
	}
	selected := faces[0]
	out := []giofont.FontFace{selected}
	if roleName != "" && roleName != string(selected.Font.Typeface) {
		aliased := selected
		aliased.Font.Typeface = giofont.Typeface(roleName)
		out = append(out, aliased)
	}
	return out, nil
}

// linuxRoleFaces resolves one role: the first preference family present
// on disk, its file parsed and aliased under roleName. A file that is
// found but will not parse (a corrupt copy, a type gio cannot read) is
// not an answer — the next family tries, and only when nothing answers
// does the embedded gofont fill the role.
func linuxRoleFaces(files []string, preferences []string, roleName string) []giofont.FontFace {
	for _, family := range preferences {
		path, ok := pickFontFile(files, family)
		if !ok {
			continue
		}
		faces, err := loadFontFaces(path, roleName)
		if err != nil {
			continue
		}
		return faces
	}
	return goFontFaces(roleName)
}

// goFontFaces mirrors winfonts.Resolver.fallbackToGoFont: the embedded
// gofont collection, plus the same faces aliased under roleName.
func goFontFaces(roleName string) []giofont.FontFace {
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
	return aliased
}
