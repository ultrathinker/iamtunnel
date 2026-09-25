// Package macfonts resolves the font faces the macOS window draws with
// (IAMT-262, the macOS half of the font seam whose Windows half is
// internal/ui/winfonts and whose Linux half is internal/ui/fonts_linux.go).
//
// Where winfonts asks the Windows registry and reads the files it names,
// macOS has no such index: every font is a file, and the system, the
// local administrator and the user each own a directory of them. So the
// resolver here is a directory scan plus a name match, and the two things
// macOS-specific about it are data, not code:
//
//   - DefaultDirs is the macOS font search path (the system collection,
//     the Supplemental collection Apple moved the extra faces into, and
//     the machine-wide /Library/Fonts), plus the user's ~/Library/Fonts;
//   - PreferenceSerif / PreferenceMono name macOS families (SPEC §7.1);
//   - the separator: a path that is macOS data is built with path.Join and
//     keeps its forward slashes wherever this package is compiled, which
//     is the one place filepath.Join would be wrong (see UserFontDir).
//
// Everything else — walking the directories, reading each file's family
// names, choosing the face inside a .ttc collection, aliasing a face
// under a role name, and falling back to the embedded gofont — is plain
// portable Go, and this package is deliberately NOT build-tagged to
// darwin. A darwin tag would mean it is compiled only on a Mac, and the
// macOS window cannot be built here at all (gioui.org/app needs cgo and
// Cocoa), so the whole resolver would ship with no test ever running
// anywhere except a human's laptop. Untagged, the logic below is built,
// vetted and tested on every platform the gates cover, and only the
// three-line wiring that calls it (internal/ui/fonts_darwin.go) plus the
// one that builds it (cmd/iamtunnel/gui_darwin.go) are macOS-only.
//
// A missing font is a substitution, never a refusal — the same contract
// winfonts keeps: any error while reading a candidate file is that
// candidate's problem, not the window's.
package macfonts

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	giofont "gioui.org/font"
	"gioui.org/font/gofont"
	gio_opentype "gioui.org/font/opentype"
	x_opentype "golang.org/x/image/font/opentype"
	"golang.org/x/image/font/sfnt"
)

// DefaultDirs is where macOS keeps fonts, in the order the system itself
// prefers them: the fonts Apple ships and supports first, then the
// machine-wide collection an administrator installed.
//
// /System/Library/Fonts/Supplemental is a separate entry because macOS
// 10.15 moved the "extra" system faces (Times New Roman, Georgia, Courier
// New, …) there; both directories are scanned.
var DefaultDirs = []string{
	"/System/Library/Fonts",
	"/System/Library/Fonts/Supplemental",
	"/Library/Fonts",
}

// PreferenceSerif and PreferenceMono are SPEC §7.1's role preferences in
// macOS terms, best first: the system serif and the system monospace
// first (New York and SF Mono are what Apple's own UI uses), then the
// classics macOS has shipped for decades (the last three serifs are all
// in /System/Library/Fonts/Supplemental). A family that is absent from
// the machine is simply skipped; the gofont fallback is the last resort.
var (
	PreferenceSerif = []string{"New York", "Times New Roman", "Georgia", "Palatino", "Charter"}
	PreferenceMono  = []string{"SF Mono", "Menlo", "Monaco", "Courier New"}
)

// UserFontDir is the per-user font directory Font Book installs into.
//
// Built with path.Join, not path/filepath.Join, and that is the whole
// point of this comment: what this function returns is a macOS path — it
// is /Users/<name>/Library/Fonts on macOS and it is still that string when
// the package is compiled and tested on Windows, where filepath.Join would
// have produced \Users\<name>\Library\Fonts. This package is deliberately
// untagged (see the header), so its macOS directory list has to be data,
// not a host path. Everything in Index() below is the opposite case — it
// joins and lists directories the resolver was actually handed, which are
// host paths whenever a test points it at t.TempDir() — so filepath stays
// there.
func UserFontDir(home string) string {
	if home == "" {
		return ""
	}
	return path.Join(home, "Library", "Fonts")
}

// SearchDirs returns DefaultDirs plus the user's directory, skipping
// empty entries. It is a function of the home directory rather than of
// the current user so a caller (and a test) is explicit about whose home
// it means.
func SearchDirs(home string) []string {
	dirs := make([]string, 0, len(DefaultDirs)+1)
	dirs = append(dirs, DefaultDirs...)
	if d := UserFontDir(home); d != "" {
		dirs = append(dirs, d)
	}
	return dirs
}

// fontExtensions are the file types macOS ships fonts in: TrueType,
// TrueType collections and OpenType (both flavours).
var fontExtensions = map[string]bool{
	".ttf": true, ".ttc": true, ".otf": true, ".otc": true,
}

// FontFile is one font file found on disk: its path, how many faces it
// holds (a .ttc collection holds several), the family name of each face
// in file order, and which of those faces a family lookup should use.
type FontFile struct {
	Path         string
	IsCollection bool
	Families     []string // one per face, in file order
	FirstIndex   int      // the face this file was indexed under
}

// Resolver searches a fixed list of directories. The zero value is not
// usable; use NewResolver (the production search path) or a Resolver
// literal with your own Dirs (tests, and the resolver seam
// internal/ui.FrameConfig carries).
type Resolver struct {
	// Dirs is the search path, in preference order.
	Dirs []string

	// read is a seam for tests that want a file to fail to read without
	// arranging permissions on disk; nil means os.ReadFile.
	read func(string) ([]byte, error)
}

// NewResolver is the production resolver: the macOS search path for the
// given home directory ("" for a process with no home, which simply
// drops the per-user directory).
func NewResolver(home string) *Resolver {
	return &Resolver{Dirs: SearchDirs(home)}
}

func (r *Resolver) readFile(path string) ([]byte, error) {
	if r.read != nil {
		return r.read(path)
	}
	return os.ReadFile(path)
}

// Index walks the search directories and returns every font file, keyed
// by lower-cased family name. An earlier directory never loses a family
// to a later one (the system's own copy wins, exactly as Font Book
// resolves a duplicate), and an unreadable or malformed file is skipped:
// a bad file in ~/Library/Fonts must not cost the window its fonts.
func (r *Resolver) Index() map[string]FontFile {
	index := map[string]FontFile{}
	for _, dir := range r.Dirs {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // a missing or unreadable directory is not an error
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() || !fontExtensions[strings.ToLower(filepath.Ext(e.Name()))] {
				continue
			}
			names = append(names, e.Name())
		}
		sort.Strings(names) // deterministic when two files claim one family
		for _, name := range names {
			path := filepath.Join(dir, name)
			families, err := r.familiesOf(path)
			if err != nil || len(families) == 0 {
				continue
			}
			ff := FontFile{Path: path, IsCollection: len(families) > 1, Families: families}
			for i, fam := range families {
				key := strings.ToLower(strings.TrimSpace(fam))
				if key == "" {
					continue
				}
				if _, taken := index[key]; taken {
					continue
				}
				entry := ff
				entry.FirstIndex = i
				index[key] = entry
			}
		}
	}
	return index
}

// familiesOf reads one file and returns the family name of each face in
// it, in file order: a .ttc yields several, a plain .ttf one. The parse
// is the same one winfonts.InspectFontBytes does, for the same reason —
// x/image can name the faces, gioui's wrapper only wraps them.
func (r *Resolver) familiesOf(path string) ([]string, error) {
	data, err := r.readFile(path)
	if err != nil {
		return nil, err
	}
	if col, cerr := x_opentype.ParseCollection(data); cerr == nil && col != nil && col.NumFonts() > 0 {
		var buf sfnt.Buffer
		out := make([]string, 0, col.NumFonts())
		for i := 0; i < col.NumFonts(); i++ {
			f, ferr := col.Font(i)
			if ferr != nil {
				out = append(out, "")
				continue
			}
			fam, _ := f.Name(&buf, sfnt.NameIDFamily)
			out = append(out, fam)
		}
		return out, nil
	}
	f, err := x_opentype.Parse(data)
	if err != nil {
		return nil, err
	}
	var buf sfnt.Buffer
	fam, _ := f.Name(&buf, sfnt.NameIDFamily)
	return []string{fam}, nil
}

// MatchFamily finds the entry for a family name the way Font Book does:
// an exact (case-insensitive) match first, then a match on the leading
// word with a boundary — "Menlo" finds a face named "Menlo" inside a
// collection, and "SF Mono" finds "SF Mono Regular", but never "SF Mono
// Bold" (a bold face is a substitution the frame did not ask for).
func MatchFamily(index map[string]FontFile, target string) (FontFile, int, bool) {
	key := strings.ToLower(strings.TrimSpace(target))
	if key == "" {
		return FontFile{}, 0, false
	}
	if ff, ok := index[key]; ok {
		return ff, ff.FirstIndex, true
	}
	keys := make([]string, 0, len(index))
	for k := range index {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic pick when several faces match
	for _, k := range keys {
		if !strings.HasPrefix(k, key) {
			continue
		}
		switch rest := strings.TrimSpace(strings.TrimPrefix(k, key)); rest {
		case "", "regular":
			ff := index[k]
			return ff, ff.FirstIndex, true
		}
	}
	return FontFile{}, 0, false
}

// ResolvedFont is the face chosen for a role, in the shape the shaper
// wants. It mirrors winfonts.ResolvedFont field for field, so the two
// platform seams read alike.
type ResolvedFont struct {
	RequestedName string             // the preference that matched, or "" on fallback
	Family        string             // the family actually chosen
	FilePath      string             // "(embedded gofont)" on fallback
	IsCollection  bool               // true if the file is a .ttc
	FaceIndex     int                // face inside the collection
	IsFallback    bool               // true if the embedded gofont was used
	Faces         []giofont.FontFace // ready for the shaper
}

// ResolvePreference walks the preference list in order and returns the
// first family that exists on this machine, its face aliased under
// roleName so the frame's §7.1 role lookups keep resolving. When nothing
// matches — or the file that matched cannot be parsed after all — the
// embedded gofont is used under the same alias: a substitution, never a
// refusal (the same rule winfonts follows).
func (r *Resolver) ResolvePreference(prefs []string, roleName string) ResolvedFont {
	index := r.Index()
	for _, want := range prefs {
		ff, faceIdx, ok := MatchFamily(index, want)
		if !ok {
			continue
		}
		faces, err := LoadGioFontFaces(ff.Path, faceIdx, roleName)
		if err != nil || len(faces) == 0 {
			continue
		}
		family := strings.TrimSpace(want)
		if faceIdx >= 0 && faceIdx < len(ff.Families) && strings.TrimSpace(ff.Families[faceIdx]) != "" {
			family = strings.TrimSpace(ff.Families[faceIdx])
		}
		return ResolvedFont{
			RequestedName: want,
			Family:        family,
			FilePath:      ff.Path,
			IsCollection:  ff.IsCollection,
			FaceIndex:     faceIdx,
			Faces:         faces,
		}
	}
	return GoFontFallback(roleName)
}

// LoadGioFontFaces parses a font file with gioui.org/font/opentype and
// returns the selected face plus an alias of it under each name in
// aliasNames. Empty names, aliases equal to the face's own typeface and
// repeats of an alias already added are dropped, so the shaper's
// collection never carries the same face twice. Same shape and same error
// strings as winfonts.LoadGioFontFaces: one loader contract for both
// platforms.
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
	result := []giofont.FontFace{selected}
	added := map[giofont.Typeface]bool{selected.Font.Typeface: true}
	for _, alias := range aliasNames {
		alias = strings.TrimSpace(alias)
		if alias == "" || added[giofont.Typeface(alias)] {
			continue
		}
		added[giofont.Typeface(alias)] = true
		aliased := selected
		aliased.Font.Typeface = giofont.Typeface(alias)
		result = append(result, aliased)
	}
	return result, nil
}

// GoFontFallback is the embedded gofont collection aliased under
// roleName, the same fallback winfonts.Resolver.fallbackToGoFont and
// internal/ui's goFontFaces (fonts_linux.go) reach, so §7.1's roles
// resolve on every platform even with no system font found at all — a
// freshly imaged or tightly locked-down machine.
func GoFontFallback(roleName string) ResolvedFont {
	var faces []giofont.FontFace
	for _, f := range gofont.Collection() {
		faces = append(faces, f)
		if roleName != "" {
			aliased := f
			aliased.Font.Typeface = giofont.Typeface(roleName)
			faces = append(faces, aliased)
		}
	}
	return ResolvedFont{
		Family:     "Go",
		FilePath:   "(embedded gofont)",
		IsFallback: true,
		Faces:      faces,
	}
}

// PlatformFonts is the whole of internal/ui's macOS font seam apart from
// the three lines that find the home directory: both §7.1 roles resolved
// in preference order, each with its fallback already applied. It lives
// here rather than in fonts_darwin.go so that the preference lists, the
// role aliasing ("Serif"/"Mono") and the fallback are covered by tests on
// every platform — see the package comment.
//
// resolver, when non-nil, is a *macfonts.Resolver (the frame's own seam:
// FrameConfig.resolver, which tests inject a mock through); anything else
// means the system search path for home.
func PlatformFonts(resolver any, home string) []giofont.FontFace {
	r, ok := resolver.(*Resolver)
	if !ok || r == nil {
		r = NewResolver(home)
	}
	var all []giofont.FontFace
	all = append(all, r.ResolvePreference(PreferenceSerif, "Serif").Faces...)
	all = append(all, r.ResolvePreference(PreferenceMono, "Mono").Faces...)
	return all
}
