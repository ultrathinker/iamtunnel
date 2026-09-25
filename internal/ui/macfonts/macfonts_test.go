package macfonts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	giofont "gioui.org/font"
	"golang.org/x/image/font/gofont/goregular"
)

// writeFont lays down a real, parseable font file (the Go project's own
// Go Regular from x/image — the same bytes the embedded gofont wraps, and
// the family is "Go"). Using real bytes rather than a stub matters: the
// whole point of the index is that it parses files, so a fake file would
// test nothing.
func writeFont(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, goregular.TTF, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// TestSearchDirsAreTheMacPaths pins the search path IAMT-262 names: the
// system collection, the Supplemental collection Apple moved the extra
// faces into, the machine-wide /Library/Fonts, and the user's own
// ~/Library/Fonts last — the order Font Book itself resolves a duplicate
// in.
func TestSearchDirsAreTheMacPaths(t *testing.T) {
	dirs := SearchDirs("/Users/alice")
	want := []string{
		"/System/Library/Fonts",
		"/System/Library/Fonts/Supplemental",
		"/Library/Fonts",
		"/Users/alice/Library/Fonts",
	}
	if len(dirs) != len(want) {
		t.Fatalf("SearchDirs = %v, want %v", dirs, want)
	}
	for i := range want {
		if dirs[i] != want[i] {
			t.Errorf("SearchDirs[%d] = %q, want %q", i, dirs[i], want[i])
		}
	}

	if got := SearchDirs(""); len(got) != len(DefaultDirs) {
		t.Errorf("SearchDirs(\"\") = %v; a process with no home must simply lose the user directory, not gain an empty one", got)
	}
	if got := UserFontDir(""); got != "" {
		t.Errorf("UserFontDir(\"\") = %q, want \"\"", got)
	}
}

// TestIndexReadsTheFamilyOutOfTheFile proves the index is built from what
// the font file itself says (the name table), not from the file name: the
// file here is called "some-file.ttf" while its family is "Go".
func TestIndexReadsTheFamilyOutOfTheFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFont(t, dir, "some-file.ttf")

	r := &Resolver{Dirs: []string{dir}}
	index := r.Index()
	ff, ok := index["go"]
	if !ok {
		t.Fatalf("index has no %q family; keys: %v", "go", keysOf(index))
	}
	if ff.Path != path {
		t.Errorf("FontFile.Path = %q, want %q", ff.Path, path)
	}
	if ff.IsCollection {
		t.Errorf("a single .ttf must not be reported as a collection")
	}
	if ff.FirstIndex != 0 {
		t.Errorf("FontFile.FirstIndex = %d, want 0", ff.FirstIndex)
	}
}

// TestIndexSkipsWhatItCannotUse: a file that is not a font, a file that
// claims to be one and is not, and a directory that does not exist are
// each that candidate's own problem. A bad file in ~/Library/Fonts must
// never cost the window the fonts that do work.
func TestIndexSkipsWhatItCannotUse(t *testing.T) {
	dir := t.TempDir()
	writeFont(t, dir, "good.ttf")
	good := filepath.Join(dir, "good.ttf")
	nested := filepath.Join(dir, "subdir")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFont(t, nested, "nested.ttf") // never reached: subdirectories are not scanned
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a font"), 0o644); err != nil {
		t.Fatalf("write notes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.ttf"), []byte("not a font at all"), 0o644); err != nil {
		t.Fatalf("write broken: %v", err)
	}

	r := &Resolver{Dirs: []string{dir, filepath.Join(dir, "does-not-exist")}}
	index := r.Index()
	if len(index) != 1 {
		t.Fatalf("index = %v, want exactly the one usable family", keysOf(index))
	}
	if ff := index["go"]; ff.Path != good {
		t.Errorf("index[go].Path = %q, want %q", ff.Path, good)
	}
}

// TestIndexFileThatCannotBeReadIsSkipped uses the read seam to make one
// candidate fail at the read (an unreadable file, a broken symlink) while
// the other one still resolves.
func TestIndexFileThatCannotBeReadIsSkipped(t *testing.T) {
	dir := t.TempDir()
	writeFont(t, dir, "a-first.ttf")
	writeFont(t, dir, "b-second.ttf")
	unreadable := filepath.Join(dir, "a-first.ttf")

	r := &Resolver{Dirs: []string{dir}, read: func(path string) ([]byte, error) {
		if path == unreadable {
			return nil, errors.New("permission denied")
		}
		return os.ReadFile(path)
	}}
	ff, ok := r.Index()["go"]
	if !ok {
		t.Fatalf("the second file should still be indexed")
	}
	if ff.Path != filepath.Join(dir, "b-second.ttf") {
		t.Errorf("indexed %q, want the readable file", ff.Path)
	}
}

// TestEarlierDirectoryWinsForTheSameFamily is the Font Book rule: the
// system's own copy of a family beats one the user installed with the
// same name.
func TestEarlierDirectoryWinsForTheSameFamily(t *testing.T) {
	system := t.TempDir()
	user := t.TempDir()
	systemFont := writeFont(t, system, "system.ttf")
	writeFont(t, user, "user.ttf")

	r := &Resolver{Dirs: []string{system, user}}
	ff, ok := r.Index()["go"]
	if !ok {
		t.Fatalf("no %q family in %v", "go", keysOf(r.Index()))
	}
	if ff.Path != systemFont {
		t.Errorf("FontFile.Path = %q, want the earlier directory's %q", ff.Path, systemFont)
	}
}

// TestResolvePreferenceUsesTheSystemFont is the whole point of the
// resolver: a family found on disk is loaded, aliased under the SPEC
// §7.1 role name, and NOT reported as a fallback.
func TestResolvePreferenceUsesTheSystemFont(t *testing.T) {
	dir := t.TempDir()
	path := writeFont(t, dir, "go-regular.ttf")

	r := &Resolver{Dirs: []string{dir}}
	res := r.ResolvePreference([]string{"Go"}, "Serif")

	if res.IsFallback {
		t.Fatalf("a family that exists on disk must not be a fallback: %+v", res)
	}
	if res.RequestedName != "Go" || res.Family != "Go" {
		t.Errorf("RequestedName/Family = %q/%q, want Go/Go", res.RequestedName, res.Family)
	}
	if res.FilePath != path {
		t.Errorf("FilePath = %q, want %q", res.FilePath, path)
	}
	if !hasTypeface(res.Faces, "Serif") {
		t.Errorf("the face must be aliased under the role name %q so §7.1 keeps resolving; faces: %v", "Serif", typefacesOf(res.Faces))
	}
	if !hasTypeface(res.Faces, "Go") {
		t.Errorf("the face's own family must stay in the collection too; faces: %v", typefacesOf(res.Faces))
	}
}

// TestResolvePreferenceWalksTheListInOrder: the first family that exists
// wins, earlier ones that do not exist are simply skipped.
func TestResolvePreferenceWalksTheListInOrder(t *testing.T) {
	dir := t.TempDir()
	writeFont(t, dir, "go-regular.ttf")

	r := &Resolver{Dirs: []string{dir}}
	res := r.ResolvePreference([]string{"New York", "Times New Roman", "Go", "Menlo"}, "Mono")

	if res.IsFallback {
		t.Fatalf("Go is in the list and on disk, so this must not be a fallback: %+v", res)
	}
	if res.RequestedName != "Go" {
		t.Errorf("RequestedName = %q, want the first family that exists (Go)", res.RequestedName)
	}
	if !hasTypeface(res.Faces, "Mono") {
		t.Errorf("faces must carry the role alias; faces: %v", typefacesOf(res.Faces))
	}
}

// TestResolvePreferenceFallsBackToGoFont: an empty preference list, a
// machine with no matching font at all, and a directory that does not
// exist all end in the embedded gofont, aliased, with no error anywhere —
// the contract winfonts keeps and the reason the window never fails to
// open for want of a font.
func TestResolvePreferenceFallsBackToGoFont(t *testing.T) {
	cases := []struct {
		name string
		r    *Resolver
		pref []string
	}{
		{"no preference at all", &Resolver{Dirs: []string{t.TempDir()}}, nil},
		{"nothing matches", &Resolver{Dirs: []string{t.TempDir()}}, []string{"Nonesuch", "AnotherMissing"}},
		{"no directory exists", &Resolver{Dirs: []string{"/nonexistent/nope"}}, PreferenceSerif},
		{"no directories configured", &Resolver{}, PreferenceMono},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.r.ResolvePreference(tc.pref, "Serif")
			if !res.IsFallback {
				t.Fatalf("want the gofont fallback, got %+v", res)
			}
			if res.Family != "Go" || res.FilePath != "(embedded gofont)" {
				t.Errorf("fallback Family/FilePath = %q/%q, want Go/(embedded gofont)", res.Family, res.FilePath)
			}
			if len(res.Faces) == 0 {
				t.Errorf("fallback must still hand the shaper faces")
			}
			if !hasTypeface(res.Faces, "Serif") {
				t.Errorf("fallback faces must carry the role alias; faces: %v", typefacesOf(res.Faces))
			}
		})
	}
}

// TestMatchFamilyIsCaseInsensitiveAndExactFirst: "menlo" must find
// "Menlo", and an exact family must beat a longer one that merely starts
// with the same word.
func TestMatchFamilyIsCaseInsensitiveAndExactFirst(t *testing.T) {
	index := map[string]FontFile{
		"menlo":        {Path: "/System/Library/Fonts/Menlo.ttc", Families: []string{"Menlo", "Menlo Bold"}, FirstIndex: 0, IsCollection: true},
		"menlo bold":   {Path: "/System/Library/Fonts/Menlo.ttc", Families: []string{"Menlo", "Menlo Bold"}, FirstIndex: 1, IsCollection: true},
		"sf mono":      {Path: "/System/Library/Fonts/SFNSMono.ttf", Families: []string{"SF Mono"}},
		"sf mono bold": {Path: "/System/Library/Fonts/SFNSMono-Bold.ttf", Families: []string{"SF Mono Bold"}},
	}
	ff, idx, ok := MatchFamily(index, "MENLO")
	if !ok || idx != 0 || ff.Path != index["menlo"].Path {
		t.Errorf("MatchFamily(MENLO) = %v/%d/%v, want the plain Menlo face at index 0", ff, idx, ok)
	}
	if _, idx, ok := MatchFamily(index, "Menlo Bold"); !ok || idx != 1 {
		t.Errorf("MatchFamily(Menlo Bold) = %d/%v, want the bold face at index 1", idx, ok)
	}
	if _, _, ok := MatchFamily(index, "SF Mono"); !ok {
		t.Errorf("MatchFamily(SF Mono) must find the exact family")
	}
	if _, _, ok := MatchFamily(index, ""); ok {
		t.Errorf("MatchFamily(\"\") must not match anything")
	}
}

// TestMatchFamilyRejectsABoldSubstitution: when only "SF Mono Bold" is
// installed, "SF Mono" is NOT satisfied by it — silently drawing in bold
// because the regular face was missing is a substitution the frame did
// not ask for. The "Regular" suffix is the one exception: macOS names the
// plain face of some families that way.
func TestMatchFamilyRejectsABoldSubstitution(t *testing.T) {
	boldOnly := map[string]FontFile{
		"sf mono bold": {Path: "/x/SFNSMono-Bold.ttf", Families: []string{"SF Mono Bold"}},
	}
	if ff, _, ok := MatchFamily(boldOnly, "SF Mono"); ok {
		t.Errorf("MatchFamily(SF Mono) matched %+v; a bold face must not stand in for the regular one", ff)
	}

	regularSuffix := map[string]FontFile{
		"new york regular": {Path: "/x/NewYork.ttf", Families: []string{"New York Regular"}},
	}
	if _, _, ok := MatchFamily(regularSuffix, "New York"); !ok {
		t.Errorf("MatchFamily(New York) must accept a face macOS named \"New York Regular\"")
	}

	// And when both are present, the exact one wins.
	both := map[string]FontFile{
		"new york regular": {Path: "/x/NewYork.ttf", Families: []string{"New York Regular"}},
		"new york":         {Path: "/x/NewYork2.ttf", Families: []string{"New York"}},
	}
	if ff, _, ok := MatchFamily(both, "New York"); !ok || ff.Path != "/x/NewYork2.ttf" {
		t.Errorf("MatchFamily(New York) = %+v/%v, want the exact family", ff, ok)
	}
}

// TestLoadGioFontFacesAliasesAndClamps mirrors winfonts' loader contract:
// the face itself plus one alias per role name, duplicates and empties
// dropped, and an out-of-range index clamped to the first face rather
// than an error.
func TestLoadGioFontFacesAliasesAndClamps(t *testing.T) {
	dir := t.TempDir()
	path := writeFont(t, dir, "go-regular.ttf")

	faces, err := LoadGioFontFaces(path, 0, "Serif", "Serif", "", " Go ")
	if err != nil {
		t.Fatalf("LoadGioFontFaces: %v", err)
	}
	var wanted []string
	for _, f := range faces {
		wanted = append(wanted, string(f.Font.Typeface))
	}
	if len(faces) != 2 {
		t.Fatalf("faces = %v, want the face plus exactly one alias (duplicate, empty and self-alias dropped)", wanted)
	}
	if !hasTypeface(faces, "Serif") || !hasTypeface(faces, "Go") {
		t.Errorf("faces = %v, want the original and the Serif alias", wanted)
	}

	faces, err = LoadGioFontFaces(path, 99, "Mono")
	if err != nil {
		t.Fatalf("an out-of-range face index must clamp, not fail: %v", err)
	}
	if len(faces) != 2 || !hasTypeface(faces, "Mono") {
		t.Errorf("clamped load = %v, want the first face plus the Mono alias", typefacesOf(faces))
	}

	if _, err := LoadGioFontFaces(filepath.Join(dir, "missing.ttf"), 0); err == nil {
		t.Errorf("a missing file must be reported, not silently ignored")
	}
	broken := filepath.Join(dir, "broken.ttf")
	if err := os.WriteFile(broken, []byte("nope"), 0o644); err != nil {
		t.Fatalf("write broken: %v", err)
	}
	if _, err := LoadGioFontFaces(broken, 0); err == nil {
		t.Errorf("a file that is not a font must be reported")
	}
}

// TestPlatformFontsCoversBothRoles is the invariant internal/ui depends
// on: whatever is or is not installed, the shaper gets faces for both
// §7.1 roles, each carrying its role name as a typeface.
func TestPlatformFontsCoversBothRoles(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resolver any
		home     string
	}{
		{"system path for a home with no fonts", nil, t.TempDir()},
		{"an empty directory", &Resolver{Dirs: []string{t.TempDir()}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			faces := PlatformFonts(tc.resolver, tc.home)
			if len(faces) == 0 {
				t.Fatalf("PlatformFonts returned nothing at all")
			}
			for _, role := range []string{"Serif", "Mono"} {
				if !hasTypeface(faces, role) {
					t.Errorf("no face for role %q; faces: %v", role, typefacesOf(faces))
				}
			}
		})
	}
}

// TestPlatformFontsAcceptsTheFrameSeam proves the resolver seam
// FrameConfig.resolver carries is honoured — the same *Resolver-or-nil
// contract fonts_windows.go has, so a test that injects a mock resolver
// gets the mock's fonts on macOS too.
//
// The preference lists are package data and every real macOS family is
// absent from a Linux or Windows test host, so the only way to observe
// which resolver answered is to point the lists at the one family the
// test can put on disk ("Go", from x/image's own Go Regular). With both
// roles resolving to that file, PlatformFonts returns one face and one
// role alias per role; the fallback would return the whole 13-face
// embedded collection, aliased, per role.
func TestPlatformFontsAcceptsTheFrameSeam(t *testing.T) {
	defer func(serif, mono []string) {
		PreferenceSerif, PreferenceMono = serif, mono
	}(PreferenceSerif, PreferenceMono)
	PreferenceSerif, PreferenceMono = []string{"Go"}, []string{"Go"}

	dir := t.TempDir()
	writeFont(t, dir, "go-regular.ttf")

	faces := PlatformFonts(&Resolver{Dirs: []string{dir}}, "")
	if len(faces) != 4 {
		t.Errorf("PlatformFonts(injected resolver) = %v, want 4 (one face + one role alias, for each of the two roles)", typefacesOf(faces))
	}
	for _, role := range []string{"Serif", "Mono"} {
		if !hasTypeface(faces, role) {
			t.Errorf("no face for role %q; faces: %v", role, typefacesOf(faces))
		}
	}

	// The same two preferences against an empty directory find nothing and
	// fall back — so it really is the resolver's answer that decides.
	fallback := PlatformFonts(&Resolver{Dirs: []string{t.TempDir()}}, "")
	if len(fallback) <= len(faces) {
		t.Errorf("an empty directory returned %d faces, want the much larger embedded fallback", len(fallback))
	}
}

func keysOf(index map[string]FontFile) []string {
	out := make([]string, 0, len(index))
	for k := range index {
		out = append(out, k)
	}
	return out
}

func typefacesOf(faces []giofont.FontFace) []string {
	out := make([]string, 0, len(faces))
	for _, f := range faces {
		out = append(out, string(f.Font.Typeface))
	}
	return out
}

func hasTypeface(faces []giofont.FontFace, name string) bool {
	for _, f := range faces {
		if strings.EqualFold(string(f.Font.Typeface), name) {
			return true
		}
	}
	return false
}
