//go:build linux

package ui

// iamt253_fonts_theme_linux_test.go — IAMT-253, the seam tests for the
// Linux font discovery and the desktop theme probe.
//
// Nothing here launches a real gsettings/kreadconfig (the probeExec
// seam is a package variable, swapped per test and restored by defer),
// and nothing here needs a real desktop: the font search is exercised
// against scratch directories, and the one place a real font file is
// parsed uses the Go Regular TTF the x/image module already carries —
// a fixture by construction, not a system font.
//
// Run on the Linux host (this file is linux-only, like the code it
// tests): go test -count=1 ./internal/ui/...

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gioui.org/font"

	"golang.org/x/image/font/gofont/goregular"
)

// writeTempFont writes data under dir with the given file name and
// returns the full path.
func writeTempFont(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	full := filepath.Join(dir, name)
	if err := os.WriteFile(full, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return full
}

// TestIAMT253_CollectFontFiles pins the search: recursive under every
// root, font extensions only (case-insensitive), deterministic order,
// missing roots skipped.
//
// Canary: drop the `d.IsDir()` guard so directories enter the result,
// or make an unreadable subdirectory abort the walk. This test goes red
// on the first collected name.
func TestIAMT253_CollectFontFiles(t *testing.T) {
	root := t.TempDir()
	writeTempFont(t, root, "NotoSerif-Regular.ttf", goregular.TTF)
	writeTempFont(t, filepath.Join(root, "sub"), "DejaVuSansMono.ttf", goregular.TTF)
	writeTempFont(t, filepath.Join(root, "sub", "deeper"), "LiberationSerif-Italic.otf", goregular.TTF)
	writeTempFont(t, root, "NOTICE.txt", []byte("not a font"))
	writeTempFont(t, root, "stray.TTF", goregular.TTF)

	missing := filepath.Join(root, "does-not-exist")
	got := collectFontFiles([]string{missing, root})
	var names []string
	for _, f := range got {
		names = append(names, filepath.Base(f))
	}
	// Order: the missing root contributes nothing; the walk of root is
	// lexical: NOTICE.txt is not a font; "stray.TTF" sorts before
	// "sub" (byte-wise 't' < 'u') and NotoSerif before both, then the
	// sub tree lexically.
	if len(names) == 0 {
		t.Fatal("collectFontFiles found nothing in a populated tree")
	}
	joined := strings.Join(names, "\n")
	for _, want := range []string{"stray.TTF", "NotoSerif-Regular.ttf", "DejaVuSansMono.ttf", "LiberationSerif-Italic.otf"} {
		if !strings.Contains(joined, want) {
			t.Errorf("font file %s not collected (got %v)", want, names)
		}
	}
	if strings.Contains(joined, "NOTICE.txt") {
		t.Errorf("non-font file collected: %v", names)
	}
	// The deeper file must come after its directory prefix — recursion
	// actually descends rather than reading one level.
	if strings.Index(joined, "DejaVuSansMono.ttf") > strings.Index(joined, "LiberationSerif-Italic.otf") {
		t.Errorf("walk order not lexical/recursive: %v", names)
	}
}

// TestIAMT253_PickFontFile pins the preference resolution: family order
// decides first, the plain face beats Bold/Italic/Oblique copies, name
// folding bridges "DejaVu Sans Mono" ↔ DejaVuSansMono.ttf, and no
// match is a false, not a panic.
//
// Canary: swap the plain-face preference for "first match wins" (or
// fold away the family prefix check). This test goes red on the
// "plain face preferred" case.
func TestIAMT253_PickFontFile(t *testing.T) {
	files := []string{
		"/fonts/DejaVuSansMono-Bold.ttf",
		"/fonts/DejaVuSansMono-Oblique.ttf",
		"/fonts/DejaVuSansMono.ttf",
		"/fonts/NotoSansMono-Regular.ttf",
		"/fonts/NotoSerif-Regular.ttf",
	}
	cases := []struct {
		name   string
		family string
		want   string
		ok     bool
	}{
		{"preference order: Noto over DejaVu", "Noto Sans Mono", "/fonts/NotoSansMono-Regular.ttf", true},
		{"plain face preferred over Bold/Oblique", "DejaVu Sans Mono", "/fonts/DejaVuSansMono.ttf", true},
		{"folding bridges the file name", "noto serif", "/fonts/NotoSerif-Regular.ttf", true},
		{"unrelated family", "Ubuntu Mono", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := pickFontFile(files, tc.family)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("pickFontFile(%q) = %q,%v; want %q,%v", tc.family, got, ok, tc.want, tc.ok)
			}
		})
	}

	// Only styled copies exist: the plain-face rule falls back to the
	// first match instead of refusing the family altogether.
	onlyBold := []string{"/fonts/Xserif-Bold.ttf", "/fonts/Xserif-Italic.ttf"}
	got, ok := pickFontFile(onlyBold, "Xserif")
	if !ok || got != "/fonts/Xserif-Bold.ttf" {
		t.Fatalf("styled-only family not resolved: %q,%v", got, ok)
	}
}

// TestIAMT253_LoadFontFaces parses a real TTF (the Go Regular face the
// x/image module embeds — a fixture by construction) and pins the two
// outcomes §7.1 depends on: the face comes back under its own name AND
// aliased under the role name; bytes that are not a font are an error,
// never a face.
//
// Canary: drop the role alias in loadFontFaces (or break the roleName
// mismatch guard so the alias replaces the original). This test goes
// red on "role face not aliased under Serif".
func TestIAMT253_LoadFontFaces(t *testing.T) {
	dir := t.TempDir()
	good := writeTempFont(t, dir, "GoRegular.ttf", goregular.TTF)

	faces, err := loadFontFaces(good, "Serif")
	if err != nil {
		t.Fatalf("loadFontFaces(Go Regular): %v", err)
	}
	if len(faces) != 2 {
		t.Fatalf("want own face + role alias (2 faces), got %d", len(faces))
	}
	if string(faces[1].Font.Typeface) != "Serif" {
		t.Fatalf("role face not aliased under Serif: %q", faces[1].Font.Typeface)
	}

	bad := writeTempFont(t, dir, "garbage.ttf", []byte("this is not a font"))
	if _, err := loadFontFaces(bad, "Serif"); err == nil {
		t.Fatal("garbage bytes parsed as a font — the loader must refuse, not guess")
	}
}

// TestIAMT253_PlatformFontsRolesFromGofont is the substitution
// guarantee: with an empty search root, platformFonts still aliases the
// §7.1 role names from the embedded gofont (Cyrillic included), so the
// frame's Serif/Mono text resolves on the most minimal system.
//
// Canary: make platformFonts return nil when no font file matches (a
// "refusal" instead of the substitution). This test goes red on
// "role Serif resolved to 0 faces".
func TestIAMT253_PlatformFontsRolesFromGofont(t *testing.T) {
	origRoots := fontRoots
	fontRoots = func() []string { return []string{t.TempDir()} } // exists, empty
	defer func() { fontRoots = origRoots }()

	faces := platformFonts(nil)
	if len(faces) == 0 {
		t.Fatal("platformFonts returned no faces at all — the frame would draw nothing")
	}
	for _, role := range []string{"Serif", "Mono"} {
		n := countTypeface(faces, role)
		if n == 0 {
			t.Fatalf("role %s resolved to 0 faces — §7.1's font roles must always resolve", role)
		}
	}
}

// TestIAMT253_PlatformFontsUsesSystemFont is the feature itself: a
// preference family present under a font root is parsed and takes over
// its role — the Mono role's contribution is the file's own face plus
// the one alias (2 faces), not the gofont fallback, while Serif (not on
// the scratch disk) still falls back.
//
// Canary: break the search (drop ~/.local/share/fonts from fontRoots,
// or the fold in pickFontFile) so DejaVu Sans Mono is never found. This
// test goes red on the face count: the role silently degrades to gofont.
func TestIAMT253_PlatformFontsUsesSystemFont(t *testing.T) {
	root := t.TempDir()
	writeTempFont(t, root, "DejaVuSansMono.ttf", goregular.TTF)

	origRoots := fontRoots
	fontRoots = func() []string { return []string{root} }
	defer func() { fontRoots = origRoots }()

	faces := platformFonts(nil)
	want := len(goFontFaces("Serif")) + 2 // Serif falls back; Mono = file face + alias
	if len(faces) != want {
		t.Fatalf("platformFonts resolved %d faces, want %d (gofont Serif + the found Mono file's face and alias)", len(faces), want)
	}
	if n := countTypeface(faces, "Mono"); n != 1 {
		t.Fatalf("role Mono aliased %d times, want exactly 1", n)
	}
	if n := countTypeface(faces, "Serif"); n < 1 {
		t.Fatalf("role Serif resolved to 0 faces — the fallback must still cover the other role")
	}
}

// countTypeface counts the faces registered under a typeface name.
func countTypeface(faces []font.FontFace, name string) int {
	n := 0
	for _, f := range faces {
		if string(f.Font.Typeface) == name {
			n++
		}
	}
	return n
}

// fakeProbe is the probeExec substitute: canned per-tool answers, a
// record of what was asked, in order.
type fakeProbe struct {
	out   map[string]string // tool → canned stdout
	fail  map[string]bool   // tool → simulate absence/failure
	asked []string          // tools consulted, in order
}

func (p *fakeProbe) exec(name string, _ ...string) ([]byte, error) {
	p.asked = append(p.asked, name)
	if p.fail[name] {
		return nil, os.ErrNotExist
	}
	return []byte(p.out[name]), nil
}

// TestIAMT253_ThemeProbeOrder pins the probe priority end to end:
// GNOME's color-scheme first (prefer-dark/prefer-light/default), KDE's
// ColorScheme second (kreadconfig5, then kreadconfig6 — 5 first so both
// Plasma generations are covered by one order), $GTK_THEME third, light
// last. It also pins the two refusals-to-answer: a failed probe is not
// an answer, and a GNOME value nothing recognizes falls through to KDE
// instead of deciding.
//
// Canary: reorder the kreadconfig loop (6 before 5), skip kreadconfig6
// entirely, or return false the moment gsettings errors. This test goes
// red on the `asked` sequence of the corresponding case.
func TestIAMT253_ThemeProbeOrder(t *testing.T) {
	cases := []struct {
		name      string
		out       map[string]string
		fail      map[string]bool
		gtk       string
		want      bool
		wantAsked []string
	}{
		{
			name:      "GNOME prefer-dark",
			out:       map[string]string{"gsettings": "'prefer-dark'\n"},
			want:      true,
			wantAsked: []string{"gsettings"},
		},
		{
			name:      "GNOME default is light, KDE never asked",
			out:       map[string]string{"gsettings": "'default'\n", "kreadconfig5": "BreezeDark\n"},
			want:      false,
			wantAsked: []string{"gsettings"},
		},
		{
			name:      "GNOME prefer-light",
			out:       map[string]string{"gsettings": "'prefer-light'\n"},
			want:      false,
			wantAsked: []string{"gsettings"},
		},
		{
			name:      "GNOME absent, kreadconfig5 dark",
			out:       map[string]string{"kreadconfig5": "BreezeDark\n"},
			fail:      map[string]bool{"gsettings": true},
			want:      true,
			wantAsked: []string{"gsettings", "kreadconfig5"},
		},
		{
			name:      "kreadconfig5 absent, kreadconfig6 answers light",
			out:       map[string]string{"kreadconfig6": "Breeze\n"},
			fail:      map[string]bool{"gsettings": true, "kreadconfig5": true},
			want:      false,
			wantAsked: []string{"gsettings", "kreadconfig5", "kreadconfig6"},
		},
		{
			name:      "unrecognized GNOME value falls through to KDE",
			out:       map[string]string{"gsettings": "'weird-scheme'\n", "kreadconfig5": "Oxygen\n"},
			want:      false,
			wantAsked: []string{"gsettings", "kreadconfig5"},
		},
		{
			name:      "nothing answers, GTK_THEME dark",
			out:       map[string]string{},
			fail:      map[string]bool{"gsettings": true, "kreadconfig5": true, "kreadconfig6": true},
			gtk:       "Yaru-dark",
			want:      true,
			wantAsked: []string{"gsettings", "kreadconfig5", "kreadconfig6"},
		},
		{
			name:      "nothing answers at all — light is the default",
			out:       map[string]string{},
			fail:      map[string]bool{"gsettings": true, "kreadconfig5": true, "kreadconfig6": true},
			want:      false,
			wantAsked: []string{"gsettings", "kreadconfig5", "kreadconfig6"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := &fakeProbe{out: tc.out, fail: tc.fail}
			orig := probeExec
			probeExec = probe.exec
			defer func() { probeExec = orig }()
			t.Setenv("GTK_THEME", tc.gtk)

			if got := ReadSystemThemeIsDark(); got != tc.want {
				t.Fatalf("ReadSystemThemeIsDark() = %v, want %v (asked %v)", got, tc.want, probe.asked)
			}
			if strings.Join(probe.asked, ",") != strings.Join(tc.wantAsked, ",") {
				t.Fatalf("probe order = %v, want %v", probe.asked, tc.wantAsked)
			}
		})
	}
}

// TestIAMT253_DefaultThemeSourceIsLive pins that the production
// ThemeSource on Linux is the probe above, not a stale constant: the
// answer must follow the seam between two calls (this is what makes the
// frame's live theme switch — IAMT-75's CheckThemeSync — move at all).
//
// Canary: point defaultThemeSource at a fixed bool. This test goes red
// on the second reading.
func TestIAMT253_DefaultThemeSourceIsLive(t *testing.T) {
	probe := &fakeProbe{out: map[string]string{"gsettings": "'prefer-dark'\n"}}
	origProbe, origSource := probeExec, defaultThemeSource
	probeExec = probe.exec
	defer func() { probeExec, defaultThemeSource = origProbe, origSource }()

	if !defaultThemeSource.IsDark() {
		t.Fatal("defaultThemeSource missed a prefer-dark answer")
	}
	probe.out["gsettings"] = "'prefer-light'\n"
	if defaultThemeSource.IsDark() {
		t.Fatal("defaultThemeSource did not follow the theme change — live switching is dead")
	}
}
