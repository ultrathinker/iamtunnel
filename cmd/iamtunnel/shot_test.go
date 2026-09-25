//go:build windows && !nogui

package main

import (
	"bytes"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// TestShotWritesRealPictureForEachScreenAndTheme is the proof of
// IAMT-16: for every accepted screen and both themes the shot command
// exits 0, writes the named file, and the file — opened back from disk,
// not the in-memory image — decodes as a genuine PNG of the standard
// resolution that is not a blank canvas (SPEC §7.2).
func TestShotWritesRealPictureForEachScreenAndTheme(t *testing.T) {
	lightPNGs := make(map[string][]byte)
	darkPNGs := make(map[string][]byte)
	for _, screen := range config.ScreenNames() {
		for _, theme := range []struct {
			name string
			dark bool
		}{{"light", false}, {"dark", true}} {
			t.Run(screen+"/"+theme.name, func(t *testing.T) {
				out := filepath.Join(t.TempDir(), "shot.png")
				args := []string{"shot", screen}
				if theme.dark {
					args = append(args, "--dark")
				}
				args = append(args, "--out", out)
				stdout, errs, code := drive(t, args...)
				if code != 0 {
					t.Fatalf("%v: exit code = %d, want 0 (stderr: %s)", args, code, errs)
				}
				if errs != "" {
					t.Errorf("%v: stderr must stay empty on success, got:\n%s", args, errs)
				}
				if !strings.Contains(stdout, out) {
					t.Errorf("%v: stdout does not name the written file, got:\n%s", args, stdout)
				}

				// Open the produced file back from disk.
				f, err := os.Open(out)
				if err != nil {
					t.Fatalf("produced file %s cannot be opened: %v", out, err)
				}
				defer f.Close()
				raw, err := io.ReadAll(f)
				if err != nil {
					t.Fatalf("produced file %s cannot be read: %v", out, err)
				}

				// It must be a real picture: a decodable PNG.
				img, err := png.Decode(bytes.NewReader(raw))
				if err != nil {
					t.Fatalf("produced file %s is not a decodable PNG: %v", out, err)
				}

				// Of the expected size — the standard offscreen
				// resolution the command renders at.
				b := img.Bounds()
				if w, h := ui.DefaultShotWidth, ui.DefaultShotHeight; b.Dx() != w || b.Dy() != h {
					t.Errorf("produced picture is %dx%d, want %dx%d", b.Dx(), b.Dy(), w, h)
				}

				// And not a blank canvas: more than one color.
				if n := countColors(img, 50); n <= 1 {
					t.Errorf("produced picture is blank: %d distinct color(s)", n)
				}

				if !theme.dark {
					lightPNGs[screen] = raw
				} else {
					darkPNGs[screen] = raw
				}
			})
		}
	}

	// The named screen must reach the renderer: at least one pair of
	// screens renders differently. (Under the landed tab strip only the
	// first tab sits on the canvas — see the report on the underline
	// width — so the ON state of the other tabs paints no pixels and
	// pairwise equality for client/admin/settings is expected; a wiring
	// that ignored the argument would make ALL of these identical.)
	screens := config.ScreenNames()
	distinct := false
	for i := 0; i < len(screens) && !distinct; i++ {
		for j := i + 1; j < len(screens); j++ {
			if !bytes.Equal(lightPNGs[screens[i]], lightPNGs[screens[j]]) {
				distinct = true
				break
			}
		}
	}
	if !distinct {
		t.Error("shots of all screens are byte-identical — the screen argument did not reach the renderer")
	}

	// And the theme flag must reach the renderer too: the dark picture
	// of a screen is never byte-identical to its light picture.
	for _, screen := range config.ScreenNames() {
		if bytes.Equal(lightPNGs[screen], darkPNGs[screen]) {
			t.Errorf("dark shot of %q is identical to its light shot — --dark did not reach the renderer", screen)
		}
	}
}

// TestShotScreenNameCaseInsensitive: the accepted spelling is decided by
// config.ParseScreen alone, and its canonical name reaches the renderer
// — an upper-case argument produces the same real picture.
func TestShotScreenNameCaseInsensitive(t *testing.T) {
	out := filepath.Join(t.TempDir(), "s.png")
	stdout, errs, code := drive(t, "shot", "SERVER", "--out", out)
	if code != 0 {
		t.Fatalf("shot SERVER: exit code = %d, want 0 (stderr: %s)", code, errs)
	}
	if !strings.Contains(stdout, out) {
		t.Errorf("shot SERVER: stdout does not name %s, got:\n%s", out, stdout)
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatalf("produced file %s cannot be opened: %v", out, err)
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		t.Fatalf("produced file %s is not a decodable PNG: %v", out, err)
	}
	if n := countColors(img, 50); n <= 1 {
		t.Errorf("produced picture is blank: %d distinct color(s)", n)
	}
}

// TestShotDefaultOutName: without --out the command writes into the
// current directory under the screen's own name; the name is decided by
// the screen argument and the theme, nothing else.
func TestShotDefaultOutName(t *testing.T) {
	for _, tc := range []struct {
		screen string
		dark   bool
		want   string
	}{
		{"client", false, "client.png"},
		{"client", true, "client-dark.png"},
		{"SERVER", true, "server-dark.png"},
	} {
		if got := defaultShotName(tc.screen, tc.dark); got != tc.want {
			t.Errorf("defaultShotName(%q, %v) = %q, want %q", tc.screen, tc.dark, got, tc.want)
		}
	}
}

// TestShotOutFileErrorClasses: the four exit-code classes stay
// distinguished. A --out target that cannot hold a file at
// all (a directory) is the environment class; a path the OS refuses to
// write (a read-only file) is the access-denied class.
func TestShotOutFileErrorClasses(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		_, errs, code := drive(t, "shot", "client", "--out", t.TempDir())
		if code != 3 {
			t.Errorf("shot into a directory: exit code = %d, want 3 (stderr: %s)", code, errs)
		}
		if !strings.Contains(errs, "failed creating output file") {
			t.Errorf("shot into a directory: stderr lacks the cause, got:\n%s", errs)
		}
	})
	t.Run("read-only file", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "ro.png")
		if err := os.WriteFile(out, []byte("keep"), 0o444); err != nil {
			t.Fatalf("write read-only file: %v", err)
		}
		_, errs, code := drive(t, "shot", "client", "--out", out)
		if code != 4 {
			t.Errorf("shot over a read-only file: exit code = %d, want 4 (stderr: %s)", code, errs)
		}
		if !strings.Contains(errs, "refuses to write") {
			t.Errorf("shot over a read-only file: stderr lacks the refusal text, got:\n%s", errs)
		}
	})
}

// countColors counts distinct RGBA colors in the image, capped at max;
// it is deliberately local to this test so the blankness verdict does
// not rest on the product's own helper.
func countColors(img image.Image, max int) int {
	b := img.Bounds()
	seen := make(map[uint32]struct{})
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			seen[uint32(r>>8)<<24|uint32(g>>8)<<16|uint32(bl>>8)<<8|a>>8] = struct{}{}
			if len(seen) >= max {
				return len(seen)
			}
		}
	}
	return len(seen)
}
