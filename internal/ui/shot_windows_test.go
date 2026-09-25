//go:build windows

package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestScreenshotsAllTabsBothThemes tests Gate 4:
// "Make it possible to take a snapshot of every tab, in both themes,
// and make it work in tests. The output file must be a real picture,
// not an empty canvas: check the size and that it holds more than one
// colour."
func TestScreenshotsAllTabsBothThemes(t *testing.T) {
	tempDir := t.TempDir()

	tabs := []string{TabSetUp, TabClient, TabServer, TabSession, TabAdmin, TabSettings}
	themes := []struct {
		name   string
		isDark bool
	}{
		{"light", false},
		{"dark", true},
	}

	const w = 1024
	const h = 700

	shotCount := 0

	for _, tab := range tabs {
		for _, th := range themes {
			filename := fmt.Sprintf("shot_%s_%s.png", filepath.Clean(tab), th.name)
			outPath := filepath.Join(tempDir, filename)

			img, err := Shot(tab, th.isDark, w, h, outPath)
			if err != nil {
				t.Fatalf("Shot(%q, dark=%v) failed: %v", tab, th.isDark, err)
			}

			// 1. Verify file was created on disk
			info, err := os.Stat(outPath)
			if err != nil {
				t.Fatalf("Snapshot file %s not found on disk: %v", outPath, err)
			}

			// 2. Verify file size is substantial (not empty file)
			if info.Size() < 1000 {
				t.Errorf("Snapshot file %s too small (%d bytes), expected > 1000 bytes", outPath, info.Size())
			}

			// 3. Verify image bounds match requested resolution
			bounds := img.Bounds()
			if bounds.Dx() != w || bounds.Dy() != h {
				t.Errorf("Snapshot image %s bounds = %dx%d, want %dx%d", outPath, bounds.Dx(), bounds.Dy(), w, h)
			}

			// 4. Verify image is not an empty canvas (must have more than one color)
			colorCount := CountDistinctColors(img, 50)
			if colorCount <= 1 {
				t.Errorf("Snapshot image %s is a blank/empty canvas (found only %d distinct color)", outPath, colorCount)
			}

			shotCount++
			t.Logf("Snapshot [%d/10] %s: %dx%d px, %d bytes, %d distinct colors -> OK",
				shotCount, filename, bounds.Dx(), bounds.Dy(), info.Size(), colorCount)
		}
	}

	if shotCount != 12 {
		t.Fatalf("Expected 12 snapshots (6 tabs x 2 themes), but generated %d", shotCount)
	}
}
