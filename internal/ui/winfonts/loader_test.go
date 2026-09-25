//go:build windows

package winfonts

import (
	"os"
	"path/filepath"
	"testing"
)

func getSystemFontsDir() string {
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = `C:\Windows`
	}
	return filepath.Join(windir, "Fonts")
}

func TestInspectFontFile_CambriaCollection(t *testing.T) {
	cambriaPath := filepath.Join(getSystemFontsDir(), "cambria.ttc")
	if _, err := os.Stat(cambriaPath); os.IsNotExist(err) {
		t.Skip("cambria.ttc not found on this machine, skipping test")
	}

	insp, err := InspectFontFile(cambriaPath)
	if err != nil {
		t.Fatalf("InspectFontFile(cambria.ttc) failed: %v", err)
	}

	if !insp.IsCollection {
		t.Errorf("expected cambria.ttc to be recognized as collection")
	}
	if insp.NumFonts < 2 {
		t.Errorf("expected at least 2 fonts in cambria.ttc, got %d", insp.NumFonts)
	}

	// Verify Cambria index 0
	idx0, meta0, found0 := insp.FindFaceIndex("Cambria")
	if !found0 {
		t.Errorf("FindFaceIndex('Cambria') not found")
	}
	if idx0 != 0 {
		t.Errorf("expected Cambria index 0, got %d", idx0)
	}
	if meta0 != nil && meta0.Family != "Cambria" {
		t.Errorf("expected meta family 'Cambria', got %q", meta0.Family)
	}

	// Verify Cambria Math index 1
	idx1, meta1, found1 := insp.FindFaceIndex("Cambria Math")
	if !found1 {
		t.Errorf("FindFaceIndex('Cambria Math') not found")
	}
	if idx1 != 1 {
		t.Errorf("expected Cambria Math index 1, got %d", idx1)
	}
	if meta1 != nil && meta1.Family != "Cambria Math" {
		t.Errorf("expected meta family 'Cambria Math', got %q", meta1.Family)
	}
}

func TestLoadGioFontFaces(t *testing.T) {
	cambriaPath := filepath.Join(getSystemFontsDir(), "cambria.ttc")
	if _, err := os.Stat(cambriaPath); os.IsNotExist(err) {
		t.Skip("cambria.ttc not found on this machine, skipping test")
	}

	faces, err := LoadGioFontFaces(cambriaPath, 0, "CustomCambriaAlias")
	if err != nil {
		t.Fatalf("LoadGioFontFaces failed: %v", err)
	}

	if len(faces) < 2 {
		t.Errorf("expected at least 2 faces (original + alias), got %d", len(faces))
	}

	hasAlias := false
	for _, f := range faces {
		if string(f.Font.Typeface) == "CustomCambriaAlias" {
			hasAlias = true
			break
		}
	}
	if !hasAlias {
		t.Errorf("expected alias 'CustomCambriaAlias' to be registered in faces")
	}
}
