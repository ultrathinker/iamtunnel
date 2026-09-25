//go:build windows

package winfonts

import (
	"testing"
)

func TestResolvePreference_Selection(t *testing.T) {
	resolver := NewResolver()

	// 1. Serif preference list: Sitka Display is absent, Sitka Text is present
	prefSerif := []string{"Sitka Display", "Sitka Text", "Cambria", "Georgia"}
	resSerif, err := resolver.ResolvePreference(prefSerif, "serif")
	if err != nil {
		t.Fatalf("ResolvePreference(serif) failed: %v", err)
	}

	if resSerif.IsFallback {
		t.Errorf("expected to find a system font for serif, but fell back to gofont")
	}

	// Should have selected Sitka Text (since Sitka Display is absent on modern Win10/11)
	if resSerif.Family != "Sitka Text" && resSerif.Family != "Cambria" && resSerif.Family != "Georgia" {
		t.Errorf("expected one of system serif fonts, got %q", resSerif.Family)
	}

	if len(resSerif.Faces) == 0 {
		t.Errorf("expected non-empty Gio faces")
	}

	// 2. Mono preference list: Cascadia Mono -> Consolas
	prefMono := []string{"Cascadia Mono", "Consolas"}
	resMono, err := resolver.ResolvePreference(prefMono, "mono")
	if err != nil {
		t.Fatalf("ResolvePreference(mono) failed: %v", err)
	}

	if resMono.IsFallback {
		t.Errorf("expected to find system mono font, but fell back to gofont")
	}

	if resMono.Family != "Cascadia Mono" && resMono.Family != "Consolas" {
		t.Errorf("expected Cascadia Mono or Consolas, got %q", resMono.Family)
	}

	// 3. Substituted preference starting with lower priority
	prefCambriaFirst := []string{"NonExistentFont1", "Cambria", "Georgia"}
	resCambria, err := resolver.ResolvePreference(prefCambriaFirst, "serif")
	if err != nil {
		t.Fatalf("ResolvePreference failed: %v", err)
	}
	if resCambria.Family != "Cambria" {
		t.Errorf("expected Cambria, got %q", resCambria.Family)
	}
	if !resCambria.IsCollection {
		t.Errorf("expected Cambria to be recognized as collection (.ttc)")
	}
	if resCambria.FaceIndex != 0 {
		t.Errorf("expected Cambria collection face index 0, got %d", resCambria.FaceIndex)
	}
}

func TestResolvePreference_Fallback(t *testing.T) {
	resolver := NewResolver()

	// Intentionally non-existent font names
	fakePreferences := []string{
		"CompletelyBogusFont_XYZ_123",
		"NoSuchSerifFontInUniverse",
		"FakeFontFace404",
	}

	res, err := resolver.ResolvePreference(fakePreferences, "fallback-test")
	if err != nil {
		t.Fatalf("ResolvePreference should not error on fallback, got: %v", err)
	}

	// Must fall back to gofont
	if !res.IsFallback {
		t.Fatalf("expected IsFallback == true, but got false")
	}

	if res.Family != "Go" {
		t.Errorf("expected Family 'Go', got %q", res.Family)
	}

	if res.FilePath != "(embedded gofont)" {
		t.Errorf("expected FilePath '(embedded gofont)', got %q", res.FilePath)
	}

	if len(res.Faces) == 0 {
		t.Fatalf("expected non-empty fallback faces from gofont")
	}
}

// TestResolvePreference_EmptyList proves that when given an empty font list,
// the program does not panic or fail, but calmly steps down to the built-in fallback.
// This is an explicit requirement, Gate 3.
func TestResolvePreference_EmptyList(t *testing.T) {
	resolver := NewResolver()

	emptyList := []string{}
	res, err := resolver.ResolvePreference(emptyList, "serif")
	if err != nil {
		t.Fatalf("ResolvePreference with empty list failed: %v", err)
	}

	if !res.IsFallback {
		t.Errorf("expected IsFallback == true for empty list, got false")
	}

	if res.Family != "Go" {
		t.Errorf("expected Family 'Go', got %q", res.Family)
	}

	if res.FilePath != "(embedded gofont)" {
		t.Errorf("expected FilePath '(embedded gofont)', got %q", res.FilePath)
	}

	if len(res.Faces) == 0 {
		t.Fatalf("expected non-empty fallback faces from gofont")
	}
}

func TestFindAllFonts(t *testing.T) {
	resolver := NewResolver()
	targets := []string{
		"Sitka Display",
		"Sitka Text",
		"Cambria",
		"Georgia",
		"Cascadia Mono",
		"Consolas",
	}

	reports, err := resolver.FindAllFonts(targets)
	if err != nil {
		t.Fatalf("FindAllFonts failed: %v", err)
	}

	foundCount := 0
	for _, r := range reports {
		if r.Loaded {
			foundCount++
		}
	}

	// Gate 1 check: Minimum 4 found faces on this machine
	if foundCount < 4 {
		t.Fatalf("expected at least 4 found faces, got %d", foundCount)
	}
}
