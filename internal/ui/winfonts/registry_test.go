//go:build windows

package winfonts

import (
	"path/filepath"
	"testing"
)

func TestCleanRegistryFontName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Sitka Text (TrueType)", "Sitka Text"},
		{"Cambria & Cambria Math (TrueType)", "Cambria & Cambria Math"},
		{"Georgia (TrueType)", "Georgia"},
		{"Consolas (TrueType)", "Consolas"},
		{"Cascadia Mono Regular (TrueType)", "Cascadia Mono Regular"},
		{"Open Sans (OpenType)", "Open Sans"},
		{"Arial (All subsets)", "Arial"},
		{"Already Clean", "Already Clean"},
	}

	for _, tc := range tests {
		got := CleanRegistryFontName(tc.input)
		if got != tc.expected {
			t.Errorf("CleanRegistryFontName(%q) = %q; want %q", tc.input, got, tc.expected)
		}
	}
}

func TestRegistryReaderAndMatching(t *testing.T) {
	mockEntries := map[string]string{
		"Sitka Text (TrueType)":             "SitkaVF.ttf",
		"Cambria & Cambria Math (TrueType)": "cambria.ttc",
		"Georgia (TrueType)":                "georgia.ttf",
		"Consolas (TrueType)":               "consola.ttf",
		"Cascadia Mono Regular (TrueType)":  "CascadiaMono.ttf",
		"CustomFont (TrueType)":             `D:\Fonts\CustomFont.ttf`,
	}

	mockReader := &MockRegistryReader{
		Entries:  mockEntries,
		FontsDir: `C:\Windows\Fonts`,
	}

	entries, err := mockReader.ReadFontValues()
	if err != nil {
		t.Fatalf("ReadFontValues failed: %v", err)
	}

	if len(entries) != len(mockEntries) {
		t.Fatalf("expected %d entries, got %d", len(mockEntries), len(entries))
	}

	// Verify path joining
	for _, e := range entries {
		if e.FileName == "SitkaVF.ttf" {
			expected := filepath.Join(`C:\Windows\Fonts`, "SitkaVF.ttf")
			if e.FilePath != expected {
				t.Errorf("expected FilePath %q, got %q", expected, e.FilePath)
			}
		}
		if e.FileName == `D:\Fonts\CustomFont.ttf` {
			if e.FilePath != `D:\Fonts\CustomFont.ttf` {
				t.Errorf("expected absolute FilePath unchanged, got %q", e.FilePath)
			}
		}
	}

	// Test MatchRegistryEntry
	tests := []struct {
		target   string
		expected string
		found    bool
	}{
		{"Sitka Text", "SitkaVF.ttf", true},
		{"Cambria", "cambria.ttc", true},
		{"Cambria Math", "cambria.ttc", true},
		{"Georgia", "georgia.ttf", true},
		{"Consolas", "consola.ttf", true},
		{"Cascadia Mono", "CascadiaMono.ttf", true},
		{"NonExistentFont", "", false},
	}

	for _, tc := range tests {
		entry, found := MatchRegistryEntry(entries, tc.target)
		if found != tc.found {
			t.Errorf("MatchRegistryEntry(%q) found = %v; want %v", tc.target, found, tc.found)
			continue
		}
		if found && entry.FileName != tc.expected {
			t.Errorf("MatchRegistryEntry(%q) FileName = %q; want %q", tc.target, entry.FileName, tc.expected)
		}
	}
}
