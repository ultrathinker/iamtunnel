//go:build windows

package winfonts

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RegistryFontEntry represents a raw font record found in the Windows registry.
type RegistryFontEntry struct {
	ValueName string // Full registry value name, e.g. "Cambria & Cambria Math (TrueType)"
	CleanName string // Name stripped of format suffix, e.g. "Cambria & Cambria Math"
	FileName  string // File name stored in registry, e.g. "cambria.ttc"
	FilePath  string // Full absolute path to font file on disk
}

// CleanRegistryFontName removes common format suffixes from registry font names.
func CleanRegistryFontName(name string) string {
	s := strings.TrimSpace(name)
	suffixes := []string{
		" (TrueType)",
		" (OpenType)",
		" (All subsets)",
		" (Type 1)",
	}
	for _, suf := range suffixes {
		s = strings.TrimSuffix(s, suf)
	}
	return strings.TrimSpace(s)
}

// RegistryReader interface allows decoupling registry reading for unit testing.
type RegistryReader interface {
	ReadFontValues() ([]RegistryFontEntry, error)
}

// SystemRegistryReader reads font registrations from the Windows registry.
type SystemRegistryReader struct {
	KeyPath  string
	FontsDir string
}

// NewSystemRegistryReader creates a new SystemRegistryReader with default Windows paths.
func NewSystemRegistryReader() *SystemRegistryReader {
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = `C:\Windows`
	}
	return &SystemRegistryReader{
		KeyPath:  `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts`,
		FontsDir: filepath.Join(windir, "Fonts"),
	}
}

// ReadFontValues reads all font values from HKLM.
func (r *SystemRegistryReader) ReadFontValues() ([]RegistryFontEntry, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, r.KeyPath, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	var entries []RegistryFontEntry
	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err != nil {
			continue
		}
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}

		fullPath := val
		if !filepath.IsAbs(fullPath) {
			fullPath = filepath.Join(r.FontsDir, val)
		}

		clean := CleanRegistryFontName(name)
		entries = append(entries, RegistryFontEntry{
			ValueName: name,
			CleanName: clean,
			FileName:  val,
			FilePath:  fullPath,
		})
	}

	return entries, nil
}

// MockRegistryReader is an in-memory mock for testing registry parsing.
type MockRegistryReader struct {
	Entries  map[string]string // ValueName -> FileName
	FontsDir string
}

func (m *MockRegistryReader) ReadFontValues() ([]RegistryFontEntry, error) {
	var entries []RegistryFontEntry
	for k, v := range m.Entries {
		fp := v
		if !filepath.IsAbs(fp) && m.FontsDir != "" {
			fp = filepath.Join(m.FontsDir, v)
		}
		entries = append(entries, RegistryFontEntry{
			ValueName: k,
			CleanName: CleanRegistryFontName(k),
			FileName:  v,
			FilePath:  fp,
		})
	}
	return entries, nil
}
