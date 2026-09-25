package record

import (
	"path/filepath"
	"strings"
	"testing"
)

// escapes reports a genuine path escape, not merely a name that starts with dots.
func escapes(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func TestOrch3Traversal(t *testing.T) {
	bad := []string{
		"../../escaped", `..\..\escaped`, "/abs", `C:\abs`, `\server\share`,
		"..", ".", "", "  ", "a/../../b", "con", "nul", "name.", "name ",
		"a\x00b", "üñî", strings.Repeat("x", 400),
	}
	for _, m := range bad {
		base := t.TempDir()
		rec, err := NewRecorder(SessionConfig{
			BaseDir: base, Machine: m, Person: "eve",
			SessionID: "s1", SubdirLayout: true,
		})
		if err != nil {
			continue // refusing is a valid answer
		}
		p := rec.Paths().CastPath
		_ = rec.Close()
		rel, rerr := filepath.Rel(base, p)
		if rerr != nil || escapes(rel) || filepath.IsAbs(rel) {
			t.Errorf("machine %q escaped base: %s (rel=%q)", m, p, rel)
		}
	}
}

func TestOrch3BasePathTraversal(t *testing.T) {
	base := t.TempDir()
	rec, err := NewRecorder(SessionConfig{
		BaseDir: base, Machine: "win01", Person: "eve", SessionID: "s1",
		BasePath: filepath.Join(base, "..", "..", "escaped", "x"),
	})
	if err != nil {
		return
	}
	p := rec.Paths().CastPath
	_ = rec.Close()
	rel, rerr := filepath.Rel(base, p)
	if rerr != nil || escapes(rel) {
		t.Fatalf("BasePath escaped base: %s", p)
	}
}
