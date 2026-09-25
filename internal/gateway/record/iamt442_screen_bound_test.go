package record

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// IAMT-442, the second line. However a size reaches the emulator - a new
// session, a resize, a replay from scratch, a .cast header or "r" event
// read back in the window - the screen it allocates stays inside the
// bound, 1000 columns by 500 rows. The gateway clamps the request where
// it parses it; this is what holds if some future path forgets to, and
// what holds for a .cast the window reads, whoever wrote it.
//
// Sizes just past the bound, not 2^32-1: the emulator before the fix had
// to survive the test in order to fail it on its own line.
func TestIAMT442_EmulatorKeepsItsScreenInsideTheBound(t *testing.T) {
	const wantCols, wantRows = 1000, 500

	check := func(what string, v *VT) {
		t.Helper()
		if c, r := v.Size(); c != wantCols || r != wantRows {
			t.Errorf("%s: the screen is %dx%d, want the bound %dx%d", what, c, r, wantCols, wantRows)
		}
	}

	check("NewVT(1500, 800)", NewVT(1500, 800))

	v := NewVT(80, 24)
	v.Resize(1600, 900)
	check("Resize(1600, 900)", v)

	v = NewVT(80, 24)
	v.Reset(1700, 1000)
	check("Reset(1700, 1000)", v)

	v = NewVT(80, 24)
	ParseCast([]byte(`{"version":2,"width":1500,"height":800}`+"\n"), nil, v)
	check("a .cast header of 1500x800", v)

	v = NewVT(80, 24)
	ParseCast([]byte(`[0.5,"r","1600x900"]`+"\n"), nil, v)
	check(`a .cast "r" event of 1600x900`, v)
}

// The recorder writes the size into the .cast it keeps: the header and
// every "r" event must say the size the emulator really parsed in, or a
// replay of the file later is parsed in a different geometry from the
// transcript written beside it.
func TestIAMT442_RecorderWritesTheBoundedSize(t *testing.T) {
	rec, err := NewRecorder(SessionConfig{BaseDir: t.TempDir(), Person: "alice", SessionID: "iamt442", Cols: 1500, Rows: 800})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	if err := rec.Resize(1600, 900); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(rec.Paths().CastPath)
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	headerLine := raw
	if i := bytes.IndexByte(raw, '\n'); i >= 0 {
		headerLine = raw[:i]
	}
	var header struct{ Width, Height int }
	if err := json.Unmarshal(headerLine, &header); err != nil {
		t.Fatalf("decode cast header: %v", err)
	}
	if header.Width != 1000 || header.Height != 500 {
		t.Errorf("the .cast header is %dx%d for a session opened at 1500x800, want the bound 1000x500", header.Width, header.Height)
	}
	if !strings.Contains(string(raw), `"r","1000x500"`) {
		t.Errorf("the .cast \"r\" event does not say the bounded size 1000x500:\n%s", raw)
	}
	if m := rec.Metadata(); m.WindowSize.Cols != 1000 || m.WindowSize.Rows != 500 {
		t.Errorf("the metadata says %dx%d, want 1000x500", m.WindowSize.Cols, m.WindowSize.Rows)
	}
}
