package record

import (
	"math"
	"os"
	"strings"
	"testing"
)

// iamt441Call runs f and returns what it panicked with, if anything.
func iamt441Call(f func()) (panicked any) {
	defer func() { panicked = recover() }()
	f()
	return nil
}

// TestIAMT441_RecorderTurnsAnEmulatorFaultIntoAnError is the recorder's
// half of the second line (IAMT-441). Whatever the terminal emulator gets
// wrong ends as an error on this one recording: never as a panic out of
// Write into the bridge's copy goroutine, and never again out of Abort in
// the session goroutine that finalizes the recording - either one ends
// the gateway process, and every session on it.
//
// The fault is planted directly - a cursor far off the screen, the state
// the overflow used to leave - because once the arithmetic is right no
// byte sequence is known to reach it. That is what a second line is for.
func TestIAMT441_RecorderTurnsAnEmulatorFaultIntoAnError(t *testing.T) {
	rec, err := NewRecorder(SessionConfig{BaseDir: t.TempDir(), Person: "alice", SessionID: "iamt441", Cols: 80, Rows: 24})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	// Close the .cast even when the test stops early: Windows cannot
	// remove a temp directory holding an open file, and would leave it.
	t.Cleanup(func() { iamt441Call(func() { _ = rec.Abort("test cleanup") }) })
	if _, err := rec.Write([]byte("before the fault\r\n")); err != nil {
		t.Fatalf("a clean chunk did not record: %v", err)
	}

	rec.vt.cursorX = math.MinInt

	var werr error
	if p := iamt441Call(func() { _, werr = rec.Write([]byte("X")) }); p != nil {
		t.Fatalf("Recorder.Write let the emulator's panic out into the bridge goroutine: %v", p)
	}
	if werr == nil {
		t.Errorf("Recorder.Write reported success for a chunk the transcript could not take")
	}

	var werr2 error
	if p := iamt441Call(func() { _, werr2 = rec.Write([]byte("Y")) }); p != nil {
		t.Fatalf("a Write after the fault panicked: %v", p)
	}
	if werr2 == nil {
		t.Errorf("a Write after the fault reported success: the faulted emulator must not be fed again")
	}

	if p := iamt441Call(func() { _ = rec.Resize(100, 30) }); p != nil {
		t.Fatalf("Recorder.Resize panicked on the faulted emulator: %v", p)
	}

	if p := iamt441Call(func() { _ = rec.Abort("session aborted") }); p != nil {
		t.Fatalf("Recorder.Abort panicked on the faulted emulator: %v", p)
	}

	meta := rec.Metadata()
	if meta.Status != "error" {
		t.Errorf("the recording ended with status %q, want \"error\": its transcript stops at the fault", meta.Status)
	}
	txt, err := os.ReadFile(rec.Paths().TxtPath)
	if err != nil {
		t.Fatalf("read the transcript: %v", err)
	}
	if !strings.Contains(string(txt), "before the fault") {
		t.Errorf("the transcript lost what was drawn before the fault: %q", txt)
	}
	cast, err := os.ReadFile(rec.Paths().CastPath)
	if err != nil {
		t.Fatalf("read the cast: %v", err)
	}
	if !strings.Contains(string(cast), `"X"`) {
		t.Errorf("the chunk that tripped the emulator is missing from the .cast, which is the record:\n%s", cast)
	}
}
