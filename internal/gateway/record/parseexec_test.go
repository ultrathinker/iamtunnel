package record

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The exec journal must come back out as the text a person can read.
//
// 22.09.2026. The owner ran a command through the gateway, opened its
// row in History, pressed Transcript and got an empty window. The window
// had exactly one reader in it -- ParseCast -- and an exec recording fed
// to ParseCast yields nothing and says nothing. This test writes a real
// recording with the real recorder and reads it back the way the window
// will, so the two formats can never again be one code path.
func TestParseExec_ReadsBackWhatTheRecorderWrote(t *testing.T) {
	dir := t.TempDir()
	r, err := NewExecRecorder(ExecConfig{
		SessionConfig: SessionConfig{
			BaseDir: dir, Person: "alice", Machine: "win-vm", SessionID: "s1",
		},
		Command: "git status",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write([]byte("On branch main\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.WriteStderr([]byte("warning: LF will be replaced\n")); err != nil {
		t.Fatal(err)
	}
	if err := r.ExitStatus(3); err != nil {
		t.Fatal(err)
	}
	if err := r.Finish(); err != nil {
		t.Fatal(err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "*.exec.jsonl"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected one .exec.jsonl in %s; got %v (%v)", dir, matches, err)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}

	vt := NewVT(100, 40)
	if rest := ParseExec(raw, nil, vt); len(rest) != 0 {
		t.Errorf("a complete journal left %d bytes unparsed: %q", len(rest), rest)
	}
	got := vt.Transcript()

	for _, want := range []string{"$ git status", "On branch main", "warning: LF will be replaced", "[exit status 3]"} {
		if !strings.Contains(got, want) {
			t.Errorf("transcript is missing %q; got:\n%s", want, got)
		}
	}

	// The defect itself: the OTHER reader on these same bytes produces
	// a blank page and no error. That is why the caller must choose by
	// the recording's mode and never by looking at the bytes.
	blind := NewVT(100, 40)
	ParseCast(raw, nil, blind)
	if strings.TrimSpace(blind.Transcript()) != "" {
		t.Fatalf("ParseCast has learned to read exec journals — this test's premise is stale; got:\n%s", blind.Transcript())
	}
}

// A chunk boundary in the middle of a line must not swallow the line.
func TestParseExec_SurvivesAChunkBoundaryMidLine(t *testing.T) {
	dir := t.TempDir()
	r, err := NewExecRecorder(ExecConfig{
		SessionConfig: SessionConfig{BaseDir: dir, Person: "bob", Machine: "m", SessionID: "s2"},
		Command:       "echo hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	if err := r.Finish(); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.exec.jsonl"))
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}

	// Split at every byte: no single cut may lose a word.
	for cut := 1; cut < len(raw); cut++ {
		vt := NewVT(100, 40)
		rest := ParseExec(raw[:cut], nil, vt)
		ParseExec(raw[cut:], rest, vt)
		got := vt.Transcript()
		if !strings.Contains(got, "$ echo hello") || !strings.Contains(got, "hello") {
			t.Fatalf("cut at %d lost the transcript; got:\n%s", cut, got)
		}
	}
}
