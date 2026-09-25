package record

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// ROUND 3 TESTS
// =============================================================================

// -----------------------------------------------------------------------------
// FIX 2: Machine Name Sanitization & Path Traversal Prevention
// -----------------------------------------------------------------------------

func TestMachineNameSanitizationAllForms(t *testing.T) {
	testCases := []struct {
		category string
		machine  string
	}{
		// 1. Directory traversal up
		{"traversal_dotdot_slash", "../../escaped"},
		{"traversal_dotdot_single", "../foo"},
		{"traversal_dotdot_backslash", "..\\foo"},
		{"traversal_mixed", "legit/../../escaped"},
		{"traversal_deep", "../../../../../../etc"},

		// 2. Absolute paths
		{"abs_unix_root", "/etc/passwd"},
		{"abs_unix_nested", "/var/log/iamtunnel"},
		{"abs_win_root", "\\Windows\\System32"},
		{"abs_win_nested", "\\Temp\\pwn"},

		// 3. Drive letters (Windows)
		{"drive_letter_backslash", "C:\\Windows\\System32"},
		{"drive_letter_forward", "D:/recordings/escaped"},
		{"drive_letter_relative", "c:relative"},
		{"drive_letter_bare", "E:"},

		// 4. Network UNC paths (Windows)
		{"unc_backslash", "\\\\server\\share\\audit"},
		{"unc_forward", "//server/share/audit"},

		// 5. Windows reserved device names (case-insensitive & with extensions)
		{"reserved_con", "CON"},
		{"reserved_prn", "prn"},
		{"reserved_aux", "AUX"},
		{"reserved_nul", "NUL"},
		{"reserved_com1", "COM1"},
		{"reserved_com9", "com9"},
		{"reserved_lpt1", "LPT1"},
		{"reserved_lpt9", "lpt9"},
		{"reserved_con_ext", "con.txt"},
		{"reserved_nul_ext", "NUL.dat"},

		// 6. Slashes of both kinds
		{"mixed_slashes", "domain/sub\\machine"},
		{"trailing_slash", "domain/sub/machine/"},
		{"trailing_backslash", "domain\\sub\\machine\\"},

		// 7. Empty name
		{"empty", ""},
		{"spaces_only", "    "},

		// 8. Dot-only names
		{"single_dot", "."},
		{"double_dot", ".."},
		{"triple_dot", "..."},
		{"quad_dot", "...."},

		// 9. Trailing spaces or dots (silently stripped by Win32 filesystem)
		{"trailing_single_dot", "web-server."},
		{"trailing_multi_dots", "db-cluster..."},
		{"trailing_space", "app-server "},
		{"trailing_multi_spaces", "backup-node   "},
		{"trailing_dot_and_space", "gw-host. "},
		{"reserved_with_trailing_dot", "CON."},
		{"reserved_with_trailing_space", "NUL "},
	}

	for _, tc := range testCases {
		t.Run(tc.category, func(t *testing.T) {
			baseDir := t.TempDir()

			cfg := SessionConfig{
				BaseDir:      baseDir,
				Machine:      tc.machine,
				Person:       "auditor",
				SessionID:    "test-sess-1",
				SubdirLayout: true,
			}

			rec, err := NewRecorder(cfg)
			if err != nil {
				t.Fatalf("NewRecorder failed on machine name %q (%s): %v", tc.machine, tc.category, err)
			}
			defer rec.Close()

			paths := rec.Paths()

			// INVARIANT: every generated path MUST strictly reside inside baseDir
			cleanBase := filepath.Clean(baseDir)
			for _, p := range []string{paths.CastPath, paths.TxtPath, paths.MetaPath} {
				cleanP := filepath.Clean(p)
				rel, err := filepath.Rel(cleanBase, cleanP)
				if err != nil {
					t.Fatalf("filepath.Rel failed for %s vs %s: %v", cleanP, cleanBase, err)
				}
				if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					t.Fatalf("SECURITY ESCAPE VIOLATION: path %s escaped baseDir %s (rel: %s) for input %q",
						cleanP, cleanBase, rel, tc.machine)
				}
			}

			// Verify file can actually be written and closed on the local filesystem
			if _, err := rec.Write([]byte("test output\r\n")); err != nil {
				t.Fatalf("rec.Write failed: %v", err)
			}
			if err := rec.Close(); err != nil {
				t.Fatalf("rec.Close failed: %v", err)
			}

			// Verify all 3 files exist on disk
			for _, p := range []string{paths.CastPath, paths.TxtPath, paths.MetaPath} {
				if _, err := os.Stat(p); err != nil {
					t.Fatalf("file does not exist on disk: %s (%v)", p, err)
				}
			}
		})
	}
}

// TestBasePathTraversalRejected tests that explicitly overriding BasePath
// cannot escape the configured BaseDir.
func TestBasePathTraversalRejected(t *testing.T) {
	baseDir := t.TempDir()

	// 1. Escaping BasePath with ".." must fail
	_, err := NewRecorder(SessionConfig{
		BaseDir:   baseDir,
		BasePath:  "../../escaped-recording",
		Person:    "auditor",
		SessionID: "pwn-1",
	})
	if err == nil {
		t.Fatalf("expected NewRecorder to reject BasePath with '..' escaping BaseDir, but it succeeded")
	}

	// 2. Absolute BasePath pointing outside baseDir must fail
	otherDir := t.TempDir()
	outsidePath := filepath.Join(otherDir, "outside-sess")
	_, err = NewRecorder(SessionConfig{
		BaseDir:   baseDir,
		BasePath:  outsidePath,
		Person:    "auditor",
		SessionID: "pwn-2",
	})
	if err == nil {
		t.Fatalf("expected NewRecorder to reject absolute BasePath outside BaseDir, but it succeeded")
	}

	// 3. Relative BasePath within baseDir must succeed
	rec, err := NewRecorder(SessionConfig{
		BaseDir:   baseDir,
		BasePath:  filepath.Join("sub", "valid-sess"),
		Person:    "auditor",
		SessionID: "ok-1",
	})
	if err != nil {
		t.Fatalf("NewRecorder failed on valid relative BasePath: %v", err)
	}
	defer rec.Close()

	rel, err := filepath.Rel(baseDir, rec.Paths().CastPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("valid BasePath escaped baseDir: %s", rec.Paths().CastPath)
	}
}

// -----------------------------------------------------------------------------
// FIX 4: Scrollback Ceiling Honest Truncation Notice
// -----------------------------------------------------------------------------

func TestScrollbackCeilingHonestTruncationNotice(t *testing.T) {
	vt := NewVT(80, 24)

	// Feed 25,500 lines into VT: past the head the transcript keeps and the
	// ring together (2 x maxHistoryLines since R4 F-05), so the middle goes.
	totalLines := 25500
	for i := 0; i < totalLines; i++ {
		line := fmt.Sprintf("LOG-ENTRY-%06d\r\n", i)
		_, err := vt.Write([]byte(line))
		if err != nil {
			t.Fatalf("vt.Write failed at line %d: %v", i, err)
		}
	}

	dropped := vt.DroppedHistoryLines()
	if dropped <= 0 {
		t.Fatalf("expected droppedHistoryLines > 0 after %d lines, got %d", totalLines, dropped)
	}

	transcript := vt.Transcript()
	lines := strings.Split(transcript, "\n")
	if len(lines) == 0 {
		t.Fatalf("transcript is empty")
	}

	if lines[0] != "LOG-ENTRY-000000" {
		t.Fatalf("the transcript must keep the session's first line (R4 F-05), got: %q", lines[0])
	}
	omitted := vt.OmittedLines()
	if omitted <= 0 {
		t.Fatalf("expected OmittedLines > 0 after %d lines, got %d", totalLines, omitted)
	}
	// The honest notice stands where the lines are missing.
	var notice string
	for _, l := range lines {
		if strings.Contains(l, "truncated") && strings.Contains(l, "omitted") {
			notice = l
			break
		}
	}
	if notice == "" {
		t.Fatalf("expected an honest truncation notice in the transcript")
	}

	expectedNoticeSubstr := fmt.Sprintf("%d lines truncated", omitted)
	if !strings.Contains(notice, expectedNoticeSubstr) {
		t.Errorf("notice does not mention exact omitted count %d: got %q", omitted, notice)
	}

	expectedNoticeOmitted := fmt.Sprintf("%d lines omitted", omitted)
	if !strings.Contains(notice, expectedNoticeOmitted) {
		t.Errorf("notice does not mention the omitted count: got %q", notice)
	}
}

func TestScrollbackNoTruncationNoticeWhenUnderLimit(t *testing.T) {
	vt := NewVT(80, 24)

	// Write 50 lines (well under maxHistoryLines = 10,000)
	for i := 0; i < 50; i++ {
		_, _ = vt.Write([]byte(fmt.Sprintf("NORMAL-LINE-%02d\r\n", i)))
	}

	if vt.DroppedHistoryLines() != 0 {
		t.Fatalf("expected 0 dropped lines, got %d", vt.DroppedHistoryLines())
	}

	transcript := vt.Transcript()
	if strings.Contains(transcript, "truncated") || strings.Contains(transcript, "omitted") {
		t.Fatalf("transcript should NOT contain truncation notice when under limit: %q", transcript[:min(100, len(transcript))])
	}
}
