package record

// Tests written independently of the implementation, round 3.
// None of them repeats the name/sequence shapes used by the main test files.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// 1. §3.1: no path from the connecting code may put an "input" event into the recording.
// -----------------------------------------------------------------------------

func TestRev3NoTypedInputEventReachableFromAPI(t *testing.T) {
	// 1a. Reflection: no type in the package has a method that writes input.
	for _, tc := range []struct {
		name string
		typ  reflect.Type
	}{
		{"Recorder", reflect.TypeOf((*Recorder)(nil))},
		{"CastWriter", reflect.TypeOf((*CastWriter)(nil))},
		{"VT", reflect.TypeOf((*VT)(nil))},
	} {
		for i := 0; i < tc.typ.NumMethod(); i++ {
			m := tc.typ.Method(i).Name
			low := strings.ToLower(m)
			for _, bad := range []string{"input", "stdin", "keystroke", "password", "typein"} {
				if strings.Contains(low, bad) {
					t.Fatalf("SECURITY: %s exports method %q (contains %q) — typed-input path exists", tc.name, m, bad)
				}
			}
		}
	}

	// 1b. A full session through ALL exported methods that reach the recording.
	//  A fake "i" event line is planted into the output data — it must remain
	//  escaped DATA of an "o" event, not become a separate line.
	baseDir := t.TempDir()
	rec, err := NewRecorder(SessionConfig{
		BaseDir: baseDir, Machine: "win11-x", Person: "rev3", SessionID: "inp-1",
		Clock: NewSimClock(testBaseTime),
	})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	injected := `[1.5,"i","P4ssw0rd"]`
	if _, err := rec.Write([]byte("user typed: " + injected + "\r\n")); err != nil {
		t.Fatalf("Write 1: %v", err)
	}
	if _, err := rec.Write([]byte("\x1b[2;3H\x1b]0;title\x07some output\r\n")); err != nil {
		t.Fatalf("Write 2: %v", err)
	}
	if err := rec.Resize(100, 30); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if err := rec.CloseWithReason("completed", false, "rev3 close"); err != nil {
		t.Fatalf("CloseWithReason: %v", err)
	}

	f, err := os.Open(rec.Paths().CastPath)
	if err != nil {
		t.Fatalf("open cast: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	eventCount := 0
	lastT := -1.0
	for sc.Scan() {
		lineNo++
		raw := sc.Bytes()
		if lineNo == 1 {
			var hdr CastHeader
			if err := json.Unmarshal(raw, &hdr); err != nil {
				t.Fatalf("header: %v", err)
			}
			if hdr.Version != 2 {
				t.Fatalf("header version %d", hdr.Version)
			}
			continue
		}
		var ev []any
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatalf("line %d is not a JSON array (injection?): %v; line=%s", lineNo, err, raw)
		}
		if len(ev) != 3 {
			t.Fatalf("line %d: expected [t,type,data], got %v", lineNo, ev)
		}
		tt, _ := ev[0].(float64)
		et, _ := ev[1].(string)
		if et != "o" && et != "r" {
			t.Fatalf("SECURITY: event type %q at line %d — only \"o\"/\"r\" allowed; line=%s", et, lineNo, raw)
		}
		if et == "o" && strings.Contains(ev[2].(string), "P4ssw0rd") {
			// Allowed ONLY as an echo inside "o" data — that is the output content itself.
			if !strings.Contains(ev[2].(string), "user typed: "+injected) {
				t.Fatalf("injected payload appeared outside expected echo context: %q", ev[2])
			}
		}
		if tt < lastT {
			t.Fatalf("time went backwards: %v after %v", tt, lastT)
		}
		lastT = tt
		eventCount++
	}
	if eventCount != 3 {
		t.Fatalf("expected exactly 3 events (2×o + 1×r), got %d", eventCount)
	}

	// 1c. The underlying format writer: "i" is rejected and the buffer is left
	//  untouched; the other spellings ("I", " in", "input", "m", "") — documented.
	var buf bytes.Buffer
	cw := NewCastWriter(&buf)
	if err := cw.WriteEvent(1.25, "i", "SecretPassword123\n"); err == nil {
		t.Fatalf("WriteEvent('i') must return error, got nil")
	}
	if buf.Len() != 0 {
		t.Fatalf("buffer must stay empty after rejected 'i', got %q", buf.String())
	}
	for _, spelling := range []string{"I", " in", "in", "input", "INPUT", "m", ""} {
		buf.Reset()
		err := cw.WriteEvent(0.5, spelling, "x")
		if err == nil {
			t.Logf("WriteEvent type %-8q → accepted, wrote into the CALLER'S OWN buffer: %s (cannot reach a Recorder recording: castCW is not exported)", spelling, strings.TrimRight(buf.String(), "\n"))
		} else {
			t.Logf("WriteEvent type %-8q → rejected: %v", spelling, err)
			if buf.Len() != 0 {
				t.Fatalf("spelling %q rejected but buffer written", spelling)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// 2. §3.2: OWN forms of hostile names. The invariant is checked against the
//    ACTUAL position of files on disk (tree walk + parent chain), not against
//    the path string.
// -----------------------------------------------------------------------------

func TestRev3HostileMachineNamesRealDiskLocation(t *testing.T) {
	forms := []struct {
		name    string
		machine string
	}{
		// Reserved Windows names ABSENT from the authorial list.
		{"reserved_conin", "CONIN$"},
		{"reserved_conout", "CONOUT$"},
		{"reserved_clock", "CLOCK$"},
		{"reserved_com_superscript", "COM¹"},
		{"reserved_with_tab", "con\t"},
		// Unicode normalized by Win32 to a dot: candidates for escaping through "..".
		{"unicode_dot_ff0e_x2", "．．"},
		{"unicode_dot_u3002_x2", "。。"},
		{"unicode_dot_ff61_x2", "｡｡"},
		{"unicode_dot_mixed_ascii", ".。."},
		{"unicode_dot_x4_u3002", "。。。。"},
		{"unicode_dot_internal", "a．．b"},
		{"trailing_ff0e", "host．"},
		{"trailing_u3002", "host。"},
		{"trailing_ff61", "host｡"},
		{"reserved_plus_unicode_dot", "NUL。txt"},
		{"one_dot_leader_x2", "․․"},
		// Unicode separators (must not split a component).
		{"only_fullwidth_solidus", "／／／"},
		{"fraction_slash", "a⁄b⁄c"},
		{"division_slash", "a∕b"},
		{"trailing_ideographic_space", "host　"},
		{"trailing_newline", "host\n"},
		// 8.3 short names.
		{"shortname_83", "SERVIC~1"},
		{"only_tilde_one", "~1"},
		// ADS via a colon.
		{"ads_colon_form", "host:secret.txt"},
		// A name made entirely of separators.
		{"only_slashes_fwd", "////"},
		{"only_slashes_mixed", "\\/\\//"},
		{"single_backslash", "\\"},
		// Length: exactly the NTFS component limit and beyond it.
		{"ntfs_component_max_255", strings.Repeat("x", 255)},
		{"component_over_limit_300", strings.Repeat("y", 300)},
		// Collision with the service default.
		{"default_collision", "unknown-machine"},
	}

	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Dir(base)

			// Snapshot of the parent directory before the write.
			before, _ := os.ReadDir(parent)

			rec, err := NewRecorder(SessionConfig{
				BaseDir: base, Machine: form.machine,
				Person: "rev3", SessionID: "n1",
				SubdirLayout: true, // SPEC §6.5: recordings/<machine>/<date>/<...> — the machine name is in the path
				Clock:        NewSimClock(testBaseTime),
			})
			if err != nil {
				t.Logf("outcome: REFUSED (fail-closed): %v", err)
				// The refusal must be complete: no session file anywhere in the parent chain.
				want := "120000-rev3-n1.cast"
				for anc := parent; ; anc = filepath.Dir(anc) {
					if _, e := os.Stat(filepath.Join(anc, want)); e == nil {
						t.Fatalf("rejected, but session file exists OUTSIDE base at %s", filepath.Join(anc, want))
					}
					if anc == filepath.Dir(anc) {
						break
					}
				}
				return
			}

			if _, werr := rec.Write([]byte("probe output\r\n")); werr != nil {
				t.Fatalf("Write: %v", werr)
			}
			if cerr := rec.Close(); cerr != nil {
				t.Logf("Close returned an error (fail-closed is acceptable): %v", cerr)
			}

			want := filepath.Base(rec.Paths().CastPath)

			// (a) The files must exist in the base tree OR (b) nowhere outside it.
			inTree := false
			_ = filepath.WalkDir(base, func(p string, d os.DirEntry, werr error) error {
				if werr != nil || d.IsDir() {
					return nil // long paths: keep walking; what we found, we found
				}
				if d.Name() == want {
					inTree = true
				}
				return nil
			})

			stray := ""
			for anc := parent; ; anc = filepath.Dir(anc) {
				p := filepath.Join(anc, want)
				if _, e := os.Stat(p); e == nil {
					stray = p
					break
				}
				if anc == filepath.Dir(anc) {
					break
				}
			}

			// (c) NO new entries may appear in the parent chain.
			after, _ := os.ReadDir(parent)
			newInParent := map[string]bool{}
			now := map[string]bool{}
			for _, e := range after {
				now[e.Name()] = true
			}
			for _, e := range before {
				delete(now, e.Name())
			}
			for n := range now {
				newInParent[n] = true
			}
			if len(newInParent) > 0 {
				names := make([]string, 0, len(newInParent))
				for n := range newInParent {
					names = append(names, n)
				}
				t.Fatalf("ESCAPE: a recording appeared OUTSIDE base: %v appeared in parent %s (form=%q)", names, parent, form.machine)
			}
			if stray != "" {
				t.Fatalf("ESCAPE: session file found outside base: %s (form=%q, reported=%s)", stray, form.machine, rec.Paths().CastPath)
			}
			if !inTree {
				t.Fatalf("session files found neither in the base tree nor outside — the recording is lost (form=%q)", form.machine)
			}
			t.Logf("outcome: SANITIZED to a safe form, inside base; the machine directory on disk: %s", machineDirOnDisk(t, base))
		})
	}
}

// machineDirOnDisk — what the machine directory inside base is actually named (after Win32 normalization).
func machineDirOnDisk(t *testing.T, base string) string {
	t.Helper()
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) == 0 {
		return "<unreadable>"
	}
	return entries[0].Name()
}

// -----------------------------------------------------------------------------
// 3. §3.4: the exactness of the truncation count and the honesty of the marker.
// -----------------------------------------------------------------------------

const rev3Rows = 24

func rev3FeedLines(vt *VT, from, to int) {
	var sb strings.Builder
	for i := from; i < to; i++ {
		fmt.Fprintf(&sb, "L%05d\r\n", i)
	}
	_, _ = vt.Write([]byte(sb.String()))
}

// rev3WholeHistory checks a transcript that has lost nothing: no marker,
// and it begins with the session's first line.
func rev3WholeHistory(t *testing.T, vt *VT) {
	t.Helper()
	marker, rest := rev3MarkerOf(vt.Transcript())
	if marker != "" {
		t.Fatalf("no line is missing yet, but the transcript carries a marker: %q", marker)
	}
	if len(rest) == 0 || rest[0] != "L00000" {
		t.Fatalf("first line = %v, want L00000", firstOf(rest))
	}
	if got := vt.OmittedLines(); got != 0 {
		t.Fatalf("OmittedLines = %d, want 0", got)
	}
}

func rev3MarkerOf(transcript string) (string, []string) {
	lines := strings.Split(transcript, "\n")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "[... ") {
		return lines[0], lines[1:]
	}
	return "", lines
}

func TestRev3TruncationExactCountAndHonestMarker(t *testing.T) {
	t.Run("exact_ceiling_no_notice", func(t *testing.T) {
		vt := NewVT(80, rev3Rows)
		rev3FeedLines(vt, 0, 10023) // 10023-23 = 10000 in history — exactly the ceiling
		if got := vt.DroppedHistoryLines(); got != 0 {
			t.Fatalf("dropped = %d, want 0", got)
		}
		marker, rest := rev3MarkerOf(vt.Transcript())
		if marker != "" {
			t.Fatalf("marker must be absent at exact ceiling, got %q", marker)
		}
		if len(rest) == 0 || rest[0] != "L00000" {
			t.Fatalf("first history line = %v, want L00000", firstOf(rest))
		}
	})

	t.Run("one_over_notice_is_exact", func(t *testing.T) {
		vt := NewVT(80, rev3Rows)
		rev3FeedLines(vt, 0, 10024) // 10001 in history → 1 cut off
		if got := vt.DroppedHistoryLines(); got != 1 {
			t.Fatalf("dropped = %d, want exactly 1", got)
		}
		// The ring dropped these lines, but the head kept them: nothing is
		// missing from the transcript yet (R4 F-05).
		rev3WholeHistory(t, vt)
	})

	t.Run("double_truncation_accumulates_exactly", func(t *testing.T) {
		vt := NewVT(80, rev3Rows)
		rev3FeedLines(vt, 0, 10300) // cut (10300-23)-10000 = 277
		if got := vt.DroppedHistoryLines(); got != 277 {
			t.Fatalf("after first burst dropped = %d, want 277", got)
		}
		rev3FeedLines(vt, 10300, 10800) // 500 more → 777 cut in total
		if got := vt.DroppedHistoryLines(); got != 777 {
			t.Fatalf("after second burst dropped = %d, want exactly 777", got)
		}
		// The ring dropped these lines, but the head kept them: nothing is
		// missing from the transcript yet (R4 F-05).
		rev3WholeHistory(t, vt)
	})

	t.Run("resize_driven_truncation_counted", func(t *testing.T) {
		vt := NewVT(80, rev3Rows)
		rev3FeedLines(vt, 0, 10020) // history 9996, screen 24 lines
		if got := vt.DroppedHistoryLines(); got != 0 {
			t.Fatalf("pre-resize dropped = %d, want 0", got)
		}
		vt.Resize(80, 3) // 24 non-empty screen lines − 3 = 21 move into history → 10017 → 17 cut
		if got := vt.DroppedHistoryLines(); got != 17 {
			t.Fatalf("resize-driven dropped = %d, want exactly 17", got)
		}
		// The ring dropped these lines, but the head kept them: nothing is
		// missing from the transcript yet (R4 F-05).
		rev3WholeHistory(t, vt)
	})

	t.Run("truncation_then_scroll_then_resize_counts_exact", func(t *testing.T) {
		vt := NewVT(80, rev3Rows)
		rev3FeedLines(vt, 0, 10500) // cut (10500-23)-10000 = 477
		if got := vt.DroppedHistoryLines(); got != 477 {
			t.Fatalf("dropped = %d, want 477", got)
		}
		rev3FeedLines(vt, 10500, 10530) // +30 lines → 507 cut
		if got := vt.DroppedHistoryLines(); got != 507 {
			t.Fatalf("after scroll dropped = %d, want 507", got)
		}
		vt.Resize(80, 10) // 23 non-empty screen lines − 10 = 13 into history → 10013 → 520 cut
		if got := vt.DroppedHistoryLines(); got != 520 {
			t.Fatalf("after resize dropped = %d, want exactly 520", got)
		}
		// The ring dropped these lines, but the head kept them: nothing is
		// missing from the transcript yet (R4 F-05).
		rev3WholeHistory(t, vt)
	})

	t.Run("notice_only_in_txt_not_in_cast", func(t *testing.T) {
		base := t.TempDir()
		rec, err := NewRecorder(SessionConfig{
			BaseDir: base, Machine: "m", Person: "rev3", SessionID: "trunc-1",
			Clock: NewSimClock(testBaseTime),
		})
		if err != nil {
			t.Fatalf("NewRecorder: %v", err)
		}
		var sb strings.Builder
		for i := 0; i < 25500; i++ {
			fmt.Fprintf(&sb, "L%05d\r\n", i)
		}
		if _, err := rec.Write([]byte(sb.String())); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := rec.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		txt, err := os.ReadFile(rec.Paths().TxtPath)
		if err != nil {
			t.Fatalf("read txt: %v", err)
		}
		// 25 477 lines of history: the head keeps L00000..L09999, the ring
		// L15477..L25476, and the 5 477 between them are the marker (R4 F-05).
		txtLines := strings.Split(string(txt), "\n")
		if len(txtLines) == 0 || txtLines[0] != "L00000" {
			t.Fatalf(".txt first line = %v, want L00000", firstOf(txtLines))
		}
		var marker string
		var after string
		for i, l := range txtLines {
			if strings.HasPrefix(l, "[... ") {
				marker = l
				if i+1 < len(txtLines) {
					after = txtLines[i+1]
				}
				break
			}
		}
		if !strings.Contains(marker, "5477 lines truncated") {
			t.Fatalf(".txt marker wrong: %q", marker)
		}
		if after != "L15477" {
			t.Fatalf(".txt first line after the marker = %q, want L15477", after)
		}

		cast, err := os.ReadFile(rec.Paths().CastPath)
		if err != nil {
			t.Fatalf("read cast: %v", err)
		}
		if strings.Contains(string(cast), "lines truncated") || strings.Contains(string(cast), "lines omitted") {
			t.Fatalf("the machine format (.cast) must not carry the truncation notice")
		}
		lines := strings.Count(string(cast), "\n")
		if lines != 2 { // header + one "o" event with all the output
			t.Fatalf("cast lines = %d, want 2", lines)
		}
	})
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return "<empty>"
	}
	return s[0]
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// 4. Checksums: match against the disk + tampering is detected.
// -----------------------------------------------------------------------------

func TestRev3ChecksumsMatchDiskAndTamperDetected(t *testing.T) {
	base := t.TempDir()
	rec, err := NewRecorder(SessionConfig{
		BaseDir: base, Machine: "srv", Person: "rev3", SessionID: "sha-1",
		Clock: NewSimClock(testBaseTime),
	})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	_, _ = rec.Write([]byte("chunk one\r\n"))
	_, _ = rec.Write([]byte("chunk two with \x1b[31mcolor\x1b[0m\r\n"))
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	meta, err := ReadMeta(rec.Paths().MetaPath)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}

	for _, fc := range []struct {
		label string
		path  string
		got   FileInfo
	}{
		{"cast", rec.Paths().CastPath, meta.CastFile},
		{"txt", rec.Paths().TxtPath, meta.TxtFile},
	} {
		data, err := os.ReadFile(fc.path)
		if err != nil {
			t.Fatalf("read %s: %v", fc.label, err)
		}
		sum := sha256.Sum256(data)
		wantSHA := hex.EncodeToString(sum[:])
		if fc.got.SHA256 != wantSHA {
			t.Errorf("%s: meta SHA256 does not match the actual disk content: meta=%s disk=%s", fc.label, fc.got.SHA256, wantSHA)
		}
		if fc.got.Size != int64(len(data)) {
			t.Errorf("%s: meta size %d != disk %d", fc.label, fc.got.Size, len(data))
		}
	}

	if meta.TotalBytes != int64(len("chunk one\r\n")+len("chunk two with \x1b[31mcolor\x1b[0m\r\n")) {
		t.Errorf("TotalBytes = %d, want the exact sum of the fed bytes", meta.TotalBytes)
	}

	// Tampering: append bytes to the .cast AFTER the close — the meta must diverge from the disk.
	f, err := os.OpenFile(rec.Paths().CastPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open for tamper: %v", err)
	}
	_, _ = f.WriteString("[9.9,\"i\",\"forged\"]\n")
	_ = f.Close()

	data, _ := os.ReadFile(rec.Paths().CastPath)
	sum := sha256.Sum256(data)
	if meta.CastFile.SHA256 == hex.EncodeToString(sum[:]) {
		t.Fatalf(".cast tampering is NOT detected: the meta checksum matched the modified file")
	}
	t.Logf("tamper detected: meta=%s disk-after-forge=%s", meta.CastFile.SHA256, hex.EncodeToString(sum[:]))
}

// -----------------------------------------------------------------------------
// 5. Own hostile VT probes: no crashes, no ESC leaking into text, memory bounded.
// -----------------------------------------------------------------------------

func TestRev3MyVTProbesStaySane(t *testing.T) {
	probes := []struct {
		name string
		seq  string
	}{
		{"sgr_mouse_press", "\x1b[<0;33;44M"},
		{"sgr_mouse_release", "\x1b[<0;33;44m"},
		{"osc8_hyperlink", "\x1b]8;;http://x/\x1b\\link\x1b]8;;\x1b\\"},
		{"dcs_sixel_payload", "\x1bP1;2q#0;2;0;0;0#0~~\x1b\\"},
		{"sos_payload", "\x1bX SOS PAYLOAD \x1b\\"},
		{"apc_payload", "\x1b_ APC PAYLOAD \x1b\\"},
		{"esc_percent_G", "\x1b%G"},
		{"esc_hash_8", "\x1b#8"},
		{"da_private", "\x1b[>0c"},
		{"mouse_modes_on", "\x1b[?1000;1002;1006;1015h"},
		{"window_ops", "\x1b[9;1t\x1b[22;0t"},
		{"overlong_utf8", "\xC0\xAF"},
		{"truncated_e0", "\xE0\x80\x80A"},
		{"csi_malformed_sign", "\x1b[-H\x1b[;H\x1b[;;;H"},
		{"csi_mixed_sep", "\x1b[3-5H\x1b[1:2H"},
		{"long_sgr", "\x1b[38;2;255;255;255;48;2;0;0;0m"},
		{"decaln_like", "\x1b[3;3H\x1b[0J\x1b[2;2H"},
	}
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %s: %v", p.name, r)
				}
			}()
			v := NewVT(80, 24)
			// Cursor to the corner before the probe, as the method requires.
			_, _ = v.Write([]byte("before\r\nafter line\r\n"))
			_, _ = v.Write([]byte("\x1b[3;1H"))
			// Probe at every possible chunk cut.
			for cut := 0; cut <= len(p.seq); cut++ {
				vv := NewVT(80, 24)
				_, _ = vv.Write([]byte("seed\r\n"))
				_, _ = vv.Write([]byte(p.seq[:cut]))
				_, _ = vv.Write([]byte(p.seq[cut:]))
				vv.Flush()
				got := vv.Transcript()
				if strings.ContainsRune(got, 0x1B) {
					t.Fatalf("raw ESC byte leaked into transcript for %s (cut=%d)", p.name, cut)
				}
			}
			_, _ = v.Write([]byte(p.seq))
			v.Flush()
			got := v.Transcript()
			if strings.ContainsRune(got, 0x1B) {
				t.Fatalf("raw ESC byte leaked into transcript for %s", p.name)
			}
			if !strings.Contains(got, "after line") && p.name != "sgr_mouse_press" {
				t.Logf("note: transcript for %s: %q", p.name, got)
			}
		})
	}

	// SGR mouse in the OUTGOING stream: the semantics must be exactly the ones
	// round-2 described for `ESC [ M` — delete one line, print the coordinate bytes.
	t.Run("esc_M_semantics_unchanged_delete_one_line", func(t *testing.T) {
		v := NewVT(80, 24)
		_, _ = v.Write([]byte("line A\r\nline B\r\nline C\r\n"))
		_, _ = v.Write([]byte("\x1b[2;1H"))
		_, _ = v.Write([]byte("\x1b[M !!"))
		v.Flush()
		got := v.Transcript()
		want := "line A\n !!e C"
		if got != want {
			t.Fatalf("ESC[M semantics changed since round-2 review: got %q, want %q", got, want)
		}
	})

	// Memory: 200k cycles of short OSC/CSI — the history ceiling holds, no growth.
	t.Run("repeated_short_sequences_bounded", func(t *testing.T) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		v := NewVT(80, 24)
		for i := 0; i < 200000; i++ {
			_, _ = v.Write([]byte("\x1b]0;a\x07"))
			_, _ = v.Write([]byte("\x1b[1m"))
			_, _ = v.Write([]byte("x\r\n"))
		}
		v.Flush()
		runtime.ReadMemStats(&after)
		v.mu.RLock()
		histLen := len(v.history)
		v.mu.RUnlock()
		if histLen > maxHistoryLines {
			t.Fatalf("history = %d > ceiling %d", histLen, maxHistoryLines)
		}
		grown := after.TotalAlloc - before.TotalAlloc
		t.Logf("total alloc during 600k writes: %d MB (history=%d)", grown>>20, histLen)
		_ = v.Transcript()
	})
}

// -----------------------------------------------------------------------------
// 6. Size-based rotation: the oldest in-progress recording must survive (an
//    independent take on the critical scenario).
// -----------------------------------------------------------------------------

func TestRev3LiveOldestSessionSurvivesSizeRotation(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := NewSimClock(now)

	sLive := createFakeSession(t, dir, "srv", "u", "live", now.Add(-3*time.Hour), 15000, "recording")
	sMid := createFakeSession(t, dir, "srv", "u", "mid", now.Add(-2*time.Hour), 10000, "completed")
	sRecent := createFakeSession(t, dir, "srv", "u", "recent", now.Add(-10*time.Minute), 10000, "completed")

	res, err := Rotate(RotateConfig{Dir: dir, MaxTotalBytes: 12000, Clock: clock})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	for _, d := range res.DeletedSessions {
		if d == sLive {
			t.Fatalf("LIVE-RECORDING PROTECTION IS GONE: rotation deleted the oldest in-progress session %s", sLive)
		}
	}
	if _, err := os.Stat(sLive + ".cast"); err != nil {
		t.Fatalf("live .cast disappeared: %v", err)
	}
	t.Logf("deleted=%v (mid=%v recent=%v)", res.DeletedSessions, sMid, sRecent)
	if res.RemainingSessions < 1 {
		t.Fatalf("the archive was emptied to zero")
	}
}

// -----------------------------------------------------------------------------
// 7. Concurrent hammer: Write + Transcript + Resize + Metadata + Abort.
// -----------------------------------------------------------------------------

func TestRev3ConcurrentHammerNoRace(t *testing.T) {
	base := t.TempDir()
	rec, err := NewRecorder(SessionConfig{
		BaseDir: base, Machine: "hammer", Person: "rev3", SessionID: "conc-1",
		Clock: NewSimClock(testBaseTime),
	})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	payloads := [][]byte{
		[]byte("plain output\r\n"),
		[]byte("\x1b[<0;33;44M\x1b[2J\x1b[999;999H\x1b[M"),
		[]byte("\xE0\x80broken utf8 \xC0\xAF tail\r\n"),
		[]byte("\x1b]0;title\x07\x1b]8;;u\x1b\\l\x1b]8;;\x1b\\"),
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := rec.Write(payloads[(id+j)%len(payloads)]); err != nil {
					return
				}
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = rec.Transcript()
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; ; j++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = rec.Resize(80+j%20, 24+j%10)
			_ = rec.Metadata()
			_ = rec.Paths()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	if err := rec.Abort("hammer done"); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	for _, p := range []string{rec.Paths().CastPath, rec.Paths().TxtPath, rec.Paths().MetaPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("file %s missing after the hammer: %v", p, err)
		}
	}
	m := rec.Metadata()
	if m.Status != "aborted" || !m.Aborted {
		t.Fatalf("meta after Abort: %+v", m)
	}
}
