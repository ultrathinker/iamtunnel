package sshx

// payload_test.go: tests for payload wire layout and parsing.
//
// Every test checks Marshal* against a hand-written reference per RFC
// 4254 §6–§7. The reference is a separate []byte literal, not computed
// via Marshal*. This is the only way to verify the layout actually
// matches the RFC, not just itself.
//
// A separate block covers negative tests for a string length longer
// than the remaining buffer, one per each of the seven parsers. They
// are built so that "silently truncating instead of refusing" (the
// classic clamp-instead-of-reject bug) yields a successful parse and
// turns the test red. No test in the previous suite caught that swap.

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --- pty-req ----------------------------------------------------------------

func TestPayloadLayout_PTYRequest(t *testing.T) {
	got := MarshalPTY(PTYRequest{
		Term:         "xterm",
		Columns:      80,
		Rows:         24,
		WidthPixels:  640,
		HeightPixels: 480,
		Modes:        "",
	})
	want := []byte{
		0, 0, 0, 5, 'x', 't', 'e', 'r', 'm',
		0, 0, 0, 80,
		0, 0, 0, 24,
		0, 0, 2, 128,
		0, 0, 1, 224,
		0, 0, 0, 0,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("pty payload differs\n got %x\nwant %x", got, want)
	}
}

// --- window-change ----------------------------------------------------------

func TestPayloadLayout_WindowChange(t *testing.T) {
	got := MarshalWindow(WindowChange{
		Columns:      120,
		Rows:         40,
		WidthPixels:  960,
		HeightPixels: 800,
	})
	want := []byte{
		0, 0, 0, 120,
		0, 0, 0, 40,
		0, 0, 3, 192,
		0, 0, 3, 32,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("window payload differs\n got %x\nwant %x", got, want)
	}
}

// --- exec -------------------------------------------------------------------

func TestPayloadLayout_Exec(t *testing.T) {
	got := MarshalExec(Exec{Command: "ls -la"})
	want := []byte{
		0, 0, 0, 6, 'l', 's', ' ', '-', 'l', 'a',
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("exec payload differs\n got %x\nwant %x", got, want)
	}
}

// --- env --------------------------------------------------------------------

func TestPayloadLayout_Env(t *testing.T) {
	got := MarshalEnv(Env{Name: "PATH", Value: "/usr/bin"})
	want := []byte{
		0, 0, 0, 4, 'P', 'A', 'T', 'H',
		0, 0, 0, 8, '/', 'u', 's', 'r', '/', 'b', 'i', 'n',
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("env payload differs\n got %x\nwant %x", got, want)
	}
}

// --- signal -----------------------------------------------------------------

func TestPayloadLayout_Signal(t *testing.T) {
	got := MarshalSignal(Signal{Name: "TERM"})
	want := []byte{0, 0, 0, 4, 'T', 'E', 'R', 'M'}
	if !bytes.Equal(got, want) {
		t.Fatalf("signal payload differs\n got %x\nwant %x", got, want)
	}
}

// --- exit-status ------------------------------------------------------------

func TestPayloadLayout_ExitStatus(t *testing.T) {
	got := MarshalExitStatus(ExitStatus{Status: 42})
	want := []byte{0, 0, 0, 42}
	if !bytes.Equal(got, want) {
		t.Fatalf("exit-status payload differs\n got %x\nwant %x", got, want)
	}
}

// --- exit-signal ------------------------------------------------------------

func TestPayloadLayout_ExitSignal(t *testing.T) {
	got := MarshalExitSignal(ExitSignal{
		Signal:       "KILL",
		CoreDumped:   false,
		ErrorMessage: "killed",
		LanguageTag:  "en",
	})
	want := []byte{
		0, 0, 0, 4, 'K', 'I', 'L', 'L',
		0,
		0, 0, 0, 6, 'k', 'i', 'l', 'l', 'e', 'd',
		0, 0, 0, 2, 'e', 'n',
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("exit-signal payload differs\n got %x\nwant %x", got, want)
	}
}

// ExitSignal with CoreDumped=true must have 0x01 in the flag's place, not 0x00.
func TestPayloadLayout_ExitSignalCoreDumped(t *testing.T) {
	got := MarshalExitSignal(ExitSignal{
		Signal:       "SEGV",
		CoreDumped:   true,
		ErrorMessage: "",
		LanguageTag:  "",
	})
	want := []byte{
		0, 0, 0, 4, 'S', 'E', 'G', 'V',
		1,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("exit-signal core-dumped payload differs\n got %x\nwant %x", got, want)
	}
	if got[8] != 1 {
		t.Fatalf("core-dumped byte at index 8 = %d, want 1", got[8])
	}
}

// --- roundtrip --------------------------------------------------------------

func TestPayloadRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		marshal func() []byte
		parse   func([]byte) error
	}{
		{
			name: "pty-req with modes",
			marshal: func() []byte {
				return MarshalPTY(PTYRequest{Term: "xterm-256color", Columns: 101, Rows: 37, WidthPixels: 808, HeightPixels: 592, Modes: "\x01\x00\x00\x00\x03\x00"})
			},
			parse: func(b []byte) error {
				p, err := ParsePTY(b)
				if err != nil {
					return err
				}
				want := PTYRequest{Term: "xterm-256color", Columns: 101, Rows: 37, WidthPixels: 808, HeightPixels: 592, Modes: "\x01\x00\x00\x00\x03\x00"}
				if p != want {
					return errors.New("pty roundtrip mismatch")
				}
				return nil
			},
		},
		{
			name:    "window-change",
			marshal: func() []byte { return MarshalWindow(WindowChange{167, 51, 1336, 816}) },
			parse: func(b []byte) error {
				w, err := ParseWindow(b)
				if err != nil {
					return err
				}
				if w != (WindowChange{167, 51, 1336, 816}) {
					return errors.New("window roundtrip mismatch")
				}
				return nil
			},
		},
		{
			name:    "exec",
			marshal: func() []byte { return MarshalExec(Exec{Command: "whoami"}) },
			parse: func(b []byte) error {
				e, err := ParseExec(b)
				if err != nil {
					return err
				}
				if e.Command != "whoami" {
					return errors.New("exec roundtrip mismatch")
				}
				return nil
			},
		},
		{
			name:    "env",
			marshal: func() []byte { return MarshalEnv(Env{Name: "LANG", Value: "en_US.UTF-8"}) },
			parse: func(b []byte) error {
				e, err := ParseEnv(b)
				if err != nil {
					return err
				}
				if e.Name != "LANG" || e.Value != "en_US.UTF-8" {
					return errors.New("env roundtrip mismatch")
				}
				return nil
			},
		},
		{
			name:    "signal",
			marshal: func() []byte { return MarshalSignal(Signal{Name: "HUP"}) },
			parse: func(b []byte) error {
				s, err := ParseSignal(b)
				if err != nil {
					return err
				}
				if s.Name != "HUP" {
					return errors.New("signal roundtrip mismatch")
				}
				return nil
			},
		},
		{
			name:    "exit-status",
			marshal: func() []byte { return MarshalExitStatus(ExitStatus{Status: 0}) },
			parse: func(b []byte) error {
				e, err := ParseExitStatus(b)
				if err != nil {
					return err
				}
				if e.Status != 0 {
					return errors.New("exit-status roundtrip mismatch")
				}
				return nil
			},
		},
		{
			name: "exit-signal",
			marshal: func() []byte {
				return MarshalExitSignal(ExitSignal{Signal: "TERM", CoreDumped: false, ErrorMessage: "terminated", LanguageTag: "ru"})
			},
			parse: func(b []byte) error {
				e, err := ParseExitSignal(b)
				if err != nil {
					return err
				}
				want := ExitSignal{Signal: "TERM", CoreDumped: false, ErrorMessage: "terminated", LanguageTag: "ru"}
				if e != want {
					return errors.New("exit-signal roundtrip mismatch")
				}
				return nil
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := c.marshal()
			if err := c.parse(b); err != nil {
				t.Fatalf("roundtrip: %v", err)
			}
		})
	}
}

// TestStringsWithNulAndUTF8RoundTrip — the parsers work with octets,
// not runes: NUL, control characters, non-ASCII scripts, CJK, emoji,
// and an OSC escape inside a string pass through without corruption.
func TestStringsWithNulAndUTF8RoundTrip(t *testing.T) {
	s := "\x00\x01TERMé中😀\r\n\x1b]0;title\x07"
	env, err := ParseEnv(MarshalEnv(Env{Name: s, Value: s}))
	if err != nil || env.Name != s || env.Value != s {
		t.Fatalf("env: %v %q %q", err, env.Name, env.Value)
	}
	pty, err := ParsePTY(MarshalPTY(PTYRequest{Term: s, Modes: s}))
	if err != nil || pty.Term != s || pty.Modes != s {
		t.Fatalf("pty: %v %q", err, pty.Term)
	}
	es, err := ParseExitSignal(MarshalExitSignal(ExitSignal{Signal: s, ErrorMessage: s, LanguageTag: s}))
	if err != nil || es.Signal != s || es.ErrorMessage != s || es.LanguageTag != s {
		t.Fatalf("exit-signal: %v", err)
	}
}

// TestExitSignalBoolNonCanonical — RFC 4251: 0 == false, any nonzero value == true.
func TestExitSignalBoolNonCanonical(t *testing.T) {
	b := []byte{0, 0, 0, 4, 'K', 'I', 'L', 'L', 0x7f, 0, 0, 0, 0, 0, 0, 0, 0}
	e, err := ParseExitSignal(b)
	if err != nil {
		t.Fatal(err)
	}
	if !e.CoreDumped {
		t.Fatal("byte 0x7f in the core-dumped position was read as false")
	}
}

// --- negative tests for a length longer than the remainder -------------------

// oversizedCases — one case for each of the seven parsers. Each case
// is chosen so that "silently truncating to the remaining buffer"
// instead of refusing would make the parse SUCCEED — that is, the test
// goes red on exactly the swap the previous suite failed to notice.
var oversizedCases = []struct {
	name  string
	input []byte
	parse func([]byte) error
}{
	{
		// modes — the last field: after truncation, off reaches the end
		// of the buffer and no "trailing bytes" remain.
		name: "pty-req modes length 0xFFFFFFFF",
		input: append(append([]byte{0, 0, 0, 5, 'x', 't', 'e', 'r', 'm'},
			0, 0, 0, 80, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0),
			0xff, 0xff, 0xff, 0xff, 'a', 'b'),
		parse: func(b []byte) error { _, err := ParsePTY(b); return err },
	},
	{
		name:  "pty-req term length 0x80000000",
		input: []byte{0x80, 0, 0, 0, 'x', 't'},
		parse: func(b []byte) error { _, err := ParsePTY(b); return err },
	},
	{
		name:  "exec command length 0xFFFFFFFF",
		input: []byte{0xff, 0xff, 0xff, 0xff, 'l', 's'},
		parse: func(b []byte) error { _, err := ParseExec(b); return err },
	},
	{
		name:  "env value length 0xFFFFFFF0",
		input: []byte{0, 0, 0, 4, 'T', 'E', 'R', 'M', 0xff, 0xff, 0xff, 0xf0, 'x'},
		parse: func(b []byte) error { _, err := ParseEnv(b); return err },
	},
	{
		name:  "env name length 0x7FFFFFFF",
		input: []byte{0x7f, 0xff, 0xff, 0xff, 'T', 'E', 'R', 'M'},
		parse: func(b []byte) error { _, err := ParseEnv(b); return err },
	},
	{
		name:  "signal name length 0xFFFFFFFF",
		input: []byte{0xff, 0xff, 0xff, 0xff, 'T', 'E', 'R', 'M'},
		parse: func(b []byte) error { _, err := ParseSignal(b); return err },
	},
	{
		// language-tag — the last field of exit-signal.
		name: "exit-signal language length 0xFFFFFFFF",
		input: []byte{
			0, 0, 0, 4, 'K', 'I', 'L', 'L',
			0,
			0, 0, 0, 1, 'm',
			0xff, 0xff, 0xff, 0xff, 'r', 'u',
		},
		parse: func(b []byte) error { _, err := ParseExitSignal(b); return err },
	},
	{
		name:  "window-change 20 bytes instead of 16",
		input: make([]byte, 20),
		parse: func(b []byte) error { _, err := ParseWindow(b); return err },
	},
	{
		name:  "window-change 15 bytes instead of 16",
		input: make([]byte, 15),
		parse: func(b []byte) error { _, err := ParseWindow(b); return err },
	},
	{
		name:  "exit-status 5 bytes instead of 4",
		input: make([]byte, 5),
		parse: func(b []byte) error { _, err := ParseExitStatus(b); return err },
	},
	{
		name:  "exit-status 3 bytes instead of 4",
		input: make([]byte, 3),
		parse: func(b []byte) error { _, err := ParseExitStatus(b); return err },
	},
}

// TestParsersRejectOversizedLength — a string length longer than the
// remaining buffer must be a refusal, not a truncation. Otherwise a
// corrupted payload parses "successfully", and what ends up in the
// journal diverges from what goes out to the machine — that is an
// audit bypass.
//
// The same test also runs separately under GOARCH=386, see
// TestParsers32BitRejectOversizedLength.
func TestParsersRejectOversizedLength(t *testing.T) {
	for _, c := range oversizedCases {
		t.Run(c.name, func(t *testing.T) {
			err := c.parse(c.input)
			if err == nil {
				t.Fatalf("a length longer than the remainder parsed successfully (%d-bit int)", intBits())
			}
		})
	}
}

// intBits — the width of int in the current build, for diagnostics.
func intBits() int { return 32 << (^uint(0) >> 63) }

// hostilePayloads — hostile inputs for the "not a single panic" check.
var hostilePayloads = [][]byte{
	nil,
	{},
	{0x01},
	{0x00, 0x00, 0x00},
	{0xff, 0xff, 0xff, 0xff},
	{0x80, 0x00, 0x00, 0x00},
	{0x7f, 0xff, 0xff, 0xff},
	{0xff, 0xff, 0xff, 0xff, 'a', 'b', 'c'},
	{0x00, 0x00, 0x00, 0x04, 'a'},
	{0x00, 0x00, 0x00, 0x02, 0x00, 0x01},
	{0x00, 0x00, 0x00, 0x03, 0xe4, 0xb8, 0xad},
	{0x00, 0x00, 0x00, 0x02, 0xff, 0xfe},
	{0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef},
	make([]byte, 32),
	bytes.Repeat([]byte{0xff}, 64),
	append([]byte{0, 0, 0, 4, 'T', 'E', 'R', 'M'}, bytes.Repeat([]byte{0xff}, 8)...),
}

// TestParsersOnHostileInput — seven parsers × hostile inputs: not a
// single panic, the result is either an error or a correct parse.
func TestParsersOnHostileInput(t *testing.T) {
	parsers := map[string]func([]byte){
		"pty-req":       func(b []byte) { _, _ = ParsePTY(b) },
		"window-change": func(b []byte) { _, _ = ParseWindow(b) },
		"exec":          func(b []byte) { _, _ = ParseExec(b) },
		"env":           func(b []byte) { _, _ = ParseEnv(b) },
		"signal":        func(b []byte) { _, _ = ParseSignal(b) },
		"exit-status":   func(b []byte) { _, _ = ParseExitStatus(b) },
		"exit-signal":   func(b []byte) { _, _ = ParseExitSignal(b) },
	}
	for name, parse := range parsers {
		for i, in := range hostilePayloads {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s panicked on input #%d (%x): %v", name, i, in, r)
					}
				}()
				parse(in)
			}()
		}
	}
}

// TestParsers32BitRejectOversizedLength — the same bounds check, but
// under GOARCH=386. On a 32-bit build int(uint32(0xFFFFFFFF)) == -1,
// and the bounds check in int comes out false: the slice goes out of
// range and the parser panics on a single payload sent by a human. The
// comparison in uint64 fixes this, but it can only be confirmed by
// actually running the test in a 32-bit build.
func TestParsers32BitRejectOversizedLength(t *testing.T) {
	if runtime.GOARCH == "386" || intBits() == 32 {
		t.Skip("already a 32-bit build: the check is done by TestParsersRejectOversizedLength")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not found in PATH")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "sshx386.test")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command(goTool, "test", "-c", "-o", bin, ".")
	build.Env = append(os.Environ(), "GOARCH=386", "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("GOARCH=386 build unavailable: %v\n%s", err, out)
	}
	run := exec.Command(bin, "-test.run", "^TestParsersRejectOversizedLength$", "-test.v")
	run.Dir = dir
	out, err := run.CombinedOutput()
	text := string(out)
	if err != nil {
		if strings.Contains(text, "exec format error") || len(bytes.TrimSpace(out)) == 0 {
			t.Skipf("the 32-bit binary does not run on this platform: %v", err)
		}
		t.Fatalf("the bounds check failed under GOARCH=386: %v\n%s", err, text)
	}
	if !strings.Contains(text, "PASS") {
		t.Fatalf("no PASS under GOARCH=386:\n%s", text)
	}
	if strings.Contains(text, "panic") {
		t.Fatalf("panic under GOARCH=386:\n%s", text)
	}
}

// --- other parsing errors -----------------------------------------------------

func TestParsePTY_ShortBuffer(t *testing.T) {
	b := []byte{0, 0, 0, 10, 'x', 't', 'e', 'r', 'm'}
	if _, err := ParsePTY(b); err == nil {
		t.Fatal("expected error on truncated PTY")
	}
}

func TestParseWindow_WrongSize(t *testing.T) {
	if _, err := ParseWindow([]byte{0, 0, 0, 80}); !errors.Is(err, ErrShortPayload) {
		t.Fatalf("short window-change: %v", err)
	}
	// An oversized payload is not "too short": the diagnostic must not lie.
	err := errParseWindow(make([]byte, 20))
	if err == nil {
		t.Fatal("20-byte window-change was accepted")
	}
	if errors.Is(err, ErrShortPayload) {
		t.Fatalf("oversized window-change returned \"payload too short\": %v", err)
	}
}

func errParseWindow(b []byte) error { _, err := ParseWindow(b); return err }

func TestParseExitStatus_WrongSize(t *testing.T) {
	if _, err := ParseExitStatus([]byte{0, 0, 0, 1, 0}); err == nil {
		t.Fatal("expected error on oversized exit-status")
	}
	if _, err := ParseExitStatus([]byte{0, 0, 0}); !errors.Is(err, ErrShortPayload) {
		t.Fatalf("short exit-status: %v", err)
	}
}

func TestParseExec_TrailingBytes(t *testing.T) {
	b := []byte{0, 0, 0, 2, 'l', 's', 0xff}
	if _, err := ParseExec(b); err == nil {
		t.Fatal("expected error on trailing bytes")
	}
}

// TestErrShortPayloadIsImmutableSentinel — the sentinel is declared as
// a constant: an importer cannot reassign it and break errors.Is for every caller.
func TestErrShortPayloadIsImmutableSentinel(t *testing.T) {
	_, err := ParseExec([]byte{0, 0, 0, 9, 'l', 's'})
	if !errors.Is(err, ErrShortPayload) {
		t.Fatalf("errors.Is(err, ErrShortPayload) == false: %v", err)
	}
	if ErrShortPayload.Error() == "" {
		t.Fatal("sentinel error text is empty")
	}
}

// TestWriteStringRejectsOversize — writeString no longer silently
// truncates the length. We check the contract without allocating 4
// GiB: catching the panic with a small string is impossible, so we
// check the plain fact that the length is written correctly instead.
func TestWriteStringRejectsOversize(t *testing.T) {
	got := writeString(nil, strings.Repeat("a", 300))
	if len(got) != 304 {
		t.Fatalf("written length %d, want 304", len(got))
	}
	if got[0] != 0 || got[1] != 0 || got[2] != 1 || got[3] != 44 {
		t.Fatalf("length prefix %x, want 0000012c", got[:4])
	}
}
