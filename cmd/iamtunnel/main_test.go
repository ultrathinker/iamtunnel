package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// Test data with shapes valid under the §3.1/§3.4/§3.3 grammars: the
// fingerprint is 43 base64 characters (SHA-256), the tokens are opaque.
const (
	fpr43 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	// 127.0.0.1:1 on purpose: a command that really tries to connect
	// must fail by refused connection, never by a DNS lookup - a test
	// that resolves a name behaves differently on a machine whose
	// resolver answers for everything.
	connStr = "iamtunnel://127.0.0.1:1/alice#" + fpr43
	// 127.0.0.1:1 here too (IAMT-73): enrol and admin claim now really
	// dial the gateway, so a hostname that might resolve over the network
	// would make these tests flaky/slow depending on the runner's DNS.
	enrolCode = "iamtunnel-enrol://127.0.0.1:1#" + fpr43 + ":s3cret-token1"
	claimRef  = "127.0.0.1:1#" + fpr43 + ":bootstrap-token1"
)

// pubKeyLine generates a real ed25519 public key line; the CLI parses
// keys with x/crypto/ssh, so the base64 must be genuine.
func pubKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// drive runs the CLI in-process with empty environment and a
// non-interactive stdin; returns stdout, stderr, exit code.
func drive(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	return driveFull(t, "", false, map[string]string{}, args...)
}

// driveEnv runs the CLI with the given environment variables.
func driveEnv(t *testing.T, env map[string]string, args ...string) (string, string, int) {
	t.Helper()
	return driveFull(t, "", false, env, args...)
}

// driveIn runs the CLI with stdin content and the interactive flag,
// which is what the confirmation gate of destructive commands reads.
func driveIn(t *testing.T, stdin string, interactive bool, args ...string) (string, string, int) {
	t.Helper()
	return driveFull(t, stdin, interactive, map[string]string{}, args...)
}

func driveFull(t *testing.T, stdin string, interactive bool, env map[string]string, args ...string) (string, string, int) {
	t.Helper()
	// Every run gets its own role directories. Without this the empty
	// environment makes config.DirsFor fall back to a RELATIVE path and
	// the commands that now really execute (client, IAMT-64) write the
	// saved connection string and the client's private key into the
	// package directory. A test must never leave anything outside its
	// own temporary directory - and the product defect behind the
	// fallback is tracked separately.
	merged := testsupport.PlatformDataEnv(t)
	for k, v := range env {
		merged[k] = v
	}
	if runtime.GOOS != "windows" {
		if _, set := merged["IAMTUNNEL_DATA_DIR"]; !set {
			merged["IAMTUNNEL_DATA_DIR"] = merged["XDG_DATA_HOME"]
		}
	}
	env = merged
	var out, errs bytes.Buffer
	s := &streams{
		in:          strings.NewReader(stdin),
		interactive: interactive,
		out:         &out,
		errs:        &errs,
		env:         env,
		isElevated: func() (bool, error) {
			return true, nil
		},
	}
	code := run(args, s)
	return out.String(), errs.String(), code
}

// driveInDir runs the CLI with the role directories pinned to dir, so a
// sequence of invocations shares state the way a real user's machine
// does: save a connection string with one call, use it with the next.
func driveInDir(t *testing.T, dir string, args ...string) (string, string, int) {
	t.Helper()
	return driveEnv(t, testsupport.PlatformDataEnvAt(t, dir), args...)
}

// driveGUI runs the CLI with no arguments and openGUI substituted for
// the real window launcher (IAMT-157). This is the ONLY way a test may
// exercise the len(args)==0 branch of run() where a window exists
// (Windows and Linux since IAMT-252, macOS since IAMT-262): the real
// runGUI calls ui.Run, which opens an actual OS window and then blocks
// forever on those platforms (app.Main() never returns —
// internal/ui/gui.go), so reaching it from a test binary would hang the
// test run rather than fail it. ui.Run also panics on its own if
// testing.Testing() ever sees it called un-mocked, as a second line of
// defence — but this seam is what is meant to keep any test from getting
// that far in the first place. See
// TestNoArgsOpensTheWindowOnWindowsLinuxOrDarwin.
func driveGUI(t *testing.T, openGUI func(*streams) int) (string, string, int) {
	t.Helper()
	var out, errs bytes.Buffer
	s := &streams{
		in:      strings.NewReader(""),
		out:     &out,
		errs:    &errs,
		env:     testsupport.PlatformDataEnv(t),
		openGUI: openGUI,
	}
	code := run(nil, s)
	return out.String(), errs.String(), code
}

// TestVersion covers gate 4: "version" prints version, sha and platform,
// exit code 0.
func TestVersion(t *testing.T) {
	out, _, code := drive(t, "version")
	if code != 0 {
		t.Fatalf("version: exit code = %d, want 0", code)
	}
	for _, want := range []string{version, gitSHA, runtime.GOOS + "/" + runtime.GOARCH} {
		if !strings.Contains(out, want) {
			t.Errorf("version output missing %q, got:\n%s", want, out)
		}
	}
}

// TestUnknownSubcommand: an unknown command gives exit code 2 and a
// clear message pointing at --help.
func TestUnknownSubcommand(t *testing.T) {
	out, errs, code := drive(t, "frobnicate")
	if code != 2 {
		t.Fatalf("unknown command: exit code = %d, want 2", code)
	}
	if !strings.Contains(errs, `unknown command "frobnicate"`) {
		t.Errorf("stderr lacks the unknown-command text, got:\n%s", errs)
	}
	if !strings.Contains(errs, "--help") {
		t.Errorf("stderr does not point at --help, got:\n%s", errs)
	}
	if out != "" {
		t.Errorf("stdout should be empty, got:\n%s", out)
	}
}

// TestNoCommandAnswersNotImplemented pins that execPoint and
// its "not implemented yet" text are gone from the product entirely.
// This walks a representative shape of every subcommand of SPEC §7.2
// (plus every admin verb of §3.3, plus the internal doorwatch of §6.3)
// in a fresh, unconfigured environment and fails if any output — on
// either stream, whatever the outcome — still contains the stub
// sentence. "gateway run" is probed only with a value that fails
// argument validation (port 1): a value that passes validation would
// really start serving and block forever, which is proven separately
// (not with this sweep) by TestGatewayRunServesReal.
func TestNoCommandAnswersNotImplemented(t *testing.T) {
	pub := pubKeyLine(t)
	restore := writeFile(t, "backup.tar.gz", "tarball")
	cases := [][]string{
		{"server", "start"},
		{"server", "start", "--idle-minutes", "30"},
		{"server", "stop"},
		{"server", "status"},
		{"enrol", enrolCode},
		{"admin", "people", "list"},
		{"admin", "people", "list", "--json"},
		{"admin", "people", "add", "bob", "--role", "admin", "--key", pub},
		{"admin", "machines", "enrol-code", "win01"},
		{"admin", "machines", "enrol-code", "win01", "--os-user", `CONTOSO\svc-ssh`},
		{"admin", "machines", "rekey", "win01", "--confirm-fingerprint", fpr43, "--yes"},
		{"admin", "claim", claimRef, "--key", pub},
		{"gateway", "install"},
		{"gateway", "run", "--port", "1", "--public-host", "gw.example.test"}, // fails port validation, never blocks
		{"gateway", "status"},
		{"gateway", "backup"},
		{"gateway", "restore", restore, "--yes"},
		{"gateway", "rotate-hostkey", "--yes"},
		{"selftest"},
	}
	for _, args := range cases {
		out, errs, _ := drive(t, args...)
		if strings.Contains(out, "not implemented") || strings.Contains(errs, "not implemented") {
			t.Errorf("%v: still answers with the old stub text — out=%q errs=%q", args, out, errs)
		}
	}
}

// TestArgumentParsingErrors checks the parser: malformed invocations
// give exit code 2 and say what was wanted instead.
func TestArgumentParsingErrors(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"client"}, `want "connect-string`},
		{[]string{"client", "frob"}, "unknown subcommand"},
		{[]string{"client", "connect-string"}, "exactly one"},
		{[]string{"client", "connect"}, "exactly one"},
		{[]string{"client", "connect", "a", "b"}, "exactly one"},
		{[]string{"client", "machines", "extra"}, "unexpected argument"},
		{[]string{"server"}, "want exactly one"},
		// IAMT-249 made "server install"/"server uninstall" real subcommands;
		// the unknown-subcommand case stays on the parser surface it tests.
		{[]string{"server", "frob"}, "unknown subcommand"},
		{[]string{"server", "start", "now"}, "unexpected argument"},
		{[]string{"enrol"}, "exactly one"},
		{[]string{"enrol", "a", "b"}, "exactly one"},
		{[]string{"admin"}, "<group> <verb>"},
		{[]string{"admin", "people"}, "<group> <verb>"},
		{[]string{"admin", "bogus", "list"}, "unknown group"},
		{[]string{"admin", "people", "list", "--yaml"}, "unknown flag"},
		{[]string{"admin", "claim", "x"}, "--key"},
		{[]string{"gateway"}, "want exactly one"},
		{[]string{"gateway", "frob"}, "unknown subcommand"},
		{[]string{"gateway", "run", "extra"}, "unexpected argument"},
		{[]string{"shot"}, "exactly one"},
		{[]string{"shot", "a", "b"}, "exactly one"},
		{[]string{"shot", "client", "--out"}, "--out needs a value"},
		{[]string{"shot", "client", "--bright"}, "unknown flag"},
		{[]string{"selftest", "x"}, "unexpected argument"},
		{[]string{"version", "x"}, "unexpected argument"},
	}
	// The `server doorwatch` rows are built for this host's argv layout
	// rather than spelled out by hand: five positional fields on Windows,
	// eight on Linux and macOS (IAMT-247/263 appended the DoorOptions tail).
	// The helpers live in cli_matrix_test.go, next to the matrix that asks
	// the same questions — IAMT-287 fixed it there, IAMT-297 here, where the
	// rows were still five-field and every one of them died at the arity
	// check on Unix before reaching the validation it is about.
	type argCase = struct {
		args []string
		want string
	}
	arityHint := doorwatchArityHint()
	cases = append(cases,
		[]argCase{
			{[]string{"server", "doorwatch"}, arityHint},
			{[]string{"server", "doorwatch", "door1"}, arityHint},
			{[]string{"server", "doorwatch", "door1", "123"}, arityHint},
			{doorwatchArgs(0, "INVALID!"), "not a valid name"},
			{doorwatchArgs(1, "0"), "must be a number"},
			{doorwatchArgs(1, "not_a_pid"), "must be a number"},
			{doorwatchArgs(2, "   "), "keyfile path must not be empty"},
		}...)

	for _, tc := range cases {
		_, errs, code := drive(t, tc.args...)
		if code != 2 {
			t.Errorf("%v: exit code = %d, want 2", tc.args, code)
		}
		if !strings.Contains(errs, tc.want) {
			t.Errorf("%v: stderr lacks %q, got:\n%s", tc.args, tc.want, errs)
		}
	}
}

// TestHelpAtEveryLevel: --help (and aliases) at any level print usage
// and exit 0.
func TestHelpAtEveryLevel(t *testing.T) {
	for _, args := range [][]string{
		{"--help"},
		{"-h"},
		{"help"},
		{"client", "--help"},
		{"server", "--help"},
		{"enrol", "--help"},
		{"admin", "--help"},
		{"gateway", "--help"},
		{"shot", "--help"},
		{"selftest", "--help"},
	} {
		out, _, code := drive(t, args...)
		if code != 0 {
			t.Errorf("%v: exit code = %d, want 0", args, code)
		}
		if !strings.Contains(out, "Usage:") {
			t.Errorf("%v: stdout lacks usage, got:\n%s", args, out)
		}
	}
}

// TestNoArgsOpensTheWindowOnWindowsLinuxOrDarwin (IAMT-157; widened to
// Linux by IAMT-252 and to macOS by IAMT-262): without arguments, on all
// three platforms that have a live window, run() reaches the GUI launcher
// through the same command path. Proven ONLY through the substitutable
// seam (streams.openGUI) — never through the real runGUI, which calls
// ui.Run and would open an actual window on the machine running the test,
// then block forever (see driveGUI's own doc comment).
//
// The darwin skip that used to stand here was the same stale gate the
// IAMT-286 sweep found in the install tests: the window arrived on macOS
// with IAMT-262 (cmd/iamtunnel/gui_darwin.go), but the skip — and the
// test's name — still said otherwise, and a test that skips cannot
// complain about it.
func TestNoArgsOpensTheWindowOnWindowsLinuxOrDarwin(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the GUI launch path only exists on windows, linux and darwin; see TestNoArgsPrintsUsageOnOtherPlatforms")
	}
	called := false
	var gotStreams *streams
	fake := func(s *streams) int {
		called = true
		gotStreams = s
		return 42
	}
	_, _, code := driveGUI(t, fake)
	if !called {
		t.Fatalf("run() with no arguments on %s did not call the substituted GUI launcher", runtime.GOOS)
	}
	if code != 42 {
		t.Errorf("run() with no arguments on %s = %d, want the launcher's own return value 42", runtime.GOOS, code)
	}
	if gotStreams == nil {
		t.Errorf("the GUI launcher was called with a nil *streams")
	}
}

// TestNoArgsPrintsUsageOnOtherPlatforms: on every platform without a
// live window behind no arguments (the BSDs and friends — Windows, Linux
// and, since IAMT-262, macOS open the window instead), no arguments still
// just print usage and exit 2.
func TestNoArgsPrintsUsageOnOtherPlatforms(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		t.Skip(runtime.GOOS + " opens the window instead; see TestNoArgsOpensTheWindowOnWindowsLinuxOrDarwin")
	}
	out, errs, code := drive(t)
	if code != 2 {
		t.Fatalf("no args: exit code = %d, want 2", code)
	}
	if !strings.Contains(errs, "Usage:") {
		t.Errorf("non-windows no-args: stderr lacks usage, got:\n%s", errs)
	}
	_ = out
}

func TestServerDoorwatchConfigError(t *testing.T) {
	_, errs, code := drive(t, "server", "doorwatch", "door1", "123", "testkeys", "1000", "journal", "--config", "nonexistent_config_file.json")
	if code != exitEnv && code != exitUser {
		t.Fatalf("expected env/user exit code for missing config, got %d (errs: %s)", code, errs)
	}
}
