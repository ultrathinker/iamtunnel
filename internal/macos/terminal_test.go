package macos

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

type startCall struct {
	name string
	args []string
}

// fakeStart installs a recording startFn for one test: no "open", no
// "osascript", ever — the seam is the only way this package reaches the
// system, and every test of the callers replaces it.
func fakeStart(t *testing.T, err error) *[]startCall {
	t.Helper()
	var calls []startCall
	orig := startFn
	startFn = func(name string, args ...string) error {
		calls = append(calls, startCall{name: name, args: append([]string(nil), args...)})
		return err
	}
	t.Cleanup(func() { startFn = orig })
	return &calls
}

// TestConnectTerminalOpensTerminalAppWithTheScript: Connect is
// "open -a Terminal.app <script>" — the script path is one argv element
// handed to open(1), and the machine name is inside the script, quoted.
func TestConnectTerminalOpensTerminalAppWithTheScript(t *testing.T) {
	calls := fakeStart(t, nil)
	dir := t.TempDir()

	msg, err := connectTerminal(dir, "/Applications/iamtunnel", "win01")
	if err != nil {
		t.Fatalf("connectTerminal: %v", err)
	}
	if msg != "Opened a terminal on win01." {
		t.Errorf("message = %q", msg)
	}
	if len(*calls) != 1 {
		t.Fatalf("started %d programs, want exactly open(1): %+v", len(*calls), *calls)
	}
	call := (*calls)[0]
	if call.name != openPath {
		t.Errorf("started %q, want %s", call.name, openPath)
	}
	if len(call.args) != 3 || call.args[0] != "-a" || call.args[1] != "Terminal.app" {
		t.Fatalf("open args = %v, want [-a Terminal.app <script>]", call.args)
	}
	script := call.args[2]
	if !strings.HasPrefix(script, dir) {
		t.Errorf("the script %q was not written into the requested directory %q", script, dir)
	}

	info, err := os.Stat(script)
	if err != nil {
		t.Fatalf("stat %s: %v", script, err)
	}
	// The 0700 the writer sets is what makes Terminal.app willing to run the
	// script, and it is a Unix mode — Windows has no such bits (os.Chmod
	// there only toggles the read-only attribute), so on a Windows host this
	// one assertion is about a platform fact that does not exist, not about
	// our code. The Chmod call itself still runs on every platform; only the
	// reading of it back is Unix-only, which keeps the rest of this test —
	// the file exists, is readable, and says what it should — cross-platform.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("script mode = %v, want 0700: it runs with this person's rights", info.Mode().Perm())
	}
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read %s: %v", script, err)
	}
	text := string(body)
	if !strings.HasPrefix(text, "#!/bin/sh\n") {
		t.Errorf("script must start with a shebang so Terminal can run it:\n%s", text)
	}
	want := "exec " + ShellCommand("/Applications/iamtunnel", "client", "connect", "win01")
	if !strings.Contains(text, want+"\n") {
		t.Errorf("script = \n%s\nwant a line %q", text, want)
	}
	// IAMT-296: the file removes itself, and the removal line comes BEFORE
	// the exec — see ConnectScript's comment for why that order is what
	// makes it safe (the shell already has the file open) and effective
	// (exec replaces the shell, so a line after it would never run).
	// The execution proof of both claims is in quote_test.go, which hands
	// the same script to a real /bin/sh.
	rmLine := `/bin/rm -f -- "$0"`
	rmAt := strings.Index(text, rmLine)
	execAt := strings.Index(text, "exec ")
	if rmAt < 0 {
		t.Fatalf("script must remove itself (IAMT-296), got:\n%s", text)
	}
	if execAt < 0 || rmAt > execAt {
		t.Fatalf("the self-removal must come before the exec line (it is the first command of the file), got:\n%s", text)
	}
}

// TestConnectTerminalReportsFailureAndRemovesTheScript: when open(1)
// refuses (no Terminal.app, a locked-down account), the failure must say
// so in open(1)'s own words AND leave nothing behind. Nothing was started,
// so nothing will ever run the script's self-removal (IAMT-296) — the old
// text here promised the person they could run the file by hand, which
// would have meant one orphaned 0700 script per failed Connect.
func TestConnectTerminalReportsFailureAndRemovesTheScript(t *testing.T) {
	fakeStart(t, errors.New("open: no such application"))
	dir := t.TempDir()

	_, err := connectTerminal(dir, "/Applications/iamtunnel", "win01")
	if err == nil {
		t.Fatalf("a failing open(1) must be reported, not swallowed")
	}
	if !strings.Contains(err.Error(), "no such application") {
		t.Errorf("error = %v, want open(1)'s own words", err)
	}
	// The directory held exactly one thing (the script the call wrote), so
	// an empty directory is the whole claim: it was removed.
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatalf("read %s: %v", dir, rerr)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("a failed Connect must not leave the script behind (IAMT-296): %v", names)
	}
}

// TestWriteConnectScriptNamesAreUnpredictable: two calls must not land on
// the same file (os.CreateTemp's O_EXCL name), so one connect can never
// overwrite or race another.
func TestWriteConnectScriptNamesAreUnpredictable(t *testing.T) {
	dir := t.TempDir()
	first, err := WriteConnectScript(dir, "/x/iamtunnel", "win01")
	if err != nil {
		t.Fatalf("WriteConnectScript: %v", err)
	}
	second, err := WriteConnectScript(dir, "/x/iamtunnel", "win01")
	if err != nil {
		t.Fatalf("WriteConnectScript: %v", err)
	}
	if first == second {
		t.Fatalf("both scripts were written to %s", first)
	}
	if _, err := WriteConnectScript("/nonexistent/dir", "/x/iamtunnel", "win01"); err == nil {
		t.Errorf("an unwritable directory must be reported")
	}
}

// TestRelaunchAsAdminInvokesOsascript: the elevation path is one
// osascript invocation with one -e script, the command inside it
// shell-quoted and AppleScript-escaped, backgrounded so that osascript
// answers as soon as the person agrees, and carrying the phrase macOS
// requires for the consent dialog.
func TestRelaunchAsAdminInvokesOsascript(t *testing.T) {
	var (
		gotName string
		gotArgs []string
		answer  error
	)
	orig := outputFn
	outputFn = func(name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, append([]string(nil), args...)
		return nil, answer
	}
	t.Cleanup(func() { outputFn = orig })

	const exe = "/Applications/iamtunnel.app/Contents/MacOS/iamtunnel"
	if err := RelaunchAsAdmin(exe, "server", "start"); err != nil {
		t.Fatalf("RelaunchAsAdmin: %v", err)
	}
	if gotName != osascriptPath || len(gotArgs) != 2 || gotArgs[0] != "-e" {
		t.Fatalf("ran %q %v, want [%s -e <script>]", gotName, gotArgs, osascriptPath)
	}
	script := gotArgs[1]
	if !strings.HasPrefix(script, "do shell script ") || !strings.HasSuffix(script, "with administrator privileges") {
		t.Errorf("script = %s, want the consent-prompt form", script)
	}
	inner, err := AdminShellCommand(exe, "server", "start")
	if err != nil {
		t.Fatalf("AdminShellCommand: %v", err)
	}
	if !strings.Contains(script, inner) {
		t.Errorf("script = %s, want the shell-quoted command %q inside it", script, inner)
	}
	// Backgrounded, with the streams redirected: otherwise "do shell script"
	// holds osascript until the elevated window is closed, and a refusal
	// could not be told from agreement.
	if !strings.Contains(script, inner+" < /dev/null > /dev/null 2>&1 &") {
		t.Errorf("script = %s, want the command detached inside the shell", script)
	}

	// A cancelled dialog is osascript exiting non-zero: it must be an error,
	// never a silent success.
	answer = errors.New("exit status 1 (stderr: execution error: User canceled. (-128))")
	err = RelaunchAsAdmin(exe, "server", "start")
	if err == nil {
		t.Fatalf("a cancelled consent prompt must be reported as an error")
	}
	if !strings.Contains(err.Error(), "User canceled") {
		t.Errorf("error = %v, want osascript's own words so the person can see they cancelled", err)
	}

	answer = nil
	if err := RelaunchAsAdmin(""); err == nil {
		t.Errorf("an empty program path must be refused")
	}
}
