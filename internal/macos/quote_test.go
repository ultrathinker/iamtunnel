package macos

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestShellQuoteIsOneLiteralWord(t *testing.T) {
	cases := []struct{ in, want string }{
		{"win01", "'win01'"},
		{"", "''"},
		{"a b", "'a b'"},
		{"it's ok", `'it'\''s ok'`},
		{"a; rm -rf /", "'a; rm -rf /'"},
		{"$(whoami)", "'$(whoami)'"},
		{"`whoami`", "'`whoami`'"},
		{"a\nb", "'a\nb'"},
		{`back\slash`, `'back\slash'`},
		{`"quoted"`, `'"quoted"'`},
	}
	for _, tc := range cases {
		if got := ShellQuote(tc.in); got != tc.want {
			t.Errorf("ShellQuote(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestShellCommandQuotesEveryWord(t *testing.T) {
	got := ShellCommand("/Applications/My App/iamtunnel", "client", "connect", "it's ok")
	want := `'/Applications/My App/iamtunnel' 'client' 'connect' 'it'\''s ok'`
	if got != want {
		t.Errorf("ShellCommand = %s, want %s", got, want)
	}
}

// TestConnectScriptSurvivesHostileMachineNames is the proof that IAMT-262's
// "script file, not AppleScript interpolation" choice actually holds: the
// script the Connect button writes is handed to a real /bin/sh, with names
// that would be syntax if they were spliced in unquoted, and the program
// on the other end reports the argv it received. The canary at the end
// runs the same experiment unquoted and requires it to break — without
// that, a green run here would prove nothing.
//
// Skipped on Windows: there is no sh(1) there, and this test's whole point
// is the real parser. The Unix gates host (scripts/gates.sh) runs it.
func TestConnectScriptSurvivesHostileMachineNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /bin/sh on this host; the quoting proof runs on the Unix gates host")
	}
	dir := t.TempDir()
	program := filepath.Join(dir, "iamtunnel")
	// A stand-in for the real client that prints the argv it was given,
	// one word per line.
	if err := os.WriteFile(program, []byte("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"), 0o755); err != nil {
		t.Fatalf("write stand-in program: %v", err)
	}

	hostile := []string{
		"win01",
		"a; touch pwned",
		"$(touch pwned2)",
		"`touch pwned3`",
		"a && touch pwned4",
		"it's ok",
		"' ; touch pwned5 ; '",
		"a b\tc",
		"new\nline",
		"--machine",
	}
	for _, machine := range hostile {
		script := filepath.Join(dir, "connect.sh")
		if err := os.WriteFile(script, []byte(ConnectScript(program, machine)), 0o700); err != nil {
			t.Fatalf("write connect script: %v", err)
		}
		cmd := exec.Command("sh", script)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("machine %q: sh %s failed: %v\n%s", machine, script, err, out)
		}
		want := "client\nconnect\n" + machine + "\n"
		if string(out) != want {
			t.Errorf("machine %q: the program received\n%q\nwant\n%q", machine, string(out), want)
		}
	}

	if file := firstPwned(t, dir); file != "" {
		t.Fatalf("a machine name executed as shell syntax: %s appeared", file)
	}

	// Canary: the same name, unquoted (and without exec, since exec would
	// replace the shell before the injected command could run). If this
	// does NOT inject, the loop above was never able to prove anything.
	canaryScript := filepath.Join(dir, "canary.sh")
	canary := "#!/bin/sh\n" + program + " client connect " + "a; touch pwned-canary\n"
	if err := os.WriteFile(canaryScript, []byte(canary), 0o700); err != nil {
		t.Fatalf("write canary: %v", err)
	}
	cmd := exec.Command("sh", canaryScript)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("canary: sh failed: %v\n%s", err, out)
	}
	if firstPwned(t, dir) != "pwned-canary" {
		t.Fatalf("canary: the unquoted script did not inject (output %q) — this test is not measuring what it claims", out)
	}
}

// TestAdminShellCommandSurvivesHostileArguments does the same for the
// command the administrator-privileged "do shell script" would run:
// osascript hands it to /bin/sh -c, so that is exactly how it is run here.
func TestAdminShellCommandSurvivesHostileArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /bin/sh on this host; the quoting proof runs on the Unix gates host")
	}
	dir := t.TempDir()
	program := filepath.Join(dir, "iamtunnel")
	if err := os.WriteFile(program, []byte("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"), 0o755); err != nil {
		t.Fatalf("write stand-in program: %v", err)
	}

	arg := "a; touch pwned-admin"
	command, err := AdminShellCommand(program, "admin", "grants", "grant", arg)
	if err != nil {
		t.Fatalf("AdminShellCommand: %v", err)
	}
	if !strings.Contains(command, ShellQuote(program)) {
		t.Fatalf("AdminShellCommand = %s, want the program path quoted", command)
	}
	cmd := exec.Command("sh", "-c", command)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sh -c failed: %v\n%s", err, out)
	}
	want := "admin\ngrants\ngrant\n" + arg + "\n"
	if string(out) != want {
		t.Errorf("the program received\n%q\nwant\n%q", string(out), want)
	}
	if file := firstPwned(t, dir); file != "" {
		t.Fatalf("an argument executed as shell syntax: %s appeared", file)
	}

	if _, err := AdminShellCommand(""); err == nil {
		t.Errorf("an empty program path must be refused, not quoted into a command")
	}
}

func TestAppleScriptStringEscapesAndRefuses(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", `"plain"`},
		{`'/x/iamtunnel' 'client'`, `"'/x/iamtunnel' 'client'"`},
		{`say "hi"`, `"say \"hi\""`},
		{`back\slash`, `"back\\slash"`},
		{`both \ and "`, `"both \\ and \""`},
		{"ünïcode ✓", `"ünïcode ✓"`},
	}
	for _, tc := range cases {
		got, err := AppleScriptString(tc.in)
		if err != nil {
			t.Fatalf("AppleScriptString(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("AppleScriptString(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}

	for _, bad := range []string{"a\nb", "a\rb", "a\x00b", "\x1b", "del\x7f"} {
		if got, err := AppleScriptString(bad); err == nil {
			t.Errorf("AppleScriptString(%q) = %s; a control character must be refused, not mangled", bad, got)
		}
	}
}

func TestAppleScriptDoShellWithAdminShape(t *testing.T) {
	script, err := AppleScriptDoShellWithAdmin(`'/Applications/iamtunnel' 'server' 'start'`)
	if err != nil {
		t.Fatalf("AppleScriptDoShellWithAdmin: %v", err)
	}
	want := `do shell script "'/Applications/iamtunnel' 'server' 'start'" with administrator privileges`
	if script != want {
		t.Errorf("got  %s\nwant %s", script, want)
	}

	// A command containing a double quote must come out escaped inside the
	// AppleScript literal — the two escaping layers must not fight.
	script, err = AppleScriptDoShellWithAdmin(`'/x/a"b' 'arg'`)
	if err != nil {
		t.Fatalf("AppleScriptDoShellWithAdmin: %v", err)
	}
	if !strings.Contains(script, `a\"b`) {
		t.Errorf("got %s; the embedded double quote must be escaped for AppleScript", script)
	}
	if _, err := AppleScriptDoShellWithAdmin("a\nb"); err == nil {
		t.Errorf("a command with a newline must be refused: an AppleScript literal cannot carry one")
	}
}

// firstPwned reports the first file a hostile name would have created, if
// any — the side effect that proves a name really reached a shell.
func firstPwned(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "pwned") {
			return e.Name()
		}
	}
	return ""
}

// TestConnectScriptRemovesItselfAndStillRuns is IAMT-296's proof, and it is
// an execution proof rather than a text one: the generated script is handed
// to a real /bin/sh, with a stand-in program that prints the argv it got, and
// the two claims are checked together —
//
//   - the exec line still ran after the file was unlinked (a shell reads on
//     through its open descriptor, so only the name disappears);
//   - the file is gone (the first line did it).
//
// The canary is the same script with the removal moved AFTER the exec: exec
// replaces the shell, so that line never runs and the file survives. Without
// it, "the file is gone" would also pass for a script that was never there.
//
// Skipped on Windows: there is no sh(1) there, and the text assertions in
// terminal_test.go cover the same script on every platform.
func TestConnectScriptRemovesItselfAndStillRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /bin/sh on this host; the script's own behaviour is proved on the Unix gates host")
	}
	dir := t.TempDir()
	program := filepath.Join(dir, "iamtunnel")
	if err := os.WriteFile(program, []byte("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"), 0o755); err != nil {
		t.Fatalf("write stand-in program: %v", err)
	}

	run := func(t *testing.T, script string) string {
		t.Helper()
		cmd := exec.Command("sh", script)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("sh %s: %v\n%s", script, err, out)
		}
		return string(out)
	}

	script := filepath.Join(dir, "connect.sh")
	if err := os.WriteFile(script, []byte(ConnectScript(program, "win01")), 0o700); err != nil {
		t.Fatalf("write connect script: %v", err)
	}
	if out := run(t, script); out != "client\nconnect\nwin01\n" {
		t.Errorf("the exec line must still run after the script removed itself; program received %q", out)
	}
	if _, err := os.Stat(script); !os.IsNotExist(err) {
		t.Errorf("the script must remove itself in its first line (IAMT-296): stat %s = %v", script, err)
	}

	// Canary: removal after the exec can never run, so the file stays.
	canary := filepath.Join(dir, "canary.sh")
	body := "#!/bin/sh\n" + "exec " + ShellCommand(program, "client", "connect", "win01") + "\n" + `/bin/rm -f -- "$0"` + "\n"
	if err := os.WriteFile(canary, []byte(body), 0o700); err != nil {
		t.Fatalf("write canary: %v", err)
	}
	run(t, canary)
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("canary: a removal line after exec must never run, yet %s is gone (%v) — the test cannot tell the two orders apart", canary, err)
	}
}
