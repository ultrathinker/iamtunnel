package risk

// R4 F-03 (round-4 review): "an exec grant = an interactive interpreter
// without classification", second half. The text classifier reads only the exec
// command line. A command that launches an interpreter with no payload —
// `powershell`, `bash`, `python -`, `powershell -Command -` — carries
// nothing to judge, but it is exactly the shape whose real commands arrive
// later on stdin, past every rule here. Until now those were
// green-unmatched: the human sees "nothing risky" while running an
// unmonitored shell.
//
// The rule under test, stdin-interpreter, marks those forms yellow: the
// reason says what will actually happen — commands are coming from stdin
// and will not be checked. Payload forms stay where they were: `bash -c
// '...'` and friends are unwrapped and classified recursively (b3), and
// `-EncodedCommand`/`-File`/`-c`/`-e` are opaque (classifyOpaqueCommand
// runs first). Yellow, not red, for the same reason sudo-at-start is
// yellow: privilege of judgment, not evidence of harm.

import "testing"

func TestF03_InterpreterReadingStdinIsFlagged(t *testing.T) {
	cases := []struct{ name, cmd string }{
		{"bare powershell", "powershell"},
		{"bare pwsh", "pwsh"},
		{"bare cmd", "cmd"},
		{"bare bash", "bash"},
		{"bare sh", "sh"},
		{"bare zsh", "zsh"},
		{"bare python", "python"},
		{"bare perl", "perl"},
		{"bare node", "node"},
		{"bare ruby", "ruby"},
		{"bash -s", "bash -s"},
		{"sh -s", "sh -s"},
		{"bash -ls", "bash -ls"},
		{"python dash", "python -"},
		{"python3 dash", "python3 -"},
		{"perl dash", "perl -"},
		{"node dash", "node -"},
		{"ruby dash", "ruby -"},
		{"python flags only", "python -i -u"},
		{"powershell options only", "powershell -NoProfile"},
		{"powershell command dash", "powershell -Command -"},
		{"powershell com prefix dash", "pwsh -c -"},
		{"cmd /k", "cmd /k"},
		{"sudo python bare", "sudo python"},
		{"sudo bash -s", "sudo bash -s"},
	}
	for _, tc := range cases {
		v := Classify(tc.cmd)
		if v.Level != Yellow || v.Rule != "stdin-interpreter" {
			t.Fatalf("%s (%s): got %+v, want yellow stdin-interpreter", tc.name, tc.cmd, v)
		}
		if v.Reason == "" {
			t.Fatalf("%s (%s): stdin-interpreter verdict carries no reason", tc.name, tc.cmd)
		}
	}
}

func TestF03_PayloadFormsAreNotStdinRule(t *testing.T) {
	// Every one of these has a real payload — a -c/-Command body for the
	// wrapper unwinder, a script file, or an opaque flag. The stdin rule
	// must leave them alone; what they classify as is already pinned
	// elsewhere (b3, the bypass samples, opaque tests).
	for _, cmd := range []string{
		`bash -c 'echo hi'`,
		`cmd /c echo hi`,
		`powershell -Command Get-Date`,
		`bash script.sh`,
		`python script.py`,
		`node server.js`,
		`bash -lc 'ls'`,
		`powershell -Command`, // bare command flag: the unwrapper's unreadable, not stdin
		`sudo -l`,
	} {
		if v := Classify(cmd); v.Rule == "stdin-interpreter" {
			t.Fatalf("%q: payload form must not fire stdin-interpreter, got %+v", cmd, v)
		}
	}
}
