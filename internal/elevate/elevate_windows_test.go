//go:build windows

// Tests for the elevate package. The real UAC prompt cannot be
// triggered from inside a test (it would block the test waiting
// for user input). The negative paths are tested: the package
// must refuse to relaunch in situations that would loop or that
// would surface a wrong prompt.
//
// The positive "Relaunch returned a handle and we wrote events"
// path is not covered here for the same reason.

package elevate

import (
	"strings"
	"testing"
)

// TestIsElevatedReturnsBool confirms the API surface — it
// either returns true (running as admin) or false (running
// without elevation). It never panics on a non-admin token.
func TestIsElevatedReturnsBool(t *testing.T) {
	got, err := IsElevated()
	if err != nil {
		t.Fatalf("IsElevated: %v", err)
	}
	t.Logf("IsElevated = %v", got)
}

// TestRelaunchRejectsAlreadyElevatedFlag confirms the loop
// guard: the second relaunch would otherwise prompt again,
// forever. This is the single most important regression test
// for this package.
func TestRelaunchRejectsAlreadyElevatedFlag(t *testing.T) {
	err := Relaunch([]string{"C:\\Program Files\\iamtunnel\\iamtunnel.exe", AlreadyElevatedFlag, "server"}, true)
	if err == nil {
		t.Fatal("Relaunch with AlreadyElevatedFlag must error")
	}
	if !strings.Contains(err.Error(), "loop") {
		t.Errorf("error must mention 'loop' to make the cause obvious, got %q", err.Error())
	}
}

// TestRelaunchRejectsEmptyArgv: empty argv means we'd have
// nothing to launch — refuse rather than panic.
func TestRelaunchRejectsEmptyArgv(t *testing.T) {
	if err := Relaunch(nil, true); err == nil {
		t.Fatal("Relaunch(nil) must error")
	}
	if err := Relaunch([]string{}, true); err == nil {
		t.Fatal("Relaunch([]) must error")
	}
}

// TestRelaunchRejectsAlreadyElevatedProc: when the current
// process is already elevated, no relaunch is required. The
// skip is automatic — a build run as admin will see this branch
// trip and skip; the assertion only matters for non-admin
// builds.
func TestRelaunchRejectsAlreadyElevatedProc(t *testing.T) {
	elevated, err := IsElevated()
	if err != nil {
		t.Fatal(err)
	}
	if !elevated {
		t.Skip("running non-elevated; cannot exercise already-elevated branch")
	}
	err = Relaunch([]string{"C:\\some\\path\\app.exe"}, true)
	if err == nil {
		t.Fatal("Relaunch when already elevated must error")
	}
}

// TestContainsAlreadyElevated locks the marker-parsing rule.
func TestContainsAlreadyElevated(t *testing.T) {
	cases := []struct {
		argv []string
		want bool
	}{
		{nil, false},
		{[]string{`C:\app.exe`}, false},
		{[]string{`C:\app.exe`, "--elevated-child"}, true},
		{[]string{`C:\app.exe`, "server", "--elevated-child"}, true},
		{[]string{`C:\app.exe`, "--NOT-ELEVATED"}, false},
		{[]string{`C:\app.exe`, "elevated-child"}, false}, // substring is not enough
	}
	for _, c := range cases {
		got := containsAlreadyElevated(c.argv)
		if got != c.want {
			t.Errorf("containsAlreadyElevated(%v) = %v, want %v", c.argv, got, c.want)
		}
	}
}

// TestQuoteArg verifies that quoteArg wraps the argument in
// double quotes — its only job. quoteCommandLine is the caller
// that decides whether to apply quoteArg; here we just check
// the wrapper exists.
func TestQuoteArg(t *testing.T) {
	for _, in := range []string{"", "foo", "foo bar", `a"b`} {
		got := quoteArg(in)
		if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
			t.Errorf("quoteArg(%q) = %q, must be wrapped in double quotes", in, got)
		}
	}
}

// TestNeedsQuoting splits out the predicate that quoteCommandLine
// uses to decide whether to invoke quoteArg.
func TestNeedsQuoting(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{``, false},
		{`foo`, false},
		{`foo bar`, true},
		{`a"b`, true},
		{`a<=b`, false},
	}
	for _, c := range cases {
		if got := needsQuoting(c.in); got != c.want {
			t.Errorf("needsQuoting(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestQuoteCommandLine joins a list of args the way ShellExecuteEx
// expects — quoted segments separated by spaces. Plain ASCII
// tokens pass through raw; tokens with whitespace are wrapped.
func TestQuoteCommandLine(t *testing.T) {
	// Plain ASCII tokens: no quoting, joined by spaces.
	got := quoteCommandLine([]string{"app.exe", AlreadyElevatedFlag, "server"})
	want := "app.exe --elevated-child server"
	if got != want {
		t.Errorf("quoteCommandLine (plain): got %q want %q", got, want)
	}
	// A token with a space: must be wrapped.
	got = quoteCommandLine([]string{"app.exe", "server role"})
	want = `app.exe "server role"`
	if got != want {
		t.Errorf("quoteCommandLine (space): got %q want %q", got, want)
	}
}
