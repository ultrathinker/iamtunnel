package macos

// R1-CX F-25 on macOS: the administrator prompt (osascript "with
// administrator privileges", whose script then runs as root), the Connect
// terminal (open) and the theme probe (defaults) were started by name -
// whatever the first directory on $PATH held. The system's own programs
// are in /usr/bin, which System Integrity Protection keeps as shipped.

import "testing"

func TestR1CX_F25_MacOSRunsTheSystemsOwnPrograms(t *testing.T) {
	var ran []string
	origOut, origStart := outputFn, startFn
	outputFn = func(name string, args ...string) ([]byte, error) {
		ran = append(ran, name)
		return []byte("Dark\n"), nil
	}
	startFn = func(name string, args ...string) error {
		ran = append(ran, name)
		return nil
	}
	t.Cleanup(func() { outputFn, startFn = origOut, origStart })

	if err := RelaunchAsAdmin("/Applications/iamtunnel.app/Contents/MacOS/iamtunnel"); err != nil {
		t.Fatal(err)
	}
	if _, err := connectTerminal(t.TempDir(), "/Applications/iamtunnel.app/Contents/MacOS/iamtunnel", "m1"); err != nil {
		t.Fatal(err)
	}
	SystemThemeIsDark()

	want := []string{"/usr/bin/osascript", "/usr/bin/open", "/usr/bin/defaults"}
	if len(ran) != len(want) {
		t.Fatalf("ran %v, want %v", ran, want)
	}
	for i := range want {
		if ran[i] != want[i] {
			t.Errorf("ran %q, want %q: a program found through $PATH is whatever the first directory on it holds", ran[i], want[i])
		}
	}
}
