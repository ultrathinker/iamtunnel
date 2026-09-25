//go:build windows

package main

// R1-CX F-25: server install runs with an administrator's token, and it
// ran schtasks by name - whatever the first directory on %PATH% held. A
// directory on %PATH% that another account can write to is common on
// Windows (an installer's folder at the root of C:, where Authenticated
// Users may Modify - IAMT-445's case), and a schtasks.exe put there ran
// with the administrator's rights. Go no longer looks in the current
// directory (exec: ErrDot), so %PATH% is the whole of it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// r1cxF25PlantOnPATH puts a stand-in program of that name in a directory
// first on %PATH%. Nothing runs it: the tests only ask which file a
// command would start.
func r1cxF25PlantOnPATH(t *testing.T, name string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("MZ planted"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// r1cxF25System is the system's own copy of name.
func r1cxF25System(t *testing.T, name string) string {
	t.Helper()
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name)
}

func TestR1CX_F25_ServerInstallRunsTheSystemsSchtasks(t *testing.T) {
	r1cxF25PlantOnPATH(t, "schtasks.exe")
	cmd, err := schtasksCommand("/Query")
	if err != nil {
		t.Fatal(err)
	}
	if want := r1cxF25System(t, "schtasks.exe"); !strings.EqualFold(cmd.Path, want) {
		t.Fatalf("server install would run %s with an administrator's token, not %s", cmd.Path, want)
	}
}
