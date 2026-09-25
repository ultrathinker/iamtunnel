//go:build windows && !nogui

package main

// R1-CX F-25, the window's half: Connect opens a console through cmd.exe,
// and the window may be the one "Restart as administrator" started. Both
// the cmd.exe that runs "start" and the one "start" opens were found by
// name - the first through %PATH%, the second by cmd itself, which looks
// in the current directory before %PATH%.

import (
	"strings"
	"testing"
)

func TestR1CX_F25_TheConnectConsoleIsTheSystemsCmd(t *testing.T) {
	r1cxF25PlantOnPATH(t, "cmd.exe")
	cmd, err := connectTerminalCommand(`C:\Program Files\iamtunnel\iamtunnel.exe`, "m1")
	if err != nil {
		t.Fatal(err)
	}
	want := r1cxF25System(t, "cmd.exe")
	if !strings.EqualFold(cmd.Path, want) {
		t.Errorf("Connect would start %s, not %s", cmd.Path, want)
	}
	line := strings.ToLower(cmd.SysProcAttr.CmdLine)
	if n := strings.Count(line, strings.ToLower(`"`+want+`"`)); n != 2 {
		t.Errorf("the command line names the system cmd.exe %d times, want both - the one running start and the one start opens: %s", n, cmd.SysProcAttr.CmdLine)
	}
}
