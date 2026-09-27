//go:build (windows || linux || darwin) && !nogui

package main

// The Server tab's two setup facts and the actions behind them (1.49).
//
// Both used to exist only as console commands, and the maintainer's live
// run hit the second one as a clipped error with the remedy cut off:
//
//   - Autostart at sign-in is a checkbox, OFF unless the person turns it
//     on. The program is meant to be started for one occasion; a machine
//     that comes back reachable after every reboot is the exception, and
//     choosing it is a deliberate act. Turning it on is "server install",
//     turning it off is "server uninstall", run as the same child process
//     a console user would start.
//   - A registration made before the enrolment anchor existed (R4 F-04)
//     is shown as such, and only when it really is one: the profile record
//     is there and the anchor is missing. One press lays the anchor down,
//     the same way "server install" does for it.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// guiServerSetupFacts reads what the Server tab shows about this machine's
// setup. Windows only: the autostart there is a logon task named after the
// registration, and the anchor exists only there. Anything it cannot learn
// comes back as "not known", which draws nothing.
func guiServerSetupFacts(env map[string]string, dir string) (autostartKnown, autostart, needsConfirm bool) {
	if runtime.GOOS != "windows" {
		return false, false, false
	}
	rec, err := loadGatewayRecord(dir)
	if err != nil {
		return false, false, false
	}
	machine := strings.TrimSpace(rec.MachineID)
	if machine == "" {
		return false, false, false
	}
	if ok, qerr := windowsTasks.taskExists(logonTaskName(machine)); qerr == nil {
		autostartKnown, autostart = true, ok
	}
	// Only a MISSING anchor is an old registration. An anchor that could
	// not be read (an unelevated window cannot read the tree) is not
	// evidence of anything, and the block must not appear on a guess.
	if _, aerr := readMachineEnrolmentAnchor(env); aerr != nil && isAnchorMissing(aerr) {
		needsConfirm = true
	}
	return autostartKnown, autostart, needsConfirm
}

// guiServerAutostart turns autostart at sign-in on or off by running
// "server install" or "server uninstall" as a child of this window, with
// this window's rights. Its own words come back as the result or the error.
func guiServerAutostart(serverDir string, enable bool, configure func(*exec.Cmd)) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not resolve this program's own executable path: %w", err)
	}
	verb := "uninstall"
	if enable {
		verb = "install"
	}
	cmd := exec.Command(exe, "server", verb, "--data-dir", serverDir)
	if configure != nil {
		configure(cmd)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Run()
	text := strings.TrimSpace(out.String())
	if runErr != nil {
		if text == "" {
			text = runErr.Error()
		}
		return "", fmt.Errorf("%s", text)
	}
	if enable {
		return "Autostart is on: the agent starts by itself when you sign in to Windows.", nil
	}
	return "Autostart is off: the agent starts only when you press START.", nil
}

// guiServerConfirmRegistration lays the enrolment anchor down for a
// registration that predates it. The window must be elevated; the screen
// asks for that before it gets here.
func guiServerConfirmRegistration(env map[string]string, serverDir string) (string, error) {
	if err := ensureMachineEnrolmentAnchor(env, serverDir); err != nil {
		return "", err
	}
	return "Setup confirmed — the agent can start now.", nil
}
