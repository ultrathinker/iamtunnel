package macos

import (
	"errors"
	"fmt"
)

// AdminShellCommand returns the shell command line that becomes the
// command of an administrator-privileged "do shell script": the program
// and its arguments, every word shell-quoted by ShellCommand.
//
// It is exported so the escaping can be proved by execution rather than
// by inspection: the test hands its result to a real /bin/sh and reads
// back the argv the program actually received.
func AdminShellCommand(program string, args ...string) (string, error) {
	if program == "" {
		return "", errors.New("macos: refusing to build an administrator command with an empty program path")
	}
	return ShellCommand(program, args...), nil
}

// RelaunchAsAdmin starts program with administrator privileges through
// osascript(1)'s "do shell script ... with administrator privileges"
// (see AppleScriptDoShellWithAdmin) and waits only long enough to learn
// whether the person agreed.
//
// This is the macOS answer to Windows's UAC relaunch (internal/elevate's
// Relaunch): the standard SecurityAgent dialog names osascript, and no
// password or secret passes through iamtunnel — we name a command, macOS
// checks the rights. Deliberately not routed through internal/elevate,
// whose Unix Relaunch is the server role's "run it again as root"
// primitive and whose darwin gate (Supported() == false) IAMT-262 leaves
// alone.
//
// Two details of that AppleScript interface are load-bearing:
//
//   - The command is backgrounded inside the shell ("> /dev/null 2>&1 &")
//     and its standard streams are redirected away. Without both, "do
//     shell script" waits for the elevated process to finish AND for the
//     pipe to close, so osascript would block for the whole life of the
//     new window and we could not tell agreement from refusal.
//   - It therefore returns nil as soon as the command has been started,
//     and an error when the person cancels the prompt or macOS refuses —
//     a cancelled prompt must not look like a window that is coming up.
//
// Caveat worth knowing when reading a report from an elevated window:
// macOS has no "same user, more rights" relaunch (that is what UAC is),
// so the new process runs as root with root's own home directory. The
// server half is unaffected (its data directory is the absolute
// /var/lib/iamtunnel-machine), but the Client screen will not see the
// client configuration of the person who pressed the button.
func RelaunchAsAdmin(program string, args ...string) error {
	command, err := AdminShellCommand(program, args...)
	if err != nil {
		return err
	}
	detached := command + " < /dev/null > /dev/null 2>&1 &"
	script, err := AppleScriptDoShellWithAdmin(detached)
	if err != nil {
		return err
	}
	if _, err := outputFn(osascriptPath, "-e", script); err != nil {
		return fmt.Errorf("macOS did not grant administrator rights (a cancelled prompt and a refused one read the same way here): %w", err)
	}
	return nil
}
