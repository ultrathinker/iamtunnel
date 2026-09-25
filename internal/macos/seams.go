package macos

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// The two production OS calls this package makes, each behind a seam var
// a test replaces. Both defaults refuse to run inside a test binary:
// forgetting to install a fake must be a loud failure, never a real
// Terminal window, a real consent dialog, or a real read of the
// operator's appearance settings.
//
// The guards are the same discipline internal/server's launchctlFn and
// internal/winkeys' spawn seams follow.
var (
	// outputFn runs a program, waits for it and returns its combined
	// output — the shape "defaults read" needs (we want the answer, and
	// its failure too) and the shape the administrator consent prompt
	// needs (we must know whether osascript came back with an error).
	outputFn = runOutput
	// startFn starts a program and does not wait for it — the shape "open"
	// needs (the Terminal window outlives this process by design).
	startFn = runStartDetached
)

// The system programs this package runs, by full path (R1-CX F-25): a
// program started by name is whatever the first directory on $PATH holds,
// and osascript shows the administrator prompt and runs what it guards as
// root. /usr/bin is part of the system volume System Integrity Protection
// keeps as shipped.
const (
	osascriptPath = "/usr/bin/osascript"
	openPath      = "/usr/bin/open"
	defaultsPath  = "/usr/bin/defaults"
)

// runOutput is outputFn's production default. A non-zero exit is returned
// as an error together with whatever the command wrote, because the
// caller's decision (is the interface style Dark?) depends on both.
func runOutput(name string, args ...string) ([]byte, error) {
	if testing.Testing() {
		panic("macos: outputFn invoked in a test binary; tests must install a fake outputFn")
	}
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s %s: %w (stderr: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// runStartDetached is startFn's production default: start the program,
// release it, and return at once. The child inherits this process's
// standard streams, which is intentional — "open" prints nothing worth
// capturing, and osascript's own output belongs to the person watching
// the consent dialog.
func runStartDetached(name string, args ...string) error {
	if testing.Testing() {
		panic("macos: startFn invoked in a test binary; tests must install a fake startFn")
	}
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return cmd.Process.Release()
}
