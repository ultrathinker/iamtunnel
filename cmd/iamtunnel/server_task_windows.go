//go:build windows

// server_task_windows.go — the production implementation of the logon-task
// seam (windowsTasks), IAMT-337. Every call in the test binary panics:
// substituting the seam is each test's duty, and a miss must fail loudly
// rather than register a task in the real Task Scheduler — the same scheme
// as guardProductionSCM for the gateway service.

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func guardProductionTasks(op string) {
	if testing.Testing() {
		panic("iamtunnel server: the production Windows logon-task seam (" + op + ") ran inside a test binary — substitute windowsTasks with withFakeLogonTasks like the systemd and SCM seams")
	}
}

// runSchtasks runs one schtasks command and returns its combined output.
// The output is folded into the error because schtasks says useful things
// there ("Access is denied", "The system cannot find the file specified")
// and says nothing but an exit code otherwise.
func runSchtasks(args ...string) (string, error) {
	cmd, err := schtasksCommand(args...)
	if err != nil {
		return "", err
	}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("%w: %s", err, text)
		}
		return text, err
	}
	return text, nil
}

// schtasksCommand is one schtasks command line, run as Windows' own
// schtasks.exe (R1-CX F-25). It used to be reached by name, on the
// argument that install already holds an administrator's token and so a
// %PATH% an attacker could rewrite was one they could have done worse
// with. That confused the two: a directory on %PATH% writable by another
// account - an installer's folder at the root of C:, IAMT-445's case - is
// that account's way in, and the administrator running install is who
// would have started their schtasks.exe.
func schtasksCommand(args ...string) (*exec.Cmd, error) {
	exe, err := systemTool("schtasks.exe")
	if err != nil {
		return nil, err
	}
	return exec.Command(exe, args...), nil
}

// exitCode returns the process exit code of an exec error, or -1 when the
// error is not one (the binary could not be started at all).
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// utf16LE encodes the task document the way schtasks /XML insists on
// reading it. The documentation says "Unicode" and means UTF-16 with a
// byte-order mark: given UTF-8 it either refuses the file or, worse,
// mangles the non-ASCII parts of it — and the values interpolated into
// this document are a Windows principal and a profile path, both of which
// are Cyrillic on a Russian-language Windows.
func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	buf := make([]byte, 0, 2+len(units)*2)
	buf = append(buf, 0xFF, 0xFE) // BOM
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	return buf
}

// taskFilePresent reports whether Task Scheduler's own file for this
// task exists. It is the second opinion resolveQueryRefusal asks for
// when schtasks refuses a query with its ambiguous exit code 1 — see
// there for why a second opinion is needed at all.
//
// Two things about this path are worth writing down. It is an
// implementation detail of Windows rather than a documented contract,
// but a stable one since Vista, and the cost of it changing is exactly
// the behaviour this code had before: "not there" and the old "not
// registered". And System32 is subject to the WOW64 redirector, so a
// 32-bit build would be sent to SysWOW64\Tasks, which does not exist —
// this product is built for amd64 (gate 1) and would notice, again, by
// degrading to what it already did.
func taskFilePresent(name string) (bool, error) {
	root := strings.TrimSpace(os.Getenv("SystemRoot"))
	if root == "" {
		root = `C:\Windows`
	}
	rel := filepath.FromSlash(strings.TrimPrefix(name, `\`))
	fi, err := os.Stat(filepath.Join(root, "System32", "Tasks", rel))
	if err == nil {
		return !fi.IsDir(), nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

var windowsTasks = logonTaskSetup{
	createTask: func(name, document string) error {
		guardProductionTasks("createTask")
		// schtasks reads the document from a FILE, so install writes one
		// and removes it again. The temp file holds no secret — a path, a
		// principal and a set of scheduler flags — but it is removed on
		// every path out regardless, because a stray *.xml named after a
		// registration in %TEMP% is confusing to find later.
		f, err := os.CreateTemp("", "iamtunnel-task-*.xml")
		if err != nil {
			return err
		}
		path := f.Name()
		defer func() { _ = os.Remove(path) }()
		if _, err := f.Write(utf16LE(document)); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		// /F replaces an existing task of the same name: install is
		// repeatable by contract (see logonTaskSetup.createTask).
		_, err = runSchtasks("/Create", "/TN", name, "/XML", path, "/F")
		return err
	},

	taskExists: func(name string) (bool, error) {
		guardProductionTasks("taskExists")
		_, err := runSchtasks("/Query", "/TN", name, "/FO", "LIST")
		if err == nil {
			return true, nil
		}
		// Anything that is not schtasks's own exit 1 — the binary missing,
		// a crash, a signal — is a failure on its face and is reported as
		// one. Exit 1 is the ambiguous one, and resolveQueryRefusal says
		// why and asks the filesystem for a second opinion.
		if exitCode(err) != 1 {
			return false, err
		}
		present, statErr := taskFilePresent(name)
		return resolveQueryRefusal(err, present, statErr)
	},

	deleteTask: func(name string) error {
		guardProductionTasks("deleteTask")
		_, err := runSchtasks("/Delete", "/TN", name, "/F")
		return err
	},

	runTask: func(name string) error {
		guardProductionTasks("runTask")
		_, err := runSchtasks("/Run", "/TN", name)
		return err
	},
}
