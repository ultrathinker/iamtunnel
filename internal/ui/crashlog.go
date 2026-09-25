//go:build windows || linux || darwin

package ui

// Where a crash goes (IAMT-367).
//
// On 19.09.2026 the maintainer watched a live session, pressed backspace,
// and the whole program vanished -- both windows at once. The first
// question was the right one: are there any logs to look at, to see what
// happened. There were none. A window program on Windows has no
// console to print a panic to: the process writes its last words to a
// handle nobody is holding, and they are gone.
//
// So a panic in a window goroutine is written to a file first, with its
// stack, before anything else happens. One file, appended to, next to
// the client data this program already owns -- not a log of ordinary
// life, which would be a different feature with different questions
// about what may be written down. Only crashes, only here.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// crashLogPath is where the last words go. os.UserCacheDir rather than
// the client data directory, because this package is not told where that
// is and being told would be a new argument threaded through the whole
// window for the sake of a file written at most once in a program's
// life.
func crashLogPath() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "iamtunnel", "crash.log"), nil
}

// recordPanic appends one crash to the file and returns where it went.
//
// Every failure here is swallowed: this runs while the program is
// already dying, and a program that cannot write its crash note must
// still finish crashing.
func recordPanic(where string, r any, stack []byte) string {
	path, err := crashLogPath()
	if err != nil {
		return ""
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return ""
	}
	f, err := datafile.OpenAppend(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fmt.Fprintf(f, "\n=== %s  %s  version %s ===\n%v\n\n%s\n",
		time.Now().Format(time.RFC3339), where, crashVersion, r, stack)
	return path
}

// crashVersion is stamped into the note so a report can be matched to a
// build. Set by the program that opens the window; empty in a test.
var crashVersion = "unknown"

// SetCrashVersion records which build this is, for the crash note.
func SetCrashVersion(v string) { crashVersion = v }

// guardWindow runs a window's goroutine so that a panic inside it is
// written down and, where it can be, survived.
//
// The second window is allowed to die alone: losing the transcript
// window is a bad afternoon, losing the process takes the session
// controls with it, and the maintainer lost both at once.
func guardWindow(where string, onPanic func(note string)) {
	r := recover()
	if r == nil {
		return
	}
	note := recordPanic(where, r, debug.Stack())
	if onPanic != nil {
		onPanic(note)
	}
}
