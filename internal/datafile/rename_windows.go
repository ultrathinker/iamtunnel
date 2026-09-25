//go:build windows

package datafile

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// replaceBudget bounds how long replaceEntry waits for readers to let go.
// A reader of a data file holds its handle for the length of one ReadFile
// -- microseconds, milliseconds on a loaded host -- so two seconds is far
// past any honest reader and still short enough that a genuine refusal
// (a DACL, a file held open for good) reaches the caller promptly.
const replaceBudget = 2 * time.Second

// replaceEntry is the rename at the end of WriteFileAtomic (IAMT-503).
// On Windows a rename over a file another handle holds open is refused
// with ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION: Go opens files
// without FILE_SHARE_DELETE, and a reader that does share delete does not
// make the replace succeed either. Before this, any replace that met a
// concurrent reader failed and the new content was lost -- a finished
// recording's .meta, read by an admin listing at that moment, stayed
// "recording, 0 bytes" for good.
//
// So those two refusals are retried, with a short growing pause, until
// replaceBudget runs out; any other error, and the last refusal once the
// budget is spent, is returned as it came. The rename still acts on the
// entry and never opens the final name, so nothing in WriteFileAtomic's
// contract changes.
func replaceEntry(tmpPath, path string) error {
	deadline := time.Now().Add(replaceBudget)
	pause := 2 * time.Millisecond
	for {
		err := os.Rename(tmpPath, path)
		if err == nil || !heldByAnotherHandle(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(pause)
		if pause < 50*time.Millisecond {
			pause *= 2
		}
	}
}

func heldByAnotherHandle(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
