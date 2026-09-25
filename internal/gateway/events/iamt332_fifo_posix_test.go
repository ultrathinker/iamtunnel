//go:build !windows

package events

// iamt332_fifo_posix_test.go — IAMT-332 round four, end to end: OpenLog's
// first step is repairTornTail, whose read handle opens the log's name
// read-only. A FIFO planted at events.jsonl therefore hangs OpenLog
// itself — the privileged `gateway pair` never reaches its own refusal.
// After the fix the no-follow open fstats the descriptor and refuses the
// non-regular file, and OpenLog reports it as an error instead.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestOpenLogRefusesAFIFOAtTheLogFilesName plants a FIFO at the log's real
// name and requires OpenLog to come back promptly with a refusal, not to
// hang inside the torn-tail repair.
func TestOpenLogRefusesAFIFOAtTheLogFilesName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultLogFileName)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("plant the FIFO: %v", err)
	}

	type outcome struct {
		l   *Log
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		l, err := OpenLog(path)
		done <- outcome{l, err}
	}()
	select {
	case r := <-done:
		if r.err == nil {
			_ = r.l.Close()
			t.Fatalf("OpenLog opened a log whose name is a planted FIFO — the torn-tail repair's read-only open blocks forever on a FIFO, wedging the privileged caller; a non-regular file at the log's name must be refused (IAMT-332 round 4)")
		}
		if !strings.Contains(r.err.Error(), "not a regular file") {
			t.Errorf("the refusal %q does not say the name is not a regular file — the error must name what was planted and what to do", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("OpenLog did not return within 3s — repairTornTail is blocked on the planted FIFO instead of refusing a non-regular file at the log's name (IAMT-332 round 4)")
	}

	if st, serr := os.Lstat(path); serr != nil || st.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("the planted FIFO did not survive the refused open (Lstat: %v, %#v) — the refusal must leave the name as it found it", serr, st)
	}
}
