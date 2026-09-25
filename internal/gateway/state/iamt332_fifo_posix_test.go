//go:build !windows

package state

// iamt332_fifo_posix_test.go — IAMT-332 round four: O_NOFOLLOW refuses a
// symlink, but a FIFO (or device, or socket) planted at a long-lived data
// file's name is not a symlink — it passes O_NOFOLLOW, opens successfully,
// and a READ-ONLY open of a FIFO then blocks forever waiting for a writer
// that will never come. The privileged recovery paths open read-only
// (the torn-tail repair, the enrol HMAC key read), so the hang wedges
// `gateway pair` itself: a reproducible denial of service from the same
// unprivileged data-directory owner as the symlink case. The fix fstats
// the opened descriptor (no path to follow) and refuses anything that is
// not a regular file.
//
// The bounded-wait pattern below is part of the test's meaning: a genuine
// hang must fail the test with the finding's name, not wedge the suite.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// boundedOpen runs open in a goroutine and fails the test naming the
// finding if it does not come back within the deadline. A blocked open(2)
// cannot be cancelled, so on a red run the goroutine leaks until the test
// binary exits — acceptable: the test FAILS at its own line either way.
func boundedOpen(t *testing.T, what string, open func() (*os.File, error)) (*os.File, error) {
	t.Helper()
	type outcome struct {
		f   *os.File
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		f, err := open()
		done <- outcome{f, err}
	}()
	select {
	case r := <-done:
		return r.f, r.err
	case <-time.After(3 * time.Second):
		t.Fatalf("%s did not return within 3s — it is blocked on the planted FIFO instead of refusing a non-regular file at a data file's name (IAMT-332 round 4)", what)
		return nil, nil // unreachable; Fatalf above ends the test
	}
}

// TestOpenDataFileRefusesAFIFOPlantedAtTheName plants a FIFO where a
// long-lived data file belongs and requires BOTH entries of the two-legged
// open to return promptly with the actionable refusal — the EEXIST leg
// reroutes into the no-follow open, which is where a FIFO would otherwise
// block a read-only caller forever.
func TestOpenDataFileRefusesAFIFOPlantedAtTheName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.dat")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("plant the FIFO: %v", err)
	}

	for _, tt := range []struct {
		name string
		open func() (*os.File, error)
	}{
		{"OpenDataFile (create-or-refuse)", func() (*os.File, error) { return OpenDataFile(path, os.O_RDONLY, 0o600) }},
		{"OpenExistingDataFile (no-follow reopen)", func() (*os.File, error) { return OpenExistingDataFile(path, os.O_RDONLY) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, err := boundedOpen(t, tt.name, tt.open)
			if err == nil {
				_ = f.Close()
				t.Fatalf("%s opened a FIFO planted at a data file's name — a read-only open of a FIFO blocks forever, wedging the privileged recovery path; a non-regular file at such a name must be refused (IAMT-332 round 4)", tt.name)
			}
			if !strings.Contains(err.Error(), "not a regular file") {
				t.Errorf("the refusal %q does not say the name is not a regular file — the error must name what was planted and what to do", err)
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("the refusal %q does not name the path %q", err, path)
			}
			if st, serr := os.Lstat(path); serr != nil || st.Mode()&os.ModeNamedPipe == 0 {
				t.Errorf("the planted FIFO did not survive the refused open (Lstat: %v, %#v) — the refusal must leave the name as it found it", serr, st)
			}
		})
	}
}
