//go:build !windows

package events

// iamt332_fifo_readers_posix_test.go — IAMT-332 round five. OpenLog (the
// write side) was covered in round four; the READ side — ReadFile and
// ReadHistory, the event-history reads behind `iamtunnel gateway status`,
// the admin event feed and every operator dump — still opened the log and
// its archives by final pathname. A FIFO planted at the log's name (or at
// an archive's) by the unprivileged data-directory owner hung those reads
// inside open(2) forever. Round five routes readLogFile through
// state.OpenExistingDataFile, so both entry points must refuse promptly.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestIAMT332Round5EventReadsRefuseAFIFOAtTheLogNames plants a FIFO at the
// current log's name and at an archive's name in turn and requires each
// history read to come back promptly with the actionable refusal. The
// bounded-wait pattern is part of the test's meaning: a genuine hang fails
// the test naming the reader, it does not wedge the suite.
func TestIAMT332Round5EventReadsRefuseAFIFOAtTheLogNames(t *testing.T) {
	for _, tt := range []struct {
		name string
		// call plants the FIFO and returns its path plus the production
		// read to run against it.
		call func(t *testing.T) (string, func() error)
	}{
		{
			name: "ReadHistory's read of the current log",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, DefaultLogFileName)
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatalf("plant the FIFO: %v", err)
				}
				return path, func() error { _, _, err := ReadHistory(dir, Filter{}); return err }
			},
		},
		{
			name: "ReadFile's read of a rotated archive",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, "events-20260917T000000Z.jsonl")
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatalf("plant the FIFO: %v", err)
				}
				return path, func() error { _, _, err := ReadFile(path, Filter{}); return err }
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path, call := tt.call(t)
			done := make(chan error, 1)
			go func() { done <- call() }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatalf("%s read through a FIFO planted at %s — a log file's name must be refused when it is not a regular file (IAMT-332 round 5)", tt.name, path)
				}
				if !strings.Contains(err.Error(), "not a regular file") {
					t.Errorf("%s refused %s with %q — the error must say the name is not a regular file and what to do", tt.name, path, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("%s did not return within 3s — it is blocked on the FIFO planted at %s instead of refusing a non-regular file at a log file's name (IAMT-332 round 5)", tt.name, path)
			}
			if st, serr := os.Lstat(path); serr != nil || st.Mode()&os.ModeNamedPipe == 0 {
				t.Errorf("the planted FIFO did not survive the refused read (Lstat: %v, %#v) — the refusal must leave the name as it found it", serr, st)
			}
		})
	}
}
