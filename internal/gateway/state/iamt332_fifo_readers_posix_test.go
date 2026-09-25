//go:build !windows

package state

// iamt332_fifo_readers_posix_test.go — IAMT-332 round five. Round four put
// the no-follow, regular-file-only open behind the WRITE/LOCK paths; every
// READ of a data file still went through plain os.ReadFile/os.Open, so a
// FIFO planted at state.json (same unprivileged data-directory owner) hung
// every reader of it: the `gateway pair` recovery read, the read-only
// status path, the after-restore read, the rollback re-read. Round five
// routes all of them through ReadDataFile, which opens via
// OpenExistingDataFile — O_NOFOLLOW, prompt (O_NONBLOCK), fstat, regular
// files only — before the first byte is read.
//
// This table plants a FIFO at state.json's name once per READER, not once
// per call site: each row below is a different production entry point, and
// all of them must come back promptly with the actionable refusal instead
// of blocking on the planted FIFO. The bounded-wait pattern is part of the
// test's meaning: a genuine hang fails the test naming the reader, it does
// not wedge the suite (a blocked read cannot be cancelled, so on a red run
// the goroutine leaks until the test binary exits).

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// plantFIFO replaces name (removing any file already there) with a FIFO,
// the one entry kind an unprivileged data-directory owner can plant that
// wedges a reader: open(2) itself blocks on it.
func plantFIFO(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatalf("clear the name before planting: %v", err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("plant the FIFO: %v", err)
	}
}

// boundedRead runs call in a goroutine and requires a prompt refusal: a
// timeout names the reader that hung, a nil error names the reader that
// read through the planted FIFO, and anything short of the actionable
// "not a regular file" wording fails the assertion on its own line.
func boundedRead(t *testing.T, what, path string, call func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- call() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("%s read through a FIFO planted at %s — a data file's name must be refused when it is not a regular file (IAMT-332 round 5)", what, path)
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("%s refused %s with %q — the error must say the name is not a regular file and what to do", what, path, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("%s did not return within 3s — it is blocked on the FIFO planted at %s instead of refusing a non-regular file at a data file's name (IAMT-332 round 5)", what, path)
	}
}

// TestIAMT332Round5ReadersRefuseAFIFOPlantedAtStateJson drives every
// state.json READER this package exposes against a FIFO at its name.
func TestIAMT332Round5ReadersRefuseAFIFOPlantedAtStateJson(t *testing.T) {
	for _, tt := range []struct {
		name string
		// call plants the FIFO and returns its path plus the production
		// read to run against it.
		call func(t *testing.T) (string, func() error)
	}{
		{
			name: "Store.Open's main read (the gateway pair recovery read)",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, StateFileName)
				plantFIFO(t, path)
				return path, func() error { _, err := Open(dir); return err }
			},
		},
		{
			name: "OpenForRead's locked read (status while the gateway is stopped)",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, StateFileName)
				plantFIFO(t, path)
				// A lock file that exists and is free puts OpenForRead on
				// its locked branch: take the lock, then read state.json.
				if err := os.WriteFile(filepath.Join(dir, LockFileName), nil, 0o600); err != nil {
					t.Fatalf("create the lock file: %v", err)
				}
				return path, func() error { _, err := OpenForRead(dir); return err }
			},
		},
		{
			name: "OpenForRead's lock-absent read (the after-restore path)",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, StateFileName)
				plantFIFO(t, path)
				// No state.lock: OpenForRead must take the after-restore
				// branch and read state.json without a lock.
				return path, func() error { _, err := OpenForRead(dir); return err }
			},
		},
		{
			name: "verifyDiskMatchesLocked's rollback re-read",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				s, err := Open(dir) // fresh init writes a valid state.json
				if err != nil {
					t.Fatalf("open a valid store: %v", err)
				}
				t.Cleanup(func() { _ = s.Close() })
				path := filepath.Join(dir, StateFileName)
				plantFIFO(t, path) // swap the valid file out from under the store
				return path, func() error { return s.verifyDiskMatchesLocked() }
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path, call := tt.call(t)
			boundedRead(t, tt.name, path, call)
		})
	}
}
