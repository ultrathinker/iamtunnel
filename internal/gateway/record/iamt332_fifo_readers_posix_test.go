//go:build !windows

package record

// iamt332_fifo_readers_posix_test.go — IAMT-332 round six, completeness on
// the recordings side. ReadMeta and hashFile opened recording parts by
// final pathname; a non-regular entry planted at such a name (the
// recordings directory lives under the gateway data directory) was read
// through or hung on. Round six routes both through the same no-follow
// regular-file-only open as every other data-file reader: ReadMeta via
// state.ReadDataFile, hashFile via state.OpenExistingDataFile (the hash
// must keep streaming — recordings can be large, so no whole-file read).

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestIAMT332Round6RecordingReadsRefuseAFIFOPlantedAtTheName plants a FIFO
// at a recording part's name in turn and requires each reader to come back
// promptly with the actionable refusal. The bounded-wait pattern is part
// of the test's meaning: a genuine hang fails the test naming the reader,
// it does not wedge the suite.
func TestIAMT332Round6RecordingReadsRefuseAFIFOPlantedAtTheName(t *testing.T) {
	for _, tt := range []struct {
		name string
		// call plants the FIFO and returns its path plus the production
		// read to run against it.
		call func(t *testing.T) (string, func() error)
	}{
		{
			name: "ReadMeta's read of a recording's metadata",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, "session.meta")
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatalf("plant the FIFO: %v", err)
				}
				return path, func() error { _, err := ReadMeta(path); return err }
			},
		},
		{
			name: "hashFile's stream of a recording part",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, "session.cast")
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatalf("plant the FIFO: %v", err)
				}
				return path, func() error { _, _, err := hashFile(path); return err }
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
					t.Fatalf("%s read through a FIFO planted at %s — a recording file's name must be refused when it is not a regular file (IAMT-332 round 6)", tt.name, path)
				}
				if !strings.Contains(err.Error(), "not a regular file") {
					t.Errorf("%s refused %s with %q — the error must say the name is not a regular file and what to do", tt.name, path, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("%s did not return within 3s — it is blocked on the FIFO planted at %s instead of refusing a non-regular file at a recording file's name (IAMT-332 round 6)", tt.name, path)
			}
			if st, serr := os.Lstat(path); serr != nil || st.Mode()&os.ModeNamedPipe == 0 {
				t.Errorf("the planted FIFO did not survive the refused read (Lstat: %v, %#v) — the refusal must leave the name as it found it", serr, st)
			}
		})
	}
}
