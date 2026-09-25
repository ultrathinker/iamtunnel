//go:build !windows

package gateway

// iamt332_fifo_readers_posix_test.go — IAMT-332 round five. The gateway
// package's own final-pathname readers — the host-key load behind every
// command that touches the gateway role, and the per-member backup read
// behind "gateway backup"/gateway.backup — opened gateway data files by
// final pathname. A FIFO planted at either name by the unprivileged
// data-directory owner hung the privileged command inside open(2) forever.
// Round five routes both through state.ReadDataFile, so each must refuse
// promptly.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestIAMT332Round5GatewayReadsRefuseAFIFOPlantedAtTheName plants a FIFO
// at the host key's name and at state.json's name (the required backup
// member) in turn and requires each reader to come back promptly with the
// actionable refusal. The bounded-wait pattern is part of the test's
// meaning: a genuine hang fails the test naming the reader, it does not
// wedge the suite (a blocked read cannot be cancelled, so on a red run the
// goroutine leaks until the test binary exits).
func TestIAMT332Round5GatewayReadsRefuseAFIFOPlantedAtTheName(t *testing.T) {
	for _, tt := range []struct {
		name string
		// call plants the FIFO and returns its path plus the production
		// read to run against it.
		call func(t *testing.T) (string, func() error)
	}{
		{
			name: "loadOrGenerateHostKey's read of the gateway host key",
			call: func(t *testing.T) (string, func() error) {
				dir := t.TempDir()
				path := filepath.Join(dir, HostKeyFileName)
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatalf("plant the FIFO: %v", err)
				}
				return path, func() error { _, err := loadOrGenerateHostKey(path); return err }
			},
		},
		{
			name: "WriteBackupTarGz's read of state.json (the required member)",
			call: func(t *testing.T) (string, func() error) {
				dataDir := t.TempDir()
				outDir := t.TempDir()
				path := filepath.Join(dataDir, state.StateFileName)
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatalf("plant the FIFO: %v", err)
				}
				out := filepath.Join(outDir, "backup.tar.gz")
				return path, func() error { return WriteBackupTarGz(out, dataDir) }
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
					t.Fatalf("%s read through a FIFO planted at %s — a gateway data file's name must be refused when it is not a regular file (IAMT-332 round 5)", tt.name, path)
				}
				if !strings.Contains(err.Error(), "not a regular file") {
					t.Errorf("%s refused %s with %q — the error must say the name is not a regular file and what to do", tt.name, path, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("%s did not return within 3s — it is blocked on the FIFO planted at %s instead of refusing a non-regular file at a data file's name (IAMT-332 round 5)", tt.name, path)
			}
			if st, serr := os.Lstat(path); serr != nil || st.Mode()&os.ModeNamedPipe == 0 {
				t.Errorf("the planted FIFO did not survive the refused read (Lstat: %v, %#v) — the refusal must leave the name as it found it", serr, st)
			}
		})
	}
}
