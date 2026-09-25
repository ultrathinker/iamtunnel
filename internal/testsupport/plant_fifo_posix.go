//go:build !windows

package testsupport

import (
	"syscall"
	"testing"
)

// PlantFIFOAt plants a FIFO at path — the POSIX-only member of the
// plant kinds. A FIFO is the one plant whose damage is a WEDGE: a plain
// open of it blocks inside open(2) (read-only: until a writer appears;
// write-only: until a reader), so every reader/writer row that plants
// one must run the production call through RunBounded, never directly.
func PlantFIFOAt(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("plant the FIFO at %s: %v", path, err)
	}
}
