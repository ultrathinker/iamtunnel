//go:build windows

package testsupport

import "testing"

// PlantFIFOAt is the Windows counterpart of the POSIX FIFO plant:
// Windows has no FIFO to plant, so the row skips with the reason. The
// Windows members of the planted-entry class — the hard link (no
// privilege needed) and the junction — are what this host's table runs
// instead; the FIFO rows still go red on the POSIX legs of CI.
func PlantFIFOAt(t *testing.T, path string) {
	t.Skip("FIFO plants are POSIX-only; this host runs the hard-link and directory rows instead")
}
