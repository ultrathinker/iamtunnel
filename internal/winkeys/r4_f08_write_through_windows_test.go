//go:build windows

package winkeys

// r4_f08_write_through_windows_test.go — R4 F-08.
//
// administrators_authorized_keys is one file shared by every administrator
// on the machine (SPEC §3.2.2). The Windows writer created the temporary,
// wrote, closed and renamed it over the old file with neither
// FlushFileBuffers nor MOVEFILE_WRITE_THROUGH. NTFS journals metadata, not
// data, so a power cut right after the rename can leave the file empty —
// every administrator's key gone, not the "dead line until next Start" the
// SPEC §6.3 failure matrix accepts. The Unix half fsyncs the temporary and
// the directory. A power cut cannot be staged in a test, so the test pins
// the two calls that make the write durable: the temporary is flushed
// before it is closed, and the replace asks for write-through.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestR4F08_TheKeyFileReplaceIsFlushedAndWrittenThrough(t *testing.T) {
	var steps []string
	var flags uint32
	origSync, origMove := syncTmpFile, moveFileEx
	t.Cleanup(func() { syncTmpFile, moveFileEx = origSync, origMove })
	syncTmpFile = func(f *os.File) error {
		steps = append(steps, "sync")
		return origSync(f)
	}
	moveFileEx = func(from, to *uint16, fl uint32) error {
		steps = append(steps, "move")
		flags = fl
		return origMove(from, to, fl)
	}

	keyPath := filepath.Join(t.TempDir(), "administrators_authorized_keys")
	if err := writeAtomicBytesPlatform(keyPath, []byte("door line\n"), DoorOptions{}); err != nil {
		t.Fatalf("writeAtomicBytesPlatform: %v", err)
	}
	if len(steps) < 2 || steps[0] != "sync" {
		t.Fatalf("R4 F-08: the temporary was not flushed before the replace (steps %v) — a power cut after the rename can leave the shared key file empty", steps)
	}
	const writeThrough = 0x8 // MOVEFILE_WRITE_THROUGH
	if flags&writeThrough == 0 {
		t.Fatalf("R4 F-08: the replace did not ask for MOVEFILE_WRITE_THROUGH (flags %#x)", flags)
	}
	if got, err := os.ReadFile(keyPath); err != nil || string(got) != "door line\n" {
		t.Fatalf("the key file did not come out of the write (read %q, %v)", got, err)
	}
}
