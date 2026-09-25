package testsupport

// plant.go — the shared plant/assert harness for the IAMT-332
// planted-entry tests (round 9). One place grows the plant kinds and the
// bounded-wait runner, so every package's table rows read the same and
// the no-hang rule is the harness's job rather than each test's.
//
// The helpers are deliberately stdlib-only and do NOT import
// internal/datafile: a red-first test has to compile against the tree
// it proves the bug in, and importing the fix would make that
// impossible. Refusal assertions are therefore done by the refusal
// wording (the contract text SPEC §3.5 pins), not by error type.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// SentinelBytes is the deterministic sentinel content for a planted
// name's target: a file an elevated process must never write through or
// truncate. The assertion is byte-identity, so any write through the
// plant — the exact defect these tests exist for — fails them.
func SentinelBytes(name string) []byte {
	return []byte("iamt332 sentinel for " + name + ": a planted name must never be written through, truncated, or wedged on")
}

// WriteSentinelFile writes the sentinel to path and returns the bytes
// the caller must require back, byte for byte, after the exercise.
func WriteSentinelFile(t *testing.T, path string) []byte {
	t.Helper()
	s := SentinelBytes(filepath.Base(path))
	if err := os.WriteFile(path, s, 0o600); err != nil {
		t.Fatalf("write the sentinel %s: %v", path, err)
	}
	return s
}

// PlantSymlinkAt plants a symlink at linkPath pointing at a fresh
// sentinel file in the same directory, and returns the sentinel's path
// and bytes. Skips with a reason on a host that refuses symlink
// creation (an unprivileged Windows without Developer Mode); the
// directory and hard-link rows in the same table still run there.
func PlantSymlinkAt(t *testing.T, linkPath string) (sentinelPath string, sentinel []byte) {
	t.Helper()
	sentinelPath = linkPath + ".sentinel"
	sentinel = WriteSentinelFile(t, sentinelPath)
	if err := os.Symlink(sentinelPath, linkPath); err != nil {
		t.Skipf("this host does not grant symlink creation, so the corruption the fix removes cannot be planted here (%v)", err)
	}
	return sentinelPath, sentinel
}

// PlantHardLinkAt plants a hard link at linkPath pointing at targetPath,
// which must already exist (write the sentinel first). A hard link is
// the Windows-native member of this class — it needs no privilege at
// all, unlike a symlink — so a skip here is a finding about the host,
// not a pass for the writer.
func PlantHardLinkAt(t *testing.T, linkPath, targetPath string) {
	t.Helper()
	if err := os.Link(targetPath, linkPath); err != nil {
		t.Skipf("this host refuses hard link creation at %s (%v)", linkPath, err)
	}
}

// PlantDirectoryAt plants a directory at path — the one plant kind that
// works on every platform, so it anchors every table.
func PlantDirectoryAt(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("plant the directory at %s: %v", path, err)
	}
}

// AssertBytesUnchanged fails the test unless path's content is still
// exactly want — the byte-identity half of every planted-sentinel
// assertion. A truncate-then-restore (write through the plant, then
// fix up the length) cannot pass this.
func AssertBytesUnchanged(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("the sentinel %s became unreadable: %v — the plant's target was destroyed", path, err)
		return
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the sentinel %s was written through: got %q, want %q", path, got, want)
	}
}

// AssertKindStillThere fails the test unless path still exists and is
// still an entry of kind want ("symlink", "directory", "fifo", "file"):
// the plant itself must survive the operation untouched, not be
// consumed by it.
func AssertKindStillThere(t *testing.T, path, want string) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Errorf("the planted %s at %s vanished (Lstat: %v)", want, path, err)
		return
	}
	mode := st.Mode()
	var got string
	switch {
	case mode&os.ModeSymlink != 0:
		got = "symlink"
	case mode&os.ModeNamedPipe != 0:
		got = "fifo"
	case mode.IsDir():
		got = "directory"
	case mode.IsRegular():
		got = "file"
	default:
		got = mode.String()
	}
	if got != want {
		t.Errorf("the planted entry at %s changed kind: got %s, want %s — the operation must leave the predictable name as it found it", path, got, want)
	}
}

// RunBounded runs op in a goroutine and requires it to finish within
// timeout. A hang IS the failure mode under test — a FIFO wedging a
// privileged open — so on timeout the test FAILS with the operation
// named, and the process is not left blocked on the plant. Returning
// the error is the success path; asserting on it is the caller's job.
func RunBounded(t *testing.T, timeout time.Duration, what string, op func() error) error {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- op() }()
	select {
	case err := <-errc:
		return err
	case <-time.After(timeout):
		t.Fatalf("%s did not return within %s — it is wedged inside the planted entry instead of refusing it", what, timeout)
		return nil
	}
}

// RefusalIn reports whether err's chain mentions the contract's refusal
// wording for kind ("is a symlink" / "not a regular file"). The
// stdlib-only stand-in for datafile.IsRefusal, for the red-first reason
// above.
func RefusalIn(err error, kind string) bool {
	if err == nil {
		return false
	}
	return bytes.Contains([]byte(err.Error()), []byte(kind))
}

// RequireRefusal fails the test unless err names the expected refusal —
// the positive assertion of every refusal row.
func RequireRefusal(t *testing.T, err error, kind string) {
	t.Helper()
	if err == nil {
		t.Errorf("expected a %q refusal, got success — a planted entry must be refused in words, not used", kind)
		return
	}
	if !RefusalIn(err, kind) {
		t.Errorf("expected a %q refusal, got: %v", kind, err)
	}
}
