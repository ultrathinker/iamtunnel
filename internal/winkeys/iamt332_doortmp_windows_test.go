//go:build windows

package winkeys

// iamt332_doortmp_windows_test.go — IAMT-332 round 8, the door layer's
// Windows writer. writeAtomicBytesPlatform built its temporary as
// path+"."+pid+".tmp" — a name an attacker can compute: the door user
// knows their own authorized_keys path, and the machine service's PID at
// write time is enumerable, so a pre-planted symlink at that name aimed
// the privileged write (and the DACL lockdown that follows it) at
// whatever the user pointed the link at. The Unix half of the door layer
// is openat-based (SPEC §3.2.1) and never had this shape; the Windows
// half now takes the same random O_EXCL temporary the rest of the repo
// writes through (IAMT-332 round 2, machine writers in round 8) —
// without touching the path-based read/verify discipline explicitly
// permitted for this layer.
//
// In-process os.Getpid() IS the pid the writer would have used, so the
// planted name below is exactly the pre-fix temporary name. Writing
// through a link does not hang, so the assertions run directly.

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestIAMT332Round8DoorKeyWriterNeverWritesThroughAPredictableTmpName(t *testing.T) {
	t.Run("a directory planted at the pid-name", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "authorized_keys")
		tmpName := keyPath + "." + strconv.Itoa(os.Getpid()) + ".tmp"
		if err := os.Mkdir(tmpName, 0o700); err != nil {
			t.Fatalf("plant the directory: %v", err)
		}
		if err := writeAtomicBytesPlatform(keyPath, []byte("door line\n"), DoorOptions{}); err != nil {
			t.Fatalf("writeAtomicBytesPlatform failed over a plant at its predictable tmp name %s: %v — the writer must use a random temporary (IAMT-332 round 8)", tmpName, err)
		}
		if got, rerr := os.ReadFile(keyPath); rerr != nil || string(got) != "door line\n" {
			t.Errorf("the real file did not come out of the write (read %q, %v)", got, rerr)
		}
		if st, err := os.Lstat(tmpName); err != nil || !st.IsDir() {
			t.Errorf("the planted directory at %s did not survive the write (Lstat: %v, %#v) — the writer must leave the predictable name as it found it", tmpName, err, st)
		}
	})

	t.Run("a symlink planted at the pid-name", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "authorized_keys")
		sentinelPath := filepath.Join(dir, "outside-target.txt")
		sentinel := []byte("iamt332 sentinel: a predictable tmp name must never be written through")
		if err := os.WriteFile(sentinelPath, sentinel, 0o600); err != nil {
			t.Fatalf("write the sentinel: %v", err)
		}
		tmpName := keyPath + "." + strconv.Itoa(os.Getpid()) + ".tmp"
		if err := os.Symlink(sentinelPath, tmpName); err != nil {
			t.Skipf("this host does not grant symlink creation, so the corruption the fix removes cannot be planted here (%v)", err)
		}
		if err := writeAtomicBytesPlatform(keyPath, []byte("door line\n"), DoorOptions{}); err != nil {
			t.Fatalf("writeAtomicBytesPlatform failed over a plant at its predictable tmp name %s: %v — the writer must use a random temporary (IAMT-332 round 8)", tmpName, err)
		}
		got, rerr := os.ReadFile(sentinelPath)
		if rerr != nil || !bytes.Equal(got, sentinel) {
			t.Errorf("the door writer followed the symlink planted at %s and destroyed or rewrote its target (read %q, %v) — the temporary must be a random O_EXCL name the plant cannot aim at (IAMT-332 round 8)", tmpName, got, rerr)
		}
		if st, err := os.Lstat(tmpName); err != nil || st.Mode()&os.ModeSymlink == 0 {
			t.Errorf("the planted symlink at %s did not survive the write (Lstat: %v, %#v) — the writer must leave the predictable name as it found it", tmpName, err, st)
		}
		if got, rerr := os.ReadFile(keyPath); rerr != nil || string(got) != "door line\n" {
			t.Errorf("the real file did not come out of the write (read %q, %v)", got, rerr)
		}
	})
}
