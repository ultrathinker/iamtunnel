//go:build linux || darwin

package winkeys

// doors_fifo_nonblock_unix_test.go — M-9a (code review 23.09.2026,
// review F-11): a FIFO planted at the key file's name must be
// REFUSED in words, not wedged on.
//
// The door's three file openings all ran O_RDONLY|O_NOFOLLOW and
// checked the entry type with fstat AFTERWARDS. On POSIX a plain
// read-only open of a FIFO blocks inside open(2) until a writer
// appears, so the fstat that would have refused the plant never ran:
// Install/Remove/SweepStale hung with the door's file lock held, and
// the read and the read-back hung the same way. No root is needed to
// arrange it — the owner of the .ssh directory can plant the FIFO.
//
// The bounded wait is part of the test's meaning (the pattern
// iamt332_fifo_journal_posix_test.go set): a genuine hang fails the
// test naming the open that hung, it does not wedge the suite. The
// door-level row reaches only the first of the three openings (the
// strict preflight refuses the plant before the read and the
// read-back are reached), so the other two are driven directly —
// they are the same shape and each one is its own line of the fix.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// mustReturnWithin runs op in a goroutine and requires it to come back
// within d. A hang IS the failure mode under test here — a FIFO
// wedging an open that holds the door's lock — so the timeout branch
// fails the test on this line, naming the operation.
func mustReturnWithin(t *testing.T, d time.Duration, what string, op func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- op() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("%s did not return within %s — it is blocked inside open(2) on the FIFO planted at the key file's name instead of refusing a non-regular file (M-9a, review F-11)", what, d)
		return nil
	}
}

// TestM9aDoorOperationsRefuseAFIFOAtTheKeyFileName plants a FIFO where
// the key file goes and requires every door open of that name to come
// back promptly with the actionable refusal.
func TestM9aDoorOperationsRefuseAFIFOAtTheKeyFileName(t *testing.T) {
	t.Run("door.Install (the strict preflight, before the read)", func(t *testing.T) {
		tree := testsupport.NewSSHTree(t)
		keyFile := tree.KeyPath("auth_keys")
		testsupport.PlantFIFOAt(t, keyFile)

		d := newUnixDoor(t, keyFile)
		done := mustReturnWithin(t, 3*time.Second, "door.Install over a FIFO at the key file's name", func() error {
			return d.Install(makeID(t), TestKey)
		})
		if done == nil {
			t.Fatalf("door.Install accepted the FIFO planted at %s — the key file's name must be refused when it is not a regular file", keyFile)
		}
		if !strings.Contains(done.Error(), "not a regular file") {
			t.Errorf("door.Install refused the FIFO with %q — the refusal must say the name is not a regular file", done)
		}
		testsupport.AssertKindStillThere(t, keyFile, "fifo")
	})

	t.Run("readExistingInSSHDir (the read before the write)", func(t *testing.T) {
		tree := testsupport.NewSSHTree(t)
		keyFile := tree.KeyPath("auth_keys")
		testsupport.PlantFIFOAt(t, keyFile)

		sshFD := openSSHDirFD(t, tree.SSHDir)
		done := mustReturnWithin(t, 3*time.Second, "readExistingInSSHDir over a FIFO at the key file's name", func() error {
			_, err := readExistingInSSHDir(sshFD, filepath.Base(keyFile))
			return err
		})
		if done == nil {
			t.Fatalf("readExistingInSSHDir read a FIFO planted at %s — a non-regular entry must be refused, not read", keyFile)
		}
		if !strings.Contains(done.Error(), "not a regular file") {
			t.Errorf("readExistingInSSHDir refused the FIFO with %q — the refusal must say the name is not a regular file", done)
		}
		testsupport.AssertKindStillThere(t, keyFile, "fifo")
	})

	t.Run("verifyWriteBack (the read-back after the write)", func(t *testing.T) {
		tree := testsupport.NewSSHTree(t)
		keyFile := tree.KeyPath("auth_keys")
		testsupport.PlantFIFOAt(t, keyFile)

		sshFD := openSSHDirFD(t, tree.SSHDir)
		done := mustReturnWithin(t, 3*time.Second, "verifyWriteBack over a FIFO at the key file's name", func() error {
			return verifyWriteBack(sshFD, filepath.Base(keyFile), []byte("door line\n"), 0)
		})
		if done == nil {
			t.Fatalf("verifyWriteBack accepted a FIFO planted at %s — the read-back must refuse a non-regular entry, not read it", keyFile)
		}
		if !strings.Contains(done.Error(), "not a regular file") {
			t.Errorf("verifyWriteBack refused the FIFO with %q — the refusal must say the name is not a regular file", done)
		}
		testsupport.AssertKindStillThere(t, keyFile, "fifo")
	})
}

// openSSHDirFD opens the .ssh directory itself O_DIRECTORY|O_NOFOLLOW:
// the descriptor the two directly-driven helpers take, the same one
// modifyKeyFilePlatform hands them after its own preflight.
func openSSHDirFD(t *testing.T, sshDir string) int {
	t.Helper()
	fd, err := unix.Open(sshDir, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open the .ssh directory %s: %v", sshDir, err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}
