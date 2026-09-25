package main

// iamt332_tmpnames_test.go — IAMT-332 round 8. The machine-role atomic
// writers still used the pre-round-2 predictable-tmp pattern: tmp :=
// path + ".tmp" and os.WriteFile through it. A directory owner who can
// choose --data-dir plants a symlink at the predictable name (say
// machine.key.tmp) pointing at somebody else's file, and the privileged
// run that generates the key — "sudo iamtunnel enrol <code> --data-dir
// <dir>" — writes the private-key bytes THROUGH the link, destroying the
// target. Round 8 moves both writers to the same random O_EXCL
// temporary atomicWriteBytes has used since round 2: a name an attacker
// cannot pre-plant at, so the write and the DACL lockdown that follows
// it can only ever land on a file this process just created.
//
// The planted name must survive untouched (the fix ignores it: the
// random suffix never collides with the literal name), the sentinel
// behind a planted symlink must come out byte-for-byte intact, and the
// real write must still succeed. Writing through a link does not hang,
// so unlike the FIFO tests these assertions run directly, no bounded
// wait. The directory rows are the portable half: on a Windows box
// without symlink rights the symlink rows skip themselves with the
// reason (the directory plant cannot corrupt, but it still proves the
// writer no longer touches the predictable name — pre-fix the write
// failed outright).
//
// Verification note: this package's tests do not run in the Linux docker
// harness (the GUI-side packages need cgo/X11), so the POSIX behaviour
// of these rows is exercised on a real POSIX host (the live checks); on
// Windows the same file runs its rows natively.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestIAMT332Round8MachineWritersNeverWriteThroughAPredictableTmpName
// plants a non-file entry at each writer's predictable temporary name and
// requires the writer to ignore it — succeed, leave the plant exactly as
// found, and land the write on the real name via a fresh random
// temporary.
func TestIAMT332Round8MachineWritersNeverWriteThroughAPredictableTmpName(t *testing.T) {
	t.Run("atomicWriteMachineBytes with a directory planted at <machine.id>.tmp", func(t *testing.T) {
		dir := t.TempDir()
		idPath := filepath.Join(dir, "machine.id")
		if err := os.Mkdir(idPath+".tmp", 0o700); err != nil {
			t.Fatalf("plant the directory: %v", err)
		}
		if err := atomicWriteMachineBytes(idPath, []byte("machine-332")); err != nil {
			t.Fatalf("atomicWriteMachineBytes failed over a plant at its predictable tmp name %s: %v — the writer must use a random temporary, not the flat path+\".tmp\" (IAMT-332 round 8)", idPath+".tmp", err)
		}
		if got, rerr := os.ReadFile(idPath); rerr != nil || string(got) != "machine-332" {
			t.Errorf("the real file did not come out of the write (read %q, %v)", got, rerr)
		}
		assertStillADirectory(t, idPath+".tmp")
	})

	t.Run("generateMachineSigner with a directory planted at <machine.key>.tmp", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "machine.key")
		if err := os.Mkdir(keyPath+".tmp", 0o700); err != nil {
			t.Fatalf("plant the directory: %v", err)
		}
		signer, err := generateMachineSigner(keyPath)
		if err != nil {
			t.Fatalf("generateMachineSigner failed over a plant at its predictable tmp name %s: %v — the writer must use a random temporary, not the flat path+\".tmp\" (IAMT-332 round 8)", keyPath+".tmp", err)
		}
		if signer == nil {
			t.Fatal("generateMachineSigner returned a nil signer alongside a nil error")
		}
		if _, serr := os.Stat(keyPath); serr != nil {
			t.Errorf("the key file did not come out of the generation: %v", serr)
		}
		assertStillADirectory(t, keyPath+".tmp")
	})

	for _, tc := range []struct {
		name    string
		final   string
		symlink func(t *testing.T, final, sentinel string)
	}{
		{
			name:  "atomicWriteMachineBytes with a symlink planted at <machine.id>.tmp",
			final: "machine.id",
			symlink: func(t *testing.T, final, sentinel string) {
				if err := atomicWriteMachineBytes(final, []byte("machine-332")); err != nil {
					t.Fatalf("atomicWriteMachineBytes failed over a plant at its predictable tmp name: %v — the writer must use a random temporary, not the flat path+\".tmp\" (IAMT-332 round 8)", err)
				}
				if got, rerr := os.ReadFile(final); rerr != nil || string(got) != "machine-332" {
					t.Errorf("the real file did not come out of the write (read %q, %v)", got, rerr)
				}
			},
		},
		{
			name:  "generateMachineSigner with a symlink planted at <machine.key>.tmp",
			final: "machine.key",
			symlink: func(t *testing.T, final, sentinel string) {
				signer, err := generateMachineSigner(final)
				if err != nil {
					t.Fatalf("generateMachineSigner failed over a plant at its predictable tmp name: %v — the writer must use a random temporary, not the flat path+\".tmp\" (IAMT-332 round 8)", err)
				}
				if signer == nil {
					t.Fatal("generateMachineSigner returned a nil signer alongside a nil error")
				}
				if _, serr := os.Stat(final); serr != nil {
					t.Errorf("the key file did not come out of the generation: %v", serr)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			final := filepath.Join(dir, tc.final)
			sentinelPath := filepath.Join(dir, "outside-target.txt")
			sentinel := []byte("iamt332 sentinel: a predictable tmp name must never be written through")
			if err := os.WriteFile(sentinelPath, sentinel, 0o600); err != nil {
				t.Fatalf("write the sentinel: %v", err)
			}
			if err := os.Symlink(sentinelPath, final+".tmp"); err != nil {
				t.Skipf("this host does not grant symlink creation, so the corruption the fix removes cannot be planted here (%v) — the directory rows above still pin the random-tmp behaviour", err)
			}
			tc.symlink(t, final, sentinelPath)
			got, rerr := os.ReadFile(sentinelPath)
			if rerr != nil || !bytes.Equal(got, sentinel) {
				t.Errorf("the writer followed the symlink planted at the predictable tmp name %s and destroyed or rewrote its target (read %q, %v) — the temporary must be a random O_EXCL name the plant cannot aim at (IAMT-332 round 8)", final+".tmp", got, rerr)
			}
			assertStillASymlink(t, final+".tmp")
		})
	}
}

// assertStillADirectory requires the planted entry to be exactly what was
// planted: the fix ignores the predictable name, it neither removes nor
// replaces it.
func assertStillADirectory(t *testing.T, path string) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() {
		t.Errorf("the planted directory at %s did not survive the write (Lstat: %v, %#v) — the writer must leave the predictable name as it found it", path, err, st)
	}
}

// assertStillASymlink is assertStillADirectory for the link plants.
func assertStillASymlink(t *testing.T, path string) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the planted symlink at %s did not survive the write (Lstat: %v, %#v) — the writer must leave the predictable name as it found it", path, err, st)
	}
}
