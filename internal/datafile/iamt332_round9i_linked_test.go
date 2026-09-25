package datafile

// iamt332_round9i_linked_test.go — the link-count guard on the
// create-or-refuse path (IAMT-332 round 9i).
//
// Round nine's Create refuses a symlink, a FIFO, a directory, a socket
// and a Windows reparse point, and reports a plain os.ErrExist for "a
// regular file is already at this name" so callers can tell "the name is
// taken by a file of ours" from "somebody planted something". The hard
// link is the one plant that satisfies every one of those checks: it IS
// a regular file. It is also the one plant an unprivileged attacker on
// Windows can create for free, which is why the door layer already
// refuses nlink != 1 for its key file on POSIX
// (internal/winkeys/doors_unix.go) and why IAMT-291 refuses Nlink > 1 in
// its chown walk. This is the cross-platform form of that guard, and it
// is what separates the two callers' cases:
//
//   - a linked name is a plant: refuse it loudly, never write through it
//     (LinkedRefusal), because writing would land on the file the link
//     points at;
//   - a plain regular file is a name some earlier run of ours took:
//     plain os.ErrExist, which the session recorders turn into "take the
//     next name" (internal/gateway/record/sessionname.go) and the
//     journal archives already treat the same way.
//
// Red-first note: this file cannot compile against 1b92fad, where the
// package does not exist. The red-first proof of the same property is at
// the callers — internal/gateway/record/iamt332_round9_test.go's
// "hard link" row, which fails on 1b92fad because the old O_TRUNC create
// wrote straight through the link and destroyed the sentinel behind it.
//
// The suite runs on Windows as well as POSIX: the hard-link plant itself
// skips on a host that refuses it, but the classification rows (a plain
// file, a symlink, a directory) run everywhere.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestIAMT332R9ICreateRefusesALinkedName plants a hard link at the name
// and requires Create to refuse it as a linked entry while leaving the
// file the link points at byte-for-byte intact.
func TestIAMT332R9ICreateRefusesALinkedName(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sentinel")
	sentinel := []byte("iamt332 sentinel: a hard link must never be written through")
	if err := os.WriteFile(target, sentinel, 0o600); err != nil {
		t.Fatalf("write the sentinel: %v", err)
	}
	linked := filepath.Join(dir, "session.cast")
	if err := os.Link(target, linked); err != nil {
		t.Skipf("this host refuses hard link creation, so the plant cannot be made here (%v)", err)
	}

	f, err := Create(linked, 0o600)
	if err == nil {
		_ = f.Close()
		t.Fatalf("Create accepted a name that is a hard link to %s — the create must refuse a linked name instead of opening it", target)
	}
	var re *RefusalError
	if !errors.As(err, &re) || re.Kind != KindLinked {
		t.Fatalf("Create over a hard link must report the linked refusal, got: %v", err)
	}
	if re.Links < 2 {
		t.Errorf("the linked refusal must carry the link count (got %d)", re.Links)
	}
	got, rerr := os.ReadFile(target)
	if rerr != nil {
		t.Fatalf("the sentinel became unreadable: %v", rerr)
	}
	if string(got) != string(sentinel) {
		t.Errorf("the sentinel behind the hard link was written through: got %q, want %q", got, sentinel)
	}
}

// TestIAMT332R9ICreateKeepsAPlainRegularFileAsErrExist is the other half:
// a singly-linked regular file at the name is NOT a plant, and it must
// stay distinguishable by errors.Is so the callers that legitimately
// reuse a clock-derived name can advance instead of dropping a session.
func TestIAMT332R9ICreateKeepsAPlainRegularFileAsErrExist(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "session.cast")
	if err := os.WriteFile(name, []byte("an earlier session of ours"), 0o600); err != nil {
		t.Fatalf("write the existing file: %v", err)
	}

	f, err := Create(name, 0o600)
	if err == nil {
		_ = f.Close()
		t.Fatalf("Create must not take a name that is already taken")
	}
	if IsRefusal(err) {
		t.Fatalf("a plain regular file at the name must NOT be a refusal — it is the legitimate reuse case the callers advance on; got: %v", err)
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("a plain regular file at the name must report os.ErrExist, got: %v", err)
	}
	if raw, rerr := os.ReadFile(name); rerr != nil || string(raw) != "an earlier session of ours" {
		t.Errorf("the existing file must be untouched (got %q, %v)", raw, rerr)
	}
}

// TestIAMT332R9ICreateClassifiesTheOtherPlants keeps the round-nine
// contract in one place: everything that is not a plain regular file
// gets its own typed refusal, never a bare OS error and never os.ErrExist.
func TestIAMT332R9ICreateClassifiesTheOtherPlants(t *testing.T) {
	for _, row := range []struct {
		name string
		kind string
		// plant makes the entry; ok=false skips the row (a host that
		// refuses the plant kind).
		plant func(t *testing.T, path string) bool
	}{
		{
			name:  "symlink",
			kind:  KindSymlink,
			plant: func(t *testing.T, path string) bool { return os.Symlink(path+".target", path) == nil },
		},
		{
			name:  "directory",
			kind:  KindDirectory,
			plant: func(t *testing.T, path string) bool { return os.Mkdir(path, 0o700) == nil },
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			name := filepath.Join(dir, "session.cast")
			if !row.plant(t, name) {
				t.Skipf("this host refuses to plant a %s here", row.name)
			}
			f, err := Create(name, 0o600)
			if err == nil {
				_ = f.Close()
				t.Fatalf("Create accepted a planted %s", row.name)
			}
			var re *RefusalError
			if !errors.As(err, &re) || re.Kind != row.kind {
				t.Fatalf("a planted %s must get the %s refusal, got: %v", row.name, row.kind, err)
			}
			if errors.Is(err, os.ErrExist) {
				t.Errorf("a planted %s must not read as a benign os.ErrExist — callers advance on that", row.name)
			}
		})
	}
}
