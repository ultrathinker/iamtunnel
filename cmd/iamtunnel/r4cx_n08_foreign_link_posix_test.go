//go:build !windows

package main

// r4cx_n08_foreign_link_posix_test.go — review finding R4 N-08, the POSIX half: a
// symlink at the data directory is judged as a link, not by the owner of
// what it points at (see the Windows file for the why).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR4CXN08_ASymlinkAtTheDataDirIsNotJudgedByItsTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	reason, err := dataDirOwnerForeignOS(link)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if reason == "" || !strings.Contains(reason, "link") {
		t.Fatalf("review finding R4 N-08: a symlink at the data directory passed the gate on its target's owner (reason %q)", reason)
	}
}

// review finding R4 N-10, the POSIX half: a symlink root does not own, in one of the
// data directory's parents, re-aims the whole route.
func TestR4CXN10_AUserOwnedSymlinkAboveTheDataDirIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run as root the symlink below is root's own, which the check rightly trusts")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	reason, err := dataDirOwnerForeignOS(filepath.Join(link, "client"))
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !strings.Contains(reason, "reached through the link "+link) {
		t.Fatalf("review finding R4 N-10: a user-owned symlink above the data directory passed the gate (reason %q)", reason)
	}
}
