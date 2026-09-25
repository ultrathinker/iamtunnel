//go:build windows

package main

// R1-CX F-18: before starting iamtunnel.exe with an administrator's token
// (the logon task of server install, "Restart as administrator"), Windows
// checked who can change the program and the folder it is in - and no
// folder above. A folder above that another account may rename (DELETE on
// it) or empty of its children (FILE_DELETE_CHILD) lets them move the
// whole locked home aside and put their own in its place; the next
// elevated start runs theirs. The Unix check (exe_owner.go) has always
// walked every folder up to the root.
//
// Every ACL here is set on folders inside t.TempDir() (gate 11); like the
// other ACL tests of this package they need an elevated test process.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// r1cxF18On keeps the entries of who that name root or a path under it.
// What the folders above t.TempDir() allow is the machine's own business:
// on the one this was written on, the accounts of an installed sandbox may
// modify the whole of %TEMP% - and since F-18 they are named, as they
// should be, so a test cannot expect silence from them.
func r1cxF18On(who []string, root string) []string {
	var out []string
	for _, w := range who {
		i := strings.LastIndex(w, " (on ")
		if i < 0 {
			out = append(out, w)
			continue
		}
		path := strings.TrimSuffix(w[i+len(" (on "):], ")")
		if strings.EqualFold(path, root) || strings.HasPrefix(strings.ToLower(path), strings.ToLower(root)+`\`) {
			out = append(out, w)
		}
	}
	return out
}

func TestR1CX_F18_AFolderAboveTheProgramThatOthersCanRenameIsNamed(t *testing.T) {
	requireWritableLockedFiles(t)
	root := t.TempDir()
	iamt445OpenLikeTheSystemDrive(t, root)
	// Made at a root like C:, a folder inherits Modify for every signed-in
	// account - DELETE on itself included.
	mid := filepath.Join(root, "tools")
	if err := os.Mkdir(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(mid, "iamtunnel")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(home, "iamtunnel.exe")
	if err := os.WriteFile(exe, []byte("stand-in"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := lockProgramHome(home, exe); err != nil {
		t.Fatal(err)
	}
	relaxACLOnCleanup(t, exe, home)

	who, err := exeWriters(exe, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(who, "; "), "(on "+mid+")") {
		t.Fatalf("writers=%v: %s and the program are locked to administrators, but %s above them can be renamed by every signed-in account - and a folder of theirs put in its place", who, home, mid)
	}
}

func TestR1CX_F18_AChainOnlyYouAndAdministratorsCanChangePasses(t *testing.T) {
	requireWritableLockedFiles(t)
	root := t.TempDir()
	iamt445OnlyThisAccount(t, root)
	mid := filepath.Join(root, "tools")
	if err := os.Mkdir(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(mid, "iamtunnel.exe")
	if err := os.WriteFile(exe, []byte("stand-in"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The window's rule: the person answering the prompt is trusted. The
	// root of the drive lets every account add a folder to it - that
	// cannot move one that is there, and must not refuse every program.
	who, err := exeWriters(exe, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := r1cxF18On(who, root); len(got) != 0 {
		t.Errorf("a program only this account and administrators can change, at any depth, was said to be changeable by %v", got)
	}
	vol := filepath.VolumeName(root) + `\`
	for _, w := range who {
		if strings.HasSuffix(w, "(on "+vol+")") {
			t.Errorf("the root of the drive was counted (%s): adding a folder to it cannot move one that is there", w)
		}
	}
}
