//go:build windows

package main

// r4cx_n08_foreign_link_windows_test.go — review finding R4 N-08.
//
// The foreign-data-directory gate (IAMT-333) read the owner of whatever
// the path resolved to: a junction at --data-dir aimed at a directory
// Administrators own passed the gate, and whoever owns the junction could
// re-aim it at their own folder before the elevated write lands. The
// directory the command writes into must be a directory, not a link to one.

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestR4CXN08_AJunctionAtTheDataDirIsNotJudgedByItsTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if out, err := exec.Command("cmd", "/c", "mkdir", target).CombinedOutput(); err != nil {
		t.Fatalf("mkdir target: %v %s", err, out)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("this host cannot create a junction (%v %s)", err, out)
	}
	reason, err := dataDirOwnerForeignOS(link)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if reason == "" || !strings.Contains(reason, "link") {
		t.Fatalf("review finding R4 N-08: a junction at the data directory passed the gate on its target's owner (reason %q)", reason)
	}
}

// review finding R4 N-10: a junction in one of the data directory's PARENTS, owned
// by an ordinary account, re-aims the whole route just as well. The test
// hands the junction to this account explicitly: an elevated test run
// would otherwise create it owned by Administrators, which the check
// rightly trusts.
func TestR4CXN10_AUserOwnedJunctionAboveTheDataDirIsRefused(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if out, err := exec.Command("cmd", "/c", "mkdir", target).CombinedOutput(); err != nil {
		t.Fatalf("mkdir target: %v %s", err, out)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("this host cannot create a junction (%v %s)", err, out)
	}
	if err := r4cxOwnLinkAsSelf(link); err != nil {
		t.Skipf("cannot hand the junction to this account (%v)", err)
	}
	reason, err := dataDirOwnerForeignOS(filepath.Join(link, "client"))
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !strings.Contains(reason, "reached through the link "+link) {
		t.Fatalf("review finding R4 N-10: a user-owned junction above the data directory passed the gate (reason %q)", reason)
	}
}

func r4cxOwnLinkAsSelf(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.WRITE_OWNER|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil)
}
