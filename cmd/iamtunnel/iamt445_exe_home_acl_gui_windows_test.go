//go:build windows && !nogui

package main

// IAMT-445, the window's half: "Move it there for me" is a button of the
// window, so its test builds only where the window does (IAMT-470). The
// helpers and the rest of IAMT-445 are in iamt445_exe_home_acl_windows_test.go.

import (
	"path/filepath"
	"testing"
)

func TestIAMT445_TheCopyIntoTheProgramHomeIsLockedToAdministrators(t *testing.T) {
	requireWritableLockedFiles(t)
	root := t.TempDir()
	iamt445OpenLikeTheSystemDrive(t, root)

	dst, err := guiGatewayCopyItself(map[string]string{"SystemDrive": root})
	if err != nil {
		t.Fatalf("guiGatewayCopyItself: %v", err)
	}
	home := filepath.Dir(dst)
	relaxACLOnCleanup(t, dst, home)

	if got := iamt445Writers(t, home); len(got) != 0 {
		t.Errorf("%s can be changed by %v: anybody who signs in could put their own program where the elevated one is started from", home, got)
	}
	if got := iamt445Writers(t, dst); len(got) != 0 {
		t.Errorf("the copied program %s can be changed by %v", dst, got)
	}
}
