package main

// Helpers of the R2-CX owner tests (F-07, F-13, F-12): a directory "made
// by another account" is one whose owner is that account, and only a
// process holding SeRestorePrivilege may hand an object to an owner other
// than itself. The privilege is enabled for the test process alone, and
// only for as long as a test needs it.

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// r2cxGuests is BUILTIN\Guests: an owner no data directory may keep.
const r2cxGuests = "S-1-5-32-546"

// r2cxWithPrivilege enables the named privilege in this process's token
// and puts it back the way it was when the test ends.
func r2cxWithPrivilege(t *testing.T, name string) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	var luid windows.LUID
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		t.Fatal(err)
	}
	enable := windows.Tokenprivileges{PrivilegeCount: 1}
	enable.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	var previous windows.Tokenprivileges
	var size uint32
	if err := windows.AdjustTokenPrivileges(token, false, &enable, uint32(unsafe.Sizeof(previous)), &previous, &size); err != nil {
		token.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil)
		token.Close()
	})
}

// r2cxSetOwner hands path to the account sid, as if that account had
// made it.
func r2cxSetOwner(t *testing.T, path, sid string) {
	t.Helper()
	r2cxWithPrivilege(t, "SeRestorePrivilege")
	owner, err := windows.StringToSid(sid)
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil)
	if err == windows.ERROR_INVALID_OWNER {
		// AdjustTokenPrivileges reports a privilege the token does not
		// hold as success; this is where its absence shows.
		t.Skipf("this process may not hand %s to %s (it does not hold SeRestorePrivilege) - the owner tests need an elevated console", path, sid)
	}
	if err != nil {
		t.Fatalf("hand %s to %s: %v", path, sid, err)
	}
}

// r2cxOwner is the SID of path's owner.
func r2cxOwner(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		t.Fatalf("%s: no owner: %v", path, err)
	}
	return owner.String()
}

// r2cxMe is the SID of the account running the tests.
func r2cxMe(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}
