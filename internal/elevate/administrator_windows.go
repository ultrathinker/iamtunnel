//go:build windows

package elevate

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	levelLocalGroupUsersInfo0 = 0
	localGroupIncludeIndirect = 1
	nerrUserNotFound          = syscall.Errno(2221)
)

type localGroupUsersInfo0 struct {
	name *uint16
}

// VerifyAdministrator reports whether account belongs to the local
// Administrators group. NetUserGetLocalGroups with LG_INCLUDE_INDIRECT asks
// Windows to expand nested (including domain) memberships; each returned
// local group is resolved to a SID before comparison. This function only
// calls read-only account and group APIs.
func VerifyAdministrator(account string) error {
	return newAdministratorVerifier(administratorsForAccount).verify(account)
}

// VerifyOSUser on Windows is a no-op: the Windows machine data
// directory is keyed on the built-in administrators group, not
// on a specific OS user, so there is no per-user existence check
// to run at enrol time. cmd/iamtunnel/enrol's verifyEnrolOSUser
// gate already accepted the "DOMAIN\name" shape (config.
// validOSUserWindows); the Administrators membership is checked
// when "server start" runs (VerifyAdministrator in
// requireServerElevation's downstream checks).
func VerifyOSUser(_ string) error { return nil }

func administratorsForAccount(account string) ([]string, error) {
	user, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return nil, fmt.Errorf("encode Windows account %q: %w", account, err)
	}
	var buffer *byte
	var read, total uint32
	status, _, _ := windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserGetLocalGroups").Call(
		0,
		uintptr(unsafe.Pointer(user)),
		levelLocalGroupUsersInfo0,
		localGroupIncludeIndirect,
		uintptr(unsafe.Pointer(&buffer)),
		0xffffffff, // MAX_PREFERRED_LENGTH: let the API size the read-only result.
		uintptr(unsafe.Pointer(&read)),
		uintptr(unsafe.Pointer(&total)),
	)
	if status != 0 {
		if syscall.Errno(status) == nerrUserNotFound {
			return nil, &AccountNotFoundError{Account: account}
		}
		return nil, fmt.Errorf("read local group membership for Windows account %q: %w", account, syscall.Errno(status))
	}
	if buffer != nil {
		defer windows.NetApiBufferFree(buffer)
	}
	entries := unsafe.Slice((*localGroupUsersInfo0)(unsafe.Pointer(buffer)), int(read))
	sids := make([]string, 0, len(entries))
	for _, entry := range entries {
		group := windows.UTF16PtrToString(entry.name)
		sid, _, _, err := windows.LookupSID("", group)
		if err != nil {
			return nil, fmt.Errorf("resolve local group %q to SID: %w", group, err)
		}
		sids = append(sids, sid.String())
	}
	return sids, nil
}
