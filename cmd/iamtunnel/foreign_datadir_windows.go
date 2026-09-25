//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// dataDirOwnerForeignOS is the Windows half of the IAMT-333 (P1.6) probe:
// who owns dir, read through a handle with READ_CONTROL the same way the
// exe-ACL and door-lockdown walks read owners (objectWriters,
// winkeys.OwnerTrusted) — never by asking a path API that resolves the
// name a second time. Only an elevated caller ever reaches it, and
// elevated on Windows is a token property, not another account: the
// owner comparison is "this process's own account, or the accounts whose
// objects are system locations by construction" (Administrators, SYSTEM,
// TrustedInstaller — winkeys.OwnerTrusted). A directory that does not
// exist passes (a first run is legitimate — os.ErrNotExist is what a
// missing file comes back as through CreateFile too); any other open or
// read failure comes back as the probe error the gate turns into a
// fail-closed refusal.
func dataDirOwnerForeignOS(dir string) (string, error) {
	// The route to dir first (review finding R4 N-10): a junction or symlink in one
	// of its parents that SYSTEM, Administrators or TrustedInstaller do not
	// own can be re-aimed by its owner between this check and the write -
	// the same move as a link at dir itself, one level up.
	if reason, err := parentLinkForeignWindows(dir); err != nil || reason != "" {
		return reason, err
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", err
	}
	// FILE_FLAG_OPEN_REPARSE_POINT: the name itself is judged, not what a
	// junction or symlink at it resolves to (review finding R4 N-08) - a link whose
	// target Administrators own would otherwise pass, and its owner could
	// re-aim it before the elevated write lands.
	h, err := windows.CreateFile(name, windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read the owner of %s: %w", dir, err)
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return "", fmt.Errorf("read the attributes of %s: %w", dir, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "a link, not a directory — whoever owns the link can re-aim it between this check and the write, " +
			"so the check cannot vouch for where the write lands", nil
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", fmt.Errorf("read the owner of %s: %w", dir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return "", fmt.Errorf("read the owner of %s: %w", dir, err)
	}
	if winkeys.OwnerTrusted(owner) {
		return "", nil
	}
	who := describeOwnerSID(owner)
	return fmt.Sprintf("owned by %s, and this console is elevated — "+
		"a directory somebody else owns can aim this command's writes at files of their choosing",
		who), nil
}

// describeOwnerSID names an owner the way the operator knows it: an
// account (with its domain, the form icacls prints) when the lookup
// answers, the raw SID when it does not.
func describeOwnerSID(owner *windows.SID) string {
	if owner == nil {
		return "an account this process is not"
	}
	if acc, dom, _, lerr := owner.LookupAccount(""); lerr == nil {
		if dom != "" {
			return dom + `\` + acc
		}
		return acc
	}
	return owner.String()
}

// parentLinkForeignWindows walks dir's parents to the volume root and names
// the first reparse point among them whose owner is not SYSTEM,
// Administrators or TrustedInstaller ("" - none). A parent that does not
// exist yet is skipped: it will be created by the command.
func parentLinkForeignWindows(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for p := filepath.Dir(abs); ; p = filepath.Dir(p) {
		reason, err := reparseOwnerForeign(p)
		if err != nil {
			return "", err
		}
		if reason != "" {
			return reason, nil
		}
		if filepath.Dir(p) == p {
			return "", nil
		}
	}
}

// reparseOwnerForeign answers for one path component: "" unless it is a
// reparse point whose owner is not a trusted system account.
func reparseOwnerForeign(p string) (string, error) {
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read the attributes of %s: %w", p, err)
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return "", fmt.Errorf("read the attributes of %s: %w", p, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return "", nil
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", fmt.Errorf("read the owner of %s: %w", p, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return "", fmt.Errorf("read the owner of %s: %w", p, err)
	}
	if linkOwnerSystem(owner) {
		return "", nil
	}
	return fmt.Sprintf("reached through the link %s, owned by %s — whoever owns the link can re-aim it between this check and the write", p, describeOwnerSID(owner)), nil
}

// linkOwnerSystem is the stricter owner rule for a link on the route: only
// the system accounts - Administrators, SYSTEM, TrustedInstaller - and NOT
// the running account (winkeys.OwnerTrusted trusts that one): the attacker
// the gate is about is this account's own unelevated process.
func linkOwnerSystem(owner *windows.SID) bool {
	for _, s := range []string{"S-1-5-32-544", "S-1-5-18", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"} {
		if sid, err := windows.StringToSid(s); err == nil && owner != nil && owner.Equals(sid) {
			return true
		}
	}
	return false
}

// dropToInvokerOS is P2.8's Windows half, and it never drops. An elevated
// console on Windows runs under the same account as the unelevated one --
// its own profile is its own, and the refusal never speaks there. What the
// refusal does meet is somebody ELSE's directory, and becoming another
// account takes that account's token, which an elevated process does not
// have. The refusal and --accept-foreign-data-dir stay the whole answer.
func dropToInvokerOS(env map[string]string, dir string) (bool, error) {
	return false, nil
}
