//go:build windows

package main

// exe_acl_windows.go - who may change the program that Windows starts
// with an administrator's token (IAMT-445).
//
// iamtunnel.exe is started elevated three ways: "Restart as administrator"
// in the window, the logon task server install registers (HighestAvailable,
// at every sign-in, no prompt), and the gateway service. Whoever can change
// that file, or add one beside it, runs their code with that token. The
// program's one home is C:\iamtunnel, and a folder made at the root of the
// system drive inherits the root's grant to every signed-in account:
// NT AUTHORITY\Authenticated Users, Modify, on everything inside. So the
// home is locked to Administrators when it is made (lockProgramHome), and
// nothing is started elevated from a place others can change.

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trustedExeWriters may change a program that is started elevated: the
// system, the Administrators group, and TrustedInstaller, which owns
// everything under C:\Program Files.
var trustedExeWriters = map[string]bool{
	"S-1-5-18":     true,
	"S-1-5-32-544": true,
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
}

// exeChangeRights is every right that lets a principal rewrite, replace,
// delete or re-permission a file - or, on a folder, add a file or folder
// to it (0x2, 0x4) or delete a child (0x40): whoever can put a file beside
// the program can swap it by renaming, or plant a DLL it loads.
const exeChangeRights = 0x2 | 0x4 | 0x40 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

// ancestorChangeRights is what matters on a folder further up the path: the
// right to move or delete that folder itself (DELETE), to delete or rename
// what is in it (FILE_DELETE_CHILD, 0x40), or to give oneself either
// (WRITE_DAC, WRITE_OWNER, GENERIC_ALL). Adding a file or a folder to it
// (0x2, 0x4) is not: that cannot move a folder already on the way to the
// program - and the root of every system drive grants it to every
// signed-in account.
const ancestorChangeRights = windows.DELETE | 0x40 | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL

// exeWriters names everybody outside trustedExeWriters who can change the
// program at exe, the folder it sits in, or any folder above it up to the
// root of its volume. With trustSelf the account running this is trusted
// as well: that is right for a prompt that account answers itself, and
// wrong for a task that starts with no prompt at all, where the account's
// own unelevated processes are exactly who must not be able to swap the
// program.
//
// The folders above used to go unchecked (R1-CX F-18): one another account
// may rename or empty of its children lets them move the whole locked home
// aside and put their own in its place, and the next elevated start runs
// theirs - the Unix check (exe_owner.go) has always walked to the root.
// Both paths are walked: the one Windows will be asked to start, each link
// or junction on it read as itself, not as what it points to (whoever may
// replace a link redirects the start), and, when links make it differ, the
// one the program really is at.
//
// The owner is counted as a writer, because an owner can always rewrite
// the DACL; an ACE is counted when it applies to the object itself (not
// inherit-only) and allows any of the rights that matter at that level.
// Deny ACEs are not weighed against allows - that can only make the
// answer stricter.
func exeWriters(exe string, trustSelf bool) ([]string, error) {
	self := ""
	if trustSelf {
		sid, err := currentUserSIDString()
		if err != nil {
			return nil, err
		}
		self = sid
	}
	chains := [][]string{exePathChain(exe)}
	real, err := finalExePath(exe)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(real, exe) {
		chains = append(chains, exePathChain(real))
	}
	var out []string
	seen := map[string]bool{}
	for _, chain := range chains {
		for i, path := range chain {
			rights := uint32(ancestorChangeRights)
			if i < 2 {
				rights = exeChangeRights // the program and the folder it is in
			}
			sids, err := objectWriters(path, self, rights)
			if err != nil {
				return nil, err
			}
			for _, sid := range sids {
				w := accountName(sid) + " (on " + path + ")"
				if !seen[w] {
					seen[w] = true
					out = append(out, w)
				}
			}
		}
	}
	return out, nil
}

// exePathChain is exe, the folder it is in, and every folder above that up
// to the root of its volume.
func exePathChain(exe string) []string {
	chain := []string{exe}
	for dir := filepath.Dir(exe); ; dir = filepath.Dir(dir) {
		chain = append(chain, dir)
		if filepath.Dir(dir) == dir {
			return chain
		}
	}
}

// finalExePath is where exe really is, every link, junction and mapped name
// on the way resolved by Windows itself.
func finalExePath(exe string) (string, error) {
	name, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(name, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", exe, err)
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	for {
		// flags 0: VOLUME_NAME_DOS | FILE_NAME_NORMALIZED.
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", exe, err)
		}
		if n < uint32(len(buf)) {
			path := windows.UTF16ToString(buf[:n])
			switch {
			case strings.HasPrefix(path, `\\?\UNC\`):
				path = `\\` + path[len(`\\?\UNC\`):]
			case strings.HasPrefix(path, `\\?\`):
				path = path[len(`\\?\`):]
			}
			return path, nil
		}
		buf = make([]uint16, n)
	}
}

// objectWriters reads the owner and DACL of the object at path itself - a
// link or a junction as the link, not what it points to - through a handle,
// and names who outside the trusted accounts holds any of rights.
func objectWriters(path, self string, rights uint32) ([]string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("read the permissions of %s: %w", path, err)
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("read the permissions of %s: %w", path, err)
	}
	trusted := func(sid string) bool { return trustedExeWriters[sid] || (self != "" && sid == self) }
	var out []string
	seen := map[string]bool{}
	add := func(sid string) {
		if !trusted(sid) && !seen[sid] {
			seen[sid] = true
			out = append(out, sid)
		}
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, fmt.Errorf("read the owner of %s: %w", path, err)
	}
	if owner != nil {
		add(owner.String())
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, fmt.Errorf("read the DACL of %s: %w", path, err)
	}
	if dacl == nil {
		// A NULL DACL grants everything to everybody.
		add("S-1-1-0")
		return out, nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, fmt.Errorf("read the DACL of %s: %w", path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if uint32(ace.Mask)&rights == 0 {
			continue
		}
		add((*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	return out, nil
}

func currentUserSIDString() (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return "", fmt.Errorf("open this process's token: %w", err)
	}
	defer token.Close()
	u, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read this process's account: %w", err)
	}
	return u.User.Sid.String(), nil
}

// accountName is DOMAIN\name for a SID when Windows can say it, the SID
// itself when it cannot.
func accountName(sidString string) string {
	sid, err := windows.StringToSid(sidString)
	if err != nil {
		return sidString
	}
	name, domain, _, err := sid.LookupAccount("")
	if err != nil || name == "" {
		return sidString
	}
	if domain == "" {
		return name
	}
	return domain + `\` + name
}

// lockProgramHome gives the program's folder and the program in it the
// DACL the gateway install gives them (applyGatewayExeACL): owner
// Administrators; SYSTEM and Administrators full control; BUILTIN\Users
// and the gateway service account read and execute; nothing inherited
// from the drive root. exe may be "" when the program is not there yet -
// the folder's ACEs are inheritable, so a file copied in afterwards
// starts with them.
func lockProgramHome(dir, exe string) error {
	if err := hardenGatewayExeDirACL(dir, false, nil); err != nil {
		return err
	}
	if exe != "" {
		if err := hardenGatewayExeFileACL(exe, false, nil); err != nil {
			return err
		}
	}
	return nil
}

// secureLogonTaskExe is server install's half of the rule. The logon task
// starts exe with the highest privileges the account has, at every
// sign-in and with no prompt, so nobody but SYSTEM, Administrators and
// TrustedInstaller may be able to change it - not even the account's own
// unelevated processes. In the program's home the folder is locked here
// and now (install already holds the administrator token); anywhere else
// it is only checked, because locking some other folder - Downloads, say -
// would take it away from its owner.
func secureLogonTaskExe(s *streams, path, exe string) error {
	home := serviceReachableExeDir(s.env)
	if home != "" && strings.EqualFold(filepath.Clean(filepath.Dir(exe)), filepath.Clean(home)) {
		if err := lockProgramHome(home, exe); err != nil {
			return envErrf("iamtunnel %s: could not lock %s to administrators: %v", path, home, err)
		}
	}
	who, err := exeWriters(exe, false)
	if err != nil {
		return envErrf("iamtunnel %s: could not check who can change %s: %v", path, exe, err)
	}
	if len(who) > 0 {
		return userErrf("iamtunnel %s: %s can be changed by %s — and the logon task would start it with the highest privileges at every sign-in, so whoever changes it would be running as the administrator. Put the program in %s, where only administrators can change it (the window's Gateway tab does it with \"Move it there for me\"; by hand, RUNBOOK §1.5), and run server install from there.",
			path, exe, strings.Join(who, ", "), orHome(home))
	}
	return nil
}

// refuseElevatingTamperableExe is the window's half: before "Restart as
// administrator" hands this very file to UAC, nobody but administrators
// and the person pressing the button may be able to change it or its
// folder. The person is trusted here - the prompt is theirs to answer -
// but another account that can swap the file would be answering it for
// them.
func refuseElevatingTamperableExe(exe string) error {
	who, err := exeWriters(exe, true)
	if err != nil {
		return fmt.Errorf("could not check who can change %s: %w", exe, err)
	}
	if len(who) > 0 {
		return fmt.Errorf("%s can be changed by %s, so restarting it as administrator would run whatever they put there. "+
			"Start the program from a folder only you and administrators can change, or lock this one to administrators first (RUNBOOK §1.5)",
			exe, strings.Join(who, ", "))
	}
	return nil
}

func orHome(home string) string {
	if home == "" {
		return `C:\iamtunnel`
	}
	return home
}
