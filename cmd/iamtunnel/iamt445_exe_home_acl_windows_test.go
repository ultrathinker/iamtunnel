//go:build windows

package main

// IAMT-445: the program's one home on Windows, C:\iamtunnel, was an
// ordinary folder at the root of the system drive, and the root of the
// system drive grants every signed-in account the right to create folders
// there and Modify on everything inside them (NT AUTHORITY\Authenticated
// Users:(OI)(CI)(IO)(M) - `icacls C:\` on any stock Windows). The window's
// "Move it there for me" created the folder with a plain MkdirAll, so it
// inherited exactly that; and from that folder the program is started
// with an administrator's token - "Restart as administrator", the logon
// task server install registers with HighestAvailable, the gateway
// service. Anybody who could sign in to the machine could put their own
// program in its place.
//
// Every ACL operation here is on paths inside t.TempDir() (gate 11); a
// folder open to Authenticated Users is built there to stand in for C:\.
// The tests need an elevated process - setting an owner and a protected
// DACL does - and are skipped with that reason otherwise (gate 10), like
// the other ACL tests of this package.

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// iamt445Writers lists who, apart from SYSTEM, Administrators and
// TrustedInstaller, can change path: every ACCESS_ALLOWED ACE that applies
// to the object itself (not inherit-only) and grants a right that writes,
// deletes or re-permissions it, and the owner, who can always rewrite the
// DACL. It reads the descriptor itself rather than asking the product.
func iamt445Writers(t *testing.T, path string) []string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	trusted := map[string]bool{
		"S-1-5-18":     true, // SYSTEM
		"S-1-5-32-544": true, // Administrators
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true, // TrustedInstaller
	}
	var out []string
	if owner, _, err := sd.Owner(); err == nil && owner != nil && !trusted[owner.String()] {
		out = append(out, "owner "+owner.String())
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL of %s: %v", path, err)
	}
	if dacl == nil {
		return append(out, "no DACL at all (everyone has full access)")
	}
	const writes = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce(%s, %d): %v", path, i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if uint32(ace.Mask)&writes == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if !trusted[sid] {
			out = append(out, sid)
		}
	}
	return out
}

// iamt445OpenLikeTheSystemDrive gives dir the DACL that matters about C:\:
// SYSTEM, Administrators and this account full control, and Modify for
// Authenticated Users, all inheritable - what a folder made inside it
// starts with.
func iamt445OpenLikeTheSystemDrive(t *testing.T, dir string) {
	t.Helper()
	iamt445SetDACL(t, dir, true)
	if got := iamt445Writers(t, dir); len(got) == 0 {
		t.Fatalf("setup: %s is not open to anybody after all", dir)
	}
}

// iamt445OnlyThisAccount gives dir a DACL of SYSTEM, Administrators and
// this account alone - a folder of the person's own. Not t.TempDir() as
// it comes: what else can write there depends on the machine (on the one
// this was written on, a sandbox's accounts can).
func iamt445OnlyThisAccount(t *testing.T, dir string) {
	t.Helper()
	iamt445SetDACL(t, dir, false)
}

func iamt445SetDACL(t *testing.T, dir string, authenticatedUsersToo bool) {
	t.Helper()
	user := testUserSID(t)
	authUsers, err := windows.StringToSid("S-1-5-11")
	if err != nil {
		t.Fatal(err)
	}
	system, _ := windows.StringToSid("S-1-5-18")
	admins, _ := windows.StringToSid("S-1-5-32-544")
	rp := &runtime.Pinner{}
	defer rp.Unpin()
	for _, s := range []*windows.SID{user, authUsers, system, admins} {
		rp.Pin(s)
	}
	grant := func(sid *windows.SID, mask uint32) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.ACCESS_MASK(mask),
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_USER,
				TrusteeValue:             windows.TrusteeValueFromSID(sid),
			},
		}
	}
	const modify = 0x1301BF // what icacls calls (M)
	entries := []windows.EXPLICIT_ACCESS{grant(system, testFileAllAccess), grant(admins, testFileAllAccess), grant(user, testFileAllAccess)}
	if authenticatedUsersToo {
		entries = append(entries, grant(authUsers, modify))
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user, nil, acl, nil); err != nil {
		t.Fatalf("set the DACL of %s: %v", dir, err)
	}
}

// The logon task server install registers starts the program with the
// highest privileges the account has, at every sign-in, with no prompt.
// A program file that anything but an administrator can change is then
// a standing way to run code as that administrator - the account's own
// unelevated processes included. The test binary itself is the example:
// it sits in the account's own temp folder, which the account can write.
func TestIAMT445_ServerInstallRefusesAProgramOthersCanChange(t *testing.T) {
	dir := t.TempDir()
	seedGatewayRecordForTask(t, dir, "office-pc", `EXAMPLE\dana`)
	tasks := withFakeLogonTasks(t)

	var out, errs bytes.Buffer
	s := &streams{out: &out, errs: &errs, env: map[string]string{}}
	code := runServerInstall(s, "server install", dir)

	exe, _ := os.Executable()
	if code == exitOK {
		t.Fatalf("server install registered a logon task that runs %s with the highest privileges at every sign-in, though the account's own unelevated processes can replace that file; task calls: %v", exe, tasks.calls)
	}
	for _, c := range tasks.calls {
		if strings.HasPrefix(c, "create ") {
			t.Errorf("a task was created before the refusal: %v", tasks.calls)
		}
	}
	if msg := errs.String(); !strings.Contains(msg, `iamtunnel`) || !strings.Contains(msg, filepath.Dir(exe)) {
		t.Errorf("the refusal does not name the folder and where the program belongs instead:\n%s", msg)
	}
}

// "Restart as administrator" hands this very file to UAC. The person
// pressing the button answers the prompt and is trusted to; another
// account that can swap the file first would be answering it for them.
func TestIAMT445_RestartAsAdministratorRefusesAProgramAnotherAccountCanChange(t *testing.T) {
	requireWritableLockedFiles(t)

	ownDir := t.TempDir()
	iamt445OnlyThisAccount(t, ownDir)
	own := filepath.Join(ownDir, "iamtunnel.exe")
	if err := os.WriteFile(own, []byte("stand-in"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Asked of the program and the folders the test made, not of the ones
	// above t.TempDir(): those are the machine's, and since R1-CX F-18 they
	// are checked too (r1cxF18On).
	ownWho, err := exeWriters(own, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := r1cxF18On(ownWho, ownDir); len(got) != 0 {
		t.Errorf("a program only this account and administrators can change was said to be changeable by %v", got)
	}

	open := t.TempDir()
	iamt445OpenLikeTheSystemDrive(t, open)
	shared := filepath.Join(open, "iamtunnel.exe")
	if err := os.WriteFile(shared, []byte("stand-in"), 0o755); err != nil {
		t.Fatal(err)
	}
	relaxACLOnCleanup(t, shared, open)
	err = refuseElevatingTamperableExe(shared)
	if err == nil {
		t.Fatalf("%s can be changed by every signed-in account, and restarting it as administrator was allowed", shared)
	}
	if !strings.Contains(err.Error(), "Authenticated Users") && !strings.Contains(err.Error(), "S-1-5-11") {
		t.Errorf("the refusal does not say who can change the program: %v", err)
	}
}
