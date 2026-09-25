//go:build windows

package client

// R1-CX F-14: the Windows check of the client key's access list worked by
// NAME, while the key was read from a HANDLE opened before it.
//
//   - An existing key: checkKeyFilePerms read and, when needed, re-set
//     the access list of whatever the name meant at that moment, and the
//     key came out of the file already open. NTFS pins the name of a file
//     held open without FILE_SHARE_DELETE (neither the file nor its folder
//     can be renamed meanwhile), but a junction further up the path can
//     still be turned elsewhere - and "the file that was checked is the
//     file that is read" is the promise loadKeyFile's own comment makes.
//   - A new key: datafile.Create made the file with its folder's
//     inherited access list, and protectNewKeyFile gave it its own a step
//     later, by name. In between, any account the folder lets read could
//     open the file - the creator shares it for reading - keep the handle,
//     and read the key once it had been written.
//
// Every access-list change lands in a t.TempDir().

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func r1cxF14Me(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

func r1cxF14Icacls(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %v: %v (%s)", args, err, out)
	}
}

func r1cxF14Key(t *testing.T, path string) {
	t.Helper()
	if _, err := createKeyIfAbsent(filepath.Dir(path), path); err != nil {
		t.Fatal(err)
	}
}

func TestR1CX_F14_TheKeyThatIsReadIsTheKeyThatIsJudged(t *testing.T) {
	dir := t.TempDir()
	me := r1cxF14Me(t)
	exposed := filepath.Join(dir, "key")
	r1cxF14Key(t, exposed)
	r1cxF14Icacls(t, exposed, "/grant", "*S-1-1-0:(R)")
	other := filepath.Join(dir, "sub")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(other, "key")
	r1cxF14Key(t, clean)
	r1cxF14Icacls(t, clean, "/inheritance:r", "/grant:r", "*"+me+":F")

	f, info, err := openKeyFile(exposed)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// The name the check is handed now means a clean file - what a turned
	// junction on the way would leave - while the key comes out of f.
	if _, err := loadKeyFile(clean, f, info); err == nil {
		t.Fatalf("a key Everyone can read was loaded: the check looked at %s, the read at the file already open", clean)
	}
}

func TestR1CX_F14_ANewKeyIsBornWithItsOwnAccessList(t *testing.T) {
	dir := t.TempDir()
	r1cxF14Icacls(t, dir, "/grant", "*S-1-1-0:(OI)(CI)(R)")
	path := filepath.Join(dir, "key")
	f, err := createKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	protected, perr := winkeys.DACLProtected(path)
	names, nerr := winkeys.ReadDACL(path)
	if perr != nil || nerr != nil {
		t.Fatal(perr, nerr)
	}
	me := r1cxF14Me(t)
	onlyMe := len(names) == 1 && names[0] == me
	if !protected || !onlyMe {
		t.Fatalf("the new key file exists with the access list %v (own list: %v) before any key is in it: every account its folder lets read can open it now and read the key once it is written", names, protected)
	}
}
