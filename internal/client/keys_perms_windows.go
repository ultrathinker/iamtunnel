//go:build windows

package client

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// The client's private key on Windows is protected by its own ACCESS
// LIST and by nothing else: there are no POSIX mode bits to check, and a
// file with no access list of its own inherits whatever its folder
// grants. The default data directory is per-user and benign, but the
// key's path is configurable (--data-dir, IAMTUNNEL_DATA_DIR, client_dir
// in a config file), and that is the finding this file answers (M-9d,
// code review 23.09.2026, review F-08): a key generated in a shared
// directory on a disk whose root grants Users read was readable by every
// local account, while the key is the person's whole identity (SPEC
// §3.1).
//
// TWO ANSWERS, and they cover the two states a file can be in:
//
//   - the file carries an access list of its own and that list names
//     another account: REFUSED, naming the account and the command that
//     fixes it. Somebody granted that access — the person, an installer,
//     a backup tool — and a deliberate grant is a decision to look at,
//     exactly as the Unix half refuses a key whose mode bits were
//     widened on purpose rather than silently chmod-ing it.
//   - the file carries NO list of its own (SE_DACL_PROTECTED clear).
//     Windows then gave it its folder's inherited permissions, and a
//     reader CANNOT enumerate those with the interfaces this program
//     uses — so "who can read this" is unanswerable, and the honest
//     answer is not a refusal but a list: the key is given the same
//     one-entry protected list a fresh key is born with, on the open
//     entry, and the file is verified afterwards. This is where the
//     Windows half deliberately differs from the Unix half. On Unix the
//     mode bits ARE the effective access, so 0644 is a fact the person
//     must acknowledge; on Windows an unprotected file is the absence of
//     a decision, the state every key written by an earlier build is in,
//     and refusing it would lock every existing install out of its own
//     identity over a default it never chose. The exposure ends either
//     way; nobody is left reading a key that a command could have
//     closed.
//
// The two machine-side helpers (winkeys.LockDownFileACL,
// applyGatewayExeACL) are deliberately NOT reused for the writing half:
// they lay down the machine's DACL (SYSTEM and Administrators, full
// control), which for a client key would lock out the very account that
// owns it. What IS reused is the reading half — winkeys.DACLProtectedOf
// and winkeys.ReadDACLOf — so "is this file locked down" is answered by
// the same code that answers it for the machine's own files, and asked of
// the open handle the key is read from, never of its name (R1-CX F-14).

// keyFileAllAccess is FILE_ALL_ACCESS — the mask winkeys uses for its
// file ACEs, and deliberately not GENERIC_ALL: a generic mask is
// canonicalized into two stored ACEs per trustee, and this file carries
// exactly one.
const keyFileAllAccess windows.ACCESS_MASK = 0x1F01FF

// currentAccountSID is the SID of the account running this process: the
// one account the key belongs to.
func currentAccountSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("cannot read this account's SID (%w)", err)
	}
	return user.User.Sid, nil
}

// currentAccountSIDOrEmpty is the same SID in its textual form, for the
// hint in a refusal message. An empty string only ever reaches a message
// (the paths that need the SID itself return its error).
func currentAccountSIDOrEmpty() string {
	sid, err := currentAccountSID()
	if err != nil {
		return ""
	}
	return sid.String()
}

// keyFileACL is the access list every client key carries: the account
// that owns it, full control, nothing else. SYSTEM and Administrators
// are deliberately absent — they can take ownership of any file on the
// box whether or not they hold an entry, and the machine's own DACL is
// the wrong shape for a person's identity.
//
// The caller must keep sid pinned for as long as the ACL lives: the ACL
// stores the SID by pointer, and the Win32 calls it is handed to
// dereference it.
func keyFileACL(sid *windows.SID) (*windows.ACL, error) {
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: keyFileAllAccess,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			MultipleTrustee:          nil,
			MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
			TrusteeForm:              windows.TRUSTEE_IS_SID,
			TrusteeType:              windows.TRUSTEE_IS_USER,
			TrusteeValue:             windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot build the access list for this key (%w)", err)
	}
	return acl, nil
}

// createKeyFile claims the key's name with the key's own access list
// already on it (R1-CX F-14): datafile.CreateWithDACL makes the list part
// of the create, so the file never exists with its folder's inherited
// list. The list used to be set a step after the create, by name, and in
// that step any account the folder lets read could open the file - its
// creator shares it for reading - keep the handle, and read the key once
// it was written.
//
// A filesystem that cannot hold an access list at all (FAT, some network
// shares) takes the create and drops the list without a word, so the list
// is read back through the new handle, and without it the key is not
// written: a removable disk every account can read is not a place to keep
// an identity, and saying so is better than writing the key there and
// calling it protected. The empty file stays where it is - removing it
// would race a concurrent first run reading the winner's key - and the
// next run refuses it as a key that does not parse.
func createKeyFile(path string) (*os.File, error) {
	sid, err := currentAccountSID()
	if err != nil {
		return nil, err
	}
	rp := &runtime.Pinner{}
	defer rp.Unpin()
	rp.Pin(sid)

	acl, err := keyFileACL(sid)
	if err != nil {
		return nil, err
	}
	f, err := datafile.CreateWithDACL(path, acl)
	if err != nil {
		return nil, err
	}
	protected, perr := winkeys.DACLProtectedOf(windows.Handle(f.Fd()))
	if perr != nil || !protected {
		f.Close()
		why := "the file system kept no access list"
		if perr != nil {
			why = perr.Error()
		}
		return nil, fmt.Errorf("cannot restrict this key to the account that owns it (%s) — the private key is the person's own identity, so a disk that cannot hold an access list is not a place to keep it; choose a data directory on a local NTFS volume", why)
	}
	return f, nil
}

// lockDownExistingKey gives the key file f holds the access list it should
// have had all along.
//
// Through a second HANDLE, opened on the entry itself
// (FILE_FLAG_OPEN_REPARSE_POINT) - the name is only how a handle with
// WRITE_DAC is asked for: f was opened for reading without it, and Go
// has no reopen. A name is not the file: a link planted by whoever owns
// the directory, or a junction further up turned elsewhere, would have a
// name-based call re-permission something else. So the new handle must
// hold the very file f holds - volume and file index compared - or
// nothing is changed and the key is refused (R1-CX F-14).
func lockDownExistingKey(path string, f *os.File) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return classifyPathErr(fmt.Errorf("cannot name this key file (%w)", err), path)
	}
	h, err := windows.CreateFile(
		p,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return classifyPathErr(fmt.Errorf("has no access list of its own and cannot be given one (%w) — the private key is the person's own identity, so the client will not use a file whose readers it cannot establish; restrict it with: icacls %q /inheritance:r /grant:r \"*%s:F\" — or keep the key in the default per-user data directory",
			err, path, currentAccountSIDOrEmpty()), path)
	}
	defer windows.CloseHandle(h)

	same, err := sameFile(h, windows.Handle(f.Fd()))
	if err != nil {
		return classifyPathErr(fmt.Errorf("cannot tell whether its name still holds the key being read (%w) — refusing to use a key whose protection cannot be established", err), path)
	}
	if !same {
		return classifyPathErr(errors.New("was replaced by another file while its access list was being set — refusing to use a key whose protection cannot be established"), path)
	}

	sid, err := currentAccountSID()
	if err != nil {
		return classifyPathErr(err, path)
	}
	rp := &runtime.Pinner{}
	defer rp.Unpin()
	rp.Pin(sid)

	acl, err := keyFileACL(sid)
	if err != nil {
		return classifyPathErr(err, path)
	}
	if err := windows.SetSecurityInfo(
		h,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil,
		acl,
		nil,
	); err != nil {
		return classifyPathErr(fmt.Errorf("cannot restrict this key to the account that owns it (%w); restrict it with: icacls %q /inheritance:r /grant:r \"*%s:F\"",
			err, path, currentAccountSIDOrEmpty()), path)
	}
	return nil
}

// sameFile reports whether two handles hold the same file: the same
// volume and the same file index.
func sameFile(a, b windows.Handle) (bool, error) {
	var ia, ib windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(a, &ia); err != nil {
		return false, err
	}
	if err := windows.GetFileInformationByHandle(b, &ib); err != nil {
		return false, err
	}
	return ia.VolumeSerialNumber == ib.VolumeSerialNumber &&
		ia.FileIndexHigh == ib.FileIndexHigh && ia.FileIndexLow == ib.FileIndexLow, nil
}

// checkKeyFilePerms refuses an existing key file that other accounts can
// read, and closes the one case where it cannot tell (see the file
// header): a file with no access list of its own inherits its folder's
// permissions, which a reader cannot enumerate, so the client gives it
// the list a fresh key is born with and verifies the result instead of
// demanding that the person run a command to say "yes, really".
//
// Every question is asked of f - the open file the key is read from -
// and not of path (R1-CX F-14): it read the list of whatever the name
// meant at that moment, while the key came out of the file already open.
func checkKeyFilePerms(path string, f *os.File, _ os.FileInfo) error {
	h := windows.Handle(f.Fd())
	protected, err := winkeys.DACLProtectedOf(h)
	if err != nil {
		return classifyPathErr(fmt.Errorf("cannot read the access list (%w) — refusing to use a key whose protection cannot be established", err), path)
	}
	if !protected {
		if herr := lockDownExistingKey(path, f); herr != nil {
			return herr
		}
		// Read the result back rather than trust the call: the file is
		// about to be used as an identity, and "I set it" is not the same
		// claim as "it is set".
		protected, err = winkeys.DACLProtectedOf(h)
		if err != nil || !protected {
			return classifyPathErr(fmt.Errorf("still carries no access list of its own after being given one (%v) — refusing to use a key whose readers cannot be established", err), path)
		}
	}

	names, err := winkeys.ReadDACLOf(h)
	if err != nil {
		return classifyPathErr(fmt.Errorf("cannot read the access list (%w) — refusing to use a key whose protection cannot be established", err), path)
	}
	mine := currentAccountSIDOrEmpty()
	found := false
	for _, name := range names {
		switch name {
		case mine:
			found = true
		case `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`:
			// The machine's own trustees: they can take ownership of any
			// file on the box regardless of the list, so their presence
			// withholds nothing this check could enforce — and refusing on
			// it would refuse every key an operator ever hardened by hand.
		default:
			return classifyPathErr(fmt.Errorf("is readable by %s (access list %v) — the private key is the person's own identity, so the client refuses to use a file another account can read; restrict it with: icacls %q /inheritance:r /grant:r \"*%s:F\"",
				name, names, path, mine), path)
		}
	}
	if !found {
		return classifyPathErr(fmt.Errorf("does not grant this account (%s, access list %v) access to it, so the key it holds cannot be read; restore it with: icacls %q /inheritance:r /grant:r \"*%s:F\"",
			mine, names, path, mine), path)
	}
	return nil
}
