//go:build windows

package main

// data_dir_ancestors_windows.go - who may move a data directory aside
// (R2 supplementary round, found while fixing R2-CX F-07, F-12 and F-13).
//
// Locking a data directory - its DACL, its owner, everything in it - says
// nothing about the folder it sits in. Whoever may rename that folder, or
// delete and rename what is in it, moves the locked directory aside and
// puts one of their own in its place: the gateway service takes that one
// for its own at its next start, and a machine's enrol writes its key into
// it. %ProgramData% lets every signed-in user create folders, so
// %ProgramData%\iamtunnel, the parent of the default gateway directory, is
// anybody's to make first; a --data-dir anywhere is under whatever folders
// happen to be above it. The check is exeWriters' (IAMT-445, R1-CX F-18)
// for the folders above a program, applied to the folders above a data
// directory.

import (
	"path/filepath"
	"strings"
)

// dataDirAncestorWriters names everybody outside SYSTEM, Administrators
// and TrustedInstaller - and, with trustSelf, the account running this -
// who owns a folder above dir or holds rights on it: dir's parent and
// every folder above it up to the root of its volume, each read as
// itself, a link as the link. The owner always counts, since an owner can
// always rewrite the DACL (objectWriters); an ACE counts when it allows
// any of rights - ancestorChangeRights, the right to move, delete or
// re-permission the folder or to delete or rename what is in it - and
// with rights 0 only owners are named.
func dataDirAncestorWriters(dir string, trustSelf bool, rights uint32) ([]string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	self := ""
	if trustSelf {
		if self, err = currentUserSIDString(); err != nil {
			return nil, err
		}
	}
	var out []string
	seen := map[string]bool{}
	for p := filepath.Dir(abs); ; p = filepath.Dir(p) {
		sids, err := objectWriters(p, self, rights)
		if err != nil {
			return nil, err
		}
		for _, sid := range sids {
			w := accountName(sid) + " (on " + p + ")"
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
		if filepath.Dir(p) == p {
			return out, nil
		}
	}
}

// refuseGatewayDataDirAncestorWriters is gateway install's half. The
// service starts with no prompt, so not even the installing account's own
// unelevated processes may be able to move its data directory aside - the
// rule IAMT-445 set for the program the service runs. The default path
// passes: %ProgramData% and the drive root give ordinary accounts no such
// right, and install itself makes %ProgramData%\iamtunnel, elevated,
// owned by Administrators.
func refuseGatewayDataDirAncestorWriters(dir string) error {
	who, err := dataDirAncestorWriters(dir, false, ancestorChangeRights)
	if err != nil {
		return envErrf("gateway install: could not check who can change the folders above the data directory %s: %v", dir, err)
	}
	if len(who) > 0 {
		return deniedErrf("gateway install: the folders above the data directory %s can be changed by %s — whoever can rename one of them, or delete what is in it, can move the locked data directory aside and put their own in its place, which the service would then take for its own. Create those folders from an elevated console or hand them to Administrators (takeown /f \"<folder>\" /a) and take the others' rights away, or choose another --data-dir; then repeat the install.",
			dir, strings.Join(who, ", "))
	}
	return nil
}

// refuseMachineDataDirAncestorOwners is the machine's half, and a
// narrower one. Its directory lives in the person's own profile by design
// (SPEC §3.2.2): the folders above it are theirs, and so are the rights
// they give others there - on a real box, a sandbox account's rights on
// AppData\Local - so only the owners are held to account: a folder above
// that another account owns (R2-CX F-13's case - a directory someone else
// made in advance, chosen as --data-dir) is refused, since its owner can
// always give themselves the right to move what is in it.
func refuseMachineDataDirAncestorOwners(dir string) error {
	who, err := dataDirAncestorWriters(dir, true, 0)
	if err != nil {
		return envErrf("could not check who owns the folders above the machine data directory %s: %v", dir, err)
	}
	if len(who) > 0 {
		return deniedErrf("the folders above the machine data directory %s belong to %s — an owner can always give themselves the right to delete what is in a folder, and so move the locked directory aside and put their own in its place, to have the machine key written there. Use a data directory under folders that are yours or administrators', or hand those folders to Administrators (takeown /f \"<folder>\" /a), and repeat.",
			dir, strings.Join(who, ", "))
	}
	return nil
}
