package main

import (
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
)

// IAMT-445b: server install on Linux and macOS writes a unit (a LaunchDaemon
// on macOS) that starts this very file as root at every boot. Whoever can
// change the file - or rename a directory on the way to it and put their own
// in its place - is root from the next boot on. The Windows half of the same
// question is exe_acl_windows.go (IAMT-445); this is its Unix counterpart,
// and it is stricter in one way on purpose: it walks every directory up to
// "/", because on Unix renaming any one of them swaps the whole path below.

// exeOwnerStat is what the check needs to know about one path.
type exeOwnerStat struct {
	uid, gid uint32
	mode     fs.FileMode
}

// unixExeWriters names every path through which someone other than root
// could change the service binary bin: the file itself and every directory
// above it, both along the path as it is written into the unit and along
// the path its symbolic links resolve to. A path passes when root owns it
// and neither a group other than gid 0 nor everybody may write to it. A
// world-writable directory is refused even with its sticky bit set (/tmp):
// a root service has no business being started from there.
//
// stat and resolve are the file system (statExeOwner, filepath.EvalSymlinks
// in production). A path that cannot be looked at is an error, never a pass.
func unixExeWriters(bin string, stat func(string) (exeOwnerStat, error), resolve func(string) (string, error)) ([]string, error) {
	return walkExeChains(bin, stat, resolve, exeOwnerProblem)
}

// walkExeChains asks problem about bin and every directory above it, along
// the path as written and along the path its symbolic links resolve to,
// and names every step it has something to say about.
func walkExeChains(bin string, stat func(string) (exeOwnerStat, error), resolve func(string) (string, error), problem func(exeOwnerStat) string) ([]string, error) {
	chains := []string{bin}
	real, err := resolve(bin)
	if err != nil {
		return nil, err
	}
	if real != bin {
		chains = append(chains, real)
	}
	seen := map[string]bool{}
	var who []string
	for _, p := range chains {
		for cur := path.Clean(p); ; cur = path.Dir(cur) {
			if !seen[cur] {
				seen[cur] = true
				st, err := stat(cur)
				if err != nil {
					return nil, err
				}
				if why := problem(st); why != "" {
					who = append(who, cur+" ("+why+")")
				}
			}
			if cur == "/" || cur == "." {
				break
			}
		}
	}
	return who, nil
}

// exeOwnerProblem says what, if anything, lets someone other than root
// change one path.
func exeOwnerProblem(st exeOwnerStat) string {
	var why []string
	if st.uid != 0 {
		why = append(why, fmt.Sprintf("owned by uid %d", st.uid))
	}
	if st.mode.Perm()&0o020 != 0 && st.gid != 0 {
		why = append(why, fmt.Sprintf("writable by group %d", st.gid))
	}
	if st.mode.Perm()&0o002 != 0 {
		why = append(why, "writable by everyone")
	}
	return strings.Join(why, ", ")
}

// The window's "Restart as administrator" on Linux (pkexec) and macOS (the
// administrator prompt) starts this very file as root too, and asked
// nobody's ability to change it (R1 supplementary round); the Windows window refuses
// exactly that (refuseElevatingTamperableExe, IAMT-445). The person who
// presses the button is trusted, as on Windows - the password prompt is
// theirs to answer - and so are root and the groups whose members can
// become root with their own password anyway (admin on macOS; sudo, wheel
// and admin on Linux). Anyone else who can change the file, or rename a
// directory on the way to it, would be answering the prompt for them.

// exeElevator is the person restarting the program: their uid, and the
// groups whose right to write is trusted - root's, the person's own
// primary group, and the administrators' groups.
type exeElevator struct {
	uid  uint32
	gids map[uint32]bool
}

// elevationExeWriters is unixExeWriters for that restart: every path
// through which someone other than the person, root or an administrator
// could change exe. A path that cannot be looked at is an error, never a
// pass.
func elevationExeWriters(exe string, self exeElevator, stat func(string) (exeOwnerStat, error), resolve func(string) (string, error)) ([]string, error) {
	return walkExeChains(exe, stat, resolve, func(st exeOwnerStat) string {
		return elevationExeProblem(st, self)
	})
}

// elevationExeProblem says what, if anything, lets someone other than the
// person, root or an administrator change one path. A directory with the
// sticky bit (/tmp) is not one of them however writable it is: only an
// entry's own owner may rename or remove it there, and that owner is
// asked about on the entry's own step. Server install stays stricter
// (exeOwnerProblem): a service started at every boot has no business
// living under /tmp, while a person restarting the copy they just built
// or unpacked there does.
func elevationExeProblem(st exeOwnerStat, self exeElevator) string {
	var why []string
	if st.uid != 0 && st.uid != self.uid {
		why = append(why, fmt.Sprintf("owned by uid %d", st.uid))
	}
	if st.mode.IsDir() && st.mode&fs.ModeSticky != 0 {
		return strings.Join(why, ", ")
	}
	if st.mode.Perm()&0o020 != 0 && !self.gids[st.gid] {
		why = append(why, fmt.Sprintf("writable by group %d", st.gid))
	}
	if st.mode.Perm()&0o002 != 0 {
		why = append(why, "writable by everyone")
	}
	return strings.Join(why, ", ")
}

// serviceExeWriters is unixExeWriters over the real file system: the
// production value of the exeWriters step of both service seams
// (systemdSetup, darwinLaunchdSetup).
func serviceExeWriters(bin string) ([]string, error) {
	return unixExeWriters(bin, statExeOwner, filepath.EvalSymlinks)
}

// refuseChangeableServiceExe is server install's check on Linux and macOS:
// the binary the unit or LaunchDaemon will start as root must be one only
// root can change. writers is the platform seam's exeWriters step.
func refuseChangeableServiceExe(cmdPath, bin string, writers func(string) ([]string, error)) error {
	who, err := writers(bin)
	if err != nil {
		return envErrf("iamtunnel %s: could not check who can change %s: %v", cmdPath, bin, err)
	}
	if len(who) > 0 {
		return userErrf("iamtunnel %s: %s would be started as root at every boot, and someone other than root can change it: %s. Whoever changes it would be running as root. Put the program where only root can change it - \"sudo install -o root -m 0755 iamtunnel /usr/local/bin/iamtunnel\", with every directory above it owned by root and not writable by a group or by others (RUNBOOK §1.7) - and run server install from there.",
			cmdPath, bin, strings.Join(who, "; "))
	}
	return nil
}
