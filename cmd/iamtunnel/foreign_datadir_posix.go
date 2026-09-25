//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// dataDirOwnerForeignOS is the POSIX half of the IAMT-333 (P1.6) probe.
// Only an elevated caller ever reaches it, and elevated on POSIX means
// root (the same verdict requireServerElevation enforces), which is why
// the owner comparison is "this process or root": a root-owned directory
// is root's own, and a directory the service account owns passes the
// ownership adoption path (IAMT-332) the same way it always has. An
// os.Stat that says the directory does not exist passes — a first run is
// legitimate — and any other stat failure comes back as the probe error
// the gate turns into a fail-closed refusal.
func dataDirOwnerForeignOS(dir string) (string, error) {
	// The route to dir first (review finding R4 N-10): a symlink in one of its
	// parents that root does not own can be re-aimed by its owner between
	// this check and the write - the same move as a link at dir itself,
	// one level up. Root-owned links (macOS /var, /tmp) cannot.
	if reason, err := parentLinkForeignPOSIX(dir); err != nil || reason != "" {
		return reason, err
	}
	// Lstat: the name itself is judged, not what a symlink at it points to
	// (review finding R4 N-08) - a link to a root-owned directory would otherwise
	// pass, and its owner could re-aim it before the write lands.
	fi, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "a link, not a directory — whoever owns the link can re-aim it between this check and the write, " +
			"so the check cannot vouch for where the write lands", nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("cannot read the owner of %s", dir)
	}
	if st.Uid == 0 || int(st.Uid) == os.Geteuid() {
		return "", nil
	}
	return fmt.Sprintf("owned by uid %d, and this command is running as root — "+
		"a directory somebody else owns can aim this command's writes at files of their choosing",
		st.Uid), nil
}

// parentLinkForeignPOSIX walks dir's parents to the root and names the
// first symlink among them that root does not own ("" - none). A parent
// that does not exist yet is skipped: it will be created by the command.
func parentLinkForeignPOSIX(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for p := filepath.Dir(abs); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		switch {
		case err == nil:
			if fi.Mode()&os.ModeSymlink != 0 {
				st, ok := fi.Sys().(*syscall.Stat_t)
				if !ok || st.Uid != 0 {
					return fmt.Sprintf("reached through the link %s, which root does not own — whoever owns the link can re-aim it between this check and the write", p), nil
				}
			}
		case !os.IsNotExist(err):
			return "", err
		}
		if filepath.Dir(p) == p {
			return "", nil
		}
	}
}

// sudoInvoker reads the account sudo ran this command for out of the
// SUDO_UID and SUDO_GID it sets. ok is false when either is missing or not
// a plain non-negative number, and for uid 0 -- root invoking sudo has no
// lesser account to become.
func sudoInvoker(env map[string]string) (uid, gid int, ok bool) {
	u, uerr := strconv.Atoi(env["SUDO_UID"])
	g, gerr := strconv.Atoi(env["SUDO_GID"])
	if uerr != nil || gerr != nil || u <= 0 || g < 0 {
		return 0, 0, false
	}
	return u, g, true
}

// dropToInvokerOS is the POSIX half of P2.8 (see dropToInvoker). It drops
// only when every one of these holds: the process is root; sudo named the
// account it ran for; dir is a real directory, not a link, reached through
// no link root does not own (the same route rule the refusal applies); and
// that account owns dir. Anything else is "not this case".
//
// The drop is the whole process and one-way: supplementary groups first
// (root's must not survive), then the group, then the user. Go applies
// setuid and setgid to every thread (Go 1.16+). A drop that could be
// undone is not a drop, so it ends by trying to become root again and
// fails the command if that works.
func dropToInvokerOS(env map[string]string, dir string) (bool, error) {
	if os.Geteuid() != 0 {
		return false, nil
	}
	uid, gid, ok := sudoInvoker(env)
	if !ok {
		return false, nil
	}
	if reason, err := parentLinkForeignPOSIX(dir); err != nil || reason != "" {
		return false, nil
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return false, nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != uid {
		return false, nil
	}
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return false, fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return false, fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return false, fmt.Errorf("setuid %d: %w", uid, err)
	}
	if os.Geteuid() != uid || os.Getuid() != uid || os.Getegid() != gid {
		return false, errors.New("the process still does not run as that account after setuid")
	}
	if syscall.Setuid(0) == nil {
		return false, errors.New("root could be taken back after the drop")
	}
	return true, nil
}
