//go:build linux || darwin

package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// statExeOwner is the file system half of unixExeWriters (IAMT-445b): owner,
// group and permission bits of the path, following symbolic links as the
// kernel does when it starts the program.
func statExeOwner(p string) (exeOwnerStat, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return exeOwnerStat{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return exeOwnerStat{}, fmt.Errorf("%s: the file system reports no owner", p)
	}
	return exeOwnerStat{uid: st.Uid, gid: st.Gid, mode: fi.Mode()}, nil
}

// refuseElevatingChangeableExe is the Linux and macOS window's check before
// "Restart as administrator" hands this very file to pkexec or to the
// macOS administrator prompt (R1 supplementary round): nobody but the person pressing
// the button, root and the administrators may be able to change it or
// any directory on the way to it - anyone else would be answering the
// password prompt for them. The Windows window's twin is
// refuseElevatingTamperableExe (IAMT-445).
func refuseElevatingChangeableExe(exe string) error {
	who, err := elevationExeWriters(exe, currentElevator(), statExeOwner, filepath.EvalSymlinks)
	if err != nil {
		return fmt.Errorf("could not check who can change %s: %w", exe, err)
	}
	if len(who) > 0 {
		return fmt.Errorf("%s can be changed by someone other than you and the administrators (%s), so restarting it as administrator would run whatever they put there. "+
			"Start the program from a folder only you and root can change - for example \"sudo install -o root -m 0755 iamtunnel /usr/local/bin/iamtunnel\" - and restart it from there",
			exe, strings.Join(who, "; "))
	}
	return nil
}

// currentElevator is the person running this window: their uid, and the
// groups whose right to write is trusted - root's, the person's own
// primary group, and the groups whose members can become root with their
// own password anyway. A group the system does not have is skipped.
func currentElevator() exeElevator {
	e := exeElevator{uid: uint32(os.Getuid()), gids: map[uint32]bool{0: true, uint32(os.Getgid()): true}}
	admins := []string{"sudo", "wheel", "admin"}
	if runtime.GOOS == "darwin" {
		admins = []string{"admin"}
	}
	for _, name := range admins {
		g, err := user.LookupGroup(name)
		if err != nil {
			continue
		}
		if id, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
			e.gids[uint32(id)] = true
		}
	}
	return e
}
