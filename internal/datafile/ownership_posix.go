//go:build !windows

package datafile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// PreserveOwnership gives the open file f the owner account the gateway
// service expects (IAMT-332): the owner of replacedPath when a file is
// being replaced, or — when replacedPath is empty or has vanished — the
// owner of the directory f was created in.
//
// Why this exists: rename(2) does not blend accounts — the replacement
// carries the account of whoever created the file, and a fresh create
// carries the creating process's account. The gateway service runs under
// an unprivileged account (SPEC §3.5: runs as the iamtunnel user, not
// as root), and the local commands that write its files —
// "gateway pair" (RUNBOOK §5.11), "gateway install --rebootstrap"
// (§1.4), "gateway restore" (§3.3), "gateway rotate-hostkey" (§4.3) —
// are documented to run under sudo. Without adoption, such runs handed
// state.json, the host key, the bootstrap token — and, round two, the
// files that are merely CREATED on the run: enrol-hmac.key, state.lock,
// events.jsonl — to root, and the next service start died reading files
// it owns.
//
// Both ends of the step are descriptor- or link-based, never a followed
// path: the file being examined is f.Stat() — fstat(2) on the open
// descriptor, which cannot traverse a symlink planted at a file name —
// and the adoption is f.Chown — Fchown on the same descriptor. A run
// with the rounded-two prescription (random O_EXCL temporaries, created
// through os.CreateTemp) therefore cannot be turned against a planted
// name by the directory's owner: the name the writer opens is random,
// the descriptor is what gets chowned, and the only paths ever looked at
// (replacedPath, the receiving directory) are examined with Lstat/Stat
// — Lstat so a symlink at replacedPath is measured as the thing the
// rename will actually replace, never followed; Stat so a symlinked
// data directory resolves to the directory that will really receive the
// file (round two finding 2).
//
// The common case stays cheap: the service's own writes — and any run as
// the service account, `sudo -u iamtunnel ...` — find the fresh file
// already owned by the expected account, and the call is two stat calls.
// Only a run under a different account pays the chown. The adoption
// happens BEFORE the caller renames or releases the file, so a refused
// adoption leaves the old file exactly as it was — old content, old
// owner — and the command fails with a hint instead of leaving the
// service a file it can no longer read. A chown this process is not
// allowed (a non-root run over another account's file) is such a
// refusal, not a warning.
//
// On Windows the call is a no-op (ownership_windows.go); nothing changes
// on that platform (IAMT-332).
func PreserveOwnership(f *os.File, replacedPath string) error {
	uid, gid, known, err := ownerToCarry(f, replacedPath)
	if err != nil || !known {
		return err
	}
	st, serr := f.Stat() // fstat(2): the open file itself, no path to follow
	if serr != nil {
		return fmt.Errorf("%s: %w", f.Name(), serr)
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || (s.Uid == uid && s.Gid == gid) {
		return nil
	}
	if err := f.Chown(int(uid), int(gid)); err != nil { // Fchown on the descriptor
		return fmt.Errorf("%s is about to replace %s owned by uid %d, but this process (uid %d) cannot adopt that owner: %v — run the command as the account that owns the gateway data directory (for example: sudo -u iamtunnel iamtunnel ...), or fix the directory's ownership by hand afterwards",
			f.Name(), replacedPath, uid, s.Uid, err)
	}
	return nil
}

// ownerToCarry reports the uid/gid the new file must carry: the owner of
// replacedPath when a file is being replaced — Lstat, because the rename
// replaces the entry at that path and a symlink there is what gets
// replaced, never followed — and otherwise the owner of the directory
// the file is actually created in. The directory is resolved through
// os.Stat (round two finding 2): a symlinked data directory must yield
// the owner of its target, the directory that will really receive the
// file, not the owner of the symlink. known is false when the platform
// reports no POSIX owner for the entry, and there is nothing this
// function could adopt.
func ownerToCarry(f *os.File, replacedPath string) (uid, gid uint32, known bool, err error) {
	if replacedPath != "" {
		st, serr := os.Lstat(replacedPath)
		if serr == nil {
			if s, ok := st.Sys().(*syscall.Stat_t); ok {
				return s.Uid, s.Gid, true, nil
			}
			return 0, 0, false, nil
		}
		if !errors.Is(serr, fs.ErrNotExist) {
			return 0, 0, false, fmt.Errorf("%s: %w", replacedPath, serr)
		}
		// The replaced file vanished between the write and the rename
		// (or never was): the receiving directory decides.
	}
	dir := filepath.Dir(f.Name())
	// Residual race, assessed and ACCEPTED (IAMT-332 round three; kept
	// accepted in IAMT-333): this Stat re-resolves the directory by path
	// after the caller created the temporary inside it, so a swap of the
	// directory entry between this Stat and the caller's rename would
	// point the adoption at a directory other than the one whose owner
	// was measured. Closing it takes descriptor-relative steps (one held
	// dirfd, openat/fstatat/renameat against it). Round three could say
	// Go's portable os package does not expose them; since Go 1.27 that
	// reason is gone (os.Root is exactly that family, on both platforms),
	// so the window is kept accepted on the threat-model grounds alone:
	// swapping the data directory's own entry requires write access to
	// its PARENT (/var/lib, root-owned), and the modeled attacker owns
	// only the data directory's contents; and even inside the window the
	// chown can only land on a directory whose owner the attacker is
	// already, so no privilege changes hands. Restructuring the portable
	// create→measure→rename seam onto os.Root remains undone (IAMT-333
	// spent the primitive on the walks that had no second check).
	// Accepted, not closed.
	st, serr := os.Stat(dir) // Stat, not Lstat: the resolved receiving directory
	if serr != nil {
		return 0, 0, false, fmt.Errorf("%s: %w", dir, serr)
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false, nil
	}
	return s.Uid, s.Gid, true, nil
}
