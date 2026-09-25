//go:build linux || darwin

// Unix primitives for the winkeys package: SPEC §3.2.1 layer 0
// for Linux machines (and Darwin machines, which share the same
// Unix primitives; the macOS-only differences — LaunchDaemon,
// kqueue NOTE_EXIT instead of pidfd — live in IAMT-247's
// doorwatch work and are not in this file).
//
// Path discipline (IAMT-246 fix1): every file operation in the
// Unix branch goes through a directory fd the strict-mode
// preflight verified. No path-based os.ReadFile / os.Open /
// os.Remove / os.Chmod / os.Chown runs against anything inside
// the user's home — a TOCTOU swap of ~/.ssh (or the home itself)
// cannot redirect the write to a stranger's file. The
// strict-mode preflight opens the home directory, then opens
// .ssh through it (creating it if absent), then opens
// the key file through .ssh; every subsequent step — mkdirat,
// fchmod, fchown, write, fsync, renameat — uses one of those
// fds and never returns to a path.
//
// Lock discipline: AcquireFileLock uses flock(2) on a path the
// server role owns; the seam below (chmodFn / chownFn) is what
// stops a test binary from ever reaching the real syscall. The
// seams' default IS the real syscall (production binary); in a
// test binary the seams are replaced by recording stubs in init().
//
// Basename discipline (TestAcceptance_NoKeyFileConstant): the
// forbidden substrings (including `authorized_keys`,
// `administrators_authorized_keys`, `/etc/ssh`, `C:\ssh`,
// `ProgramData`) are forbidden in the compiled archive. The
// basename of the key file is computed at runtime from
// filepath.Base(keyFile) — there is no string constant naming
// it. Error messages name the file via the runtime-derived
// basename; comments and the README's prose are exempt
// (comments are stripped before the binary's data section).

package winkeys

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// writeAtomicBytesPlatform is the Linux/Darwin half of
// writeAtomicBytes. It owns the full SPEC §3.2.1 sequence:
//
//   - open the home (resolved from keyFile) as a directory fd;
//   - strict-mode check on home (owner + mode via fstat);
//   - open or mkdirat+open .ssh as a directory fd;
//   - strict-mode check on .ssh;
//   - strict-mode check on the existing key file via openat +
//     fstat (regular, nlink==1, owner, mode); the file's
//     contents are NOT re-read here — the cross-platform
//     caller already has them and computed `content`;
//   - generate a cryptographically-random tmp name;
//   - openat the tmp file with O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY|
//     O_CLOEXEC, mode 0600;
//   - fstat the tmp fd (regular, nlink==1);
//   - write content to the tmp fd;
//   - fsync the tmp fd;
//   - fchmod the tmp fd to 0600;
//   - fchown the tmp fd to opts.OwnerUID/OwnerGID via the
//     "root changes owner" hook (the IAMT-269 lesson);
//   - renameat(sshFD, tmp, sshFD, baseName);
//   - fsync the .ssh fd;
//   - read-back through a fresh openat + fstat + read; the
//     bytes returned must equal content.
//
// Returns a clear, actionable error on every refusal path. All
// chmod/chown go through seams so a test binary never touches
// the real filesystem.
func writeAtomicBytesPlatform(path string, content []byte, opts DoorOptions) error {
	if opts.LockPath == "" {
		return errors.New("winkeys: LockPath is required on linux and darwin (SPEC §3.2.1)")
	}
	if opts.OwnerUID < 0 || opts.OwnerGID < 0 {
		return fmt.Errorf("winkeys: invalid owner %d:%d", opts.OwnerUID, opts.OwnerGID)
	}

	homeDir := filepath.Dir(filepath.Dir(path))  // ~/..
	baseName := filepath.Base(path)              // the file inside .ssh
	sshName := filepath.Base(filepath.Dir(path)) // .ssh

	// 1. Open the home directory. O_DIRECTORY|O_NOFOLLOW refuses
	//    a symlinked home. The home path itself comes from
	//    getpwnam (cmd/iamtunnel's userLookupFn), which the OS
	//    guarantees resolves to a directory the running root
	//    can reach — intermediate components under /home are
	//    owned by root by convention.
	homeFD, err := unix.Open(homeDir, unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if symlinkLikeErrno(err) {
			return fmt.Errorf("winkeys: %s is a symbolic link (or similar) — refusing to follow: %w", homeDir, err)
		}
		return fmt.Errorf("winkeys: open home %s for write: %w", homeDir, err)
	}
	defer unix.Close(homeFD)
	if err := strictModeCheckFD(homeFD, opts, "home directory", homeDir); err != nil {
		return err
	}

	// 2. Open (or create) .ssh.
	sshFD, err := openOrCreateSSHDir(homeFD, sshName, opts)
	if err != nil {
		return err
	}
	defer unix.Close(sshFD)

	// 3. Strict-mode check the existing key file (stat only —
	//    contents are caller-supplied). Missing is OK; we will
	//    create.
	if err := strictCheckExistingKeyFile(sshFD, baseName, opts); err != nil {
		return err
	}

	// 4. Atomic write + fsync + read-back.
	writtenInode, err := atomicWriteInSSHDir(sshFD, baseName, content, opts)
	if err != nil {
		return err
	}
	if err := verifyWriteBack(sshFD, baseName, content, writtenInode); err != nil {
		return err
	}
	return nil
}

// symlinkLikeErrno reports whether err — the errno of an open or
// openat whose flags carried O_NOFOLLOW — refused the final path
// component because it is (or became) a symbolic link the kernel
// would not follow. ELOOP is the textbook O_NOFOLLOW verdict; the
// acceptance run observed that when the open also carries
// O_DIRECTORY the kernel leaves the trailing symlink unresolved
// and the failure surfaces as ENOTDIR ("not a directory") instead
// — which of the two arrives depends on the kernel version and the
// file system, so both must read as a symlink refusal. ENOENT is
// deliberately NOT in this set: a missing entry is the legitimate
// create path (mkdirat below), not a refused symlink.
func symlinkLikeErrno(err error) bool {
	return errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR)
}

// openOrCreateSSHDir opens (or mkdirat-creates) .ssh as a
// directory fd. After this call the returned fd has been fchown'd
// to opts.OwnerUID/OwnerGID and fchmod'd to 0700 — no path-based
// operation is ever performed on the new directory.
func openOrCreateSSHDir(homeFD int, name string, opts DoorOptions) (int, error) {
	fd, err := unix.Openat(homeFD, name, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		// Existing .ssh — strict-mode check it.
		if err := strictModeCheckFD(fd, opts, "directory", ".ssh"); err != nil {
			unix.Close(fd)
			return 0, err
		}
		return fd, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		if symlinkLikeErrno(err) {
			return 0, fmt.Errorf("winkeys: %s is a symbolic link (or similar) — refusing to follow: %w", name, err)
		}
		return 0, fmt.Errorf("winkeys: open %s: %w", name, err)
	}
	// Missing .ssh — mkdirat with 0700 (kernel honours umask; the
	// explicit fchmod below tightens to 0700 regardless).
	if err := unix.Mkdirat(homeFD, name, 0o700); err != nil {
		return 0, fmt.Errorf("winkeys: mkdirat %s: %w", name, err)
	}
	// fsync the parent so the new directory is durable before
	// we open it (a crash between mkdirat and openat would leave
	// the parent without the entry on disk).
	if err := unix.Fsync(homeFD); err != nil {
		return 0, fmt.Errorf("winkeys: fsync home after mkdirat %s: %w", name, err)
	}
	// Reopen the new directory so we have an fd to fchown/
	// fchmod. The reopen uses O_NOFOLLOW so a TOCTOU swap
	// (rmdir + symlink) between the mkdirat and this openat
	// would not silently re-target the open.
	fd, err = unix.Openat(homeFD, name, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if symlinkLikeErrno(err) {
			// A TOCTOU swap (rmdir + symlink) between the mkdirat
			// and this reopen landed on a symlink — name the cause.
			return 0, fmt.Errorf("winkeys: %s is a symbolic link (or similar) — refusing to follow: %w", name, err)
		}
		return 0, fmt.Errorf("winkeys: reopen %s after mkdirat: %w", name, err)
	}
	// Owner / mode on the new directory. Right after mkdirat the
	// owner is the running euid (root in production) — sshd's
	// StrictModes accepts root-owned .ssh, so the file is
	// serviceable immediately; we still apply the requested
	// owner so the dir matches the eventual key-file owner.
	if err := fchownIfRoot(fd, opts.OwnerUID, opts.OwnerGID); err != nil {
		unix.Close(fd)
		return 0, err
	}
	if err := chmodFnFD(fd, 0o700); err != nil {
		unix.Close(fd)
		return 0, err
	}
	return fd, nil
}

// strictCheckExistingKeyFile opens the existing key file through
// sshFD (refusing a symlink via O_NOFOLLOW), fstat's it (regular,
// nlink==1, owner, mode), and closes it. We do NOT read the
// contents — the caller already has them and computed the new
// bytes. A symlink, non-regular file, hardlink, wrong-owner, or
// group/other-writable file is a refusal with an actionable
// text — the operator must fix it by hand before door.open can
// succeed. A missing file is fine; the write step creates a
// fresh one with mode 0600.
//
// O_NONBLOCK is what makes the non-regular refusal reachable at
// all (code review 23.09.2026, F-11): on POSIX a plain read-only
// open of a FIFO BLOCKS inside open(2) until a writer appears, so
// a FIFO planted at the key file's name — no root needed, the
// owner of the .ssh directory can arrange it — hung the door
// (Start, Install, Remove, SweepStale) before the fstat below
// could run, with the file lock held. With the flag the open
// returns at once and the fstat refuses the FIFO in words. On the
// regular files that survive the check the flag has no effect, so
// it is left set; datafile.OpenExisting does the same and for the
// same reason (IAMT-332 round four).
func strictCheckExistingKeyFile(sshFD int, baseName string, opts DoorOptions) error {
	fd, err := unix.Openat(sshFD, baseName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if symlinkLikeErrno(err) {
			return fmt.Errorf("winkeys: %s is a symbolic link (or similar) — refusing to follow: %w", baseName, err)
		}
		return fmt.Errorf("winkeys: open existing key file: %w", err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("winkeys: fstat existing key file: %w", err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return errors.New("winkeys: existing key file is a symbolic link — refusing (SPEC §3.2.1)")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("winkeys: existing key file is not a regular file — refusing")
	}
	if st.Nlink != 1 {
		return fmt.Errorf("winkeys: existing key file has nlink=%d, refusing (hard-link attack surface)", st.Nlink)
	}
	return strictModeCheckStat(st, opts, "file", baseName)
}

// modifyKeyFilePlatform is the Unix half of modifyKeyFile (Code-rev
// rall_codex round, major). It is the read-modify-write counterpart of
// writeAtomicBytesPlatform: opens the data directory's parent chain
// (home → .ssh) once, reads the existing bytes via openat, applies
// transform, writes the result through atomicWriteInSSHDir and
// verifies via verifyWriteBack — all on the same sshFD so a TOCTOU
// swap of ~/.ssh (or the home itself) between the read and the write
// cannot redirect the write to a stranger's authorized_keys. The
// door.write side already lives inside the openat-relative stream
// (SPEC §3.2.1 rule 4); this closes the last stragglers
// (installLocked / removeLocked / sweepLocked), which used to
// pre-read the file by path and then hand the bytes to
// writeAtomicBytes — opening a path-based read followed by an
// openat-based write that could disagree about which file is the
// "authorized_keys".
//
// Returns the same error class as writeAtomicBytesPlatform
// (path-based os.Open / os.MkdirAll stay no-ops; the strict-mode
// preflight, the tmp-write fchmod/fchown, the renameat and the
// read-back verifyWriteBack are exactly the same primitives).
func modifyKeyFilePlatform(path string, transform func(raw []byte) ([]byte, error), opts DoorOptions) error {
	if opts.LockPath == "" {
		return errors.New("winkeys: LockPath is required on linux and darwin (SPEC §3.2.1)")
	}
	if opts.OwnerUID < 0 || opts.OwnerGID < 0 {
		return fmt.Errorf("winkeys: invalid owner %d:%d", opts.OwnerUID, opts.OwnerGID)
	}

	homeDir := filepath.Dir(filepath.Dir(path))
	baseName := filepath.Base(path)
	sshName := filepath.Base(filepath.Dir(path))

	homeFD, err := unix.Open(homeDir, unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if symlinkLikeErrno(err) {
			return fmt.Errorf("winkeys: %s is a symbolic link (or similar) — refusing to follow: %w", homeDir, err)
		}
		return fmt.Errorf("winkeys: open home %s for write: %w", homeDir, err)
	}
	defer unix.Close(homeFD)
	if err := strictModeCheckFD(homeFD, opts, "home directory", homeDir); err != nil {
		return err
	}

	sshFD, err := openOrCreateSSHDir(homeFD, sshName, opts)
	if err != nil {
		return err
	}
	defer unix.Close(sshFD)

	if err := strictCheckExistingKeyFile(sshFD, baseName, opts); err != nil {
		return err
	}

	// Read existing bytes through sshFD — openat(O_NOFOLLOW) refuses
	// a symlink at the trailing component, so the read is anchored
	// at the inode the strict preflight validated (no path TOCTOU
	// between here and the write below).
	raw, err := readExistingInSSHDir(sshFD, baseName)
	if err != nil {
		return err
	}

	next, err := transform(raw)
	if err != nil {
		return err
	}

	// Idempotent no-op: the transform decided not to change
	// anything (e.g. SweepStale saw zero iamtunnel lines). Skip the
	// write so the inode is not churned — the next read-back would
	// otherwise be a no-op rewrite for no reason.
	if bytesEqual(raw, next) {
		return nil
	}

	writtenInode, err := atomicWriteInSSHDir(sshFD, baseName, next, opts)
	if err != nil {
		return err
	}
	if err := verifyWriteBack(sshFD, baseName, next, writtenInode); err != nil {
		return err
	}
	return nil
}

// readExistingInSSHDir opens baseName through sshFD with O_NOFOLLOW
// and reads it. The caller (modifyKeyFilePlatform) has already
// validated sshFD itself via strictModeCheckFD + openOrCreateSSHDir;
// here we just walk the file's bytes. A missing file is treated as
// "empty file" (no error) so a first-time Install writes a fresh
// line without a separate existence check — same shape as the old
// readKeyFile path's ErrNotExist handling.
//
// O_NONBLOCK for the same reason as in strictCheckExistingKeyFile
// (code review 23.09.2026, F-11): the fstat that refuses a FIFO
// sits AFTER the open, and an open of a FIFO blocks. The strict
// preflight has already refused a non-regular entry by the time
// this runs, but the flag is what keeps the two steps from
// disagreeing if the name is swapped between them.
func readExistingInSSHDir(sshFD int, baseName string) ([]byte, error) {
	fd, err := unix.Openat(sshFD, baseName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		if symlinkLikeErrno(err) {
			return nil, fmt.Errorf("winkeys: %s is a symbolic link (or similar) — refusing to follow: %w", baseName, err)
		}
		return nil, fmt.Errorf("winkeys: openat existing %s: %w", baseName, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("winkeys: fstat existing %s: %w", baseName, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("winkeys: existing %s is not a regular file (mode %#o)", baseName, uint32(st.Mode&unix.S_IFMT))
	}
	size := int(st.Size)
	if size < 0 {
		size = 0
	}
	buf := make([]byte, size)
	read := 0
	for read < size {
		n, err := unix.Read(fd, buf[read:])
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, fmt.Errorf("winkeys: read existing %s: %w", baseName, err)
		}
		if n == 0 {
			break
		}
		read += n
	}
	return buf[:read], nil
}

// bytesEqual is a tiny helper used by modifyKeyFilePlatform to detect
// a no-op rewrite (transform returned the same bytes it was handed).
// bytes.Equal from the standard library would do — this one just
// keeps the Unix file's import surface minimal.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// atomicWriteInSSHDir writes content inside the .ssh directory fd.
// The tmp file has a cryptographically-random name, is created
// with O_EXCL (no pre-existing file can win the race), and after
// openat is fstat'd to verify it is regular + nlink==1. Every
// permission / owner step goes through fd. On any error the
// tmp file is unlinked from the same sshFD.
func atomicWriteInSSHDir(sshFD int, baseName string, content []byte, opts DoorOptions) (uint64, error) {
	tmpName, err := randomTmpName()
	if err != nil {
		return 0, err
	}
	tmpFD, err := unix.Openat(sshFD, tmpName,
		unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_WRONLY|unix.O_CLOEXEC,
		0o600)
	if err != nil {
		if symlinkLikeErrno(err) {
			return 0, fmt.Errorf("winkeys: %s is a symbolic link (or similar) — refusing to follow: %w", tmpName, err)
		}
		return 0, fmt.Errorf("winkeys: openat tmp in .: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = unix.Close(tmpFD)
			// unlinkat from the same parent fd — never via path.
			_ = unix.Unlinkat(sshFD, tmpName, 0)
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(tmpFD, &st); err != nil {
		return 0, fmt.Errorf("winkeys: fstat tmp: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, fmt.Errorf("winkeys: tmp is not a regular file (mode %#o)", uint32(st.Mode&unix.S_IFMT))
	}
	if st.Nlink != 1 {
		return 0, fmt.Errorf("winkeys: tmp has nlink=%d after O_EXCL create (should be 1) — refusing", st.Nlink)
	}
	// IAMT-293: write-all loop. unix.Write is allowed to return a
	// short count without an error (quota, space, an interrupted
	// transfer); accepting that as success would fsync and renameat a
	// truncated file over the old one — the old content would already
	// be gone. Keep writing the remainder, retry on EINTR, and refuse
	// on any error or a non-progressing zero write BEFORE fsync: the
	// deferred cleanup then unlinks the tmp like any other failure,
	// and the published key file is untouched.
	written := 0
	for written < len(content) {
		n, err := unix.Write(tmpFD, content[written:])
		written += n
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return 0, fmt.Errorf("winkeys: write tmp: %w", err)
		}
		if n == 0 {
			return 0, fmt.Errorf("winkeys: write tmp: wrote %d of %d bytes with no progress — refusing to publish a truncated file", written, len(content))
		}
	}
	if err := unix.Fsync(tmpFD); err != nil {
		return 0, fmt.Errorf("winkeys: fsync tmp: %w", err)
	}
	// fchmod first (mode is independent of ownership), then
	// fchown only when the running euid is 0 and the requested
	// owner differs from the current owner — this is the
	// "root changes owner" case from the IAMT-269 lesson; if
	// the file is already owned by the right user we do not
	// touch the owner.
	if err := chmodFnFD(tmpFD, 0o600); err != nil {
		return 0, err
	}
	if err := fchownIfRoot(tmpFD, opts.OwnerUID, opts.OwnerGID); err != nil {
		return 0, err
	}
	if err := unix.Renameat(sshFD, tmpName, sshFD, baseName); err != nil {
		return 0, fmt.Errorf("winkeys: renameat %s -> %s: %w", tmpName, baseName, err)
	}
	// fsync the directory so the rename is durable; without it
	// a power-cut between rename and the next sync would leave
	// the tmp file orphaned and the key file not visible.
	if err := unix.Fsync(sshFD); err != nil {
		return 0, fmt.Errorf("winkeys: fsync .ssh after renameat: %w", err)
	}
	committed = true
	_ = unix.Close(tmpFD)
	return st.Ino, nil
}

// verifyWriteBack reopens the key file through sshFD and
// verifies that the read-back bytes match what we wrote and
// the inode matches what we recorded (a paranoid defence against
// a race the strict preflight was meant to close: a TOCTOU swap
// of the parent directory between our rename and this read-back
// would land us on a different inode).
//
// O_NONBLOCK for the same reason as in strictCheckExistingKeyFile
// (code review 23.09.2026, F-11): the read-back's fstat is the
// step that refuses a non-regular entry, and it can only run once
// the open has returned.
func verifyWriteBack(sshFD int, baseName string, want []byte, writtenInode uint64) error {
	fd, err := unix.Openat(sshFD, baseName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if symlinkLikeErrno(err) {
			return fmt.Errorf("winkeys: %s is a symbolic link (or similar) — refusing to follow: %w", baseName, err)
		}
		return fmt.Errorf("winkeys: read-back openat: %w", err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("winkeys: read-back fstat: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("winkeys: read-back file is not a regular file")
	}
	if st.Nlink != 1 {
		return fmt.Errorf("winkeys: read-back inode has nlink=%d, refusing", st.Nlink)
	}
	if st.Ino != writtenInode {
		return fmt.Errorf("winkeys: read-back inode changed (%d -> %d) — directory was swapped during the write", writtenInode, st.Ino)
	}
	// IAMT-292: read to EOF, not one fixed 1 MiB slice — authorized_keys
	// keeps foreign lines and can legitimately exceed that, and a single
	// short read failed the check on a file that was physically correct.
	// The read is still bounded: once more bytes have arrived than want
	// holds, the file cannot be the one we wrote, so stop buffering and
	// let the length check refuse it (this function's whole purpose is
	// to catch a swapped file — a swapped-in giant must not turn into an
	// unbounded read).
	got := make([]byte, 0, len(want))
	buf := make([]byte, 1<<20)
	for {
		n, err := unix.Read(fd, buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("winkeys: read-back read: %w", err)
		}
		if n == 0 {
			break
		}
		if len(got) > len(want) {
			break
		}
	}
	if len(got) != len(want) {
		return fmt.Errorf("winkeys: read-back length %d, want %d", len(got), len(want))
	}
	if string(got) != string(want) {
		return errors.New("winkeys: read-back bytes do not match what was written")
	}
	return nil
}

// strictModeCheckFD fstat's fd and runs strictModeCheckStat. The
// label and a path-shaped name are echoed back in the refusal
// message; the caller supplies the path-shaped name so the
// operator sees the same string they would type in a shell.
func strictModeCheckFD(fd int, opts DoorOptions, label, name string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("winkeys: fstat %s for strict-mode check: %w", name, err)
	}
	return strictModeCheckStat(st, opts, label, name)
}

// strictModeCheckStat enforces the two Strict-mode invariants
// (SPEC §3.2.1 rule 4): owner is opts.OwnerUID or root, and the
// group/other WRITE bits are clear. sshd StrictModes itself
// refuses only group/other write (the historical "group or other
// can write" check), not group/other read; mirroring it exactly
// means a `0o755` directory (group/other `r-x`, no write) is
// fine — both `~/.ssh` and the home directory are normally
// `0o755` on Linux — while a `0o770` directory is refused. The
// check does NOT auto-fix permissions: per SPEC §3.2.1, iamtunnel
// does not "fix home directory permissions"; only the surface
// text changes. The mask is `0o022` (group-write OR world-write),
// not `0o077` — the latter would refuse a stock `0o755` home.
func strictModeCheckStat(st unix.Stat_t, opts DoorOptions, label, name string) error {
	if st.Uid != uint32(opts.OwnerUID) && st.Uid != 0 {
		return fmt.Errorf("winkeys: %s %s is owned by uid %d, expected uid %d or root — run: chown %d %s",
			label, name, st.Uid, opts.OwnerUID, opts.OwnerUID, name)
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("winkeys: %s %s is group- or world-writable (mode %#04o) — run: chmod go-w %s",
			label, name, uint32(st.Mode&0o777), name)
	}
	return nil
}

// fchownIfRoot is the "root changes owner" hook (the IAMT-269
// lesson): the door only changes the file's owner when the running
// euid is 0 AND the requested owner differs from the current
// owner. A non-root process (or a root process that wants to
// keep the file owned by the existing user) skips the syscall
// entirely. This keeps the seam's surface tiny: a non-root
// deployment that runs the door in user mode never asks the
// kernel to change ownership.
func fchownIfRoot(fd int, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return fmt.Errorf("winkeys: invalid owner %d:%d", uid, gid)
	}
	if uid == 0 && gid == 0 {
		return errors.New("winkeys: refusing to chown to uid=0,gid=0 (unset sentinel)")
	}
	if unix.Geteuid() != 0 {
		// Non-root: cannot change ownership regardless. The
		// server layer enforces this through requireServerElevation,
		// but the defence-in-depth check is here for tests that
		// drive writeAtomicBytesPlatform directly with a
		// non-root caller.
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return fmt.Errorf("winkeys: fstat before non-root chown skip: %w", err)
		}
		if int(st.Uid) != uid || int(st.Gid) != gid {
			return fmt.Errorf("winkeys: non-root process cannot chown file (current uid=%d gid=%d, want %d:%d) — re-run as root",
				st.Uid, st.Gid, uid, gid)
		}
		return nil
	}
	return chownFnFD(fd, uid, gid)
}

// randomTmpName generates the tmp file's basename inside the
// .ssh directory. The prefix is fixed (so an operator scanning
// their .ssh knows what a stray tmp file is); the suffix is 128
// bits of crypto/rand encoded as hex — enough that guessing the
// name (the IAMT-246 fix1 shape, replacing the pre-fix PID-derived
// name) is impossible.
func randomTmpName() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("winkeys: random tmp name: %w", err)
	}
	return ".winkeys.tmp." + hex.EncodeToString(buf[:]), nil
}

// FileLock is the cross-process lock on the key file. Each Door
// opens opts.LockPath via os.OpenFile and flocks it with LOCK_EX;
// the file descriptor is private to the Door so two Doors (or
// two processes, or a process and a subprocess) holding the same
// path exclude each other.
//
// Holder death closes the file descriptor, which the kernel
// releases the flock on — there is no graceful-shutdown
// requirement (matching the Windows guarantee).). The Door still
// calls Release explicitly so an in-process caller is not
// surprised by the file's lingering presence.
//
// Why flock and not POSIX fcntl: SPEC §3.2.1 names "flock on the
// door.lock file" by name; fcntl locks have process-attached
// semantics that make the "subprocess inherits the lock" story
// harder to reason about, and DoorWatchdog (IAMT-247) is going to
// be a separate process. flock(LOCK_EX) is also automatically
// released by close(2), which is what "holder death releases
// the lock" relies on.
type FileLock struct {
	file     *os.File
	held     bool
	lockPath string
}

// lockContentionWait bounds how long AcquireFileLock waits out a
// lock another writer holds before declaring contention. It mirrors
// the Windows implementation's 25 × 80 ms CreateFile retry (~2 s),
// so both platforms share the same worst-case bound.
const lockContentionWait = 2 * time.Second

// lockRetryPause is the sleep between flock retries while the lock
// is held by someone else — the same cadence the Windows
// implementation uses between CreateFile attempts.
const lockRetryPause = 80 * time.Millisecond

// AcquireFileLock opens lockPath, runs LOCK_EX|LOCK_NB inside a
// bounded retry, and returns the held lock. Returns an error if the
// file cannot be opened or the lock cannot be acquired within the
// bound; the kernel error is wrapped in a recognisable message.
//
// On Linux and Darwin a blocking flock(2) would hang on the
// "holder that never releases" failure mode, so the acquire runs
// LOCK_NB: transient contention — the normal interleaving of two
// writers' short Install/Remove critical sections
// (TestConcurrentDoors_LockSerialisesAcrossGoroutines) — is waited
// out, while a genuinely stuck holder still surfaces as a typed
// "held by another writer" error after lockContentionWait instead
// of a hung goroutine. The Windows side implements the same
// worst-case contract with a CreateFile retry; both implementations
// bound their wait to a few seconds total.
func AcquireFileLock(lockPath string) (*FileLock, error) {
	if lockPath == "" {
		return nil, errors.New("winkeys: AcquireFileLock requires a non-empty lock path")
	}
	// datafile.Open, not the flat O_CREATE open this was (IAMT-332 round
	// nine): the lock's mutual exclusion only means anything if the fd is
	// on the entry this name refers to NOW. A symlink planted at the lock
	// path used to be followed, so the "lock" was taken on the plant's
	// target and the real writers were never excluded; a FIFO or a
	// directory there is refused too, in the contract's own words.
	f, err := datafile.Open(lockPath, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("winkeys: open lock %s: %w", lockPath, err)
	}
	deadline := time.Now().Add(lockContentionWait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &FileLock{file: f, held: true, lockPath: lockPath}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || !time.Now().Before(deadline) {
			_ = f.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, fmt.Errorf("winkeys: lock %s held by another writer: %w", lockPath, err)
			}
			return nil, fmt.Errorf("winkeys: flock %s: %w", lockPath, err)
		}
		time.Sleep(lockRetryPause)
	}
}

// Release closes the underlying file descriptor. Closing the fd
// releases the flock regardless of whether the holder is still
// alive, so Release is a no-fail operation; we surface any close
// error verbatim.
func (l *FileLock) Release() error {
	if l == nil {
		return nil
	}
	if !l.held {
		return nil
	}
	l.held = false
	err := l.file.Close()
	l.file = nil
	return err
}

// validateOptionsPlatform is the linux/darwin half of
// NewDoorWithOptions's gate. LockPath is mandatory; OwnerUID/
// OwnerGID are validated as a sane pair (no negative, not
// the unset zero-zero sentinel).
func validateOptionsPlatform(opts DoorOptions) error {
	if opts.LockPath == "" {
		return errors.New("winkeys: LockPath is required on linux and darwin — the lock file must live in the server's data directory, not beside the user's key file (SPEC §3.2.1)")
	}
	if opts.OwnerUID < 0 || opts.OwnerGID < 0 {
		return fmt.Errorf("winkeys: invalid owner %d:%d", opts.OwnerUID, opts.OwnerGID)
	}
	if opts.OwnerUID == 0 && opts.OwnerGID == 0 {
		return errors.New("winkeys: OwnerUID=0 and OwnerGID=0 is the unset sentinel — resolve the OS user via elevate.VerifyOSUser (or os/user.Lookup) before constructing a Door on linux/darwin")
	}
	return nil
}

// writeAtomicBytesPlatformDispatch is the cross-platform
// dispatcher: on Linux/Darwin the openat-based sequence above
// runs; on Windows the existing path-based flow runs (see
// doors_windows.go). It is split across platforms by build tag
// at the call site — this is a comment-only marker that the
// function above is the unix half; the windows half lives in
// doors_windows.go.
//
// (The dispatcher itself is writeAtomicBytes in doors.go.)

// LockDownFileACL narrows a file's mode to 0o600 on Linux and
// Darwin (the Unix analogue of the Windows DACL lockdown). The
// production caller is cmd/iamtunnel's machine role (IAMT-213):
// atomicWriteMachineBytes and generateMachineSigner use it for
// the machine data files (machine.id, gateway record, control.json,
// the machine key). Those live in the server data directory, not
// in the user's home, so this path-based chmod never touches the
// door's fd-only in-home write path (SPEC §3.2.1); everything the
// door writes inside home goes through chmodFnFD / fchownFnFD
// exclusively. In a test binary the seam panics (gate 11) — a
// test that reaches this function must install a recording seam
// first.
//
// replaceACL is the IAMT-315 opt-in flag; it has no effect on Unix
// because the foreign-deny check is Windows-specific (Windows-only
// DACL semantics). It is present in the signature so the
// cross-platform callers (cmd/iamtunnel) can pass it without a
// build-tag split. report is the caller-supplied destination for
// the dropped-ACE printout on Windows; on Unix it has no
// destination to print to (no DACL, no ACEs) and is ignored.
func LockDownFileACL(path string, _ bool, _ io.Writer) error {
	if err := chmodFn(path, 0o600); err != nil {
		return fmt.Errorf("winkeys: chmod %s to 0600: %w", path, err)
	}
	return nil
}

// LockDownDirACL is the directory twin of LockDownFileACL.
// replaceACL is the IAMT-315 opt-in flag; see LockDownFileACL for
// why it is ignored on Unix. report is the Windows-only
// printout destination; see LockDownFileACL.
func LockDownDirACL(path string, _ bool, _ io.Writer) error {
	if err := chmodFn(path, 0o700); err != nil {
		return fmt.Errorf("winkeys: chmod %s to 0700: %w", path, err)
	}
	return nil
}

// ReadDACL returns nil. There is no DACL on Linux/Darwin; the
// matching on-disk check (mode bits) is performed by callers
// that need it (windows_test.go's analogue uses ReadDACL +
// DACLProtected). The signature matches the Windows
// implementation so internal callers do not branch.
func ReadDACL(_ string) ([]string, error) { return nil, nil }

// DACLProtected returns false. Same rationale as ReadDACL.
func DACLProtected(_ string) (bool, error) { return false, nil }

// Supported reports whether winkeys can run on this platform.
// Linux is in 1.1 (SPEC §12); Darwin is "not supported yet"
// (step 5 of the epic) but the file-system primitives are the
// same so the package compiles and unit-tests on Darwin. The
// only Darwin-specific piece (LaunchDaemon and kqueue) is in
// the doorwatch layer and is gated by IAMT-247.
func Supported() bool { return true }

// keep "testing" reachable through indirect import: the panic
// guard in the seam default lives there, even though no symbol from
// the testing package is referenced here.
var _ = func() {} // marker for "this file's build target is linux/darwin"
