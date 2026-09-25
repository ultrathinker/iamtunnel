// Package datafile is the one door through which every production read
// and write of a long-lived data file passes (IAMT-332 round 9). It owns
// the no-follow open discipline — create-or-refuse for fresh names,
// O_NOFOLLOW + prompt-open + fstat + REGULAR-only for existing ones, the
// loud typed refusal for anything planted at a name — and the one atomic
// replace (WriteFileAtomic), so a new data file cannot be added anywhere
// in the program without inheriting all of it.
//
// The package is a leaf: it imports the standard library and nothing
// else, so every subsystem that touches files — internal/client,
// internal/winkeys, internal/server, internal/gateway/*, cmd/iamtunnel —
// can depend on it without a cycle. That placement is the point: the
// safe primitives used to live inside internal/gateway/state, and any
// package that did not already import the gateway's state store
// (internal/client is the example that cost round 8) had no obvious
// place to get them from, so it rolled its own writer — six independent
// copies of the same dance, one of which nobody had fixed.
//
// The threat model every function here answers: a directory an attacker
// can write is not only the service's own data directory. ANY role
// directory may be attacker-controlled whenever a privileged command is
// aimed at it — --data-dir, IAMTUNNEL_DATA_DIR, client_dir in a config
// file, a preserved HOME, a symlinked parent, and on Windows a hard link
// (which needs no privilege at all, unlike a symlink). So no function
// here ever opens a final pathname component the caller does not already
// hold a descriptor for; planted entries are refused in words, never
// followed, and never wedged on.
package datafile

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

// Open opens one of the LONG-LIVED data files at its final name — state
// locks, journals, keys — without ever following a symlink planted at
// that name (IAMT-332 round three).
//
// These files are reused across process restarts, so their open cannot
// be O_EXCL-unconditionally: the normal case is that a previous run
// created the file legitimately. The open is therefore two-legged. The
// first leg tries O_CREATE|O_EXCL: either the file did not exist and
// this call created it (safe by construction — a planted name would have
// made this leg fail, not follow), or the name already exists and the
// leg fails with EEXIST. The second leg reopens the existing name the
// no-follow way (OpenExisting) and REFUSES the name outright when it is
// a symlink or anything else that is not a regular file: the
// unprivileged service account owns the writable data directory and can
// plant a link to any file on the system, so a root-run maintenance
// command that opened through it would point its descriptor — its
// writes, its flock, its ownership adoption — at the attacker's target.
//
// The refusal is loud and actionable, never a silent open-through: a
// planted entry at a data file's name is a broken or tampered install,
// and every consumer of this helper reports it as such.
//
// Flags carry no O_CREATE/O_EXCL — this function owns the creation
// discipline. perm applies to the creation leg only.
func Open(path string, flags int, perm fs.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flags|os.O_CREATE|os.O_EXCL, perm)
	if err == nil {
		return f, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	return OpenExisting(path, flags)
}

// ReadFile is the READ half of the same contract (IAMT-332 round five):
// it returns the bytes of an existing data file at its final name, having
// opened that name the no-follow way — O_NOFOLLOW (or the Windows Lstat
// check), prompt (O_NONBLOCK), fstat, REGULAR files only — so a symlink
// or FIFO planted at the name is refused outright instead of being read
// through or wedged on. Every final-pathname reader of a data file goes
// through here rather than os.ReadFile, so the whole read side carries
// the same refusal the write and lock sides have had since rounds three
// and four.
//
// The file must already exist: ReadFile never creates anything, and a
// missing name comes back as os.ErrNotExist verbatim, so callers keep
// their "first run"/"must create" branches unchanged.
func ReadFile(path string) ([]byte, error) {
	f, err := OpenExisting(path, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// OpenAppend opens — or, only if the name is genuinely missing, creates
// — a LONG-LIVED append-mode data file at its final name: a journal the
// process keeps its handle to and writes to for its whole life, the
// WRITE-side twin of ReadFile (IAMT-332 round seven). An existing name
// is opened the no-follow way, so a symlink or FIFO planted at the name
// is refused before the first byte instead of being written through or
// wedged on; only a missing name takes Open's fresh O_CREATE|O_EXCL
// creation leg, which is safe by construction.
//
// The probe-first shape (OpenExisting, then Open only on os.ErrNotExist)
// rather than Open alone is deliberate: the creation leg answers a
// planted non-regular entry with the raw creation error on some
// platforms (Windows: "is a directory"), not the actionable refusal.
func OpenAppend(path string) (*os.File, error) {
	f, err := OpenExisting(path, os.O_WRONLY|os.O_APPEND)
	if !errors.Is(err, os.ErrNotExist) {
		return f, err
	}
	return Open(path, os.O_WRONLY|os.O_APPEND, 0o600)
}
