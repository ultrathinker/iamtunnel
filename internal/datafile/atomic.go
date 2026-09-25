package datafile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteFileAtomic is THE atomic replace of this program (IAMT-332 round
// nine, §5.6 of the audit): it writes data to a fresh random O_EXCL
// temporary in path's directory and renames it over path. Round 8
// happened because the same dance existed as six independent copies and
// one of them had never been fixed; from this round there is one
// function, and a new data file cannot be added without inheriting the
// discipline, because there is no second way to spell it.
//
// The security properties, none of them optional:
//
//   - The temporary is os.CreateTemp's random O_EXCL name, never the
//     flat path+".tmp": that name was predictable, and a hostile
//     directory owner could pre-plant a file — or, on Windows where a
//     hard link needs no privilege at all, a hard link to somebody
//     else's file — there, aiming both the write and every post-write
//     step at it (IAMT-332 round 2, round 8).
//   - The final name is never OPENED. The replace is a rename, and
//     rename(2)/MoveFileEx act on the entry, never through it: a symlink
//     or hard link planted at path is replaced wholesale while its
//     target's bytes, inode and mtime stay exactly as they were. A
//     directory at path fails the rename — refused, not replaced.
//   - Every optional step runs BEFORE the rename, on the open temporary,
//     while the content is still invisible under the real name: mode
//     (WithMode), POSIX owner adoption (WithAdoptOwner), a file sync
//     (WithSync), and the caller's own step — the Windows DACL lockdown
//     — as WithPreRename. A failure at any of them leaves the old file
//     in place, content and owner, and removes the temporary.
//
// The directory must already exist: creating it is the caller's decision
// (the roles differ in what mode and what error classification a mkdir
// gets), and this function refuses to invent policy there.
func WriteFileAtomic(path string, data []byte, opts ...ReplaceOption) error {
	return WriteFileAtomicFunc(path, func(f *os.File) error {
		_, err := f.Write(data)
		return err
	}, opts...)
}

// WriteFileAtomicFunc is WriteFileAtomic for content that is produced
// incrementally — the backup tar.gz streams through a gzip/tar writer,
// so it cannot be handed over as one byte slice. The write function
// receives the open temporary and must leave it positioned after the
// last byte; sync, chmod, adoption, close, the pre-rename step and the
// rename itself stay this function's job, in that order.
func WriteFileAtomicFunc(path string, write func(*os.File) error, opts ...ReplaceOption) error {
	plan := replacePlan{}
	for _, o := range opts {
		o(&plan)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	if werr := write(tmp); werr != nil {
		cleanup()
		return fmt.Errorf("%s: %w", tmpPath, werr)
	}
	if plan.sync {
		if serr := tmp.Sync(); serr != nil {
			cleanup()
			return fmt.Errorf("%s: %w", tmpPath, serr)
		}
	}
	// WithMode narrows the temporary's permissions before it becomes the
	// real file. os.CreateTemp already creates 0600, so this only ever
	// widens (the desktop entries' 0644) or restates. On Windows Chmod
	// maps to the read-only bit only — the DACL is the mechanism there,
	// set by the WithPreRename lockdown — and a failure is not fatal,
	// exactly as record.WriteMeta judged it before this function
	// absorbed that writer.
	if plan.chmod {
		if cerr := tmp.Chmod(plan.mode); cerr != nil && !isChmodNoopPlatform() {
			cleanup()
			return fmt.Errorf("%s: %w", tmpPath, cerr)
		}
	}
	if plan.adoptFn != nil || plan.adopt {
		// The rename below hands the file to whoever runs this process:
		// the documented sudo runs would leave the service's own files
		// owned by root, and the next service start would die reading
		// them (IAMT-332). Adopt the replaced file's owner BEFORE the
		// rename, on the open descriptor, so a refused adoption leaves
		// the old file in place, content and owner.
		adopt := plan.adoptFn
		if adopt == nil {
			adopt = PreserveOwnership
		}
		if aerr := adopt(tmp, path); aerr != nil {
			cleanup()
			return fmt.Errorf("%s: %w", path, aerr)
		}
	}
	if cerr := tmp.Close(); cerr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("%s: %w", tmpPath, cerr)
	}
	if plan.preRename != nil {
		// The caller's step — on Windows the DACL lockdown — runs by the
		// temporary's random path, which is safe exactly because the
		// attacker never learns that name before the file exists, and
		// always BEFORE the rename, because after it the content is
		// already visible under the real name (IAMT-214).
		if perr := plan.preRename(tmp); perr != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("%s: %w", tmpPath, perr)
		}
	}
	// replaceEntry, not a bare os.Rename: on Windows a concurrent reader of
	// the old file refuses the replace, and it waits that out (IAMT-503).
	if rerr := replaceEntry(tmpPath, path); rerr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("%s: %w", path, rerr)
	}
	return nil
}

// replacePlan carries the options WriteFileAtomicFunc was called with.
type replacePlan struct {
	mode      fs.FileMode
	chmod     bool
	adopt     bool
	adoptFn   func(f *os.File, replacedPath string) error
	sync      bool
	preRename func(tmp *os.File) error
}

// ReplaceOption tunes one WriteFileAtomic / WriteFileAtomicFunc call.
type ReplaceOption func(*replacePlan)

// WithMode sets the permissions the file carries after the replace.
// Without it the file keeps os.CreateTemp's 0600.
func WithMode(m fs.FileMode) ReplaceOption {
	return func(p *replacePlan) { p.mode, p.chmod = m, true }
}

// WithAdoptOwner gives the new file the owner of the file it replaces
// (or of the receiving directory, when nothing stood there) — the
// POSIX PreserveOwnership step, a no-op on Windows. Every writer whose
// replace lands in the unprivileged gateway service's directory under a
// documented sudo run needs it (IAMT-332).
func WithAdoptOwner() ReplaceOption {
	return func(p *replacePlan) { p.adopt = true }
}

// WithAdoptOwnerFn is WithAdoptOwner with the adoption step swapped for
// fn: the seam the packages that own a swap-able adoptOwnership variable
// (internal/gateway, cmd/iamtunnel) thread through to keep their
// ownership tests recorder-based. Production code passes
// WithAdoptOwner and never needs this option.
func WithAdoptOwnerFn(fn func(f *os.File, replacedPath string) error) ReplaceOption {
	return func(p *replacePlan) { p.adoptFn = fn }
}

// WithSync fsyncs the temporary before the rename, so a crash after the
// rename cannot surface a zero-length or half-written real file.
func WithSync() ReplaceOption {
	return func(p *replacePlan) { p.sync = true }
}

// WithPreRename installs a step that runs after the temporary is written
// and closed, and before the rename: the Windows DACL lockdown
// (winkeys.LockDownFileACL) is the user this exists for. The hook
// receives the closed temporary; its name is still the random one, and
// removing it is still this function's job if the hook fails.
func WithPreRename(fn func(tmp *os.File) error) ReplaceOption {
	return func(p *replacePlan) { p.preRename = fn }
}

// isChmodNoopPlatform reports whether os.File.Chmod on this platform is
// too narrow to fail the write over (Windows: it maps to the read-only
// bit; the DACL set by the pre-rename lockdown is the real mechanism).
func isChmodNoopPlatform() bool {
	return os.PathSeparator == '\\' // windows — no build tag, so atomic.go stays in one file
}
