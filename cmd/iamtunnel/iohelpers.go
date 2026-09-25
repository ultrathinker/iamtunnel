package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// atomicWriteJSON marshals v and writes it to path via a temp file plus
// rename, so a crash mid-write never leaves a half-written role file
// behind — the same discipline internal/client/store.go and
// internal/gateway/state.Store already use for their own files. Every
// caller in this package passes a path inside the role directory
// loadConfig resolved, never a path this package invents on its own.
func atomicWriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteBytes(path, append(data, '\n'))
}

// adoptOwnership is the ownership-adoption seam for the atomic replaces
// this package writes into the gateway data dir (IAMT-332): the bootstrap
// token and the host key are rewritten by root-run maintenance commands
// ("gateway install --rebootstrap", "gateway pair"), and the
// unprivileged service account must go on reading them. The default is
// the real platform step, state.PreserveOwnership (a no-op on Windows);
// tests swap in a recorder so nothing is chowned for real and root is
// never needed.
var adoptOwnership = state.PreserveOwnership

// atomicWriteBytes is atomicWriteJSON's underlying primitive, also used
// directly for the plain-text machine.id file. The replace goes through
// datafile.WriteFileAtomic: the temporary is a random O_EXCL creation,
// never the flat path+".tmp" this function used before IAMT-332 round 2
// — that name was predictable, and a hostile directory owner could
// pre-plant a file — or a symlink to somebody else's file — there,
// aiming both the write and the ownership step at it — and an entry
// already holding the real name is refused, never written through. The
// ownership adoption is WithAdoptOwnerFn, the adoptOwnership seam: the
// rename would hand the file to whoever runs this process — the
// gateway's bootstrap token is written by root-run "gateway install"
// and "install --rebootstrap" (RUNBOOK §1.4), and the service account
// must go on reading the directory's files — so it runs BEFORE the
// rename, on the open descriptor, and a refused adoption leaves the old
// file in place, content and owner.
func atomicWriteBytes(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return classifyPathErr(err, dir)
	}
	return classifyDatafileErr(datafile.WriteFileAtomic(path, data,
		datafile.WithAdoptOwnerFn(adoptOwnership)))
}

// atomicWriteMachineBytes is the machine-data variant of
// atomicWriteBytes (IAMT-213). The two exist apart on purpose: the
// shared helper also serves non-machine data — downloaded recordings
// (admin_exec.go), the gateway bootstrap token and the gateway hostkey
// (gateway.go) — and an administrator must keep reading those with a
// normal console. Only THIS variant narrows the tmp file's Windows
// DACL to the protected {SYSTEM, Administrators} pair (the same
// primitive the door key file uses, winkeys.LockDownFileACL; a no-op
// on non-Windows), as the engine's pre-rename step: a freshly created
// tmp file inherits the data directory's entries (a stock ProgramData
// directory lets every Authenticated User read), and after the rename
// the content is already visible under the real name. os.Rename on
// Windows is MoveFileEx(REPLACE_EXISTING): it moves the security
// descriptor together with the file and discards the replaced target
// with its own DACL, so the final file carries exactly the tmp file's
// protected DACL. The replace itself goes through
// datafile.WriteFileAtomic — a random O_EXCL temporary, never the flat
// path+".tmp" this function used before IAMT-332 round 8: that name
// was predictable, and a hostile directory owner could pre-plant a
// symlink there, aiming the write — and the DACL lockdown that follows
// it — at somebody else's file. The lockdown runs by the temporary's
// random name exactly because the attacker never learns that name
// before the file exists, and a refusal at any step leaves the old
// file in place and removes the temporary.
func atomicWriteMachineBytes(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return classifyMachinePathErr(err, dir)
	}
	// replaceACL=false: the tmp file was just written, so its DACL
	// carries only inherited entries (no explicit ACEs); the
	// IAMT-315 check finds nothing and proceeds.
	return classifyMachineDatafileErr(datafile.WriteFileAtomic(path, data,
		datafile.WithPreRename(func(tmp *os.File) error {
			return winkeys.LockDownFileACL(tmp.Name(), false, nil)
		})))
}

// atomicWriteMachineJSON is atomicWriteJSON for the machine role's own
// data files (machine.id, enrolment.json, control.json): the locked
// write path of atomicWriteMachineBytes, the same JSON shape.
func atomicWriteMachineJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteMachineBytes(path, append(data, '\n'))
}

// classifyMachinePathErr is classifyPathErr for the machine role's own
// data: since IAMT-213 that data is locked to SYSTEM/Administrators, so
// on a healthy machine a permission failure means "this console is not
// elevated". The message names the fix in the same words the elevation
// gate uses (server.go's requireServerElevation) instead of a bare
// "Access is denied"; every other failure stays an environment error.
func classifyMachinePathErr(err error, path string) error {
	// Already put in words and class (the folders above the directory,
	// R2 supplementary round): kept as it is.
	var ce *cliError
	if errors.As(err, &ce) {
		return ce
	}
	// R2-CX F-13: an owner the lockdown refuses is the operator's to fix,
	// not the environment's - the same exit code as a refused DENY. So is
	// a data directory that is a link (R2-CX F-12).
	var fo *winkeys.ForeignOwnerRefusalError
	var lp *winkeys.LinkedPathRefusalError
	if errors.As(err, &fo) || errors.As(err, &lp) {
		return deniedErrf("%v.", err)
	}
	if os.IsPermission(err) {
		return deniedErrf("%s: %v — machine data is restricted to administrators; close this console and run it using \"Run as administrator\".", path, err)
	}
	return envErrf("%s: %v", path, err)
}

// hardenServerDir applies the machine-owned lockdown (IAMT-213) to the
// server role's data directory: the directory itself gets the
// protected {SYSTEM, Administrators} DACL with (OI)(CI) inheritance —
// every object created below it starts from those two trustees and
// nothing leaks in from the parent — and every object ALREADY inside
// is healed (files with the file variant, subdirectories with the
// directory variant), so a directory an older binary created with
// inherited Users-read rights is fixed in place, without manual steps.
// On non-Windows the lockdown is the simpler POSIX analogue: the
// directory mode is narrowed to 0o700 (owner-only rwx). The cmd/iamtunnel
// package owns the chmod directly rather than going through
// winkeys.LockDownDirACL, because winkeys's LockDownDirACL on Unix
// routes through a test-binary panic guard (the door's
// seam-with-panic-in-testing.Testing() discipline: only the door
// layer itself may chmod its own files). The server data dir is not
// the door layer — the cmd/iamtunnel binary always has the rights
// to chmod it on its own (IAMT-213's production elevation gate).
//
// Both "enrol" and "server start" call this: enrol before any secret
// is written, server start before anything is read or written. A
// failure refuses the command — running with world-readable machine
// material is the defect this prevents, not a degraded mode.
//
// replaceACL is the IAMT-315 opt-in flag. The server role's harden
// path (called by enrol and server start, not install) has no CLI
// flag for it: a foreign explicit DENY ACE on the machine data
// directory is unusual enough that refusing with a "remove by hand"
// message is the safer default than a silent overwrite. Pass true
// from a code path that has obtained explicit operator consent.
func hardenServerDir(dir string, replaceACL bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return classifyMachinePathErr(err, dir)
	}
	// The branch is on GOOS, not on winkeys.Supported(): Supported()
	// is also true on Linux/Darwin (the door layer is supported
	// there), but LockDownDirACL on Unix routes through the door
	// layer's path-based chmodFn seam — a test binary panics on it,
	// and production would spend an AT_FDCWD-relative chmod where a
	// plain chmod is all this directory needs. The server data dir is
	// not the door layer — cmd/iamtunnel is its only owner, so the
	// chmod is always legal under the elevation gate
	// (requireServerElevation) that ran before this function.
	if runtime.GOOS == "windows" {
		// Windows: the protected DACL on the directory and on every
		// object already in it, through handles (R2-CX F-12).
		return hardenServerDirChildren(dir, replaceACL)
	}
	// Unix: a plain os.Chmod is the cmd-side analogue of
	// LockDownDirACL. No panic guard, no seam — and no child walk:
	// every writer this package points at the machine data dir
	// (atomicWriteBytes / atomicWriteMachineBytes / generateSigner)
	// already creates its files 0o600 and its directories 0o700, and
	// there is no legacy Unix layout to heal (the Linux server role
	// ships in this epic).
	if err := os.Chmod(dir, 0o700); err != nil {
		return classifyMachinePathErr(err, dir)
	}
	// R4 F-04, the Unix side: for root, the folders above the data
	// directory are part of the registration's custody — the elevation
	// that kept the invoking user's $HOME (sudo -E, osascript) would
	// have root act on a chain that account owns. A non-root process is
	// not gated here: reading one's own catalogue is the per-user
	// design (SPEC §3.2.2), and requireServerElevation sends the
	// machine commands to sudo anyway — what reaches this branch
	// unelevated is a test's injected elevation.
	if os.Geteuid() == 0 {
		if err := serverDirAncestorCheck(dir); err != nil {
			return err
		}
	}
	return nil
}

// hardenServerDirChildren locks dir and heals every existing object
// below it: each file gets the protected file DACL, each subdirectory
// the protected directory DACL, and every one of them goes to
// Administrators (R2-CX F-13). Windows-only: it is called only from the
// GOOS=="windows" branch. replaceACL is threaded through for IAMT-315:
// every child we heal goes through the same read-before-overwrite
// discipline.
//
// A child that is not what its name looks like — a symlink or a
// junction — is left untouched, not healed: the walk's job is to heal
// OUR objects, and the datafile readers refuse a name held by anything
// of that kind anyway (IAMT-332). So is a file with more than one name,
// which is not this directory's alone; dir itself as a link is refused.
//
// R2-CX F-12: every object is checked and locked through the one handle
// it was classified by (lockServerTree -> winkeys.LockTree). The walk
// this replaces classified a child by the directory listing and locked
// it by name, and a name that came to mean a hard link to a file outside
// the directory, or a directory link, got the lockdown instead.
func hardenServerDirChildren(dir string, replaceACL bool) error {
	if err := lockServerTree(dir, replaceACL); err != nil {
		return classifyMachinePathErr(err, dir)
	}
	return nil
}

// classifyPathErr turns a filesystem error into the CLI's own error
// classes (main.go's exitEnv/exitDenied), mirroring
// internal/client/keys.go's classifyPathErr for the same reason: a
// permission problem and a missing/broken path are different classes of
// failure for the person reading the message.
func classifyPathErr(err error, path string) error {
	if os.IsPermission(err) {
		return deniedErrf("%s: %v", path, err)
	}
	return envErrf("%s: %v", path, err)
}

// classifyDatafileErr is classifyPathErr's denied/env split for errors
// internal/datafile's writers return: they wrap every failure in their
// own "%s: %w" with the path already in the message, so the class is
// read with errors.Is on fs.ErrPermission instead of re-attaching the
// path here — the same split classifyPathErr gives errors this package
// raised itself. The writers run on the success path too, so nil must
// pass through as nil — a classifier called unconditionally on a
// writer's return must not wrap it into a fake "%v: <nil>" environment
// error.
func classifyDatafileErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, fs.ErrPermission) {
		return deniedErrf("%v", err)
	}
	return envErrf("%v", err)
}

// classifyMachineDatafileErr is classifyDatafileErr for the machine
// role's own data: since IAMT-213 that data is locked to
// SYSTEM/Administrators, so on a healthy machine a permission failure
// means "this console is not elevated". The message names the fix in
// the same words the elevation gate uses (server.go's
// requireServerElevation) instead of a bare "Access is denied"; every
// other failure stays an environment error. nil passes through as nil
// (see classifyDatafileErr).
func classifyMachineDatafileErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, fs.ErrPermission) {
		return deniedErrf("%v — machine data is restricted to administrators; close this console and run it using \"Run as administrator\".", err)
	}
	return envErrf("%v", err)
}

// classifySharedErr classifies an error raised by the gateway lifecycle
// helpers in internal/gateway/lifecycle.go (backup, restore, host key
// rotation), which this package shares with the gateway runtime, and by
// internal/datafile's writers: plain wrapped errors with the paths
// already in the message, so the class goes through errors.Is rather
// than os.IsPermission — classifyDatafileErr's split.
func classifySharedErr(err error) error {
	var invalidArchive *gateway.InvalidArchiveError
	if errors.As(err, &invalidArchive) {
		return userErrf("%v", err)
	}
	return classifyDatafileErr(err)
}

// loadSignerStrict reads an ed25519 private key PEM from path without
// ever generating one: used by "server start", which must refuse
// outright when the machine was never enrolled rather than silently
// minting a fresh, unregistered identity. A missing file is reported as
// os.ErrNotExist (checkable with os.IsNotExist) so the caller can give
// the specific "run enrol first" message.
func loadSignerStrict(path string) (ssh.Signer, error) {
	data, err := state.ReadDataFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, classifyPathErr(err, path)
	}
	raw, perr := ssh.ParseRawPrivateKey(data)
	if perr != nil {
		return nil, envErrf("%s: does not parse as a private key (%v) — enrol again", path, perr)
	}
	return ssh.NewSignerFromKey(raw)
}

// loadOrGenerateSigner reads an ed25519 private key PEM from path,
// generating and saving one the first time it is needed. This mirrors
// internal/client/keys.go's EnsureKey, kept as its own small copy here
// (rather than importing internal/client for a server-role file) because
// the two roles keep their identity in different directories under
// different file names, and reaching for a same-named mechanism in
// another role's package just to save a dozen lines is not worth it.
func loadOrGenerateSigner(path string) (ssh.Signer, error) {
	data, err := state.ReadDataFile(path)
	switch {
	case err == nil:
		raw, perr := ssh.ParseRawPrivateKey(data)
		if perr != nil {
			return nil, envErrf("%s: does not parse as a private key (%v) — remove it and enrol again", path, perr)
		}
		signer, serr := ssh.NewSignerFromKey(raw)
		if serr != nil {
			return nil, envErrf("%s: is not a supported key type (%v)", path, serr)
		}
		return signer, nil
	case os.IsNotExist(err):
		return generateSigner(path)
	default:
		return nil, classifyPathErr(err, path)
	}
}

func generateSigner(path string) (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "iamtunnel machine key")
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, classifyPathErr(err, dir)
	}
	// The write goes through datafile.WriteFileAtomic: a random O_EXCL
	// temporary — never the flat path+".tmp", for the same reason
	// atomicWriteBytes has one (IAMT-332 round 2) — and a refusal
	// instead of a write-through when an entry already holds the name.
	// The gateway's host key is minted by root-run "gateway pair" and
	// "gateway install" (RUNBOOK §5.11, §1.3); the service account must go
	// on reading it after those runs (IAMT-332), so the ownership
	// adoption is WithAdoptOwnerFn: before the rename, on the open
	// descriptor, and a refused adoption leaves the old file in place.
	// For the machine's own key this is a no-op: the file lives in the
	// user's own directory, already owned by the running account.
	if err := classifyDatafileErr(datafile.WriteFileAtomic(path, pem.EncodeToMemory(block),
		datafile.WithAdoptOwnerFn(adoptOwnership))); err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// generateMachineSigner is generateSigner's variant for the machine's
// own private key (IAMT-213): before the rename, the tmp file's
// Windows DACL is narrowed to the protected {SYSTEM, Administrators}
// pair, so the key is never visible under its real name with the
// inherited directory ACL (no-op on non-Windows). The write goes
// through datafile.WriteFileAtomic like every other writer in this
// file: the flat path+".tmp" this function used before round 8 was
// predictable, and a planted symlink there would have the
// key-generation write the machine's brand-new private key through it,
// destroying the target — and the lockdown runs as the pre-rename
// step, by the temporary's random name, exactly because the attacker
// never learns that name before the file exists.
func generateMachineSigner(path string) (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "iamtunnel machine key")
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, classifyMachinePathErr(err, dir)
	}
	// replaceACL=false: the tmp file was just written, so its DACL
	// carries only inherited entries (no explicit ACEs); the
	// IAMT-315 check finds nothing and proceeds.
	if err := classifyMachineDatafileErr(datafile.WriteFileAtomic(path, pem.EncodeToMemory(block),
		datafile.WithPreRename(func(tmp *os.File) error {
			return winkeys.LockDownFileACL(tmp.Name(), false, nil)
		}))); err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// loadOrGenerateMachineSigner is loadOrGenerateSigner for the machine's
// own key file: the read side is identical (same messages, so a corrupt
// machine.key reads the same in "enrol" as everywhere else), only the
// generation side goes through generateMachineSigner's locked write.
func loadOrGenerateMachineSigner(path string) (ssh.Signer, error) {
	data, err := state.ReadDataFile(path)
	switch {
	case err == nil:
		raw, perr := ssh.ParseRawPrivateKey(data)
		if perr != nil {
			return nil, envErrf("%s: does not parse as a private key (%v) — remove it and enrol again", path, perr)
		}
		signer, serr := ssh.NewSignerFromKey(raw)
		if serr != nil {
			return nil, envErrf("%s: is not a supported key type (%v)", path, serr)
		}
		return signer, nil
	case os.IsNotExist(err):
		return generateMachineSigner(path)
	default:
		return nil, classifyMachinePathErr(err, path)
	}
}
