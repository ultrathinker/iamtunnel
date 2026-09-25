//go:build darwin

package main

// gateway_launchd_darwin.go — the production implementation of the
// macOS seam (SPEC §3.5.1): dscl for the service user, launchctl for
// the daemon, direct plist writes with 0644 root:wheel. Every closure
// panics in a test binary (guardProductionLaunchd) — tests must plug
// in the recording fake, as the IAMT-177 seam rule requires.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// darwinTestPath is the absolute, documented macOS system location of
// the BSD "test" utility (IAMT-308 round 9, review finding F-308-5):
// probeAccountCanReach must never resolve a privileged helper through
// PATH. Present on every supported macOS release; unlike a PATH lookup,
// a missing binary here fails closed through probeAccountCanReach's
// existing "could not even start" handling (errProbeCouldNotRun) rather
// than silently falling back to anything else.
const darwinTestPath = "/bin/test"

// darwinDsclPath and darwinLaunchctlPath are the absolute, documented
// macOS system locations of dscl(1) and launchctl(1) (IAMT-318, review
// finding on top of F-308-5's own dscl/launchctl gap): install runs as
// root from the moment it first looks up the _iamtunnel account, well
// before any reachability check — a bare exec.Command("dscl", ...) or
// exec.Command("launchctl", ...) resolved through PATH would let anyone
// who can influence that root process's PATH (in particular a run from
// an already-privileged shell) plant their own helper and get arbitrary
// code execution as root. Every call site below uses one of these two
// constants; a missing binary fails closed with the process's own error
// (a *PathError from exec, since these paths contain a separator and so
// are never looked up through PATH at all) rather than falling through
// to any branch that creates secrets.
const (
	darwinDsclPath      = "/usr/bin/dscl"
	darwinLaunchctlPath = "/bin/launchctl"
)

// darwinLsPath is the absolute, documented macOS system location of
// ls(1) (IAMT-308 round 11, review finding F-308-9): darwinPathHasACL
// shells out to it — the same PATH-pinning reasoning as darwinDsclPath
// and darwinLaunchctlPath above applies verbatim, since this runs from
// the same already-root install path.
const darwinLsPath = "/bin/ls"

// runDscl and runLaunchctl are the ONLY two places darwinLaunchd's
// closures ever invoke the two helpers — pulled out on their own,
// mirroring probeAccountCanReach (IAMT-308 round 9), so IAMT-318's
// pinning can be tested directly without a real _iamtunnel account or
// root and without tripping guardProductionLaunchd (which the seam
// closures themselves panic through in a test binary).
func runDscl(args []string) ([]byte, error) {
	return exec.Command(darwinDsclPath, args...).CombinedOutput()
}

func runLaunchctl(args []string) ([]byte, error) {
	return exec.Command(darwinLaunchctlPath, args...).CombinedOutput()
}

// darwinLaunchd is the production seam implementation; see
// gateway_launchd.go for the sequence that drives it.
var darwinLaunchd = darwinLaunchdSetup{
	currentUserIsRoot: func() (bool, error) {
		guardProductionLaunchd("currentUserIsRoot")
		return os.Geteuid() == 0, nil
	},
	makeLogDir: func(path string) error {
		guardProductionLaunchd("makeLogDir")
		return os.MkdirAll(path, 0o755)
	},
	lookupUser: func(name string) (int, bool, error) {
		guardProductionLaunchd("lookupUser")
		args := dsclUserReadArgs(name)
		out, err := runDscl(args)
		if err != nil {
			if dsclSaysNoUser(string(out)) {
				return 0, false, nil
			}
			return 0, false, fmt.Errorf("dscl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		uid, ok := parseDSCLUniqueID(string(out))
		if !ok {
			return 0, false, fmt.Errorf("dscl %s: no UniqueID in the output %q", strings.Join(args, " "), strings.TrimSpace(string(out)))
		}
		return uid, true, nil
	},
	systemUIDsTaken: func() (map[int]bool, error) {
		guardProductionLaunchd("systemUIDsTaken")
		out, err := runDscl(dsclListUsersArgs())
		if err != nil {
			return nil, fmt.Errorf("dscl %s: %v: %s", strings.Join(dsclListUsersArgs(), " "), err, strings.TrimSpace(string(out)))
		}
		return parseDSCLUIDList(string(out)), nil
	},
	createUser: func(spec darwinServiceUserSpec) error {
		guardProductionLaunchd("createUser")
		for _, args := range dsclCreateUserCalls(spec) {
			if out, err := runDscl(args); err != nil {
				return fmt.Errorf("dscl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
		}
		return nil
	},
	chownDir: func(path string, uid, gid int) error {
		guardProductionLaunchd("chownDir")
		// Code-rev (rall_codex round): os.Chown changes the
		// directory itself but never its children. The data
		// directory at this point already holds hostkey,
		// state.json, bootstrap-token, enrol-hmac.key and
		// state.lock — every one of them created as root by
		// runGatewayInstall BEFORE the OS branch reached
		// setupLaunchdDaemon. Without this walk the daemon
		// started under _iamtunnel sees root-owned hostkey and
		// dies with EACCES on the first read, then launchd
		// restart-loops the service. The walk covers every
		// pre-existing entry inside path; future files created
		// by the gateway land inside the directory the daemon
		// owns, so they keep the right owner naturally.
		//
		// IAMT-291: the traversal never turns a path back into
		// a syscall. The IAMT-278 shape — filepath.Walk's lstat,
		// a symlink type check on the result, then a path-based
		// os.Chown — closed the "link was already there at
		// lstat time" case but left a TOCTOU window between
		// that lstat and the chown: os.Chown re-dereferences
		// the path at call time, and after the first install
		// the tree belongs to _iamtunnel, so the service user
		// can swap a regular file for a symlink inside that
		// window and hand the chown to an arbitrary target
		// outside the tree. This traversal works purely on
		// descriptors instead: entries are classified by
		// fstatat(AT_SYMLINK_NOFOLLOW) BEFORE anything is
		// opened, only regular files and directories are opened
		// at all (O_NOFOLLOW; regular files O_NONBLOCK — the
		// round-one shape opened every entry with a blocking
		// O_RDONLY just to learn its type and hung the install
		// on a FIFO), the opened fd is re-checked against the
		// classified dev/ino, and fchown names the fd — there
		// is no path left to re-resolve, hence no window to
		// race. The root is opened O_NOFOLLOW too: a symlinked
		// data dir is refused rather than followed, the same
		// principle as THREATS §3.12.1.
		return chownTreeNoFollow(path, uid, gid)
	},
	writePlist: func(path string, content []byte, mode os.FileMode, uid, gid int) error {
		guardProductionLaunchd("writePlist")
		if err := os.WriteFile(path, content, mode); err != nil {
			return classifyPathErr(err, path)
		}
		return os.Chown(path, uid, gid)
	},
	plistExists: func(path string) (bool, error) {
		guardProductionLaunchd("plistExists")
		_, err := os.Stat(path)
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, classifyPathErr(err, path)
	},
	removePlist: func(path string) error {
		guardProductionLaunchd("removePlist")
		if err := os.Remove(path); err != nil {
			return classifyPathErr(err, path)
		}
		return nil
	},
	// Read-only: it looks at owners and permission bits and touches neither
	// launchd nor the file system, so it carries no production guard.
	exeWriters: serviceExeWriters,
	serviceLoaded: func(label string) (bool, error) {
		guardProductionLaunchd("serviceLoaded")
		return launchctlIsLoaded(label)
	},
	bootout: func(label string) (bool, error) {
		guardProductionLaunchd("bootout")
		args := launchctlBootoutArgs(label)
		out, err := runLaunchctl(args)
		if err != nil {
			// The daemon may have exited between the loaded check and the
			// bootout: launchd answers "No such process", which is the
			// already-stopped outcome, not a failure.
			if launchctlSaysNotLoaded(string(out)) {
				return false, nil
			}
			return false, fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		// IAMT-308 round 4: bootout returns as soon as launchd ACCEPTS
		// the teardown request, not once its own job table has actually
		// forgotten the label — a live Mac hit exactly that race:
		// install's very next call, bootstrap, raced the still-settling
		// teardown and answered "Bootstrap failed: 5: Input/output
		// error" (confirmed by hand: bootstrapping a label that is
		// still genuinely loaded gives the identical error). Wait for
		// launchctl itself to agree the label is gone before this call
		// returns, so the caller's bootstrap never races the teardown.
		if werr := waitForGone(func() (bool, error) { return launchctlIsLoaded(label) }); werr != nil {
			return true, fmt.Errorf("bootout accepted for %s but launchctl still reports it loaded: %w", label, werr)
		}
		return true, nil
	},
	bootstrap: func(plistPath string) error {
		guardProductionLaunchd("bootstrap")
		args := launchctlBootstrapArgs(plistPath)
		if out, err := runLaunchctl(args); err != nil {
			return fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	},
	// serviceRunning polls launchctl print itself (waitForLiveness, up to
	// installLivenessAttempts times with installLivenessInterval between
	// them) instead of leaving the retry to the caller: launchdBootstrapTail
	// calls this seam field exactly once, so the polling stays invisible
	// to anything that counts or orders seam calls (IAMT-258 round 2).
	serviceRunning: func(label string) (bool, error) {
		guardProductionLaunchd("serviceRunning")
		return waitForLiveness(func() (bool, error) {
			args := launchctlPrintArgs(label)
			out, err := runLaunchctl(args)
			if err != nil {
				if launchctlSaysNotLoaded(string(out)) {
					return false, nil
				}
				return false, fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
			return launchctlPrintSaysRunning(string(out)), nil
		})
	},
	parentTraversable: func(dataDir string, uid, gid int) error {
		guardProductionLaunchd("parentTraversable")
		return parentTraversableByAccount(dataDir, uid, gid)
	},
	ancestorsAreSafe: func(dataDir string) error {
		guardProductionLaunchd("ancestorsAreSafe")
		return darwinCustomDataDirAncestorsAreSafe(dataDir)
	},
	leafIsSafe: func(dataDir string, serviceUID int) error {
		guardProductionLaunchd("leafIsSafe")
		return darwinEnsureCustomDataDirLeafIsSafe(dataDir, serviceUID)
	},
}

// darwinCustomDataDirAncestorsAreSafe is IAMT-308 round 10's fix for
// review finding F-308-8: round 9's re-check (verifyGatewayReachable,
// immediately before the first secret write) only ever SHRANK the
// window between checking reachability and using the path again — a
// successful "test -x" and the next path-based syscall are still two
// different actions, so whoever controls a custom --data-dir's
// grandparent could rename a component, or replace it with a symlink,
// in between, and root's writes of the host key, the bootstrap token
// and state.json would then resolve into wherever that party pointed.
//
// Rather than pinning the whole write path through open file
// descriptors (a much larger change touching every shared secret-write
// helper in this codebase, for a single narrow call site), this removes
// the THREAT the window exists for: it walks from dataDir's parent all
// the way up to the filesystem root and refuses unless EVERY ancestor is
// exclusively controlled by root — not owned by root, writable by group
// or other, or itself a symbolic link. There is no early exit the moment
// one ancestor LOOKS safe: a party who controls a GRANDparent can
// rename or delete an otherwise perfectly root-owned PARENT and put
// something else in its place with the same name, so a directory's own
// attributes say nothing about whether it is safe from what is above
// it — every single ancestor has to be checked. A party who owns none of
// them cannot swap, rename or symlink one out from under install, no
// matter how long any window between a check and a later syscall is.
//
// Never applied to the standard macOS path — prepareGatewayParentDir
// already creates and owns that whole tree itself (rounds 5-6) — only to
// a custom --data-dir, which is what F-308-8 is about.
func darwinCustomDataDirAncestorsAreSafe(dataDir string) error {
	return darwinAncestorsAreSafeUpTo(filepath.Dir(dataDir), string(filepath.Separator))
}

// darwinAncestorsAreSafeUpTo is darwinCustomDataDirAncestorsAreSafe's
// walk, parameterized by where to stop climbing. Production always
// passes the filesystem root ("/"), identical to walking unconditionally
// — the parameter exists so a test can prove the ACCEPT case
// self-contained, bounded to a tree it built and owns itself, without
// depending on the real system directories above a test's own
// t.TempDir() (this codebase has no way to know, and must not assume,
// whether those happen to be root-owned on any given machine).
//
// Every ancestor must be controlled EXCLUSIVELY by root — extraTrustedUID
// of -1 (never a real uid) in the shared darwinPathIsExclusivelyControlled
// check below means no other owner is ever accepted here, unlike the leaf
// itself (darwinEnsureCustomDataDirLeafIsSafe), which a previous install's
// own run may already have handed to the service account.
func darwinAncestorsAreSafeUpTo(dir, stopAt string) error {
	for {
		if err := darwinPathIsExclusivelyControlled(dir, -1); err != nil {
			return err
		}
		if dir == stopAt {
			return nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil // reached the filesystem root — every ancestor checked out
		}
		dir = parent
	}
}

// darwinPathIsExclusivelyControlled is the single per-path check shared
// by the ancestor walk above and the leaf check below (IAMT-308 round
// 11, review finding F-308-9): a path is safe only if it is not a
// symlink, owned by root or by extraTrustedUID (pass -1 to accept only
// root), not writable by group or other, and carries no macOS ACL at
// all. An ACL can grant an identity rights — delete_child, add_file —
// that POSIX mode bits alone say nothing about (the review's own example:
// /opt stays root:wheel 0755 but an ACL hands a non-root identity the
// right to replace what root just checked), so mode bits passing is not
// enough on its own; darwinPathHasACL is deliberately as strict as
// "does this path carry ANY acl entry at all", not an attempt to parse
// and reason about what a given entry grants to whom, since a wrong
// parse of an ACE's rights would be worse than refusing a legitimate but
// unrelated ACL outright.
func darwinPathIsExclusivelyControlled(path string, extraTrustedUID int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link — a custom --data-dir and its ancestors must not be symlinks (a party who controls where one points could redirect install's writes)", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s", path)
	}
	if st.Uid != 0 && (extraTrustedUID < 0 || st.Uid != uint32(extraTrustedUID)) {
		return fmt.Errorf("%s is not exclusively controlled by root (owner uid %d) — a custom --data-dir and its ancestors must all be root-owned, or another party could swap a component out from under install between a reachability check and the writes that follow it; place --data-dir under a tree only root controls, or prepare %s by hand (\"sudo chown root %s\") and repeat the install", path, st.Uid, path, path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or other (mode %#o) — a custom --data-dir and its ancestors must not be, or another party could swap a component out from under install between a reachability check and the writes that follow it; prepare %s by hand (\"sudo chmod go-w %s\") and repeat the install", path, fi.Mode().Perm(), path, path)
	}
	hasACL, aerr := darwinPathHasACL(path)
	if aerr != nil {
		return aerr
	}
	if hasACL {
		return fmt.Errorf("%s carries a macOS access control list (ACL) — an ACL can grant a non-root identity rights (such as delete_child or add_file) that its owner and mode bits alone never show, so a custom --data-dir and its ancestors must carry none at all; remove it by hand (\"sudo chmod -N %s\") and repeat the install", path, path)
	}
	return nil
}

// darwinPathHasACL reports whether path carries any macOS ACL entry at
// all. golang.org/x/sys/unix exposes no acl_get_file-equivalent for
// darwin, and this codebase takes on no cgo dependency for one check
// (cgo would also make this unable to even cross-vet from the non-Mac
// dev machine that wrote it) — ls(1) itself already has to ask the same
// question to decide whether to print the trailing "+" IAMT-308's own
// operators would see by hand ("ls -lde"), so this reads that instead of
// reimplementing the ACL query.
func darwinPathHasACL(path string) (bool, error) {
	out, err := exec.Command(darwinLsPath, "-lde", path).Output()
	if err != nil {
		return false, fmt.Errorf("check %s for a macOS ACL: %w", path, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return false, fmt.Errorf("check %s for a macOS ACL: %s produced no output", path, darwinLsPath)
	}
	// ls(1) marks the mode field with a trailing "+" when the path
	// carries an ACL (a trailing "@" instead means only extended
	// attributes, which this check has no reason to care about).
	return strings.HasSuffix(fields[0], "+"), nil
}

// darwinEnsureCustomDataDirLeafIsSafe is IAMT-308 round 11's fix for
// review finding F-308-9: darwinAncestorsAreSafeUpTo's walk starts at
// dataDir's PARENT and climbs upward — it never once looks at dataDir
// itself, so a symlink (or an ACL grant) planted at the leaf, before
// this install ever ran, was invisible to it. serviceUID is the account
// preflightGatewayReachability already resolved: a REPEAT install's own
// dataDir was chowned to that account by a previous run's
// setupLaunchdDaemon (chownDir), so — unlike every ancestor above it,
// which must be root and only root — the leaf itself accepts root OR
// that one specific, already-known account.
//
// When dataDir does not exist yet, this creates it right here, as root,
// mode 0700 — closing the gap between this check and the later
// os.MkdirAll in runGatewayInstall, which would otherwise be the first
// thing to ever touch the path again after it was last examined.
//
// Out of scope, deliberately, not silently assumed to be covered: a
// party who can remount a different filesystem over an already-checked
// path between this call and the writes that follow it could still
// swap what dataDir resolves to. Closing that needs directory-descriptor
// pinning (openat with O_NOFOLLOW, all the way down, for every open this
// install performs) instead of any path-based check, a much larger
// change than this one; mounting anything at all already needs
// privilege no party but the operator running this install is assumed
// to have.
func darwinEnsureCustomDataDirLeafIsSafe(dataDir string, serviceUID int) error {
	if _, err := os.Lstat(dataDir); err != nil {
		if os.IsNotExist(err) {
			return os.Mkdir(dataDir, 0o700)
		}
		return fmt.Errorf("stat %s: %w", dataDir, err)
	}
	return darwinPathIsExclusivelyControlled(dataDir, serviceUID)
}

// parentTraversableByAccount answers whether the real _iamtunnel account
// can reach dataDir's parent directory. Round 6 answered this itself, by
// comparing dataDir's immediate parent's permission bits — owner, a
// single gid, or "other" — against uid/gid from THIS (root) process.
// review finding F-308-3 named three gaps in that: it only ever looked at
// filepath.Dir(dataDir), so a non-traversable GRANDparent (or any higher
// ancestor) was invisible; it knew only one gid, not every group the
// account actually belongs to; and it could not see POSIX ACLs at all —
// root's own unix.Stat call never consults them, because DAC/ACL
// enforcement only applies when something other than root is actually
// doing the access.
//
// Round 7 asks the kernel directly instead of modelling any of that by
// hand: it spawns a real "test -x" subprocess UNDER the account's exact
// credential (uid, primary gid, AND every supplementary group
// accountGroupIDs reports) and lets THAT process's own access(2) check
// of the parent succeed or fail. The kernel then walks every ancestor
// component, checking bits, ACLs and resolving any symlink exactly as
// it will later for the real LaunchDaemon — there is no separate
// filesystem model here that could disagree with reality.
//
// Round 8: failing to even determine the account's groups is a "could
// not check" outcome, not a "not reachable" one — errProbeCouldNotRun
// marks it so the caller (preflightGatewayReachability) can word its
// refusal accordingly instead of suggesting a chmod that would not fix
// an id(1) that could not run.
func parentTraversableByAccount(dataDir string, uid, gid int) error {
	parent := filepath.Dir(dataDir)
	if parent == dataDir || parent == string(filepath.Separator) {
		return nil
	}
	groups, err := accountGroupIDs(darwinServiceUser)
	if err != nil {
		return fmt.Errorf("%w: look up %s's group memberships: %v", errProbeCouldNotRun, darwinServiceUser, err)
	}
	return probeAccountCanReach(parent, uint32(uid), uint32(gid), groups)
}

// accountGroupIDs returns the complete group membership list the OS
// would hand the account — not just the single primary gid dscl
// recorded for it — the same list the kernel's own initgroups gives a
// real launchd job at startup.
//
// IAMT-308 round 9 (review finding F-308-5, CRITICAL): this used to shell
// out to "id -G <name>", resolved through PATH — install runs as root,
// so a planted "id" earlier in PATH would be arbitrary code execution as
// root, and sudo's secure_path is not a property of this program (it
// also does not cover a run from an already-privileged shell). Using
// os/user.LookupGroupId/user.Current's sibling, user.Lookup, instead
// removes the external helper — and the whole PATH attack surface it
// carried — entirely: it resolves the account through the system's own
// getpwnam_r/getgrouplist (cgo on Darwin, which this build already
// requires for gio), never spawning a subprocess at all.
func accountGroupIDs(name string) ([]uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("look up account %s: %w", name, err)
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("list %s's group memberships: %w", name, err)
	}
	groups := make([]uint32, 0, len(ids))
	for _, id := range ids {
		n, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("account %s: parse group id %q: %w", name, id, err)
		}
		groups = append(groups, uint32(n))
	}
	return groups, nil
}

// probeAccountCanReach spawns "test -x path" as a subprocess and reports
// whatever that subprocess's own access(2) check of path found (see
// parentTraversableByAccount for why -x, not stat). uid/gid/groups name
// the credential the subprocess should run under.
//
// PRIVILEGE (round 8, a real-Mac test run found this the hard way):
// applying a Credential to a child process at ALL is a privileged
// operation on Darwin — Go always issues setgroups() as part of it, and
// setgroups() itself needs root REGARDLESS of the target list, even one
// that changes nothing. A Credential is therefore only set here when
// uid/gid actually differ from this process's own identity: production
// always calls this with the real _iamtunnel uid/gid, which is never
// this (root, confirmed by the caller) process's own, so the switch
// always applies there. When uid/gid already match this process,
// skipping the Credential changes nothing observable — the subprocess
// would inherit that exact identity through a plain fork/exec anyway —
// and it is what lets the WALKING logic (every ancestor, symlinks
// included) be exercised honestly by a test running as a normal,
// non-root user, without ever touching the privileged path.
//
// FAILURE SHAPE: cmd.Run() returning an *exec.ExitError means the
// subprocess actually STARTED, ran its access(2) check, and got a real
// denial — that is a genuine "not reachable" and is exactly what this
// function's ordinary error return means. Any OTHER error — the
// subprocess could not even be started (EPERM applying a Credential
// without CAP_SETUID/CAP_SETGID, "test" missing from PATH, a sandbox) —
// means the check itself never ran; that is reported wrapped in
// errProbeCouldNotRun so the caller can tell "denied" and "could not
// tell" apart and word its refusal accordingly, instead of silently
// treating "could not check" as either "fine" (which is exactly the
// F-308-3 gap) or "denied" (which would break every ordinary install
// the moment the probe binary or privilege was ever unavailable).
func probeAccountCanReach(path string, uid, gid uint32, groups []uint32) error {
	// IAMT-308 round 9 (review finding F-308-5, CRITICAL): darwinTestPath
	// is an absolute path, never resolved through PATH — a bare "test"
	// would let a planted binary earlier in PATH forge a successful
	// reachability check (exit 0) while the real LaunchDaemon can never
	// reach the tree, and install would go on to create and print the
	// secrets anyway. exec.Command never consults PATH for a name that
	// already contains a separator, so this is the whole fix.
	cmd := exec.Command(darwinTestPath, "-x", path)
	if uid != uint32(os.Getuid()) || gid != uint32(os.Getgid()) {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups},
		}
	}
	err := cmd.Run()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Errorf("%s is not searchable by uid %d (an ancestor directory may not be traversable, or an ACL/symlink along the path may redirect somewhere that isn't): %v", path, uid, exitErr)
	}
	return fmt.Errorf("%w: %v", errProbeCouldNotRun, err)
}

// launchctlIsLoaded is a single "launchctl print" query, shared by
// serviceLoaded (a one-shot check) and bootout's post-teardown wait
// (IAMT-308 round 4): both need the same raw loaded/not-loaded read
// against the same label.
func launchctlIsLoaded(label string) (bool, error) {
	args := launchctlPrintArgs(label)
	out, err := runLaunchctl(args)
	if err == nil {
		return true, nil
	}
	if launchctlSaysNotLoaded(string(out)) {
		return false, nil
	}
	return false, fmt.Errorf("launchctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
}

// launchctlPrintSaysRunning reports whether launchctl print's own state
// line says the job is running right now (IAMT-308 family): a job can be
// loaded and even mid-bootstrap ("state = spawn scheduled, runs = 4,
// last exit code = 4" on a real crash-looping Mac) without ever being
// "state = running".
func launchctlPrintSaysRunning(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "state =")
		if !ok {
			continue
		}
		return strings.TrimSpace(rest) == "running"
	}
	return false
}

// chownTreeNoFollow hands the directory at root and every entry below
// it to uid:gid without ever dereferencing a symbolic link (IAMT-291).
// The root is classified by lstat before it is opened and opened
// O_NOFOLLOW; a symlinked data dir is refused by name instead of
// followed. The root directory itself is chowned inside chownDirByFD,
// before its entries are walked. All further work names descriptors:
// entries are classified by fstatat(AT_SYMLINK_NOFOLLOW) before
// anything is opened, only regular files and directories are ever
// opened (openat O_NOFOLLOW), the opened fd is re-checked against the
// classified dev/ino, and fchown itself takes the fd. A symlink or a
// FIFO that appears anywhere in the walk cannot be followed or blocked
// on: fstatat answers the type without an open, and a stale
// classification surfaces as an ELOOP/ENOTDIR refusal on openat —
// named as a symlink after a re-classification — or as a dev/ino
// mismatch, never as a chown on faith. Entries that are neither
// regular files nor directories are refused outright — the data
// directory holds plain files by design, and chowning a device or
// socket nobody created would be its own anomaly. The walk also
// bounds itself: at most maxChownDepth directory levels (every
// recursion level holds its parent directory open, so an unbounded
// walk turns a deeply nested leftover tree into an EMFILE install
// failure), and a regular file with more than one hard link is
// refused — a link planted inside the tree can pin an inode that
// lives outside it, and fchown by fd would re-own that outside file.

// chownFDFn is the fchown seam of the chown walk: production names
// unix.Fchown; the IAMT-291 tests swap in a recording fake (which
// resolves each fd's dev/ino at call time) so the walk's targets can
// be pinned without changing real ownership — the tests run as a
// plain non-root user.
var chownFDFn = unix.Fchown

// maxChownDepth is how deep the chown walk may descend. The product's
// own tree is a few levels deep — the data dir and its log sibling,
// with nothing below them created by iamtunnel — so 64 sits two orders
// of magnitude above anything the product makes, while holding the
// walk's fd budget far below the default soft limit (~256 on darwin):
// each recursion level keeps its parent directory open, and a tree of
// a few hundred nested one-letter directories — small enough for
// PATH_MAX, plausible as a leftover once the service user owns the
// tree — would otherwise end the install with EMFILE. The limit is
// checked before the next level is opened, so the walk stops with a
// clear named error instead of an fd shortage.
const maxChownDepth = 64

// symlinkRefusalErr is the wording of every symlink refusal in the
// chown walk: it names the offending path and says plainly that the
// chown refuses to go through it. The operator must read "symbolic
// link" in the install log, not a bare ELOOP — or darwin's ENOTDIR,
// which open(O_NOFOLLOW|O_DIRECTORY) returns for a symlink and which
// reads as "not a directory", naming nothing.
func symlinkRefusalErr(path string) error {
	return fmt.Errorf("%s is a symbolic link — refusing to chown through it: the data directory must not contain symlinks; remove it and repeat the install", path)
}

// isSymlinkOpenErr reports whether an open/openat refusal has the
// shape a symlink produces behind O_NOFOLLOW: ELOOP generally, and
// ENOTDIR on darwin when O_DIRECTORY is also set.
func isSymlinkOpenErr(err error) bool {
	return errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR)
}

// refuseEntryOpen turns a failed openat into the walk's error. When
// the failure is the shape a symlink produces behind O_NOFOLLOW and a
// re-classification confirms it (the entry swapped between fstatat
// and openat), the refusal names the symlink instead of leaking a
// bare ELOOP/ENOTDIR; otherwise the raw error is returned.
func refuseEntryOpen(dirfd int, dir, entry string, openErr error) error {
	if isSymlinkOpenErr(openErr) {
		var again unix.Stat_t
		if err := unix.Fstatat(dirfd, entry, &again, unix.AT_SYMLINK_NOFOLLOW); err == nil && again.Mode&unix.S_IFMT == unix.S_IFLNK {
			return symlinkRefusalErr(dir + "/" + entry)
		}
	}
	return fmt.Errorf("chown %s/%s: %w", dir, entry, openErr)
}

func chownTreeNoFollow(root string, uid, gid int) error {
	// Classify the root before opening: darwin answers
	// open(O_NOFOLLOW|O_DIRECTORY) on a symlink with ENOTDIR, and a
	// refusal that reads "not a directory" tells the operator
	// nothing. The open below keeps O_NOFOLLOW — this lstat only
	// names the problem, the open flag remains the race guard.
	var rst unix.Stat_t
	if err := unix.Lstat(root, &rst); err != nil {
		return fmt.Errorf("chown %s: stat: %w", root, err)
	}
	if rst.Mode&unix.S_IFMT == unix.S_IFLNK {
		return symlinkRefusalErr(root)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if isSymlinkOpenErr(err) {
			// The classification went stale: the root swapped
			// to a symlink after the lstat above. Re-check and
			// name it; anything else keeps the raw error.
			var again unix.Stat_t
			if lerr := unix.Lstat(root, &again); lerr == nil && again.Mode&unix.S_IFMT == unix.S_IFLNK {
				return symlinkRefusalErr(root)
			}
		}
		return fmt.Errorf("chown %s: %w", root, err)
	}
	// fd ownership passes to chownDirByFD here: it FIRST wraps this
	// very fd in an *os.File (sole owner, closed exactly once on every
	// path out — a failing fchown included, round five), then chowns
	// the directory through it (round two: the walk once chowned only
	// the entries and left a first-install data dir root:root 0700 — a
	// directory the _iamtunnel daemon cannot enter, which KeepAlive
	// turns into a crash loop). The root is level 1.
	return chownDirByFD(fd, root, uid, gid, 1)
}

// chownDirByFD chowns the open directory fd itself and recurses into
// its entries. fd is consumed: it is wrapped in an *os.File whose
// Close is the only close on every path out of the function — the wrap
// happens before the fchown, so even a failing fchown closes the fd
// (round five: the fchown used to run before the wrap existed, and its
// failure leaked the fd; the caller's defer only ever covered the
// caller's own). Names are
// sorted to keep the traversal order deterministic, the way
// filepath.Walk's lexical order did before this fd-based walk replaced
// it (IAMT-291). Entries are classified with fstatat before any open
// (round two: a blocking open of an unclassified entry waits forever
// on a FIFO); only regular files and directories are opened, and the
// opened fd must still name the classified dev/ino. depth counts
// directory levels including the tree root: a level deeper than
// maxChownDepth is refused before it is opened (every open level
// holds its parent directory, so depth bounds the fd budget). A
// regular file whose opened fd reports Nlink > 1 is refused — its
// inode may be hard-linked from outside the tree, and fchown would
// re-own that outside file.
func chownDirByFD(fd int, name string, uid, gid int, depth int) error {
	// The wrap comes FIRST: this *os.File's Close is the only close on
	// every path out of here, so it must exist before anything can
	// fail — the fchown just below included (round five: a failing
	// fchown used to return before the wrap existed and leaked this
	// very fd, and the caller's defer only covers the caller's own).
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	// The directory itself first (IAMT-291, round two): the first
	// install creates the data dir root:root 0700 and the LaunchDaemon
	// runs as _iamtunnel, which cannot even enter a root-owned 0700
	// directory, let alone read the files now owned by it.
	if err := chownFDFn(fd, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", name, err)
	}
	names, err := f.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("chown %s: reading the directory: %w", name, err)
	}
	sort.Strings(names)
	for _, entry := range names {
		// Classify without opening: fstatat with
		// AT_SYMLINK_NOFOLLOW answers the type — and never
		// blocks, which is the point (opening a FIFO for
		// reading waits for a writer; a refusal branch must not
		// sit behind the very open it refuses).
		var lst unix.Stat_t
		if err := unix.Fstatat(fd, entry, &lst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("chown %s/%s: stat: %w", name, entry, err)
		}
		switch lst.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			// O_NONBLOCK so even an entry swapped in after the
			// fstatat cannot park the install: a FIFO opened
			// non-blocking returns at once and is thrown out
			// by the type/identity re-check below instead.
			child, err := unix.Openat(fd, entry, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				// ELOOP/ENOTDIR with a confirming
				// re-classification names the symlink the
				// entry swapped into; anything else keeps
				// the raw error.
				return refuseEntryOpen(fd, name, entry, err)
			}
			var st unix.Stat_t
			if err := unix.Fstat(child, &st); err != nil {
				_ = unix.Close(child)
				return fmt.Errorf("chown %s/%s: fstat: %w", name, entry, err)
			}
			// The fd must still name the inode the fstatat
			// classified: an entry swapped between the two
			// calls (regular -> another file, or -> a FIFO
			// that the non-blocking open let through) is
			// refused here, not chowned on faith.
			if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Dev != lst.Dev || st.Ino != lst.Ino {
				_ = unix.Close(child)
				return fmt.Errorf("chown %s/%s: changed between stat and open (now mode %#o, dev %d, ino %d) — refusing", name, entry, uint32(st.Mode&unix.S_IFMT), st.Dev, st.Ino)
			}
			// A hard link inside the tree can pin an inode that
			// lives outside it, and fchown by fd would change
			// that outside file's owner. Nlink is read from the
			// opened, identity-checked fd — not from the earlier
			// fstatat: between the two calls the count could
			// change with the very link the check exists for.
			if st.Nlink > 1 {
				_ = unix.Close(child)
				return fmt.Errorf("chown %s/%s: has %d hard links — refusing to chown a file that may live outside the tree", name, entry, st.Nlink)
			}
			if err := chownFDFn(child, uid, gid); err != nil {
				_ = unix.Close(child)
				return fmt.Errorf("chown %s/%s: %w", name, entry, err)
			}
			_ = unix.Close(child)
		case unix.S_IFDIR:
			// Depth is checked BEFORE the next level is opened:
			// the refusal must be a named error, not an EMFILE
			// from the fd budget the open walk is already
			// holding.
			if depth+1 > maxChownDepth {
				return fmt.Errorf("chown %s/%s: deeper than %d directory levels — refusing to go deeper (every level of the walk holds its parent directory open and a deep-enough tree exhausts the process fd limit; the product's own tree is a few levels deep)", name, entry, maxChownDepth)
			}
			child, err := unix.Openat(fd, entry, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return refuseEntryOpen(fd, name, entry, err)
			}
			var st unix.Stat_t
			if err := unix.Fstat(child, &st); err != nil {
				_ = unix.Close(child)
				return fmt.Errorf("chown %s/%s: fstat: %w", name, entry, err)
			}
			if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Dev != lst.Dev || st.Ino != lst.Ino {
				_ = unix.Close(child)
				return fmt.Errorf("chown %s/%s: changed between stat and open (now mode %#o, dev %d, ino %d) — refusing", name, entry, uint32(st.Mode&unix.S_IFMT), st.Dev, st.Ino)
			}
			// The recursion chowns this directory through its
			// own fd (top of chownDirByFD) and consumes child
			// — do not close it twice.
			if err := chownDirByFD(child, name+"/"+entry, uid, gid, depth+1); err != nil {
				return err
			}
		case unix.S_IFLNK:
			return symlinkRefusalErr(name + "/" + entry)
		default:
			return fmt.Errorf("chown %s/%s: not a regular file or directory (fifo, socket or device, mode %#o) — the data directory must contain only plain files; remove it and repeat the install", name, entry, uint32(lst.Mode&unix.S_IFMT))
		}
	}
	return nil
}

// guardProductionLaunchd panics when a production macOS call is reached
// from a test binary: the iamt259 tests substitute a recording fake for
// darwinLaunchd, and any test that misses the substitution must fail
// loudly instead of touching DirectoryService or launchd.
func guardProductionLaunchd(op string) {
	if testing.Testing() {
		panic("production macOS launchd call " + op + " in the test binary — substitute the darwinLaunchd seam with a fake")
	}
}
