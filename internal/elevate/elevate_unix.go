//go:build linux || darwin

// Linux/Darwin elevation layer (SPEC §3.2.1).
//
// Linux is in 1.1 (the IAMT-246 + IAMT-248 epic). The server
// role on Linux runs as root so it can write into the user's
// ~/.ssh/authorized_keys; the door layer's strict-mode
// preflight then narrows mode/owner to the target user before
// the rename. The elevation check at start time is therefore
// the whole "is this process privileged" question for the rest
// of the run — once `server start` has established it has
// euid==0, every subsequent operation inherits that fact.
//
// Darwin is the second-class citizen of this epic: the
// file-system primitives are the same so
// the package compiles and unit-tests there, but production
// install / run / status on Darwin goes through a separate
// code path that is out of scope for IAMT-248. Supported()
// reflects that: Linux is true, Darwin is false. A binary
// built on Darwin still has a working IsElevated() /
// VerifyOSUser() — operators can develop and unit-test
// against it — but a Darwin production launch is gated on
// "not supported" elsewhere, not here.

package elevate

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// IsElevated reports whether the current process is running as
// root. On Linux and Darwin the only check that matters is
// unix.Geteuid() == 0: there is no UAC, no consent prompt, and
// no other surface that could elevate a process without going
// through execve. The function returns (true, nil) on root,
// (false, nil) otherwise.
//
// Geteuid never returns an error; the (bool, error) signature
// matches the Windows IsElevated so callers do not branch on
// platform. geteuidFn is the seam tests use (default
// unix.Geteuid) — Docker/CI often run tests as root, so a test
// cannot assume a specific uid without the seam.
func IsElevated() (bool, error) {
	return geteuidFn() == 0, nil
}

// geteuidFn is the seam IsElevated reaches for. Production
// default is unix.Geteuid (an infallible syscall); tests
// install a fake in init() so the IsElevated_DoesNotPanic
// family covers both branches (root and non-root) without
// depending on the runner's uid.
var geteuidFn = func() int {
	return int(unix.Geteuid())
}

// Relaunch returns an error. Linux does not have a runas-style
// consent primitive iamtunnel can drive without spawning an
// xdg-su / pkexec / sudo subprocess — and SPEC §3.2.1 explicitly
// forbids "silent elevation". The error names the operator's
// fix ("sudo iamtunnel …") so the failure is actionable
// instead of mysterious. The exact command text is left to
// the caller, which knows the role and the argv.
func Relaunch(_ []string, _ bool) error {
	return errors.New("elevate: iamtunnel does not relaunch itself on linux — invoke it again as root (e.g. \"sudo iamtunnel server start\")")
}

// VerifyOSUser reports whether name resolves to a real local
// account. Linux/Darwin do not have Windows's "is this account
// in the local Administrators group" question; the analogue
// the SPEC asks for is "does this user exist on the machine"
// — iamtunnel writes into that user's home directory, so a
// non-existent user means the door's first write would fail
// with EACCES or ENOENT.
//
// The lookup goes through userLookupFn so a test binary
// never touches the real NSS / DirectoryService database; the
// default is os/user.Lookup which honours /etc/passwd,
// libnss-mysql, LDAP, sssd, etc.
func VerifyOSUser(name string) error {
	if name == "" {
		return errors.New("elevate: VerifyOSUser requires a non-empty name")
	}
	if strings.ContainsAny(name, "\\") {
		return fmt.Errorf("elevate: Linux/Darwin OS user %q must be a bare local name (no DOMAIN\\ prefix — that is the Windows form)", name)
	}
	u, err := userLookupFn(name)
	if err != nil {
		return fmt.Errorf("elevate: OS user %q does not exist on this machine — enrol again or run set-user to pick a different account: %w", name, err)
	}
	if u == nil {
		return fmt.Errorf("elevate: OS user %q does not exist on this machine — enrol again or run set-user to pick a different account", name)
	}
	if u.Uid == "" {
		return fmt.Errorf("elevate: OS user %q resolves without a uid — refusing", name)
	}
	return nil
}

// AlreadyElevatedFlag is the argv marker. Declared on every
// platform so callers can build argv lists portably; the
// value is irrelevant on Linux/Darwin because Relaunch does
// not run.
const AlreadyElevatedFlag = "--elevated-child"
