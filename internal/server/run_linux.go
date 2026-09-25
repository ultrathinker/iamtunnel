//go:build linux

// Linux implementation of the sshd pre-flight check that runs
// before the machine's tunnel is dialled (SPEC §3.2.1).
//
// On Windows the same path runs through windows SCM via
// QueryServiceStatusEx; the analogue on Linux is `systemctl
// is-active` against one of the unit names Ubuntu/Debian/etc.
// ship OpenSSH with — `ssh.service`, `sshd.service`, or
// `ssh.socket` (Ubuntu 22.10+ uses socket activation, so a
// service-status query alone would falsely report "not
// running"). The sshd -T pre-flight follows the active probe
// and verifies the runtime config the daemon would actually
// read when a connection arrives.
//
// Every code path that touches the host system goes through a
// seam so a test binary never actually runs systemctl or sshd:
// defaultCheckSSHDService calls systemctlFn (production: a
// real exec.Command), defaultCheckSSHDConfig calls sshdTOutputFn,
// and the parsing of the key=value stream sshd -T prints is a
// pure function (parseSSHDConfig) that tests can exercise
// without a running sshd at all. Since IAMT-263 the sshd -T
// seam and that parser live in sshd_config_unix.go — macOS asks the
// daemon exactly the same question and answers it with its own
// launchd probe.

package server

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// systemctlFn runs `systemctl is-active <unit>` and returns
// (true, nil) if the response is "active", (false, nil)
// otherwise. Production: a real exec.Command against the
// supplied unit; tests install a fake. There is no exported
// setter — production code only reaches this through
// defaultCheckSSHDService, and tests reset it via init() in
// the same package.
//
// The test-binary guard lives inside the seam default — the
// same pattern as the winkeys seams (winkeys/seams_unix.go) —
// not on defaultCheckSSHDService: a guard on the wrapper would
// fire even when a test legitimately swapped the seam in, while
// a guard here fires only when the real exec.Command is about
// to run. Production never sees it because testing.Testing()
// is false outside the test binary.
var systemctlFn = func(unit string) (bool, error) {
	if testing.Testing() {
		panic("server: systemctlFn invoked in test binary; tests must install a fake systemctlFn or inject checkService via CheckSSHD(target, checkService)")
	}
	stdout, err := runServerSystemctl([]string{"is-active", unit})
	if err != nil {
		// systemctl exit codes are: 0 = active, 1/2/3 =
		// not-active / dead / failed; a missing unit
		// also returns non-zero. The pre-flight only
		// cares about "active", so any non-zero is a
		// single (false, nil).
		return false, nil
	}
	return strings.TrimSpace(stdout) == "active", nil
}

// serverSystemctlPath is the absolute, documented location of
// systemctl(1) on every systemd-based Linux distribution this pre-flight
// targets (IAMT-319: the same PATH-injection class IAMT-318 fixed
// inside the gateway install path, here on the server-start path —
// requireServerElevation already gates this on root, so a bare
// exec.Command("systemctl", ...) resolved through PATH would let anyone
// who can influence that root process's PATH plant their own helper and
// get arbitrary code execution as root). A missing binary here fails
// closed through systemctlFn's own error handling (a *PathError from
// exec, since this path contains a separator and so is never looked up
// through PATH at all) rather than falling back to anything else.
const serverSystemctlPath = "/usr/bin/systemctl"

// runServerSystemctl is the only place systemctlFn invokes systemctl —
// pulled out on its own so IAMT-319's PATH pinning can be tested
// directly, without tripping systemctlFn's own testing.Testing() guard.
func runServerSystemctl(args []string) (string, error) {
	cmd := exec.Command(serverSystemctlPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return stdout.String(), nil
}

// linuxSSHUnits is the canonical list of unit names Linux
// distributions ship OpenSSH with. The pre-flight accepts the
// machine if ANY of them is active — Ubuntu 22.10+ uses socket
// activation, Debian/RHEL still use a regular service, etc.
var linuxSSHUnits = []string{"ssh.service", "sshd.service", "ssh.socket"}

// sshdStartHint is the "how do I switch the daemon on" sentence
// CheckSSHD puts in its dial-failure text when 127.0.0.1:22 does not
// answer (run.go). Linux distributions start sshd through systemd —
// `sudo systemctl start ssh` (Debian/Ubuntu) or `sshd` (RHEL) — but
// the sentence stays the distribution-neutral one this message has
// carried since before the platform split, because a wrong unit name
// would send the operator to a command that does not exist on their
// host.
const sshdStartHint = "start OpenSSH Server and retry"

// defaultCheckSSHDService probes each canonical sshd unit
// through systemctlFn in order and returns nil as soon as any
// of them is active. There is no guard on the wrapper itself —
// the function trusts its seam, exactly like defaultCheckSSHDConfig
// below trusts sshdTOutputFn; the refusals live in the seam: a
// test binary without an installed fake panics inside the
// default systemctlFn before any host interaction, and a nil
// seam panics on the call itself.
//
// The probe is deliberately sequential (no goroutine fan-out):
// every seam call runs in the caller's goroutine, so a refusal
// surfaces as an ordinary panic that recover() observes where
// the caller is, instead of aborting the whole process from
// inside a spawned goroutine. systemctl is-active is a cheap
// call and the seam is the only thing that can slow it down, so
// the fan-out bought nothing the strict dial-after could rely
// on.
//
// The TestCheckSSHD_* family never reaches this function — it
// passes its own checkService() closure to CheckSSHD;
// run_linux_test.go's TestDefaultCheckSSHDService_* call it
// directly with the seam swapped or nilled.
func defaultCheckSSHDService() error {
	for _, unit := range linuxSSHUnits {
		ok, err := systemctlFn(unit)
		if ok {
			return nil
		}
		if err != nil {
			return fmt.Errorf("sshd service check (%s): %w", unit, err)
		}
	}
	return errors.New("sshd is not active: tried " + strings.Join(linuxSSHUnits, ", "))
}

// defaultCheckSSHDConfig verifies sshd will actually accept
// pubkey auth for the gateway-bound OS user. SPEC §3.2.1:
// "sshd is active ... and sshd -T -C user=<osUser> confirms
// pubkeyauthentication yes and that authorizedkeysfile contains
// .ssh/authorized_keys". The check runs sshd -T, parses the
// output (the daemon emits one "key value\n" per config
// directive on stdout) and refuses if either condition fails.
//
// osUser is the gateway-bound account from enrolment.json.
// Empty osUser is treated as a refusal with an actionable
// "not enrolled" hint rather than letting sshd -T default to
// the running user (which would silently return config that
// may not match the gateway-bound user at all).
func defaultCheckSSHDConfig(osUser string) error {
	if osUser == "" {
		return errors.New("sshd -T pre-flight: OS user is empty — was this machine enrolled?")
	}
	if strings.Contains(osUser, `\`) {
		return fmt.Errorf("sshd -T pre-flight: OS user %q contains a backslash — Linux uses a bare username with no DOMAIN\\ prefix", osUser)
	}
	out, err := sshdTOutputFn(osUser)
	if err != nil {
		return fmt.Errorf("sshd -T pre-flight: %w", err)
	}
	cfg, err := parseSSHDConfig(out)
	if err != nil {
		return fmt.Errorf("sshd -T pre-flight: parse: %w", err)
	}
	if !cfg.PubkeyAuthentication {
		return fmt.Errorf("sshd -T pre-flight: pubkeyauthentication is %q — must be \"yes\" (edit /etc/ssh/sshd_config and reload sshd)", strings.Join(cfg.PubkeyAuthenticationRaw, " "))
	}
	if !cfg.AuthorizedKeysFileContainsDotSSH {
		return fmt.Errorf("sshd -T pre-flight: authorizedkeysfile %q does not contain \".ssh/authorized_keys\" — pass --key-file to override, or edit /etc/ssh/sshd_config", strings.Join(cfg.AuthorizedKeysFileRaw, " "))
	}
	return nil
}

// checkSSHDConfigPlatform is the Linux half of the dispatcher.
// It forwards to the production defaultCheckSSHDConfig or to
// a test-supplied fn — the cross-platform CheckSSHDConfig
// (defined in run.go) routes here.
func checkSSHDConfigPlatform(osUser string, fn func(string) error) error {
	if fn == nil {
		return defaultCheckSSHDConfig(osUser)
	}
	return fn(osUser)
}
