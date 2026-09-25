//go:build darwin

// macOS implementation of the sshd pre-flight that runs before the
// machine's tunnel is dialled (SPEC §3.2.1; IAMT-263 extends the
// Linux half of IAMT-248 to the second Unix platform).
//
// macOS ships upstream OpenSSH, so the configuration half is the
// same question the Linux half asks: `sshd -T -C user=<osUser>`
// (sshd_config(5): "-T Extended test mode... output the effective
// configuration to stdout and then exit"), parsed by the shared
// parseSSHDConfig in sshd_config_unix.go. Asking the daemon instead of
// reading /etc/ssh/sshd_config ourselves is what keeps the check
// right on a Mac where Apple's file (or a drop-in it includes) has
// moved AuthorizedKeysFile — the resolved answer is what we see.
//
// Two things genuinely differ from Linux, and they are the reason
// this file exists rather than a shared "unix" one:
//
//   - There is no systemd unit to ask. The daemon is the launchd
//     job com.openssh.sshd — what System Settings → General →
//     Sharing → Remote Login switches on (or `sudo systemsetup
//     -setremotelogin on`). The probe below asks launchctl
//     (`launchctl print system/com.openssh.sshd`, launchctl(1)),
//     and a job that is not loaded is the refusal the operator
//     needs to see, because it is the one failure whose fix is a
//     checkbox in System Settings rather than a command.
//   - The refusal texts must name macOS's own levers ("System
//     Settings → General → Sharing → Remote Login", "launchctl
//     kickstart") instead of Linux's (`/etc/ssh/sshd_config` +
//     reload sshd / systemctl).
//
// A launchctl probe that cannot answer at all (launchctl missing,
// an unexpected failure) deliberately does NOT become a refusal:
// it degrades to ErrServiceCheckNotApplicable, the same sentinel
// the Windows half uses, and the TCP dial that follows is the real
// gate — our own blind spot must not refuse a machine whose sshd
// is up. A job that IS reported missing is a refusal: that is the
// macOS form of Linux's "sshd is not active: tried ssh.service,
// sshd.service, ssh.socket" (SPEC §3.2.1 makes an inactive daemon
// a refusal on the platform that ships the pre-flight).

package server

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// darwinRemoteLoginJob is the launchd job macOS runs sshd under when
// Remote Login is on. The label comes from Apple's own
// /System/Library/LaunchDaemons/ssh.plist; `launchctl print
// system/<label>` is the launchctl(1) way to ask whether that job is
// loaded in the system domain (the pre-Big-Sur `launchctl list`
// output format was never a stable interface, print is).
const darwinRemoteLoginJob = "com.openssh.sshd"

// serverDarwinLaunchctlPath is the absolute, documented macOS system
// location of launchctl(1) (IAMT-319: the same PATH-injection class
// IAMT-318 fixed inside the gateway install path, here on the
// server-start path — requireServerElevation already gates this on
// root, so a bare exec.Command("launchctl", ...) resolved through PATH
// would let anyone who can influence that root process's PATH plant
// their own helper and get arbitrary code execution as root). A missing
// binary here fails closed through launchctlFn's own error handling
// (a *PathError from exec, since this path contains a separator and so
// is never looked up through PATH at all) rather than falling back to
// anything else.
const serverDarwinLaunchctlPath = "/bin/launchctl"

// runServerLaunchctl is the only place launchctlFn invokes launchctl —
// pulled out on its own so IAMT-319's PATH pinning can be tested
// directly, without tripping launchctlFn's own testing.Testing() guard.
func runServerLaunchctl(args []string) (stdout, stderr string, err error) {
	cmd := exec.Command(serverDarwinLaunchctlPath, args...)
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err = cmd.Run()
	return so.String(), se.String(), err
}

// launchctlFn asks launchd whether the given system job is loaded.
//
// Three outcomes, and the caller treats them differently:
//
//	(true,  nil) — the job is loaded (Remote Login is on);
//	(false, nil) — launchd answered "could not find service": the job
//	               is not loaded, and that is the operator's checkbox;
//	(false, err) — launchctl itself failed or said something we do not
//	               recognise. That is our blind spot, not a verdict.
//
// Production runs the real launchctl; tests install a fake (there is
// no exported setter — production reaches this only through
// defaultCheckSSHDService). The test-binary guard lives inside the
// seam default, the same discipline as systemctlFn (run_linux.go).
var launchctlFn = func(job string) (bool, error) {
	if testing.Testing() {
		panic("server: launchctlFn invoked in test binary; tests must install a fake launchctlFn or inject checkService via CheckSSHD(target, checkService)")
	}
	args := []string{"print", "system/" + job}
	stdout, stderr, err := runServerLaunchctl(args)
	if err != nil {
		if darwinLaunchctlSaysNoSuchJob(stdout + stderr) {
			return false, nil
		}
		return false, fmt.Errorf("launchctl %s: %w (stderr: %s)", strings.Join(args, " "), err, strings.TrimSpace(stderr))
	}
	return true, nil
}

// darwinLaunchctlSaysNoSuchJob tells "this job is not loaded" — the
// normal answer for a Mac with Remote Login switched off — apart from
// a launchctl failure we should not interpret. The strings are the
// ones launchctl(1) prints for a missing service; the cmd/iamtunnel
// launchd half matches the same phrases for its own probes
// (gateway_launchd.go's launchctlSaysNotLoaded), deliberately kept as
// two small local helpers rather than one cross-package one: this
// package must not import package main.
func darwinLaunchctlSaysNoSuchJob(output string) bool {
	s := strings.ToLower(output)
	return strings.Contains(s, "could not find service") ||
		strings.Contains(s, "no such process") ||
		strings.Contains(s, "service not found")
}

// sshdStartHint is the "how do I switch the daemon on" sentence
// CheckSSHD puts in its dial-failure text when 127.0.0.1:22 does not
// answer (run.go). It is the moment the operator most needs the macOS
// lever by name: on a Mac the reason sshd is not listening is almost
// always that Remote Login is off, and that is a checkbox, not a
// systemd command.
const sshdStartHint = "turn on Remote Login in System Settings → General → Sharing (or run \"sudo systemsetup -setremotelogin on\") and retry"

// defaultCheckSSHDService is the macOS half of the service probe: ask
// launchd for the Remote Login job. See the file header for why an
// unanswerable probe degrades to ErrServiceCheckNotApplicable while a
// missing job is a refusal.
//
// The refusal starts with a lower-case word on purpose (IAMT-263):
// "Remote Login is off: …" was flagged by staticcheck's ST1005, which
// reports an error string whose first word is capitalized and carries
// no other capital letter or digit — that shape is what makes a word
// look like an initialism or a multi-word function name, which is why
// "sshd -T pre-flight: …" below is skipped for starting lower-case and
// "QueryServiceStatusEx: …" (run_windows.go) for its interior capitals.
// "Remote" is neither, and lower-casing it is not an option: the macOS
// feature the operator has to switch on really is called Remote Login,
// and naming it is the whole value of the sentence. So the sentence is
// rephrased to let a lower-case word carry it, and the proper noun
// stays where it belongs.
func defaultCheckSSHDService() error {
	loaded, err := launchctlFn(darwinRemoteLoginJob)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrServiceCheckNotApplicable, err)
	}
	if !loaded {
		return errors.New("the Remote Login daemon is off: launchd has no " + darwinRemoteLoginJob +
			" job — turn it on in System Settings → General → Sharing → Remote Login (or run \"sudo systemsetup -setremotelogin on\") and start again")
	}
	return nil
}

// defaultCheckSSHDConfig verifies sshd will actually accept pubkey
// auth for the gateway-bound OS user — the macOS wording of the same
// two SPEC §3.2.1 conditions the Linux half checks. The probe itself
// (sshdTOutputFn) and the parser are shared (sshd_config_unix.go).
func defaultCheckSSHDConfig(osUser string) error {
	if osUser == "" {
		return errors.New("sshd -T pre-flight: OS user is empty — was this machine enrolled?")
	}
	if strings.Contains(osUser, `\`) {
		return fmt.Errorf("sshd -T pre-flight: OS user %q contains a backslash — macOS uses a bare username with no DOMAIN\\ prefix", osUser)
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
		return fmt.Errorf("sshd -T pre-flight: pubkeyauthentication is %q — must be \"yes\" (edit /etc/ssh/sshd_config, then restart Remote Login: \"sudo launchctl kickstart -k system/%s\")",
			strings.Join(cfg.PubkeyAuthenticationRaw, " "), darwinRemoteLoginJob)
	}
	if !cfg.AuthorizedKeysFileContainsDotSSH {
		return fmt.Errorf("sshd -T pre-flight: authorizedkeysfile %q does not contain \".ssh/authorized_keys\" — pass --key-file to override, or edit /etc/ssh/sshd_config and restart Remote Login (\"sudo launchctl kickstart -k system/%s\")",
			strings.Join(cfg.AuthorizedKeysFileRaw, " "), darwinRemoteLoginJob)
	}
	return nil
}

// checkSSHDConfigPlatform is the macOS half of the dispatcher —
// identical in shape to the Linux one: forward to the production
// default or to a test-supplied fn. The cross-platform CheckSSHDConfig
// (run.go) routes here.
func checkSSHDConfigPlatform(osUser string, fn func(string) error) error {
	if fn == nil {
		return defaultCheckSSHDConfig(osUser)
	}
	return fn(osUser)
}
