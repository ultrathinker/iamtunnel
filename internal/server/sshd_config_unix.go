//go:build linux || darwin

// The Unix half of the sshd pre-flight (SPEC §3.2.1, IAMT-263): the
// `sshd -T` seam and the pure parser of its output. The two platforms
// that run the pre-flight — Linux (run_linux.go) and macOS
// (run_darwin.go) — differ only in how they ask whether the daemon is
// up (systemctl vs launchctl) and in the wording of their refusals;
// the question they ask the daemon is the same one, so the seam and
// the parser live here rather than in one of the two platform files.
//
// The build tag is `linux || darwin`, not "all platforms": Windows
// does not run this pre-flight at all (run_windows.go: its sshd reads
// one well-known file) and neither do the unimplemented Unixes, so a
// neutral file would leave all three symbols unreferenced there —
// staticcheck U1000, which is exactly the signal this repository keeps
// clean. The filename says `_unix` for the same reason doors_unix.go
// does.
//
// `sshd -T` is upstream OpenSSH's extended configuration test
// (sshd_config(5): "-T Extended test mode. Check the validity of the
// configuration file, output the effective configuration to stdout and
// then exit."). Both platforms run the daemon they ship — Apple's
// macOS ships upstream OpenSSH — so the output shape this parser
// consumes ("directive value" per line) is the same on both. Asking
// the daemon, rather than reading a config file ourselves, is what
// makes the check correct on hosts that moved AuthorizedKeysFile or
// included a drop-in directory: whatever sshd resolved is what we see.

package server

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// serverSshdPath is the absolute, documented location of sshd(8) on
// both platforms this file builds for (IAMT-319: the same
// PATH-injection class IAMT-318 fixed inside the gateway install path,
// here on the server-start path — requireServerElevation already gates
// this on root, so a bare exec.Command("sshd", ...) resolved through
// PATH would let anyone who can influence that root process's PATH
// plant their own helper and get arbitrary code execution as root).
// Upstream OpenSSH — what both Linux distributions and macOS ship —
// installs sshd at this path on both; a missing binary here fails
// closed through sshdTOutputFn's own error handling (a *PathError from
// exec, since this path contains a separator and so is never looked up
// through PATH at all) rather than falling back to anything else.
const serverSshdPath = "/usr/sbin/sshd"

// runServerSshdT is the only place sshdTOutputFn invokes sshd — pulled
// out on its own so IAMT-319's PATH pinning can be tested directly,
// without tripping sshdTOutputFn's own testing.Testing() guard.
func runServerSshdT(args []string) (stdout, stderr string, err error) {
	cmd := exec.Command(serverSshdPath, args...)
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err = cmd.Run()
	return so.String(), se.String(), err
}

// sshdTOutputFn runs `sshd -T -C user=<osUser>,host=localhost,addr=127.0.0.1`
// and returns the captured stdout. Production: a real
// exec.Command; tests install a fake. The test-binary guard fires
// only when the real exec.Command is about to run, so a test that
// legitimately swapped the seam in is not affected — the same
// discipline as systemctlFn (run_linux.go) and the winkeys seams.
var sshdTOutputFn = func(osUser string) (string, error) {
	if testing.Testing() {
		panic("server: sshdTOutputFn invoked in test binary; tests must install a fake sshdTOutputFn or inject checkFn via CheckSSHDConfig")
	}
	match := fmt.Sprintf("user=%s,host=localhost,addr=127.0.0.1", osUser)
	stdout, stderr, err := runServerSshdT([]string{"-T", "-C", match})
	if err != nil {
		return "", fmt.Errorf("sshd -T -C %s: %w (stderr: %s)", match, err, strings.TrimSpace(stderr))
	}
	return stdout, nil
}

// sshdConfig is the parsed shape of `sshd -T` output we care
// about for the pre-flight. Every field keeps a Raw copy so the
// error message can echo back exactly what sshd said — the
// operator already knows sshd's config syntax, and a paraphrase
// would make the action ("edit sshd_config and reload")
// harder to take.
type sshdConfig struct {
	// PubkeyAuthentication is true if any value parses as
	// "yes" (case-insensitive). sshd accepts "yes", "no",
	// "yes|hostbased" etc.; we treat any value that is not
	// "yes" (case-insensitive) as a refusal.
	PubkeyAuthentication    bool
	PubkeyAuthenticationRaw []string
	// AuthorizedKeysFileContainsDotSSH is true if the
	// authorizedkeysfile value list contains a token that
	// ends with ".ssh/authorized_keys" — the default on
	// every distribution, but an operator may have set a
	// custom path and forgotten to align --key-file with it.
	AuthorizedKeysFileContainsDotSSH bool
	AuthorizedKeysFileRaw            []string
}

// parseSSHDConfig walks `sshd -T` stdout: one
// "directive value\n" per line, tokens space-separated. The
// daemon emits a single canonical value per directive, but it
// can be a quoted space-separated path; we keep the original
// tokens and the parsed truth.
//
// The function is pure (no IO, no global state) so it is
// trivial to unit-test against a recorded sshd -T output.
func parseSSHDConfig(out string) (sshdConfig, error) {
	cfg := sshdConfig{}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		directive := fields[0]
		values := fields[1:]
		switch directive {
		case "pubkeyauthentication":
			cfg.PubkeyAuthenticationRaw = values
			for _, v := range values {
				if strings.EqualFold(v, "yes") {
					cfg.PubkeyAuthentication = true
				}
			}
		case "authorizedkeysfile":
			cfg.AuthorizedKeysFileRaw = values
			for _, v := range values {
				if strings.HasSuffix(v, ".ssh/authorized_keys") {
					cfg.AuthorizedKeysFileContainsDotSSH = true
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return cfg, err
	}
	return cfg, nil
}
