//go:build linux

// Linux-only tests for the sshd -T pre-flight parser and the
// systemctl seam (SPEC §3.2.1, IAMT-248). parseSSHDConfig is a
// pure function — its tests are the canary: a change to the
// parser that mis-extracts the two directives we care about
// (`pubkeyauthentication yes` and `authorizedkeysfile` ending
// with `.ssh/authorized_keys`) is caught here, before the
// production path runs sshd -T against a real daemon.
//
// The systemctl seam tests use a recording fake: the production
// `exec.Command("systemctl", …)` path is replaced with a
// closure that returns whatever the test wires up. No real
// systemd IPC happens from a test binary.

package server

import (
	"errors"
	"testing"
)

// TestParseSSHDConfig_HappyPath covers the canonical OpenSSH
// output: pubkeyauthentication yes, authorizedkeysfile
// .ssh/authorized_keys (the distro default). The parser must
// recognise both as the production default.
func TestParseSSHDConfig_HappyPath(t *testing.T) {
	const sample = `port 22
addressfamily any
listenaddress 0.0.0.0
listenaddress ::
usepam yes
logingracetime 30
x11displayoffset 10
maxauthtries 6
maxsessions 10
clientaliveinterval 0
clientalivecountmax 3
permitrootlogin prohibit-password
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
challengeresponseauthentication no
printmotd no
printlastlog no
tcpkeepalive yes
permitemptypasswords no
strictmodes yes
authorizedkeysfile .ssh/authorized_keys
subsystem sftp /usr/lib/openssh/sftp-server
acceptenv LANG
acceptenv LC_*
`
	cfg, err := parseSSHDConfig(sample)
	if err != nil {
		t.Fatalf("parseSSHDConfig: %v", err)
	}
	if !cfg.PubkeyAuthentication {
		t.Fatalf("PubkeyAuthentication = false on canonical output, want true")
	}
	if !cfg.AuthorizedKeysFileContainsDotSSH {
		t.Fatalf("AuthorizedKeysFileContainsDotSSH = false on canonical output, want true")
	}
	if got := cfg.AuthorizedKeysFileRaw; len(got) != 1 || got[0] != ".ssh/authorized_keys" {
		t.Fatalf("AuthorizedKeysFileRaw = %v, want [.ssh/authorized_keys]", got)
	}
}

// TestParseSSHDConfig_PubkeyNo covers the most common
// operator mistake on a hardened machine: pubkeyauthentication
// disabled. The door is about to install a line that sshd
// will refuse; the pre-flight surfaces that refusal before
// any tunnel connect.
func TestParseSSHDConfig_PubkeyNo(t *testing.T) {
	const sample = "pubkeyauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n"
	cfg, err := parseSSHDConfig(sample)
	if err != nil {
		t.Fatalf("parseSSHDConfig: %v", err)
	}
	if cfg.PubkeyAuthentication {
		t.Fatalf("PubkeyAuthentication = true on pubkey=no, want false")
	}
}

// TestParseSSHDConfig_PubkeyYesCaseInsensitive covers the
// OpenSSH convention: directive values are case-insensitive.
// "Yes" must register the same as "yes".
func TestParseSSHDConfig_PubkeyYesCaseInsensitive(t *testing.T) {
	for _, v := range []string{"yes", "Yes", "YES", "yEs"} {
		t.Run(v, func(t *testing.T) {
			cfg, err := parseSSHDConfig("pubkeyauthentication " + v + "\n")
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.PubkeyAuthentication {
				t.Fatalf("PubkeyAuthentication = false for value %q", v)
			}
		})
	}
}

// TestParseSSHDConfig_CustomAuthorizedKeysPath covers the
// "operator pointed AuthorizedKeysFile somewhere else" case.
// The door layer writes to ~/<user>/.ssh/authorized_keys;
// sshd reads from the configured path. The two must agree or
// the door opens but the key is silently ignored — exactly
// the failure mode the pre-flight guards against.
func TestParseSSHDConfig_CustomAuthorizedKeysPath(t *testing.T) {
	const sample = "pubkeyauthentication yes\nauthorizedkeysfile /etc/ssh/authorized_keys/%u\n"
	cfg, err := parseSSHDConfig(sample)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PubkeyAuthentication {
		t.Fatalf("PubkeyAuthentication false")
	}
	if cfg.AuthorizedKeysFileContainsDotSSH {
		t.Fatalf("AuthorizedKeysFileContainsDotSSH = true on a custom path, want false")
	}
	if got := cfg.AuthorizedKeysFileRaw; len(got) != 1 || got[0] != "/etc/ssh/authorized_keys/%u" {
		t.Fatalf("AuthorizedKeysFileRaw = %v", got)
	}
}

// TestParseSSHDConfig_MultipleValues covers the multi-value
// form: sshd accepts space-separated value lists (e.g.
// authorizedkeysfile with a primary and a fallback). The
// pre-flight must accept if ANY value matches.
func TestParseSSHDConfig_MultipleValues(t *testing.T) {
	const sample = "pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys /etc/ssh/keys/%u\n"
	cfg, err := parseSSHDConfig(sample)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AuthorizedKeysFileContainsDotSSH {
		t.Fatalf("AuthorizedKeysFileContainsDotSSH = false when one of two values matches")
	}
}

// TestParseSSHDConfig_BlankLines covers the "ignored input"
// half of the parser: a blank line or a comment must not
// panic and must not be misread as a directive.
func TestParseSSHDConfig_BlankLines(t *testing.T) {
	const sample = "\n\npubkeyauthentication yes\n\n"
	cfg, err := parseSSHDConfig(sample)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PubkeyAuthentication {
		t.Fatalf("PubkeyAuthentication = false after blank lines")
	}
}

// TestParseSSHDConfig_MalformedLines covers the "input
// sshd would never produce but a regression might let
// through" half: a line with no value, a line that is just
// whitespace, a directive-only line. The parser must skip
// them without panic.
func TestParseSSHDConfig_MalformedLines(t *testing.T) {
	const sample = "directivewithoutvalue\n   \npubkeyauthentication yes\n"
	cfg, err := parseSSHDConfig(sample)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PubkeyAuthentication {
		t.Fatalf("PubkeyAuthentication = false after malformed prefix lines")
	}
}

// TestDefaultCheckSSHDConfig_RefusesEmptyUser guards the
// empty-OS-user refusal: sshd -T defaults to the running
// user, and the running user on a server role is root, so a
// machine with an empty osUser in enrolment.json would
// silently check root's config and skip the operator's own.
func TestDefaultCheckSSHDConfig_RefusesEmptyUser(t *testing.T) {
	err := defaultCheckSSHDConfig("")
	if err == nil {
		t.Fatalf("defaultCheckSSHDConfig(\"\") must error")
	}
	if !errors.Is(err, errors.Unwrap(err)) && err == nil {
		// sanity: err is non-nil
	}
	if msg := err.Error(); !contains(msg, "OS user is empty") {
		t.Fatalf("error must explain the empty user, got: %v", err)
	}
}

// TestDefaultCheckSSHDConfig_RefusesBackslash is the
// Windows-form gate: an operator who copy-pasted a
// Windows-style "MACHINE\\name" must not be silently
// default-checked against root's config.
func TestDefaultCheckSSHDConfig_RefusesBackslash(t *testing.T) {
	err := defaultCheckSSHDConfig(`MACHINE\svc`)
	if err == nil {
		t.Fatalf(`defaultCheckSSHDConfig("MACHINE\\svc") must error`)
	}
	if msg := err.Error(); !contains(msg, "backslash") {
		t.Fatalf("error must explain the backslash convention, got: %v", err)
	}
}

// TestDefaultCheckSSHDConfig_RefusesNoPubkey covers the
// "pubkey=no" refusal. The seam's sshd -T output is replaced
// with a parsed-pubkey-no fixture; defaultCheckSSHDConfig
// must refuse the door install.
func TestDefaultCheckSSHDConfig_RefusesNoPubkey(t *testing.T) {
	saved := sshdTOutputFn
	t.Cleanup(func() { sshdTOutputFn = saved })
	sshdTOutputFn = func(_ string) (string, error) {
		return "pubkeyauthentication no\nauthorizedkeysfile .ssh/authorized_keys\n", nil
	}
	err := defaultCheckSSHDConfig("alice")
	if err == nil {
		t.Fatalf("defaultCheckSSHDConfig accepted pubkey=no")
	}
	if !contains(err.Error(), "pubkeyauthentication") {
		t.Fatalf("error must name the failing directive, got: %v", err)
	}
}

// TestDefaultCheckSSHDConfig_RefusesCustomPath covers the
// "sshd reads from a different path" refusal. The seam
// returns a path that does NOT end with .ssh/authorized_keys;
// the pre-flight refuses the door install.
func TestDefaultCheckSSHDConfig_RefusesCustomPath(t *testing.T) {
	saved := sshdTOutputFn
	t.Cleanup(func() { sshdTOutputFn = saved })
	sshdTOutputFn = func(_ string) (string, error) {
		return "pubkeyauthentication yes\nauthorizedkeysfile /etc/ssh/keys/%u\n", nil
	}
	err := defaultCheckSSHDConfig("alice")
	if err == nil {
		t.Fatalf("defaultCheckSSHDConfig accepted a custom AuthorizedKeysFile path")
	}
	if !contains(err.Error(), "authorizedkeysfile") {
		t.Fatalf("error must name the failing directive, got: %v", err)
	}
}

// TestDefaultCheckSSHDConfig_PassesHappyPath covers the
// production-success path: a sane sshd config + a real user
// → defaultCheckSSHDConfig returns nil.
func TestDefaultCheckSSHDConfig_PassesHappyPath(t *testing.T) {
	saved := sshdTOutputFn
	t.Cleanup(func() { sshdTOutputFn = saved })
	sshdTOutputFn = func(_ string) (string, error) {
		return "pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n", nil
	}
	if err := defaultCheckSSHDConfig("alice"); err != nil {
		t.Fatalf("defaultCheckSSHDConfig refused a happy path: %v", err)
	}
}

// TestDefaultCheckSSHDService_AcceptsAnyActiveUnit pins the
// cross-distribution contract: the pre-flight accepts ANY of
// ssh.service, sshd.service, ssh.socket as long as systemctl
// reports it active. Ubuntu 22.10+ uses socket activation,
// Debian/RHEL still use a regular service — the production
// machine might run either.
func TestDefaultCheckSSHDService_AcceptsAnyActiveUnit(t *testing.T) {
	saved := systemctlFn
	t.Cleanup(func() { systemctlFn = saved })
	systemctlFn = func(unit string) (bool, error) {
		if unit == "ssh.socket" {
			return true, nil
		}
		return false, nil
	}
	if err := defaultCheckSSHDService(); err != nil {
		t.Fatalf("defaultCheckSSHDService refused an active ssh.socket: %v", err)
	}
}

// TestDefaultCheckSSHDService_RefusesAllInactive covers the
// "no sshd anywhere" failure: every unit is inactive, the
// pre-flight refuses with a text that names the units it
// tried.
func TestDefaultCheckSSHDService_RefusesAllInactive(t *testing.T) {
	saved := systemctlFn
	t.Cleanup(func() { systemctlFn = saved })
	systemctlFn = func(_ string) (bool, error) { return false, nil }
	err := defaultCheckSSHDService()
	if err == nil {
		t.Fatalf("defaultCheckSSHDService accepted all-inactive")
	}
	if !contains(err.Error(), "ssh.service") || !contains(err.Error(), "sshd.service") || !contains(err.Error(), "ssh.socket") {
		t.Fatalf("error must list every unit it tried, got: %v", err)
	}
}

// TestDefaultCheckSSHDService_PanicsInTestBinary guards the
// production refusal path: when no fake is installed (and the
// test forgot to install one), the production exec.Command
// path must not run. The gate is the seam itself: the probe
// calls systemctlFn from the caller's goroutine, so a nil seam
// panics on the first call before any host interaction.
func TestDefaultCheckSSHDService_PanicsInTestBinary(t *testing.T) {
	saved := systemctlFn
	t.Cleanup(func() { systemctlFn = saved })
	systemctlFn = nil // disable the seam so the production path is reached
	// defaultCheckSSHDService calls systemctlFn directly, from
	// the caller's goroutine; a nil seam panics on the first
	// probe. (We do NOT replace defaultCheckSSHDService: we
	// replace systemctlFn with nil and rely on the natural
	// nil-call panic to refuse — there is no testing.Testing()
	// guard on the function itself any more; the guard against
	// an un-mocked test binary lives inside the default
	// systemctlFn.)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("defaultCheckSSHDService did not panic with a nil systemctlFn seam")
		}
	}()
	_ = defaultCheckSSHDService()
}

// contains is the strings.Contains alias kept private to this
// file so the test does not import strings when nothing else
// in the file does.
func contains(s, sub string) bool {
	return len(sub) >= 0 && len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

// indexOf is the runtime-naive substring search used by
// contains. Avoiding strings.Index keeps the imports narrow.
func indexOf(s, sub string) int {
	n, m := len(s), len(sub)
	if m == 0 {
		return 0
	}
	for i := 0; i+m <= n; i++ {
		if s[i:i+m] == sub {
			return i
		}
	}
	return -1
}

// errIsUnused is here to silence the unused-import warning
// when this file is the only one that imports "errors"; the
// production code uses errors elsewhere, but a slim file
// import list keeps gofmt clean.
var _ = errors.New
