package main

import (
	"runtime"
	"strings"
	"testing"
)

// iamt159ConfigEnvironment is the fixture both tests below share: only
// Windows role variables are supplied on purpose — %LOCALAPPDATA% for the
// client directory and deliberately NO %ProgramData% — because the
// question they ask is what a Windows machine resolves when the
// machine-owned root is missing.
//
// That question only exists on Windows. config.DirsFor takes the machine
// defaults (server, gateway, config file) from %ProgramData% there and
// reports its absence as a deferred error, while its Linux/Darwin branch
// builds them from fixed system paths (/var/lib/iamtunnel-machine,
// /var/lib/iamtunnel, /etc/iamtunnel/gateway.json) that no environment
// variable can remove — so "no machine root" is not a state those hosts
// can be put in, and loadConfig on them never reaches the branch these
// tests pin. requireWindowsProgramData says so in each skip text.
func iamt159ConfigEnvironment(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{"LOCALAPPDATA": t.TempDir()}
}

// requireWindowsProgramData keeps the %ProgramData%-contract tests off
// hosts where the contract does not exist. what names the assertion, so
// the skip names the concrete thing that waits for a Windows host.
func requireWindowsProgramData(t *testing.T, what string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	t.Skipf("this test %s, but the fixture is a Windows-only environment (%%LOCALAPPDATA%%, no %%ProgramData%%) and the behaviour under test is what config.DirsFor/loadConfig answer when the machine data root is missing — on %s the machine defaults come from fixed system paths (/var/lib/iamtunnel-machine, /etc/iamtunnel/gateway.json) that cannot be absent, so the branch is unreachable here. The Linux/Darwin side of the same seam (an explicit --data-dir is honoured, the platform defaults are used otherwise) is covered by iamt201_config_dir_keys_test.go and iamt248_server_start_linux_test.go.", what, runtime.GOOS)
}

// TestIAMT159_ExplicitServerDataDirDoesNotNeedProgramData keeps config.Load
// from rejecting a command before loadConfig can honour its explicit dir.
func TestIAMT159_ExplicitServerDataDirDoesNotNeedProgramData(t *testing.T) {
	requireWindowsProgramData(t, "pins that an explicit role --data-dir is honoured on a machine whose %ProgramData% is absent, for a machine role (server) and again for a client-only run that must not need %ProgramData% at all")

	want := t.TempDir()
	s := &streams{env: iamt159ConfigEnvironment(t)}
	_, got, err := loadConfig(s, "server", cfgOpts{dataDir: want})
	if err != nil {
		t.Fatalf("loadConfig(server, explicit data dir, no ProgramData): %v", err)
	}
	if got != want {
		t.Fatalf("loadConfig(server, explicit data dir) = %q, want %q", got, want)
	}
	if _, _, err := loadConfig(s, "client", cfgOpts{}); err != nil {
		t.Fatalf("loadConfig(client, default dir, no ProgramData): %v", err)
	}
}

// TestIAMT159_GatewayDefaultStillNeedsProgramData is the default-path
// canary. The role it guards is the GATEWAY since 1.4: the server
// directory moved under %LOCALAPPDATA% — a registration belongs to one
// person on one machine — and no longer reads %ProgramData% at all. The
// seam itself is unchanged, and so is the rule it enforces: a default
// machine-wide path must REFUSE rather than fall back to a relative or
// invented one.
func TestIAMT159_GatewayDefaultStillNeedsProgramData(t *testing.T) {
	requireWindowsProgramData(t, "pins the other half of the seam: with no explicit --data-dir and no %ProgramData%, the gateway role's default directory must REFUSE instead of silently falling back to a relative or invented path")

	s := &streams{env: iamt159ConfigEnvironment(t)}
	_, _, err := loadConfig(s, "gateway", cfgOpts{})
	if err == nil || !strings.Contains(err.Error(), "ProgramData") {
		t.Fatalf("loadConfig(gateway, default dir, no ProgramData) error = %v, want refusal naming ProgramData", err)
	}
}
