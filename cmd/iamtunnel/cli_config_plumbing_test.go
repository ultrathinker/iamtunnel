package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeConfig writes a config file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	return writeFile(t, "gateway.json", content)
}

// TestConfigPlumbingEnvLayer: the CLI really reads IAMTUNNEL_* — a bad
// port is a user error, a broken config file named by IAMTUNNEL_CONFIG
// is an environment error, and a good file lets the command through to
// the stub.
func TestConfigPlumbingEnvLayer(t *testing.T) {
	_, errs, code := driveEnv(t, map[string]string{"IAMTUNNEL_PORT": "banana"}, "server", "status")
	if code != 2 || !strings.Contains(errs, "IAMTUNNEL_PORT") {
		t.Errorf("bad env port: code=%d errs=%q, want 2 naming IAMTUNNEL_PORT", code, errs)
	}

	bad := writeConfig(t, `{"prot": 2222}`)
	_, errs, code = driveEnv(t, map[string]string{"IAMTUNNEL_CONFIG": bad}, "server", "status")
	if code != 3 || !strings.Contains(errs, "unknown field") {
		t.Errorf("broken config via env: code=%d errs=%q, want 3 naming the key", code, errs)
	}

	good := writeConfig(t, `{"port": 2400}`)
	out, errs, code := driveEnv(t, map[string]string{"IAMTUNNEL_CONFIG": good}, "server", "status")
	if code != exitOK || !strings.Contains(out, "not running") {
		t.Errorf("good config via env: code=%d out=%q errs=%q, want the real \"not running\" outcome", code, out, errs)
	}
}

// TestConfigPlumbingFlagLayer: --config points at the file directly;
// a named-but-missing file is a user error (the invocation chose it),
// a directory is an environment error (the file itself is wrong).
func TestConfigPlumbingFlagLayer(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	_, errs, code := drive(t, "server", "status", "--config", missing)
	if code != 2 || !strings.Contains(errs, "does not exist") {
		t.Errorf("missing --config file: code=%d errs=%q, want 2 not-exist", code, errs)
	}

	_, errs, code = drive(t, "server", "status", "--config", t.TempDir())
	if code != 3 {
		t.Errorf("directory as config: code=%d errs=%q, want 3", code, errs)
	}

	good := writeConfig(t, `{"recordings_retention_days": 30}`)
	out, errs, code := drive(t, "server", "status", "--config", good)
	if code != exitOK || !strings.Contains(out, "not running") {
		t.Errorf("good config via flag: code=%d out=%q errs=%q", code, out, errs)
	}
}

// TestConfigPlumbingPrecedenceEndToEnd: the file alone cannot override
// the environment, and the environment cannot override the flag. The
// observable: a value out of range kills the run only when it survives
// the merge — a masked bad value must not.
func TestConfigPlumbingPrecedenceEndToEnd(t *testing.T) {
	badPort := `{"port": 80}` // below 1024 — invalid if it survives

	// File value survives: rejected.
	_, _, code := drive(t, "gateway", "status", "--config", writeConfig(t, badPort))
	if code != 2 {
		t.Errorf("bad file port alone: code=%d, want 2", code)
	}

	// The environment masks the file value: the run proceeds for real.
	good := writeConfig(t, badPort)
	out, errs, code := driveEnv(t, map[string]string{"IAMTUNNEL_PORT": "2300", "IAMTUNNEL_CONFIG": good}, "gateway", "status")
	if code != exitOK || !strings.Contains(out, "no gateway is installed") {
		t.Errorf("env masking bad file port: code=%d out=%q errs=%q, want the real \"not installed\" outcome", code, out, errs)
	}

	// A flag masks both. "gateway status" takes no --port, so this uses
	// "install" instead (the other non-blocking command that does): a
	// masked-out port-range error would show up as "1024 to 65535" here,
	// which the assertion below rules out — on hosts with a service
	// integration the install just succeeds through the substituted
	// seams; hosts without one get the unrelated service-half refusal.
	_ = withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	_, errs, code = driveEnv(t, map[string]string{"IAMTUNNEL_PORT": "2300"},
		"gateway", "install", "--config", good, "--port", "2400", "--public-host", "gw.example.test")
	if strings.Contains(errs, "1024 to 65535") {
		t.Errorf("flag masking env and file: port range error leaked through: %q", errs)
	}
	switch runtime.GOOS {
	case "linux", "windows", "darwin":
		if code != exitOK {
			t.Errorf("flag masking env and file on %s: code=%d errs=%q, want a real install through the substituted seams", runtime.GOOS, code, errs)
		}
	default:
		if code != exitEnv || !strings.Contains(errs, "supports Linux, Windows and macOS") {
			t.Errorf("flag masking env and file: code=%d errs=%q, want the real (non-port) refusal", code, errs)
		}
	}
}

// TestGatewayRestoreEnvErrorCode: the missing restore source is class 3
// — environment, not user syntax.
func TestGatewayRestoreEnvErrorCode(t *testing.T) {
	_, errs, code := drive(t, "gateway", "restore", filepath.Join(t.TempDir(), "gone.tar.gz"), "--yes")
	if code != 3 || !strings.Contains(errs, "does not exist") {
		t.Errorf("restore missing: code=%d errs=%q, want 3", code, errs)
	}
}

// TestHelpTopics: the topic help is meaningful — the config topic states
// the precedence rule, role helps carry usage and the resolved paths.
func TestHelpTopics(t *testing.T) {
	out, _, code := drive(t, "help", "config")
	if code != 0 {
		t.Fatalf("help config: code=%d", code)
	}
	for _, want := range []string{"environment variables", "config file", "IAMTUNNEL_PORT", "IAMTUNNEL_DATA_DIR", "IAMTUNNEL_CONFIG", "port"} {
		if !strings.Contains(out, want) {
			t.Errorf("help config lacks %q", want)
		}
	}
	if !strings.Contains(out, "Paths resolved on this machine ("+runtime.GOOS+")") {
		t.Errorf("help config lacks the resolved path block, got:\n%s", out)
	}

	for _, topic := range []string{"client", "server", "admin", "gateway", "enrol", "shot", "selftest"} {
		out, _, code := drive(t, "help", topic)
		if code != 0 || !strings.Contains(out, "Usage:") {
			t.Errorf("help %s: code=%d, want usage text", topic, code)
		}
	}

	// Deeper --help explains the concrete command.
	out, _, code = drive(t, "admin", "grants", "revoke", "--help")
	if code != 0 || !strings.Contains(out, "Usage: iamtunnel admin grants revoke <person> <machine>") {
		t.Errorf("admin leaf help wrong, got:\n%s", out)
	}
	out, _, code = drive(t, "admin", "people", "remove", "--help")
	if code != 0 || !strings.Contains(out, "Destructive") || !strings.Contains(out, "--yes") {
		t.Errorf("destructive leaf help lacks the confirmation note, got:\n%s", out)
	}

	// Unknown topic: user error listing the topics.
	_, errs, code := drive(t, "help", "frobnicate")
	if code != 2 || !strings.Contains(errs, "unknown topic") {
		t.Errorf("unknown topic: code=%d errs=%q, want 2", code, errs)
	}
}

// TestUnknownFlagListsAllowed: the unknown-flag rejection names the
// allowed set, so the reader sees what exists.
func TestUnknownFlagListsAllowed(t *testing.T) {
	_, errs, _ := drive(t, "server", "start", "--idle", "5")
	if !strings.Contains(errs, "--idle-minutes") || !strings.Contains(errs, "--max-hours") {
		t.Errorf("unknown flag error lacks the allowed list, got:\n%s", errs)
	}
	_, errs, _ = drive(t, "server", "status", "-config", "x")
	if !strings.Contains(errs, "two dashes") {
		t.Errorf("single-dash hint missing, got:\n%s", errs)
	}
}

// TestFlagAfterDoubleDashIsPositional: "--" ends the flags uniformly.
func TestFlagAfterDoubleDashIsPositional(t *testing.T) {
	_, errs, code := drive(t, "client", "connect", "--", "--weird")
	if code != 2 || !strings.Contains(errs, "not a valid name") {
		t.Errorf("-- handling: code=%d errs=%q, want a name validation error", code, errs)
	}
}

// TestNoSideEffectsOnRefusal: a refused destructive command must not
// read a restore source it was about to overwrite state with — the gate
// runs before existence checks. (Everything here is in-memory anyway;
// the test pins the ordering by demanding the refusal text.)
func TestNoSideEffectsOnRefusal(t *testing.T) {
	_, errs, code := drive(t, "gateway", "restore", "definitely-missing.tar.gz")
	if code != 2 || !strings.Contains(errs, "refusing to act") {
		t.Errorf("restore without --yes: code=%d errs=%q, want the gate refusal, not a file check", code, errs)
	}
	_ = os.Getenv // keep os import if assertions above change
}
