package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	s := Defaults()
	if s.Port != 2222 {
		t.Errorf("default port = %d, want 2222 (SPEC §3.5)", s.Port)
	}
	if s.RecordingsRetentionDays != 90 || s.RecordingsDiskStopPercent != 85 {
		t.Errorf("default recording policy = %d days / %d %%, want 90 / 85 (SPEC §12)",
			s.RecordingsRetentionDays, s.RecordingsDiskStopPercent)
	}
	if s.MaxSessionsPerPerson != 4 || s.MaxSessionsPerMachine != 8 {
		t.Errorf("default session policy = %d per person / %d per machine, want 4 / 8 (PROTOCOL §1.5)",
			s.MaxSessionsPerPerson, s.MaxSessionsPerMachine)
	}
	if s.RiskAction != "warn" {
		t.Errorf("default risk action = %q, want warn", s.RiskAction)
	}
	if s.RiskClassifier != "rules" {
		t.Errorf("default risk classifier = %q, want rules", s.RiskClassifier)
	}
}

func TestRiskSettingsAreStrictAndPlumbed(t *testing.T) {
	s, err := Load("linux", map[string]string{"HOME": "/h"}, Override{ConfigPath: "/risk.json"}, func(string) ([]byte, error) {
		return []byte(`{"risk_action":"block","external_risk_observation_enabled":true,"external_risk_observation_key_file":"/run/observer.key"}`), nil
	})
	if err != nil {
		t.Fatalf("Load risk settings: %v", err)
	}
	if s.RiskAction != "block" || s.RiskClassifier != "both" || !s.ExternalRiskObservationEnabled || s.ExternalRiskObservationKeyFile != "/run/observer.key" {
		t.Fatalf("risk settings = %+v, want block/both plus observation keys", s)
	}
	s, err = Load("linux", map[string]string{"HOME": "/h"}, Override{ConfigPath: "/risk.json"}, func(string) ([]byte, error) {
		return []byte(`{"risk_classifier":"ai","external_risk_observation_key_file":"/run/ai.key"}`), nil
	})
	if err != nil || s.RiskClassifier != "ai" {
		t.Fatalf("ai risk classifier = %q, err=%v; want accepted", s.RiskClassifier, err)
	}
	s, err = Load("linux", map[string]string{"HOME": "/h"}, Override{ConfigPath: "/risk.json"}, func(string) ([]byte, error) {
		return []byte(`{"risk_action":"ask"}`), nil
	})
	if err != nil || s.RiskAction != "ask" {
		t.Fatalf("ask risk action = %q, err=%v; want accepted", s.RiskAction, err)
	}
	_, err = Load("linux", map[string]string{"HOME": "/h"}, Override{ConfigPath: "/risk.json"}, func(string) ([]byte, error) {
		return []byte(`{"risk_action":"allow"}`), nil
	})
	if err == nil || !strings.Contains(err.Error(), "must be log, warn, ask or block") {
		t.Fatalf("allow risk action error = %v, want ladder validation", err)
	}
	_, err = Load("linux", map[string]string{"HOME": "/h"}, Override{ConfigPath: "/risk.json"}, func(string) ([]byte, error) {
		return []byte(`{"risk_classifier":"external"}`), nil
	})
	if err == nil || !strings.Contains(err.Error(), "must be rules, ai or both") {
		t.Fatalf("external risk classifier error = %v, want source validation", err)
	}
	_, err = Load("linux", map[string]string{"HOME": "/h"}, Override{ConfigPath: "/risk.json"}, func(string) ([]byte, error) {
		return []byte(`{"risk_classifier":"ai"}`), nil
	})
	if err == nil || !strings.Contains(err.Error(), "external_risk_observation_key_file is required") {
		t.Fatalf("missing AI key error = %v, want key validation", err)
	}
}

func TestDirsForWindows(t *testing.T) {
	d, err := DirsFor("windows", map[string]string{
		"LOCALAPPDATA": `C:\Users\alice\AppData\Local`,
		"ProgramData":  `C:\ProgramData`,
	})
	if err != nil {
		t.Fatalf("DirsFor: %v", err)
	}
	want := Dirs{
		Client:     `C:\Users\alice\AppData\Local\iamtunnel`,
		Server:     `C:\Users\alice\AppData\Local\iamtunnel\server`,
		Gateway:    `C:\ProgramData\iamtunnel\gateway`,
		ConfigFile: `C:\ProgramData\iamtunnel\gateway.json`,
	}
	if d != want {
		t.Errorf("DirsFor(windows) =\n%+v\nwant\n%+v", d, want)
	}
	if d.ClientKey() != filepath.Join(d.Client, "key") ||
		d.KnownHosts() != filepath.Join(d.Client, "known_hosts") ||
		d.MachinesMine() != filepath.Join(d.Client, "machines.mine") {
		t.Errorf("client subpaths wrong: %+v", d)
	}
	if d.GatewayState() != filepath.Join(d.Gateway, "state.json") ||
		d.GatewayEvents() != filepath.Join(d.Gateway, "events.jsonl") ||
		d.GatewayHostKey() != filepath.Join(d.Gateway, "hostkey") ||
		d.Recordings() != filepath.Join(d.Gateway, "recordings") {
		t.Errorf("gateway subpaths wrong (SPEC §3.5): %+v", d)
	}
}

func TestDirsForWindowsEnvFallbacks(t *testing.T) {
	d, err := DirsFor("windows", map[string]string{
		"USERPROFILE": `C:\Users\bob`,
		"ProgramData": `C:\ProgramData`,
	})
	if err != nil {
		t.Fatalf("DirsFor: %v", err)
	}
	if !strings.HasPrefix(d.Client, `C:\Users\bob\AppData\Local`) {
		t.Errorf("fallback client dir = %q", d.Client)
	}
	// Per-user since 1.4: the server directory follows the person, not
	// the machine.
	if !strings.HasPrefix(d.Server, `C:\Users\bob\AppData\Local`) {
		t.Errorf("per-user server dir = %q", d.Server)
	}
}

func TestDirsForLinux(t *testing.T) {
	d, err := DirsFor("linux", map[string]string{"HOME": "/home/alice"})
	if err != nil {
		t.Fatalf("DirsFor: %v", err)
	}
	if d.Gateway != "/var/lib/iamtunnel" {
		t.Errorf("gateway dir = %q, want /var/lib/iamtunnel (SPEC §3.5)", d.Gateway)
	}
	if d.Client != "/home/alice/.local/share/iamtunnel" {
		t.Errorf("client dir = %q, want the XDG default", d.Client)
	}
	if d.ConfigFile != "/etc/iamtunnel/gateway.json" {
		t.Errorf("config file = %q", d.ConfigFile)
	}

	dx, err := DirsFor("linux", map[string]string{"XDG_DATA_HOME": "/xdg"})
	if err != nil {
		t.Fatalf("DirsFor(XDG): %v", err)
	}
	if dx.Client != "/xdg/iamtunnel" {
		t.Errorf("XDG_DATA_HOME ignored: %q", dx.Client)
	}
	ds, err := DirsFor("linux", map[string]string{"HOME": "/home/alice"})
	if err != nil {
		t.Fatalf("DirsFor(HOME): %v", err)
	}
	if ds.Server == d.Gateway {
		t.Errorf("server dir must not collide with the gateway dir: %q", ds.Server)
	}
}

func TestRoleDir(t *testing.T) {
	d := Dirs{Client: "c", Server: "s", Gateway: "g"}
	if d.RoleDir("client") != "c" || d.RoleDir("server") != "s" || d.RoleDir("enrol") != "s" || d.RoleDir("gateway") != "g" {
		t.Errorf("RoleDir mapping wrong: %+v", d)
	}
	if d.RoleDir("admin") != "" {
		t.Error("admin must have no data dir")
	}
}

// TestSettingsRoleDir is IAMT-201's direct unit test for Settings.RoleDir:
// cmd/iamtunnel's loadConfig reads a role's directory back from the
// merged Settings (defaults < config file < ...) through exactly this
// mapping, so it must agree with Dirs.RoleDir's role set — "enrol" is
// the server role's alias, "admin" has no directory of its own (the CLI
// runs it with role "client").
func TestSettingsRoleDir(t *testing.T) {
	s := Settings{ClientDir: "c", ServerDir: "s", GatewayDir: "g"}
	if s.RoleDir("client") != "c" || s.RoleDir("server") != "s" || s.RoleDir("enrol") != "s" || s.RoleDir("gateway") != "g" {
		t.Errorf("Settings.RoleDir mapping wrong: %+v", s)
	}
	if s.RoleDir("admin") != "" {
		t.Error("admin must have no data dir")
	}
}

const fullConfigJSON = `{
  "port": 2300,
  "client_dir": "/c",
  "server_dir": "/s",
  "gateway_dir": "/g",
  "recordings_retention_days": 30,
  "recordings_disk_stop_percent": 70,
  "max_sessions_per_person": 3,
  "max_sessions_per_machine": 7
}`

func readString(s string) func(string) ([]byte, error) {
	return func(string) ([]byte, error) { return []byte(s), nil }
}

func readErr(err error) func(string) ([]byte, error) {
	return func(string) ([]byte, error) { return nil, err }
}

func TestLoadPrecedenceDefaultFileEnvFlag(t *testing.T) {
	env := map[string]string{"HOME": "/h"}
	base, err := Load("linux", env, Override{}, readString(fullConfigJSON))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if base.Port != 2300 || base.RecordingsRetentionDays != 30 || base.MaxSessionsPerPerson != 3 || base.MaxSessionsPerMachine != 7 {
		t.Fatalf("file layer not applied: %+v", base)
	}

	// Environment beats the file.
	env["IAMTUNNEL_PORT"] = "2400"
	envStep, err := Load("linux", env, Override{}, readString(fullConfigJSON))
	if err != nil {
		t.Fatalf("Load with env: %v", err)
	}
	if envStep.Port != 2400 || envStep.RecordingsRetentionDays != 30 {
		t.Errorf("env must beat file only per key: %+v", envStep)
	}

	// A flag beats both.
	flagPort := 2500
	flagStep, err := Load("linux", env, Override{Port: &flagPort}, readString(fullConfigJSON))
	if err != nil {
		t.Fatalf("Load with flag: %v", err)
	}
	if flagStep.Port != 2500 {
		t.Errorf("flag must beat env and file: %+v", flagStep)
	}

	// No file at all: defaults stand (dirs still resolve for the platform).
	def, err := Load("linux", map[string]string{"HOME": "/h"}, Override{}, readErr(os.ErrNotExist))
	if err != nil {
		t.Fatalf("Load without file: %v", err)
	}
	want := Defaults()
	want.ClientDir = "/h/.local/share/iamtunnel"
	want.ServerDir = "/h/.local/share/iamtunnel/server"
	want.GatewayDir = "/var/lib/iamtunnel"
	if !reflect.DeepEqual(def, want) {
		t.Errorf("missing file must give pure defaults, got %+v", def)
	}
}

func TestLoadOverridesCarryToDirs(t *testing.T) {
	// client_dir from the file lands in Settings.ClientDir.
	s, err := Load("linux", map[string]string{"HOME": "/h"}, Override{}, readString(fullConfigJSON))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.ClientDir != "/c" || s.ServerDir != "/s" || s.GatewayDir != "/g" {
		t.Errorf("dir keys not applied: %+v", s)
	}
	// Env dirs beat the file.
	env := map[string]string{"HOME": "/h", "IAMTUNNEL_DATA_DIR": "/envdata"}
	_, err = Load("linux", env, Override{}, readString(fullConfigJSON))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
}

// TestLoad_ServerAndGatewayRolesSurviveMissingHOME is the IAMT-310 canary:
// a launchd/systemd system daemon running the server (machine) or gateway
// role is never given $HOME, and the GATEWAY's own data directory does
// not live under $HOME — it is a fixed absolute path on both Linux and
// darwin. Before the fix, Load unconditionally failed with "cannot
// determine the client data directory: $HOME is empty" even though
// nothing here ever asked for the client directory, so the re-launched
// `iamtunnel gateway run --data-dir ...` a LaunchDaemon/systemd unit
// runs after every reboot could never come back up.
//
// The SERVER directory joined the per-user side in 1.4, so it resolves
// empty here now, with the same deferred error the client has. That is
// not a regression of this test's subject: a per-user service is given
// its own $HOME, and a root service is given its directory explicitly
// (cmd/iamtunnel's systemServerDir). What must not happen — and what
// this test still guards — is one role's missing variable refusing
// another role outright.
//
// Canary: revert Load to an unconditional ClientDir check — turns
// "Load with no $HOME (darwin, gateway role)" below red.
func TestLoad_GatewayRoleSurvivesMissingHOME(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		noHome := map[string]string{}
		s, err := Load(goos, noHome, Override{}, readErr(os.ErrNotExist))
		if err != nil {
			t.Fatalf("Load(%s, no $HOME) must succeed — the gateway role needs no $HOME: %v", goos, err)
		}
		if s.GatewayDir == "" {
			t.Errorf("Load(%s, no $HOME): GatewayDir resolved empty: %+v", goos, s)
		}
		// The two per-user roles resolve empty, and neither takes the
		// gateway down with it.
		if s.ClientDir != "" {
			t.Errorf("Load(%s, no $HOME): ClientDir unexpectedly resolved to %q", goos, s.ClientDir)
		}
		if s.ServerDir != "" {
			t.Errorf("Load(%s, no $HOME): ServerDir unexpectedly resolved to %q — it is per-user since 1.4", goos, s.ServerDir)
		}
	}
}

func TestLoadConfigFileErrors(t *testing.T) {
	cases := []struct {
		name, content, want string
		class               Class
	}{
		{"unknown key", `{"prot": 22}`, `unknown field "prot"`, ClassEnv},
		{"bad json", `{"port": `, "does not parse", ClassEnv},
		{"wrong type", `{"port": "22"}`, `key "port" must be a whole number`, ClassEnv},
		{"two objects", `{"port": 2222} {"port": 2223}`, "exactly one JSON object", ClassEnv},
		{"bad retention", `{"recordings_retention_days": 0}`, "out of range 1..36500", ClassUser},
		{"bad percent", `{"recordings_disk_stop_percent": 100}`, "out of range 1..99", ClassUser},
		{"low port", `{"port": 80}`, "1024..65535", ClassUser},
	}
	for _, tc := range cases {
		_, err := Load("linux", map[string]string{"HOME": "/h"}, Override{}, readString(tc.content))
		if err == nil {
			t.Errorf("%s: want error, got nil", tc.name)
			continue
		}
		var ce *Error
		if !errors.As(err, &ce) {
			t.Errorf("%s: error %T is not a *config.Error", tc.name, err)
			continue
		}
		if ce.Class != tc.class {
			t.Errorf("%s: class = %d, want %d (err: %v)", tc.name, ce.Class, tc.class, err)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q lacks %q", tc.name, err, tc.want)
		}
	}
}

func TestLoadExplicitFileMustExist(t *testing.T) {
	env := map[string]string{"HOME": "/h", "IAMTUNNEL_CONFIG": "/named/path.json"}
	_, err := Load("linux", env, Override{}, readErr(os.ErrNotExist))
	if err == nil || !strings.Contains(err.Error(), "/named/path.json") {
		t.Errorf("explicit missing config: err=%v, want a named not-exist error", err)
	}
	var ce *Error
	if !errors.As(err, &ce) || ce.Class != ClassUser {
		t.Errorf("explicit missing config must be a user error, got %+v", err)
	}

	flagged := Override{ConfigPath: "/flag.json"}
	_, err = Load("linux", map[string]string{"HOME": "/h"}, flagged, readErr(os.ErrNotExist))
	if err == nil || !strings.Contains(err.Error(), "/flag.json") {
		t.Errorf("flagged missing config: err=%v", err)
	}
}

func TestLoadPermissionDenied(t *testing.T) {
	_, err := Load("linux", map[string]string{"HOME": "/h"}, Override{}, readErr(os.ErrPermission))
	var ce *Error
	if !errors.As(err, &ce) || ce.Class != ClassDenied {
		t.Errorf("unreadable config must be class denied, got %v", err)
	}
}

func TestLoadEnvPortValidation(t *testing.T) {
	env := map[string]string{"HOME": "/h", "IAMTUNNEL_PORT": "banana"}
	_, err := Load("linux", env, Override{}, readErr(os.ErrNotExist))
	var ce *Error
	if !errors.As(err, &ce) || ce.Class != ClassUser {
		t.Errorf("bad IAMTUNNEL_PORT must be a user error, got %v", err)
	}
	env["IAMTUNNEL_PORT"] = "1"
	if _, err := Load("linux", env, Override{}, readErr(os.ErrNotExist)); err == nil {
		t.Error("IAMTUNNEL_PORT=1 must fail the 1024 range check")
	}
	env["IAMTUNNEL_PORT"] = "2301"
	s, err := Load("linux", env, Override{}, readErr(os.ErrNotExist))
	if err != nil || s.Port != 2301 {
		t.Errorf("valid env port: %+v, %v", s, err)
	}
}

func TestLoadRealFileOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.json")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"port": %d}`, 2401)), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	s, err := Load("linux", map[string]string{"HOME": "/h"}, Override{ConfigPath: path}, os.ReadFile)
	if err != nil {
		t.Fatalf("Load with real file: %v", err)
	}
	if s.Port != 2401 {
		t.Errorf("port = %d, want 2401", s.Port)
	}
}
