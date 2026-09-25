package main

// iamt201_config_dir_keys_test.go is the end-to-end gate for IAMT-201:
// the client_dir/server_dir/gateway_dir keys of a --config file were
// silently ignored whenever neither --data-dir nor IAMTUNNEL_DATA_DIR
// named a directory, because loadConfig (main.go) asked config.DirsFor
// for a fresh platform default instead of reading back what config.Load
// had already merged from the file into Settings.
//
// Canary: revert loadConfig's
//
//	if dir == "" {
//		dir = st.RoleDir(role)
//	}
//
// back to unconditionally recomputing
//
//	dirs, err := config.DirsFor(runtime.GOOS, s.env)
//	dir, err = dirs.RoleDirE(role)
//
// (main.go, cmdOpts.dataDir/IAMTUNNEL_DATA_DIR both empty) and every
// test below that names a *_dir config key goes red: the client one at
// its "connection.json was not written to the client_dir the config
// named" fatal, the server/gateway ones at their "loadConfig(...) dir =
// ..., want the config file's *_dir key" fatal.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// dirConfigFile writes a --config file with exactly the given *_dir
// keys set (others omitted), and returns its path.
func dirConfigFile(t *testing.T, keys map[string]string) string {
	t.Helper()
	body := "{"
	first := true
	for _, k := range []string{"client_dir", "server_dir", "gateway_dir"} {
		v, ok := keys[k]
		if !ok {
			continue
		}
		if !first {
			body += ","
		}
		first = false
		body += fmt.Sprintf("%q:%q", k, v)
	}
	body += "}"
	return writeFile(t, "dirs.json", body)
}

// TestConfigFile_ClientDirKeyIsUsedEndToEnd is the end-to-end half of
// the gate: a real CLI command ("client connect-string") that writes a
// role file, driven with a --config naming client_dir, must write that
// file inside client_dir and nowhere near the platform default — the
// two are deliberately different directories here (gate 11: both live
// inside this test's own t.TempDir() trees, never the real
// %LOCALAPPDATA%/%ProgramData%/$HOME/$XDG_DATA_HOME).
func TestConfigFile_ClientDirKeyIsUsedEndToEnd(t *testing.T) {
	customClientDir := filepath.Join(t.TempDir(), "custom-client")
	cfgPath := dirConfigFile(t, map[string]string{"client_dir": customClientDir})

	env := testsupport.PlatformDataEnv(t)
	// Neutralize driveFull's own IAMTUNNEL_DATA_DIR convenience default
	// on non-Windows (main_test.go's driveFull), so this exercises the
	// real "neither flag nor env named a directory" branch loadConfig
	// takes on every platform, not just Windows.
	env["IAMTUNNEL_DATA_DIR"] = ""

	out, errs, code := driveEnv(t, env, "client", "connect-string", connStr, "--config", cfgPath)
	if code != exitOK {
		t.Fatalf("client connect-string --config <client_dir>: code=%d out=%q errs=%q", code, out, errs)
	}

	got := filepath.Join(customClientDir, "connection.json")
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("connection.json was not written to the client_dir the config named (%s): %v", got, err)
	}

	defaults, err := config.DirsFor(runtime.GOOS, env)
	if err != nil {
		t.Fatalf("test setup: config.DirsFor: %v", err)
	}
	stray := filepath.Join(defaults.Client, "connection.json")
	if _, err := os.Stat(stray); err == nil {
		t.Fatalf("connection.json was ALSO written to the platform default client dir (%s) — client_dir did not fully replace it", stray)
	}
}

// TestConfigFile_ServerAndGatewayDirKeysAreUsed pins the same fix for
// the two roles that have no side-effect-free file-writing command to
// drive through the CLI (server start needs elevation/a real sshd;
// gateway install touches systemd on Linux) — loadConfig itself is
// package main's own function, so calling it directly still tests
// "at the cmd level", against the exact code IAMT-201 fixes, without
// any of that machinery.
func TestConfigFile_ServerAndGatewayDirKeysAreUsed(t *testing.T) {
	customServerDir := filepath.Join(t.TempDir(), "custom-server")
	customGatewayDir := filepath.Join(t.TempDir(), "custom-gateway")
	cfgPath := dirConfigFile(t, map[string]string{
		"server_dir":  customServerDir,
		"gateway_dir": customGatewayDir,
	})

	env := testsupport.PlatformDataEnv(t)
	s := &streams{env: env}

	_, dir, err := loadConfig(s, "server", cfgOpts{configPath: cfgPath})
	if err != nil {
		t.Fatalf("loadConfig(server, server_dir set): %v", err)
	}
	if dir != customServerDir {
		t.Fatalf("loadConfig(server, server_dir set) dir = %q, want the config file's server_dir %q", dir, customServerDir)
	}

	_, dir, err = loadConfig(s, "gateway", cfgOpts{configPath: cfgPath})
	if err != nil {
		t.Fatalf("loadConfig(gateway, gateway_dir set): %v", err)
	}
	if dir != customGatewayDir {
		t.Fatalf("loadConfig(gateway, gateway_dir set) dir = %q, want the config file's gateway_dir %q", dir, customGatewayDir)
	}

	defaults, derr := config.DirsFor(runtime.GOOS, env)
	if derr != nil {
		t.Fatalf("test setup: config.DirsFor: %v", derr)
	}
	if dir == defaults.Gateway {
		t.Fatalf("loadConfig(gateway) returned the platform default (%s) instead of the config file's gateway_dir", defaults.Gateway)
	}
}

// TestConfigFile_FlagAndEnvOutrankTheFileKey: --data-dir beats
// IAMTUNNEL_DATA_DIR beats the config file's *_dir key — this
// precedence is asserted for each layer independently.
func TestConfigFile_FlagAndEnvOutrankTheFileKey(t *testing.T) {
	fileDir := filepath.Join(t.TempDir(), "from-file")
	envDir := filepath.Join(t.TempDir(), "from-env")
	flagDir := filepath.Join(t.TempDir(), "from-flag")
	cfgPath := dirConfigFile(t, map[string]string{"client_dir": fileDir})

	env := testsupport.PlatformDataEnv(t)
	s := &streams{env: env}

	// File alone: wins over the platform default.
	_, dir, err := loadConfig(s, "client", cfgOpts{configPath: cfgPath})
	if err != nil {
		t.Fatalf("loadConfig(client, file only): %v", err)
	}
	if dir != fileDir {
		t.Fatalf("loadConfig(client, file only) dir = %q, want %q", dir, fileDir)
	}

	// IAMTUNNEL_DATA_DIR beats the file key.
	envWithData := testsupport.PlatformDataEnv(t)
	envWithData["IAMTUNNEL_DATA_DIR"] = envDir
	sEnv := &streams{env: envWithData}
	_, dir, err = loadConfig(sEnv, "client", cfgOpts{configPath: cfgPath})
	if err != nil {
		t.Fatalf("loadConfig(client, env+file): %v", err)
	}
	if dir != envDir {
		t.Fatalf("loadConfig(client, env+file) dir = %q, want the env value %q (env must beat the file)", dir, envDir)
	}

	// --data-dir beats both IAMTUNNEL_DATA_DIR and the file key.
	_, dir, err = loadConfig(sEnv, "client", cfgOpts{configPath: cfgPath, dataDir: flagDir})
	if err != nil {
		t.Fatalf("loadConfig(client, flag+env+file): %v", err)
	}
	if dir != flagDir {
		t.Fatalf("loadConfig(client, flag+env+file) dir = %q, want the flag value %q (flag must beat env and file)", dir, flagDir)
	}
}
