package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/server"
)

// iamt156Config builds the production "server start" config for a machine
// freshly seeded in t.TempDir(), from the given substitute environment.
// It never calls server.Run, so no key file is read, created or locked.
func iamt156Config(t *testing.T, goos string, env map[string]string, keyFileFlag string) (server.Config, error) {
	t.Helper()
	dir := t.TempDir()
	seedEnrolledMachine(t, dir)
	return serverStartConfig(goos, env, serverStartParams{
		dataDir:     dir,
		keyFileFlag: keyFileFlag,
		exe:         "unused",
		idleMinutes: 15,
		maxHours:    8,
	})
}

// TestIAMT156_ServerStartKeyFileIsOpenSSHAdministratorsFile pins the
// production seam: with ProgramData pointing at a scratch directory the
// door's key file is <ProgramData>\ssh\administrators_authorized_keys —
// the file Windows OpenSSH reads — not a file in the iamtunnel data
// directory, and an explicit --key-file beats that default. Building the
// config creates neither the file nor its directory.
func TestIAMT156_ServerStartKeyFileIsOpenSSHAdministratorsFile(t *testing.T) {
	programData := t.TempDir()
	env := map[string]string{"ProgramData": programData}
	sep := string(os.PathSeparator)
	want := programData + sep + "ssh" + sep + "administrators_authorized_keys"

	t.Run("default from ProgramData", func(t *testing.T) {
		// The fixture and the expectation are both Windows-only
		// values, so this subtest needs a Windows HOST even though
		// serverKeyFile takes the target OS as a parameter: the
		// ProgramData value is t.TempDir(), which only a Windows host
		// mints as an absolute Windows path (config.WindowsProgramData
		// refuses anything else — that refusal is the gate the
		// TestIAMT156_ServerStartKeyFileFailsClosed table below pins),
		// and the product builds the expected path with filepath.Join,
		// i.e. with the HOST separator. On Linux the same call would
		// either be refused before the assertion or answer with mixed
		// separators — a string production never produces on Windows —
		// so it would pin nothing real.
		if runtime.GOOS != "windows" {
			t.Skipf("this subtest asserts the Windows door-file default (%%ProgramData%%\\ssh\\administrators_authorized_keys), built by the product with the host path separator out of a %%ProgramData%% that only a Windows host can make absolute — config.WindowsProgramData refuses %s temp dirs. The sibling subtest (an explicit --key-file still winning over the windows default) runs here, and the %s default door file (<osUser-home>/.ssh/authorized_keys) is covered by iamt248_server_start_linux_test.go.", runtime.GOOS, runtime.GOOS)
		}
		cfg, err := iamt156Config(t, "windows", env, "")
		if err != nil {
			t.Fatalf("serverStartConfig(windows, ProgramData=%s): %v", programData, err)
		}
		if cfg.KeyFile != want {
			t.Fatalf("serverStartConfig(windows, ProgramData=%s).KeyFile = %q, want %q", programData, cfg.KeyFile, want)
		}
	})

	t.Run("explicit key file beats the default", func(t *testing.T) {
		override := filepath.Join(t.TempDir(), "override_authorized_keys")
		cfg, err := iamt156Config(t, "windows", env, override)
		if err != nil {
			t.Fatalf("serverStartConfig(windows, --key-file %s): %v", override, err)
		}
		if cfg.KeyFile != override {
			t.Fatalf("serverStartConfig(windows, ProgramData=%s, --key-file %s).KeyFile = %q, want the --key-file value", programData, override, cfg.KeyFile)
		}
		if _, err := os.Stat(override); !os.IsNotExist(err) {
			t.Errorf("building the server config touched the --key-file path %s (stat err=%v); it must write nothing", override, err)
		}
	})

	if _, err := os.Stat(filepath.Dir(want)); !os.IsNotExist(err) {
		t.Errorf("building the server config created %s (stat err=%v); it must write nothing", filepath.Dir(want), err)
	}
}

// TestIAMT156_ServerStartKeyFileFailsClosed: the default has no fallback.
// An environment without an absolute ProgramData refuses (config.DirsFor's
// C:\ProgramData fallback is exactly what once let tests write into the
// real machine), a platform without the OpenSSH administrators file needs
// --key-file, and a relative --key-file is refused rather than resolved
// against the current directory.
func TestIAMT156_ServerStartKeyFileFailsClosed(t *testing.T) {
	for _, env := range []map[string]string{
		{},
		{"ProgramData": ""},
		{"ProgramData": "ProgramData"},
	} {
		cfg, err := iamt156Config(t, "windows", env, "")
		if err == nil {
			t.Errorf("env %v: KeyFile = %q, want a refusal — no fallback for a missing ProgramData", env, cfg.KeyFile)
			continue
		}
		if !strings.Contains(err.Error(), "ProgramData") || !strings.Contains(err.Error(), "--key-file") {
			t.Errorf("env %v: error %q does not name ProgramData and --key-file", env, err)
		}
	}

	cfg, err := iamt156Config(t, "linux", map[string]string{"ProgramData": t.TempDir()}, "")
	if err == nil || !strings.Contains(err.Error(), "--key-file") {
		t.Errorf("linux without --key-file: KeyFile=%q err=%v, want a refusal naming --key-file", cfg.KeyFile, err)
	}

	cfg, err = iamt156Config(t, "windows", map[string]string{"ProgramData": t.TempDir()}, "administrators_authorized_keys")
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("relative --key-file: KeyFile=%q err=%v, want a refusal naming an absolute path", cfg.KeyFile, err)
	}
}
