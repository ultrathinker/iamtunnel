//go:build windows && !nogui

package main

// iamt183_config_path_test.go: resolvedConfigPath (round 3's fix for
// runGUI's Settings screen always showing an empty config path) follows
// the exact precedence config.Load itself uses (settings.go: flag >
// IAMTUNNEL_CONFIG > platform default) minus the flag, which the window
// does not have. This pins that precedence directly, and the one
// canary this needs: reverting to the empty dirs.ConfigFile zero
// value must go red.

import (
	"runtime"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

func TestResolvedConfigPathPrefersIAMTUNNEL_CONFIG(t *testing.T) {
	s := &streams{env: map[string]string{
		"IAMTUNNEL_CONFIG": `C:\custom\my-config.json`,
		"LOCALAPPDATA":     `C:\Users\test\AppData\Local`,
		"ProgramData":      `C:\ProgramData`,
	}}
	got := resolvedConfigPath(s)
	want := `C:\custom\my-config.json`
	if got != want {
		t.Errorf("resolvedConfigPath = %q, want %q — IAMTUNNEL_CONFIG must win over the platform default", got, want)
	}
}

func TestResolvedConfigPathFallsBackToThePlatformDefault(t *testing.T) {
	env := map[string]string{
		"LOCALAPPDATA": `C:\Users\test\AppData\Local`,
		"ProgramData":  `C:\ProgramData`,
	}
	s := &streams{env: env}

	want, err := config.DirsFor(runtime.GOOS, env)
	if err != nil {
		t.Fatalf("test setup: config.DirsFor: %v", err)
	}
	if want.ConfigFile == "" {
		t.Fatalf("test bug: the platform default resolved to an empty path — this test would verify nothing")
	}

	if got := resolvedConfigPath(s); got != want.ConfigFile {
		t.Errorf("resolvedConfigPath = %q, want config.DirsFor's own default %q", got, want.ConfigFile)
	}
}

// TestResolvedConfigPathIsNeverTheZeroDirsConfigFile is the canary:
// revert resolvedConfigPath to
// `config.Dirs{Server: serverDir, Client: clientDir}.ConfigFile` (the
// hand-built, partially-populated config.Dirs runGUI keeps only for
// MachineID()/MachineKey() — its ConfigFile field is always the zero
// value "") and this goes red.
func TestResolvedConfigPathIsNeverTheZeroDirsConfigFile(t *testing.T) {
	s := &streams{env: map[string]string{
		"LOCALAPPDATA": `C:\Users\test\AppData\Local`,
		"ProgramData":  `C:\ProgramData`,
	}}
	zero := config.Dirs{Server: `C:\ProgramData\iamtunnel`, Client: `C:\Users\test\AppData\Local\iamtunnel`}
	if got := resolvedConfigPath(s); got == zero.ConfigFile {
		t.Errorf("resolvedConfigPath = %q, the hand-built config.Dirs zero value — it must resolve the real config file path", got)
	}
}

func TestResolvedConfigPathReturnsEmptyWhenUnresolvable(t *testing.T) {
	// Neither LOCALAPPDATA nor USERPROFILE nor IAMTUNNEL_CONFIG set:
	// config.DirsFor itself refuses (IAMT-76 — never fall back to a
	// relative path). resolvedConfigPath's own contract is to say ""
	// rather than propagate that error: an unresolvable config path is
	// not a reason to refuse opening the window, only to draw "—" on the
	// Settings screen (orDash).
	s := &streams{env: map[string]string{}}
	if got := resolvedConfigPath(s); got != "" {
		t.Errorf("resolvedConfigPath with an unresolvable environment = %q, want \"\"", got)
	}
}
