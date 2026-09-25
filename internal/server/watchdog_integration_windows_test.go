//go:build windows

// watchdog_integration_windows_test.go: the watchdog is stopped by its
// handle — proven here against a REAL doorwatch subprocess (the actual
// "iamtunnel server doorwatch" subcommand,
// winkeys.SpawnWatchdog/Watchdog.Stop), the same way internal/winkeys/
// doorwatch_test.go proves the mechanism itself; this file proves that
// THIS package's door.go drives that mechanism correctly end to end: a
// confirmed door.close leaves no live watchdog process behind.
package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// buildRealIamtunnelExe compiles the actual cmd/iamtunnel binary into the
// calling test's own temporary directory, mirroring
// internal/winkeys/doorwatch_test.go's own build() helper: this is not a
// stand-in, it is the real "server doorwatch" subcommand
// (cmd/iamtunnel/server.go's cmdServerDoorwatch, wired to
// winkeys.RunWatchdog).
//
// The build is deliberately NOT cached in a sync.Once. A cached path plus
// t.TempDir() is a trap: the directory belongs to whichever test ran the
// Once first and is removed when that test ends, so every later caller
// would exec a deleted file. Caching into os.MkdirTemp instead leaks a
// build directory outside any t.TempDir(), which is the very thing gate 11
// exists to catch. With one caller the build costs nothing to repeat.
func buildRealIamtunnelExe(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "iamtunnel.exe")
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", dst, "github.com/ultrathinker/iamtunnel/cmd/iamtunnel")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build iamtunnel.exe: %v\n%s", err, out)
	}
	return dst
}

// processAlive reports whether pid names a currently running process,
// using a SYNCHRONIZE handle + zero-timeout wait — the same primitive
// winkeys.RunWatchdog itself uses to detect its parent's death.
func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	r, err := windows.WaitForSingleObject(h, 0)
	return err == nil && r == uint32(windows.WAIT_TIMEOUT)
}

func waitForProcessAlive(t *testing.T, pid int, wantAlive bool, max time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(max)
	for {
		if processAlive(pid) == wantAlive {
			return true
		}
		if time.Now().After(deadline) {
			return processAlive(pid) == wantAlive
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestDoorClose_StopsRealWatchdogProcess proves the same guarantee
// with a real subprocess: door.open spawns a real doorwatch child (via
// the real winkeys.SpawnWatchdog against the real built binary), and a
// confirmed door.close must leave that exact process not running —
// stopped "by its saved handle/PID", not by name and not left orphaned.
func TestDoorClose_StopsRealWatchdogProcess(t *testing.T) {
	exe := buildRealIamtunnelExe(t)
	keyFile := filepath.Join(t.TempDir(), "administrators_authorized_keys")
	cfg := &Config{
		KeyFile: keyFile, DoorwatchExe: exe,
		MaxDoorIdle: DefaultMaxDoorIdle, MaxDoorHard: DefaultMaxDoorHard,
		SpawnWatchdog: func(exe, id, kf string, pid int, _ time.Duration, _, _ string, _, _ int) (*winkeys.Watchdog, error) {
			return winkeys.SpawnWatchdog(exe, id, kf, pid, 10*time.Minute, "", "", 0, 0)
		},
	}
	dc, err := newDoorController(cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp := dc.open(doorOpenRequest(t, testDoorID, time.Now(), time.Minute, time.Hour))
	if !resp.OK {
		t.Fatalf("open refused: %+v", resp.Error)
	}

	dc.mu.Lock()
	wd := dc.watchdog
	dc.mu.Unlock()
	if wd == nil {
		t.Fatal("no watchdog recorded after a successful open")
	}
	pid := wd.PID()
	if pid == 0 {
		t.Fatal("watchdog PID is zero")
	}
	if !waitForProcessAlive(t, pid, true, 3*time.Second) {
		t.Fatalf("watchdog process pid=%d does not appear to be running after spawn", pid)
	}

	closeResp := dc.close(controlRequest{ID: "c1", Op: "door.close", DoorID: testDoorID, Reason: "stop"})
	if !closeResp.OK {
		t.Fatalf("close refused: %+v", closeResp.Error)
	}

	if !waitForProcessAlive(t, pid, false, 3*time.Second) {
		t.Fatalf("watchdog process pid=%d was still running after a confirmed door.close", pid)
	}
}
