package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// gate4_server_pair_test.go proves that "server start" and "server
// stop" work as a pair, and only as a real, separate OS subprocess —
// the same posture internal/server/watchdog_integration_windows_test.go
// already takes for proving the watchdog mechanism. Two calls inside
// one process would not prove anything about the case that
// actually matters here: "start" left running by a different session/
// process while "stop" and "status" are invoked from another one — a
// real subprocess is the only way to exercise that boundary honestly.
// Unlike the watchdog test, nothing here is Windows-specific in what it
// asserts (no real door ever opens, since the configured gateway
// address is unreachable on purpose — see seedEnrolledMachine), so this
// file carries no build tag. One practical platform split remains: the
// start/stop PAIR test drives the real iamtunnel binary, and on Unix
// the real SPEC §3.2.1 pre-flight (root + gateway-bound osUser + live
// sshd) cannot be satisfied — nor bypassed — inside a sandboxed test
// container, because a separate OS process can't receive this harness's
// injected seams; that test therefore skips there with the full
// explanation in its own t.Skip (gate 10), while
// TestGate4_StatusAndStopWhenNobodyIsRunning is in-process and runs on
// every platform.

var (
	buildRealExeOnce sync.Once
	realExePath      string
	buildRealExeErr  error
)

func buildRealIamtunnelExe(t *testing.T) string {
	t.Helper()
	buildRealExeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "iamtunnel-server-pair-build")
		if err != nil {
			buildRealExeErr = err
			return
		}
		name := "iamtunnel"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		dst := filepath.Join(dir, name)
		if err := testsupport.BuildIamtunnel(dst); err != nil {
			buildRealExeErr = err
			return
		}
		realExePath = dst
	})
	if buildRealExeErr != nil {
		if errors.Is(buildRealExeErr, testsupport.ErrNoCgo) {
			t.Skip("building iamtunnel binary requires cgo on Linux/macOS (no C toolchain or CGO_ENABLED=0)")
		}
		t.Fatalf("%v", buildRealExeErr)
	}
	return realExePath
}

// seedEnrolledMachine writes exactly what a successful "enrol" would
// have saved (machine.key, machine.id, gateway.json), pointed at a
// gateway address nothing listens on (127.0.0.1:1): "server start" must
// still come up and answer control requests — the outbound tunnel dials
// and retries with backoff entirely in the background (internal/server.
// Run's own contract) and never blocks the control listener this pair
// test actually exercises.
func seedEnrolledMachine(t *testing.T, dir string) {
	t.Helper()
	dirs := config.Dirs{Server: dir}
	if _, err := loadOrGenerateSigner(dirs.MachineKey()); err != nil {
		t.Fatalf("seed machine key: %v", err)
	}
	if err := atomicWriteBytes(dirs.MachineID(), []byte("testmachine")); err != nil {
		t.Fatalf("seed machine id: %v", err)
	}
	rec := gatewayRecord{Host: "127.0.0.1", Port: 1, Fingerprint: fpr43, MachineID: "testmachine"}
	if err := atomicWriteJSON(gatewayRecordPath(dir), rec); err != nil {
		t.Fatalf("seed gateway record: %v", err)
	}
}

// TestGate4_ServerStartStopPair is the named test for the pair gate:
// after a real "server start" subprocess is up, "server status" (run
// in-process, dialing the subprocess's real control port) reports
// running; after "server stop", it reports not running, and the
// subprocess has actually exited.
func TestGate4_ServerStartStopPair(t *testing.T) {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		t.Skip("this pair test drives a REAL `iamtunnel server start` subprocess, and a separate OS process cannot receive this test harness's injected seams (isElevated, streams.checkSSHD/checkSSHDConfig, the winkeys recording stubs). On Unix the real SPEC §3.2.1 pre-flight then refuses to start in every environment the suite runs in: requireServerElevation demands euid==0 (the uid-1000 band refuses here), serverKeyFile refuses the seeded gateway.json because a seeded record carries no gateway-bound os-user, and checkSSHDConfig needs a real sshd, which the golang test containers do not ship. Satisfying it would mean either weakening the production pre-flight or having a test issue real useradd/systemctl — both wrong. The Unix refusal paths are covered in-process by iamt248_server_start_linux_test.go and iamt138_server_start_sshd_test.go; the control-listener lifecycle this pair test exists for is platform-neutral (internal/server) and stays exercised on Windows.")
	}
	exe := buildRealIamtunnelExe(t)
	dir := t.TempDir()
	seedEnrolledMachine(t, dir)
	// R4 F-04: the start now checks the profile record against the
	// enrolment anchor; seed the anchor the enrol that produced this
	// record would have laid down.
	seedEnrolmentAnchor(t, testsupport.PlatformDataEnvAt(t, dir), dir)

	// The subprocess inherits this test binary's environment, which
	// TestMain stripped of ProgramData (testmain_test.go): without
	// --key-file it refuses to start rather than sweep the machine's real
	// %ProgramData%\ssh\administrators_authorized_keys (IAMT-156).
	keyFile := filepath.Join(t.TempDir(), "administrators_authorized_keys")
	cmd := exec.Command(exe, "server", "start", "--data-dir", dir, "--key-file", keyFile)
	stderr := &strings.Builder{}
	cmd.Stderr = stderr
	// R4 F-04: the anchor lives under %ProgramData%, which TestMain
	// stripped; this one command gets it back, aimed at the fixture
	// directory the anchor was seeded under. The --key-file safety above
	// is unchanged.
	cmd.Env = append(os.Environ(), "ProgramData="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start subprocess: %v", err)
	}
	// waitReady closes exactly once, whenever cmd.Wait() returns
	// (exec.Cmd.Wait itself must only ever be called once); both the
	// pair-flow's own exit check below and t.Cleanup's safety-net kill
	// select on this same closed-channel signal instead of each trying
	// to read a single-value channel, which only the first of them could
	// ever actually receive from.
	var waitErr error
	waitReady := make(chan struct{})
	go func() {
		waitErr = cmd.Wait()
		close(waitReady)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-waitReady:
		case <-time.After(5 * time.Second):
			t.Logf("subprocess did not exit within 5s of Kill (stderr so far: %s)", stderr.String())
		}
	})

	controlPath := controlFilePath(dir)
	waitFor(t, "control.json to appear", 20*time.Second, func() bool {
		_, err := os.Stat(controlPath)
		return err == nil
	})

	out, errs, code := drive(t, "server", "status", "--data-dir", dir)
	if code != exitOK || !strings.Contains(out, "running") || strings.Contains(out, "not running") {
		t.Fatalf("status while the subprocess is up: code=%d out=%q errs=%q", code, out, errs)
	}

	out, errs, code = drive(t, "server", "stop", "--data-dir", dir)
	if code != exitOK || !strings.Contains(out, "stopped") {
		t.Fatalf("stop: code=%d out=%q errs=%q", code, out, errs)
	}

	out, errs, code = drive(t, "server", "status", "--data-dir", dir)
	if code != exitOK || !strings.Contains(out, "not running") {
		t.Fatalf("status right after stop: code=%d out=%q errs=%q, want \"not running\" with no race", code, out, errs)
	}

	select {
	case <-waitReady:
		if waitErr != nil {
			t.Errorf("subprocess exited with an error after stop: %v (stderr=%s)", waitErr, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Errorf("subprocess did not exit within 5s of \"server stop\" succeeding")
	}
	if _, err := os.Stat(controlPath); !os.IsNotExist(err) {
		t.Errorf("control.json should be gone after stop, stat err=%v", err)
	}
}

// TestGate4_StatusAndStopWhenNobodyIsRunning: the pair gate also
// requires a clear answer when nobody is running — both commands must
// say so, not hang or error out, against a directory that was never
// started at all.
func TestGate4_StatusAndStopWhenNobodyIsRunning(t *testing.T) {
	dir := t.TempDir()
	seedEnrolledMachine(t, dir)
	for _, sub := range []string{"status", "stop"} {
		out, errs, code := drive(t, "server", sub, "--data-dir", dir)
		if code != exitOK || !strings.Contains(out, "not running") {
			t.Errorf("server %s (nobody running): code=%d out=%q errs=%q", sub, code, out, errs)
		}
	}
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("timed out waiting for %s", what)
	}
}
