package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// TestServerStart_RefusesWhenSSHDNotReachable verifies that "server start"
// performs a pre-flight check that sshd is reachable and running on TargetAddr
// before opening the control listener or starting the server tunnel (SPEC §3.2).
// If sshd is not reachable, the command must fail immediately with exitEnv (3),
// output an informative error message, and never reach server.Run (nor create control.json).
//
// Canary:
// In cmd/iamtunnel/server.go, replace the pre-flight check call:
//
//	if err := checkSSHD(scfg.TargetAddr); err != nil
//
// with:
//
//	if err := error(nil); err != nil
//
// Then run "go test ./cmd/iamtunnel/...".
// Result: TestServerStart_RefusesWhenSSHDNotReachable fails at line 72:
//
//	server start did not refuse unreachable sshd: command is still running after timeout (control.json exists=true)
func TestServerStart_RefusesWhenSSHDNotReachable(t *testing.T) {
	dir := t.TempDir()
	seedEnrolledMachine(t, dir)

	// The pre-flight this test is about runs after serverStartConfig has
	// resolved the door's key file, and that default is per-OS: on
	// Windows it comes from %ProgramData% (which
	// testsupport.PlatformDataEnvAt points at dir, so the seeded record
	// is enough), on Linux/Darwin from the OS user the gateway bound at
	// enrol time — and the record this test seeds carries none, so
	// "server start" would refuse there BEFORE the pre-flight and
	// checkSSHD would never be called (the addr the failure message
	// showed was the empty string). The Unix fixture therefore names the
	// key file the way an operator does, so the command reaches the
	// check the test exists for. The default itself, and its refusals,
	// are pinned by iamt248_server_start_linux_test.go and
	// iamt156_server_keyfile_test.go.
	args := []string{"server", "start", "--data-dir", dir}
	if runtime.GOOS != "windows" {
		args = append(args, "--key-file", filepath.Join(t.TempDir(), "authorized_keys"))
	}

	// R4 F-04: seed the anchor the enrol that produced this record would
	// have laid down, so the start drives past the anchor gate to the
	// sshd pre-flight this test exists for.
	env := testsupport.PlatformDataEnvAt(t, dir)
	seedEnrolmentAnchor(t, env, dir)

	var out, errs bytes.Buffer
	mockErr := errors.New("sshd on 127.0.0.1:22 is not reachable — start OpenSSH Server and retry: connection refused")
	var checkCalledWith string
	s := &streams{
		in:   strings.NewReader(""),
		out:  &out,
		errs: &errs,
		env:  env,
		checkSSHD: func(addr string) error {
			checkCalledWith = addr
			return mockErr
		},
		isElevated: func() (bool, error) { return true, nil },
	}

	done := make(chan int, 1)
	go func() {
		done <- run(args, s)
	}()

	t.Cleanup(func() {
		_, contacted, _ := sendControl(dir, "stop")
		if contacted {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
		}
	})

	select {
	case code := <-done:
		if code != exitEnv {
			t.Fatalf("server start with unreachable sshd: exit code = %d, want exitEnv (%d); errs: %s", code, exitEnv, errs.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("server start did not refuse unreachable sshd: command is still running after timeout (control.json exists=%v)", fileExists(controlFilePath(dir)))
	}

	if checkCalledWith != "127.0.0.1:22" {
		t.Fatalf("checkSSHD called with %q, want \"127.0.0.1:22\"", checkCalledWith)
	}
	if !strings.Contains(errs.String(), mockErr.Error()) {
		t.Fatalf("stderr missing expected error %q, got:\n%s", mockErr.Error(), errs.String())
	}
	if fileExists(controlFilePath(dir)) {
		t.Fatalf("control.json must not exist when sshd pre-flight fails")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
