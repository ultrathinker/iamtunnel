package main

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

const elevationRequiredMessage = "administrator privileges are required — close this console and run it using \"Run as administrator\"."

// TestIAMT190_ServerCommandsRefuseWithoutElevation keeps the token check on
// both writers of administrators_authorized_keys. The seam returns false; no
// real UAC, runas, protected path, or owner-machine token is touched.
func TestIAMT190_ServerCommandsRefuseWithoutElevation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("administrator-token requirement is a Windows server-role rule")
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"start", []string{"server", "start", "--data-dir", t.TempDir()}},
		{"doorwatch", []string{"server", "doorwatch", "door-1", "1", t.TempDir() + `\\administrators_authorized_keys`, "1000", t.TempDir() + `\\events.jsonl`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errs bytes.Buffer
			checkCalled := false
			s := &streams{
				out:  &out,
				errs: &errs,
				env:  testsupport.PlatformDataEnv(t),
				checkSSHD: func(string) error {
					checkCalled = true
					return errors.New("must not reach sshd preflight")
				},
				isElevated: func() (bool, error) { return false, nil },
			}
			if got := run(tc.args, s); got != exitDenied {
				t.Fatalf("IAMT-190 canary: %s without elevation exit code = %d, want exitDenied (%d); stderr=%q", tc.name, got, exitDenied, errs.String())
			}
			if !strings.Contains(errs.String(), elevationRequiredMessage) {
				t.Fatalf("IAMT-190 canary: %s refusal stderr=%q, want %q", tc.name, errs.String(), elevationRequiredMessage)
			}
			if checkCalled {
				t.Fatalf("IAMT-190 canary: %s reached sshd preflight before refusing the unelevated console", tc.name)
			}
		})
	}
}

// TestIAMT190_ElevatedServerStartPassesGate proves that the same seam is a
// check, not a test-only block: after a true result execution reaches the
// existing sshd preflight. It still uses only a test error and t.TempDir.
func TestIAMT190_ElevatedServerStartPassesGate(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("administrator-token requirement is a Windows server-role rule")
	}
	dir := t.TempDir()
	seedEnrolledMachine(t, dir)
	// R4 F-04: seed the anchor the enrol would have laid down, so the
	// start reaches the sshd pre-flight this gate test passes on to.
	env := testsupport.PlatformDataEnvAt(t, dir)
	seedEnrolmentAnchor(t, env, dir)
	var out, errs bytes.Buffer
	preflight := errors.New("test sshd preflight")
	called := false
	s := &streams{
		out:  &out,
		errs: &errs,
		env:  env,
		checkSSHD: func(string) error {
			called = true
			return preflight
		},
		isElevated: func() (bool, error) { return true, nil },
	}
	if got := run([]string{"server", "start", "--data-dir", dir}, s); got != exitEnv {
		t.Fatalf("IAMT-190 canary: elevated server start exit code = %d, want sshd preflight exitEnv (%d); stderr=%q", got, exitEnv, errs.String())
	}
	if !called || !strings.Contains(errs.String(), preflight.Error()) {
		t.Fatalf("IAMT-190 canary: elevated server start did not pass the elevation gate to sshd preflight; called=%v stderr=%q", called, errs.String())
	}
}
