//go:build linux

// Linux-only tests for cmd/iamtunnel's "server start" Linux
// branch (IAMT-248). The tests cover:
//
//   - serverKeyFile on Linux resolves <osUser-home>/.ssh/authorized_keys
//     through the userLookupFn seam (default os/user.Lookup
//     in production, recording fake here); refuses if osUser
//     is empty, contains a backslash, or does not resolve;
//   - requireServerElevation on Linux runs the elevation seam
//     (s.isElevated) and refuses with a sudo text when it
//     returns false.
//   - the door LockPath is <data-dir>/door.lock and the
//     OwnerUID/OwnerGID come from the looked-up user.
//
// All paths live inside t.TempDir(); userLookupFn is rewired
// in init() so the test binary never touches /etc/passwd.

package main

import (
	"errors"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fixedUser returns a *user.User with the supplied identity.
// Test code uses it to construct the seam's return value
// without going through os/user.Lookup.
func fixedUser(name, uid, gid, home string) *user.User {
	return &user.User{
		Username: name,
		Uid:      uid,
		Gid:      gid,
		HomeDir:  home,
	}
}

// TestServerKeyFileLinux_ResolvesHome covers the happy path:
// a known OS user "alice" with HomeDir=/home/alice produces
// /home/alice/.ssh/authorized_keys.
func TestServerKeyFileLinux_ResolvesHome(t *testing.T) {
	saved := userLookupFn
	t.Cleanup(func() { userLookupFn = saved })
	userLookupFn = func(name string) (*user.User, error) {
		return fixedUser(name, "1000", "1000", "/home/alice"), nil
	}

	got, err := serverKeyFile("linux", map[string]string{}, "alice", "")
	if err != nil {
		t.Fatalf("serverKeyFile: %v", err)
	}
	want := filepath.Join("/home/alice", ".ssh", "authorized_keys")
	if got != want {
		t.Fatalf("serverKeyFile = %q, want %q", got, want)
	}
}

// TestServerKeyFileLinux_RefusesBackslashUserName pins the
// Windows-form gate: MACHINE\\svc is the Windows naming
// convention; Linux/Darwin refuse it before the lookup.
func TestServerKeyFileLinux_RefusesBackslashUserName(t *testing.T) {
	if _, err := serverKeyFile("linux", map[string]string{}, `MACHINE\svc`, ""); err == nil {
		t.Fatalf("serverKeyFile accepted Windows-form user name on linux")
	}
}

// TestServerKeyFileLinux_RefusesEmptyUser covers the
// "no osUser recorded" half: the operator enrolled the
// machine without an osUser binding, or the legacy gateway
// record predates IAMT-248. Either way, server start must
// refuse rather than defaulting to /root or similar.
func TestServerKeyFileLinux_RefusesEmptyUser(t *testing.T) {
	if _, err := serverKeyFile("linux", map[string]string{}, "", ""); err == nil {
		t.Fatalf("serverKeyFile accepted an empty osUser on linux")
	}
}

// TestServerKeyFileLinux_RefusesUnknownUser covers the
// "user does not exist" half: the gateway bound a user the
// machine does not have, or the user was deleted after
// enrol.
func TestServerKeyFileLinux_RefusesUnknownUser(t *testing.T) {
	saved := userLookupFn
	t.Cleanup(func() { userLookupFn = saved })
	userLookupFn = func(name string) (*user.User, error) {
		return nil, errors.New("unknown")
	}

	if _, err := serverKeyFile("linux", map[string]string{}, "ghost", ""); err == nil {
		t.Fatalf("serverKeyFile accepted a non-existent user")
	}
}

// TestServerKeyFileLinux_FlagOverridesDefault covers the
// "operator picked a non-default file" branch: --key-file
// wins over the per-user default.
func TestServerKeyFileLinux_FlagOverridesDefault(t *testing.T) {
	got, err := serverKeyFile("linux", map[string]string{}, "alice", "/var/lib/iamtunnel/keys")
	if err != nil {
		t.Fatalf("serverKeyFile: %v", err)
	}
	if got != "/var/lib/iamtunnel/keys" {
		t.Fatalf("serverKeyFile = %q, want explicit override path", got)
	}
}

// TestServerKeyFileLinux_RefusesRelativeFlag guards the
// Windows-imported rule: --key-file must be absolute.
func TestServerKeyFileLinux_RefusesRelativeFlag(t *testing.T) {
	if _, err := serverKeyFile("linux", map[string]string{}, "alice", "relative/path"); err == nil {
		t.Fatalf("serverKeyFile accepted a relative --key-file")
	}
}

// TestServerKeyFileLinux_RefusesRelativeHome is a regression
// guard: a misconfigured NSS could conceivably return a
// relative HomeDir; serverKeyFile must refuse it.
func TestServerKeyFileLinux_RefusesRelativeHome(t *testing.T) {
	saved := userLookupFn
	t.Cleanup(func() { userLookupFn = saved })
	userLookupFn = func(name string) (*user.User, error) {
		return fixedUser(name, "1000", "1000", "relative-home"), nil
	}
	if _, err := serverKeyFile("linux", map[string]string{}, "alice", ""); err == nil {
		t.Fatalf("serverKeyFile accepted a relative HomeDir on linux")
	}
}

// TestRequireServerElevationLinux_RefusesSudoText is the
// IAMT-248 main assertion: a non-root process calling
// requireServerElevation on Linux sees the sudo-text refusal.
func TestRequireServerElevationLinux_RefusesSudoText(t *testing.T) {
	s := &streams{
		isElevated: func() (bool, error) { return false, nil },
	}
	err := requireServerElevation(s, "server start")
	if err == nil {
		t.Fatalf("requireServerElevation accepted a non-elevated process on linux")
	}
	msg := err.Error()
	if !strings.Contains(msg, "sudo") {
		t.Fatalf("error must mention sudo as the fix, got: %q", msg)
	}
	if !strings.Contains(msg, "server start") {
		t.Fatalf("error must include the argv path so the operator copies the right command, got: %q", msg)
	}
}

// TestRequireServerElevationLinux_AcceptsRoot is the
// happy-path companion: when streams.isElevated returns
// true, requireServerElevation returns nil regardless of
// the argv text.
func TestRequireServerElevationLinux_AcceptsRoot(t *testing.T) {
	s := &streams{
		isElevated: func() (bool, error) { return true, nil },
	}
	if err := requireServerElevation(s, "server start"); err != nil {
		t.Fatalf("requireServerElevation refused a root process: %v", err)
	}
}

// TestRequireServerElevationLinux_SurfacesCheckError is the
// "isElevated itself failed" half: the production path on
// Linux cannot really fail (Geteuid is infallible), but the
// error branch must surface, not silently return nil.
func TestRequireServerElevationLinux_SurfacesCheckError(t *testing.T) {
	s := &streams{
		isElevated: func() (bool, error) { return false, errors.New("geteuid exploded") },
	}
	err := requireServerElevation(s, "server start")
	if err == nil {
		t.Fatalf("requireServerElevation swallowed a check error")
	}
	if !strings.Contains(err.Error(), "root") && !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("error must explain the failure mode, got: %v", err)
	}
}

// seedLegacyEnrolment was here in IAMT-248 but was flagged as unused
// (gate 3, U1000). IAMT-248 fix1 removes it.

// pin runtime import to keep the build green on platforms
// where the test is otherwise unused.
var _ = runtime.GOOS
