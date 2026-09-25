//go:build linux || darwin

// Tests for the Linux/Darwin elevation layer (SPEC §3.2.1,
// IAMT-248). The Is elevated / Relaunch pair is so close to the
// syscall that mocking it buys little; VerifyOSUser is the
// meaty one because it goes through a seam.
//
// Production uses os/user.Lookup (NSS, libnss-mysql, LDAP,
// sssd, …). The test replaces userLookupFn with a recording
// fake so the test binary never touches /etc/passwd — the same
// discipline winkeys/doors_unix_test.go applies to chownFn /
// chmodFn.

package elevate

import (
	"errors"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// fakeLookup is the recording replacement for the seam. It
// returns a *user.User with the supplied uid/gid/home, or an
// error if the name is unknown.
type fakeLookup struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeLookup) lookup(name string) (*user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	switch name {
	case "alice":
		return &user.User{
			Username: "alice",
			Uid:      "1000",
			Gid:      "1000",
			HomeDir:  "/home/alice",
		}, nil
	case "":
		return nil, errors.New("user: unknown user empty")
	}
	return nil, errors.New("user: unknown user " + name)
}

var lookupFake *fakeLookup

func init() {
	lookupFake = &fakeLookup{}
	userLookupFn = lookupFake.lookup
}

// TestVerifyOSUser_AcceptsKnownUser is the happy path: alice
// resolves to a real *user.User with a populated HomeDir.
func TestVerifyOSUser_AcceptsKnownUser(t *testing.T) {
	if err := VerifyOSUser("alice"); err != nil {
		t.Fatalf("VerifyOSUser(alice) failed: %v", err)
	}
	if len(lookupFake.calls) != 1 || lookupFake.calls[0] != "alice" {
		t.Fatalf("userLookupFn was not called with \"alice\": %+v", lookupFake.calls)
	}
}

// TestVerifyOSUser_RejectsEmptyName covers the trivial gate:
// an empty name cannot meaningfully be looked up.
func TestVerifyOSUser_RejectsEmptyName(t *testing.T) {
	err := VerifyOSUser("")
	if err == nil {
		t.Fatalf("VerifyOSUser(\"\") must error")
	}
	if !strings.Contains(err.Error(), "non-empty") {
		t.Fatalf("error must explain the requirement, got: %v", err)
	}
}

// TestVerifyOSUser_RejectsBackslash is the Windows-form gate:
// "DOMAIN\\name" is the Windows naming convention; the Linux /
// Darwin side rejects it before the lookup so an operator
// copy-pasting a Windows enrol code does not silently end up
// with a "user does not exist" message.
func TestVerifyOSUser_RejectsBackslash(t *testing.T) {
	err := VerifyOSUser(`MACHINE\svc`)
	if err == nil {
		t.Fatalf(`VerifyOSUser("MACHINE\\svc") must error on linux/darwin`)
	}
	if !strings.Contains(err.Error(), "DOMAIN") && !strings.Contains(err.Error(), "backslash") {
		t.Fatalf("error must explain the backslash convention, got: %v", err)
	}
}

// TestVerifyOSUser_RejectsUnknownUser covers the "user does
// not exist" half: the seam returns an error, VerifyOSUser
// must surface that as an actionable refusal (not a wrapped
// generic error).
func TestVerifyOSUser_RejectsUnknownUser(t *testing.T) {
	err := VerifyOSUser("ghost")
	if err == nil {
		t.Fatalf("VerifyOSUser(\"ghost\") must error")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("error must name the missing user, got: %v", err)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("error must explain the cause, got: %v", err)
	}
}

// TestVerifyOSUser_RefusesUserWithoutUid guards against a
// hypothetical future where os/user.Lookup returns a
// half-populated *user.User (Uid="") — the door layer would
// then have nothing to chown to and would silently chmod the
// file to root:root.
func TestVerifyOSUser_RefusesUserWithoutUid(t *testing.T) {
	saved := userLookupFn
	t.Cleanup(func() { userLookupFn = saved })
	userLookupFn = func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "", Gid: "", HomeDir: "/home/empty-uid"}, nil
	}
	if err := VerifyOSUser("bob"); err == nil {
		t.Fatalf("VerifyOSUser accepted a user with empty Uid")
	}
}

// TestSupported_MatchesGOOS pins the production-support gate:
// Supported() is true on Linux (1.1), false on Darwin (step 5
// says Darwin is "not supported yet"). A regression that
// flipped the answer on either side would mislead
// cmd/iamtunnel's runtime gating.
func TestSupported_MatchesGOOS(t *testing.T) {
	switch runtime.GOOS {
	case "linux":
		if !Supported() {
			t.Fatalf("Supported() = false on linux; SPEC §12 puts linux in 1.1")
		}
	case "darwin":
		if Supported() {
			t.Fatalf("Supported() = true on darwin; step 5 keeps darwin \"not supported yet\"")
		}
	}
}

// TestIsElevated_DoesNotPanic guards the cross-process side:
// IsElevated() must always return (bool, nil) on linux/darwin,
// regardless of euid. Tests cannot exercise the euid==0 path
// safely, but the (false, nil) branch is reachable from the
// test process.
func TestIsElevated_DoesNotPanic(t *testing.T) {
	// Tests run as both root and non-root depending on the runner
	// (Docker/CI is typically root); cover both branches through
	// the geteuidFn seam, since the production IsElevated path
	// is a single-line wrapper around it.
	for _, fake := range []struct {
		name    string
		fakeUID int
		want    bool
	}{
		{"non-root runner sees false", 1000, false},
		{"root runner sees true", 0, true},
	} {
		fake := fake
		t.Run(fake.name, func(t *testing.T) {
			saved := geteuidFn
			t.Cleanup(func() { geteuidFn = saved })
			fakeUID := fake.fakeUID
			geteuidFn = func() int { return fakeUID }

			elevated, err := IsElevated()
			if err != nil {
				t.Fatalf("IsElevated: %v", err)
			}
			t.Logf("IsElevated = %v on %s with fake uid=%d", elevated, runtime.GOOS, fakeUID)
			if elevated != fake.want {
				t.Fatalf("IsElevated = %v, want %v (fake uid=%d)", elevated, fake.want, fakeUID)
			}
		})
	}
}

// TestRelaunch_ReturnsSudoHint is the only Relaunch test:
// Relaunch is a no-op on linux/darwin, and the refusal message
// must mention sudo so an operator reading the failure knows
// exactly what to run.
func TestRelaunch_ReturnsSudoHint(t *testing.T) {
	err := Relaunch([]string{"iamtunnel", "server", "start"}, false)
	if err == nil {
		t.Fatalf("Relaunch must error on linux/darwin")
	}
	if !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("error must mention sudo so the operator knows the fix, got: %v", err)
	}
}
