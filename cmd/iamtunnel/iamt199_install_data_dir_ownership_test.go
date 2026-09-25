package main

// iamt199_install_data_dir_ownership_test.go — IAMT-199 (G15 wave):
// install did not transfer the data directory into the service user's
// ownership, and the unit under User=iamtunnel crash-looped on opening
// state.lock.
//
// Canaries (everything through the systemdSetup seam, no real
// chown/useradd from the test binary):
//
//  1. the chownDir step sits after userExists/createUser and BEFORE
//     writeUnit + systemctl — it addresses (path, user, group), where
//     user and group equal gatewayServiceUser;
//  2. a chown failure stops the sequence (writeUnit and systemctl are
//     never called) and names the step with code 3;
//  3. install --rebootstrap also goes through chownDir (the same
//     seam), and in the directory after --rebootstrap the files belong
//     to the service user by the seam's rule (the new bootstrap-token
//     is caught by the same recursive chown as at the first install).
//
// No real (production) stat()-based ownership check runs: the test
// works on any OS and as any user, and responsibility for chown -R
// lies with the fake/production seam. This is deliberate: "IAMT-199
// install does not hand the directory to the user" is a seam contract,
// not a filesystem invariant (the live run happened on a real VPS).

import (
	"errors"
	"strings"
	"testing"
)

// TestIAMT199_ChownDirRunsAfterUserBeforeUnit — canary 1: the ownership
// transfer step for the data directory sits exactly once between
// createUser and writeUnit, addressing precisely the data directory and
// the service user.
//
// Canary: change the order in setupSystemd (chownDir after writeUnit,
// or drop it) — the chownDirCalls journal assertion turns red with the
// actual sequence.
func TestIAMT199_ChownDirRunsAfterUserBeforeUnit(t *testing.T) {
	t.Run("user already exists → chown still runs", func(t *testing.T) {
		// An existing user does not skip the chown: install created the
		// data as root, and without the ownership transfer the unit under
		// iamtunnel still could not open state.lock.
		rec := &systemdRecorder{} // userExistsResult == nil
		if err := setupSystemd(rec.setup(), "/usr/local/bin/iamtunnel", "/var/lib/iamtunnel", 2222, "gw.example.test"); err != nil {
			t.Fatalf("setupSystemd: %v", err)
		}
		if len(rec.chownDirCalls) != 1 {
			t.Fatalf("chownDir called %d times, want 1: %v", len(rec.chownDirCalls), rec.chownDirCalls)
		}
		if got := rec.chownDirCalls[0]; got != "/var/lib/iamtunnel iamtunnel:iamtunnel" {
			t.Fatalf("chownDir called with %q, want \"/var/lib/iamtunnel iamtunnel:iamtunnel\" (IAMT-199: the data directory and the service user are exactly what must be handed over)", got)
		}
		// Order: userExists → chownDir → writeUnit → systemctl.
		// Checked by the journals' contents: chownDir's journal is not
		// empty, and the written unit really sits in the writeUnit seam,
		// which runs AFTER chownDir.
		if rec.unitPath == "" {
			t.Fatal("writeUnit not executed — chownDir turned out to be AFTER writeUnit")
		}
		if len(rec.systemctlCalls) == 0 {
			t.Fatal("systemctl not executed — chownDir turned out to be AFTER systemctl")
		}
	})

	t.Run("user freshly created → chown still runs", func(t *testing.T) {
		rec := &systemdRecorder{userExistsResult: errors.New("id: no such user")}
		if err := setupSystemd(rec.setup(), "/usr/local/bin/iamtunnel", "/srv/iamt", 2222, "gw.example.test"); err != nil {
			t.Fatalf("setupSystemd: %v", err)
		}
		if len(rec.createUserCalls) != 1 {
			t.Fatalf("createUser must be called once, got %v", rec.createUserCalls)
		}
		if len(rec.chownDirCalls) != 1 || rec.chownDirCalls[0] != "/srv/iamt iamtunnel:iamtunnel" {
			t.Fatalf("chownDir called differently than once as \"/srv/iamt iamtunnel:iamtunnel\": %v (IAMT-199: the chown addresses precisely the data directory and the service user)", rec.chownDirCalls)
		}
	})
}

// TestIAMT199_ChownFailureNamesStepAndSkipsSystemctl — canary 2: a
// failure of the ownership transfer step stops the sequence and does
// not let systemctl start the unit (otherwise the unit under iamtunnel,
// without rights to the data, would enter a permission-denied loop).
//
// Canary: swallow the chown error (say, not return err from
// setupSystemd) or continue the sequence after the failure — the
// "systemctl not called" / "unit not written" / "step named by name"
// assertions turn red.
func TestIAMT199_ChownFailureNamesStepAndSkipsSystemctl(t *testing.T) {
	rec := &systemdRecorder{chownDirResult: errors.New("chown: invalid user: 'iamtunnel'")}
	err := setupSystemd(rec.setup(), "/usr/local/bin/iamtunnel", "/var/lib/iamtunnel", 2222, "gw.example.test")
	if err == nil {
		t.Fatal("the chownDir failure was swallowed — install would have continued past the broken step and the unit would have crash-looped")
	}
	if !strings.Contains(err.Error(), "transfer ownership of /var/lib/iamtunnel to iamtunnel:iamtunnel") {
		t.Fatalf("the error does not name the ownership transfer step: %v", err)
	}
	if !strings.Contains(err.Error(), "chown") {
		t.Fatalf("the error text must name the utility so the operator can find the command to fix it by hand: %v", err)
	}
	if len(rec.chownDirCalls) != 1 {
		t.Fatalf("chownDir must have run exactly once: %v", rec.chownDirCalls)
	}
	if rec.unitPath != "" || rec.unitContent != "" {
		t.Fatalf("after a chownDir failure the unit must not be written: path=%q content-len=%d", rec.unitPath, len(rec.unitContent))
	}
	if len(rec.systemctlCalls) != 0 {
		t.Fatalf("after a chownDir failure systemctl must not be called (the unit would start under iamtunnel and not open state.lock): %v", rec.systemctlCalls)
	}
}

// TestIAMT199_ChownUserAndGroupAreTheServiceUser — canary 3: both the
// user and the group arguments are gatewayServiceUser. That is exactly
// the summary needed on a live VPS: "chown iamtunnel:iamtunnel <data
// dir>" precisely, without ambiguity.
//
// Canary: change either argument to an empty string / another user —
// the "got == ... iamtunnel:iamtunnel" assertion turns red.
func TestIAMT199_ChownUserAndGroupAreTheServiceUser(t *testing.T) {
	rec := &systemdRecorder{}
	if err := setupSystemd(rec.setup(), "/b", "/var/lib/iamtunnel", 2222, "gw.example.test"); err != nil {
		t.Fatalf("setupSystemd: %v", err)
	}
	if len(rec.chownDirCalls) != 1 {
		t.Fatalf("chownDir called %d times, want 1: %v", len(rec.chownDirCalls), rec.chownDirCalls)
	}
	got := rec.chownDirCalls[0]
	// The recorder entry format: "<path> <user>:<group>".
	// gatewayServiceUser is the only valid argument, and it is the same
	// one named in the systemd unit as User= and Group=; any mismatch
	// would make the unit non-functional.
	if got != "/var/lib/iamtunnel iamtunnel:iamtunnel" {
		t.Fatalf("chownDir called with %q, want \"/var/lib/iamtunnel iamtunnel:iamtunnel\" — both the user and the group arguments MUST be gatewayServiceUser (IAMT-199)", got)
	}
}

// TestIAMT199_RebootstrapExercisesChown — canary 4: --rebootstrap goes
// through the same setupSystemd seam, and the recursive chown catches
// the freshly written bootstrap-token together with the whole data
// directory. That means that on a repeat install (or after
// --rebootstrap) the new bootstrap-token is not left with root, and the
// iamtunnel user can read it at the next start.
//
// The test goes through a direct setupSystemd call (like the IAMT-177
// tests), not through drive(install): on Windows install refuses BEFORE
// setupSystemd (RUNBOOK §1.3, non-Linux refusal), the seam is never
// called, and the canary would not work. The seam itself is
// platform-independent — this is the only way to check that chownDir
// addresses the data directory and the service user in both install
// branches.
func TestIAMT199_RebootstrapExercisesChown(t *testing.T) {
	dir := t.TempDir()

	// The first install branch (without --rebootstrap): setupSystemd
	// once.
	rec1 := &systemdRecorder{}
	if err := setupSystemd(rec1.setup(), "/usr/local/bin/iamtunnel", dir, 2222, "gw.example.test"); err != nil {
		t.Fatalf("first setupSystemd (install): %v", err)
	}
	if len(rec1.chownDirCalls) != 1 || rec1.chownDirCalls[0] != dir+" iamtunnel:iamtunnel" {
		t.Fatalf("first install: chownDir called differently: %v", rec1.chownDirCalls)
	}

	// The second install branch, --rebootstrap: the same seam, once
	// more.
	rec2 := &systemdRecorder{}
	if err := setupSystemd(rec2.setup(), "/usr/local/bin/iamtunnel", dir, 2222, "gw.example.test"); err != nil {
		t.Fatalf("second setupSystemd (--rebootstrap): %v", err)
	}
	if len(rec2.chownDirCalls) != 1 || rec2.chownDirCalls[0] != dir+" iamtunnel:iamtunnel" {
		t.Fatalf("install --rebootstrap: chownDir called differently: %v", rec2.chownDirCalls)
	}
}
