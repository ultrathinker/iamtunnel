//go:build darwin

package main

// iamt259_chown_darwin_test.go — darwin-only half of the IAMT-259 launchd
// tests: the recursive-chown check (Code-rev round, blocker 1; rewritten in
// IAMT-297 after the first real Mac run) and the helpers it needs, both of
// which exist only on macOS — the production walk itself
// (chownTreeNoFollow, gateway_launchd_darwin.go) and *syscall.Stat_t's
// Uid/Gid fields. Everything else in iamt259 lives in the untagged
// iamt259_launchd_test.go and runs on every host.
//
// Three things were wrong with the version that failed on the Mac (uid 501,
// gid 20, ordinary account), and each one is worth naming because each is a
// different way for a test to look like a check while checking nothing:
//
//   - it read ownership through an interface { Uid() uint32; Gid() uint32 }
//     asserted on Sys(). darwin's *syscall.Stat_t does not implement those
//     methods, so every seeded file failed with "Sys() type *syscall.Stat_t
//     does not implement Uid()/Gid()" — the test had never been able to pass on
//     a Mac. The fields are read directly now (ownerOf);
//   - the walk it exercised was a test-local copy (filepath.Walk +
//     os.Chown) that had drifted from the product: IAMT-291 replaced the
//     production walk with the fd-based, symlink-refusing chownTreeNoFollow.
//     A test that asserts on a copy of the code proves things about the
//     copy; this one now wires the production function into the seam, so
//     what it exercises is what ships;
//   - the ownership assertions could not fail. The seeded files are created
//     by this very process — already uid=501, gid=20 — and the product
//     chowns to (euid, darwinServiceGID=20): the same pair. A non-recursive
//     implementation was indistinguishable from a recursive one, which is
//     exactly what the old comment claimed as its canary.
//
// What it asserts now, and what can actually go red on this kind of account:
//
//   - the product calls chownDir exactly twice — the data directory, then
//     the log directory — in that order. The seam records the paths, so
//     dropping a call or naming a different path reddens it. This is the
//     primary canary, because it is observable no matter who the files
//     belong to;
//   - the production walk accepts a real tree (files, a subdirectory, a file
//     inside it) and returns no error;
//   - recursion is observable because the test first moves two seeded files
//     into ANOTHER group this account belongs to and then requires the walk
//     to put them back into darwinServiceGID. A non-recursive chown leaves
//     the nested file in the old group and reddens the second assertion. If
//     the account has no second group, that part logs why it cannot run and
//     the seam recording above carries the test;
//   - uid is deliberately NOT asserted: chowning to a uid this process does
//     not own is EPERM for a non-root user, so the only other outcome is a
//     walk error, which the install-error assertion already catches.
//
// The test skips under root, where chown changes nothing observable at all
// (and where Mac acceptance testing never runs as root anyway).

import (
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

// ownerOf returns the uid and gid of path straight from the platform's stat:
// macOS's *syscall.Stat_t carries them as fields, and this file is
// darwin-only, so reading them needs no interface assertion (the one that
// broke on the Mac).
func ownerOf(t *testing.T, path string) (uint32, uint32) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s: Sys() type %T, expected *syscall.Stat_t", path, fi.Sys())
	}
	return st.Uid, st.Gid
}

// otherGroup returns a gid this process is a member of, other than the
// service group — the group the test can legally chown a seeded file to in
// order to make the product's walk observable. false when the account has
// no second group.
func otherGroup() (int, bool) {
	gids, err := os.Getgroups()
	if err != nil {
		return 0, false
	}
	for _, g := range gids {
		if g != darwinServiceGID && g > 0 {
			return g, true
		}
	}
	return 0, false
}

func TestIAMT259_ChownDirIsRecursive(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("under root a chown changes nothing: there is nothing to check (macOS acceptance runs from an ordinary account)")
	}

	dataDir := t.TempDir()
	files := []string{"hostkey", "state.json", "bootstrap-token", "enrol-hmac.key"}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dataDir, name), []byte("seed"), 0o600); err != nil {
			t.Fatalf("pre-create %s: %v", name, err)
		}
	}
	subDir := filepath.Join(dataDir, "recordings")
	if err := os.MkdirAll(subDir, 0o700); err != nil {
		t.Fatalf("pre-create recordings: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "x.log"), []byte("seed"), 0o600); err != nil {
		t.Fatalf("pre-create recordings/x.log: %v", err)
	}

	// The only thing an unprivileged user can move is the group: chown
	// to a foreign uid is EPERM, while chgrp to a group the process
	// belongs to is allowed. So two files are moved into another group
	// of this account in advance, and the test requires the walk to
	// return them to the service one: a non-recursive implementation
	// would leave the LOWER file in the old group.
	topAlt, nestedAlt := filepath.Join(dataDir, "state.json"), filepath.Join(subDir, "x.log")
	altGID := 0
	if g, ok := otherGroup(); ok {
		for _, p := range []string{topAlt, nestedAlt} {
			if err := os.Chown(p, os.Geteuid(), g); err != nil {
				t.Fatalf("move %s to group %d: %v", p, g, err)
			}
		}
		altGID = g
		t.Logf("supplementary group %d: the walk must return these files to %d", g, darwinServiceGID)
	} else {
		t.Logf("the account has no second group — recursion is not observable here; the test relies on chownDir recording the paths")
	}

	rec := &launchdRecorder{
		uidsTaken:    map[int]bool{},
		rootResult:   true,
		lookupUID:    os.Geteuid(),
		lookupExists: true,
		loadedRes:    false,
	}
	prevDarwin := rec.setup()

	// setupLaunchdDaemon calls chownDir TWICE: on the data directory
	// (dataDir — the one the assertions below check) and on darwinLogDir
	// (/Library/Logs/iamtunnel). The second call was what failed on the
	// live Mac: makeLogDir no-op'ed here, the log directory did not
	// exist, and a real recursive chown honestly requires an existing
	// path — "lstat /Library/Logs/iamtunnel: no such file". The test has
	// no right to create it (gate 11: a test does not write into the
	// host's system), so the log directory is moved into t.TempDir():
	// makeLogDir creates it there, and chownDir swaps the PRODUCTION
	// path for the temporary one right before the real recursive walk.
	// The walk is the production one (chownTreeNoFollow), and its path
	// is recorded so the assertion below can check both directories.
	// IAMT-297.
	logDir := t.TempDir()
	var chownedPaths []string
	darwinLaunchd = darwinLaunchdSetup{
		currentUserIsRoot: prevDarwin.currentUserIsRoot,
		makeLogDir: func(path string) error {
			// The product names darwinLogDir as its path; create the
			// temporary one and behave as if it were that.
			if path == darwinLogDir {
				return os.MkdirAll(logDir, 0o755)
			}
			return os.MkdirAll(path, 0o755)
		},
		lookupUser:      prevDarwin.lookupUser,
		systemUIDsTaken: prevDarwin.systemUIDsTaken,
		createUser:      prevDarwin.createUser,
		chownDir: func(path string, uid, gid int) error {
			chownedPaths = append(chownedPaths, path)
			if path == darwinLogDir {
				path = logDir
			}
			return chownTreeNoFollow(path, uid, gid)
		},
		writePlist: func(string, []byte, os.FileMode, int, int) error {
			return os.WriteFile(filepath.Join(t.TempDir(), "fake.plist"), nil, 0o644)
		},
		plistExists:   func(string) (bool, error) { return false, nil },
		removePlist:   func(string) error { return nil },
		serviceLoaded: func(string) (bool, error) { return false, nil },
		bootout:       func(string) (bool, error) { return false, nil },
		bootstrap:     func(string) error { return nil },
		// IAMT-308 added this field to darwinLaunchdSetup for the post-
		// bootstrap liveness check (launchdBootstrapTail calls it once
		// after a successful bootstrap); this literal predates that and,
		// left unset, panicked on a nil func call the moment
		// setupLaunchdDaemon reached it — round 2's real-Mac crash was
		// this nil seam field, NOT the parent-directory chmod change
		// (setupLaunchdDaemon/chownTreeNoFollow never go near
		// runGatewayInstall's chmod, and this test calls
		// setupLaunchdDaemon directly).
		serviceRunning: func(string) (bool, error) { return true, nil },
		// parentTraversable is no longer called by setupLaunchdDaemon
		// itself (IAMT-308 round 8 moved that check into
		// preflightGatewayReachability, which this test does not call —
		// it drives setupLaunchdDaemon directly with an already-known
		// uid, exactly as runGatewayInstall does after its own preflight
		// call); kept wired only so an accidental future call never hits
		// the nil-func panic serviceRunning above already guards against.
		parentTraversable: func(string, int, int) error { return nil },
		// ancestorsAreSafe (IAMT-308 round 10) is not reached by this
		// test either (it drives setupLaunchdDaemon directly, never
		// runGatewayInstall's own ancestor check) — wired defensively for
		// the same reason parentTraversable/serviceRunning are above.
		ancestorsAreSafe: func(string) error { return nil },
		// leafIsSafe (IAMT-308 round 11) is not reached by this test
		// either, for the same reason as ancestorsAreSafe just above —
		// wired defensively so an accidental future call never hits a
		// nil-func panic instead of this test's own assertions.
		leafIsSafe: func(string, int) error { return nil },
	}
	defer func() { darwinLaunchd = prevDarwin }()

	if err := setupLaunchdDaemon(darwinLaunchd, "/b/iamtunnel",
		gatewayServiceArguments(dataDir, 2222, "gw.example.test"), dataDir, os.Geteuid()); err != nil {
		t.Fatalf("setupLaunchdDaemon: %v", err)
	}

	// 1. The product must name both directories, in its own order: data,
	// then logs. The main canary lives right here — dropping a call or
	// naming the wrong path.
	if !reflect.DeepEqual(chownedPaths, []string{dataDir, darwinLogDir}) {
		t.Errorf("chownDir must be called on %s and on %s (in that order), got: %v",
			dataDir, darwinLogDir, chownedPaths)
	}

	// 2. Recursion: both files moved into the other group must return to
	// the service one. The lower one is what distinguishes the walk from
	// a single os.Chown on the directory.
	if altGID != 0 {
		if _, g := ownerOf(t, topAlt); g != uint32(darwinServiceGID) {
			t.Errorf("%s: gid=%d, expected %d — the walk did not go through the upper files", topAlt, g, darwinServiceGID)
		}
		if _, g := ownerOf(t, nestedAlt); g != uint32(darwinServiceGID) {
			t.Errorf("%s: gid=%d, expected %d — a non-recursive chown would have left it in group %d",
				nestedAlt, g, darwinServiceGID, altGID)
		}
	}
	// uid is deliberately not checked here (see the file header): under
	// an unprivileged user a chown to a foreign uid is EPERM, so the
	// only other outcome is a walk error, and the setupLaunchdDaemon
	// assertion above would have caught it.
}
