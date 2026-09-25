package gateway

// testhelpers_test.go: tiny package-private helpers shared by this
// package's *_test.go files, mirroring the discipline
// internal/server/testhelpers_test.go establishes for its own fixtures.
// Nothing here touches a real filesystem path outside t.TempDir(), a
// real sshd, or a real network interface other than 127.0.0.1; the
// only non-test seam it exposes is testUIDForDoor()/testGIDForDoor(),
// which are the
// "what uid should I tell winkeys the key file is owned by" hook for
// every server.Config literal this package builds — see
// iamt198ServerConfig (iamt198_hostkey_rotation_pin_test.go) and
// startRealMachineMode (real_machine_test.go). The hostkey-rotation
// pin test (IAMT-198) and the real-machine harness are both
// end-to-end-style fixtures that dial the gateway from server.Run /
// a real subprocess and therefore reach winkeys.NewDoorWithOptions;
// without OwnerUID/OwnerGID set, validateOptionsPlatform on
// linux/darwin refuses the call with the winkeys unset-owner sentinel
// before the test's own assertions ever run.

import "os"

// testUIDForDoor and testGIDForDoor return the owner winkeys should treat
// the door line as having for unit tests in this package. The winkeys
// strict-mode preflight accepts owner == opts.OwnerUID OR owner == 0, so a
// concrete non-root owner keeps the t.TempDir()-rooted tree valid in both
// runner shapes this package is exercised under:
//
//   - non-root runner: the temp tree is owned by this very process, which
//     is exactly what comes back here — the "owner matches" branch passes,
//     and fchownIfRoot skips the chown (owner already right, non-root
//     cannot chown anyway);
//
//   - root runner (the docker root lane): os.Getuid() would be 0, and
//     DoorOptions{0, 0} is the winkeys unset-owner sentinel —
//     validateOptionsPlatform refuses it outright and fchownIfRoot refuses
//     it too, so passing 0 through would fail every door test before any
//     filesystem work. Under root both helpers return the fixed 1000
//     instead: the temp tree is still root-owned and passes through the
//     preflight's "or root" branch, and the door layer's chown step is a
//     recording seam in this test binary, so nothing is really chowned to
//     1000.
//
// IAMT-284: this used to be one value used for both fields — a shape that
// quietly claimed uid == gid. It holds in the Linux container this suite
// grew up in and nowhere else: on the real macOS runner uid=501 but gid=20
// (staff), and (501, 501) is a group the user does not belong to, so
// fchownIfRoot refused it. The ids come from the account, not from a
// convention; the same correction was made in internal/server and
// internal/winkeys.
func testUIDForDoor() int {
	if uid := os.Getuid(); uid > 0 {
		return uid
	}
	return 1000
}

func testGIDForDoor() int {
	if gid := os.Getgid(); gid > 0 {
		return gid
	}
	return 1000
}
