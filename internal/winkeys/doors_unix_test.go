//go:build linux || darwin

// Unix-platform tests for the winkeys layer-0 door primitives
// (SPEC §3.2.1 rules 1–5, IAMT-246 fix1). Two layers:
//
//   - Unit tests (the bulk of this file): every syscall the door
//     layer issues is wrapped by a seam (chmodFnFD / chownFnFD);
//     unit tests replace those seams with recording stubs in init()
//     so a Test under `go test ./...` never touches the real
//     filesystem, the real user database, or the real flock state.
//     This is the gate-11 invariant.
//
//   - Integration tests (TestIntegrationDoorOnRealSyscalls*): run
//     real syscalls in t.TempDir() under the *real* seam defaults.
//     They are guarded by a build-tag-and-euid check so they only
//     fire when the test process is not running as root; the
//     intent is exactly the IAMT-269 lesson — testing through a
//     recording seam would let a Fchmodat(AT_FDCWD) bug (the one
//     flagged in review) hide behind the fake. The integration tests
//     chdir outside .ssh before invoking writeAtomicBytesPlatform,
//     and they look at the on-disk inode / mode / owner after the
//     call to assert the syscall side effects directly.
//
// The forbidden substrings (TestAcceptance_NoKeyFileConstant):
// no string literal in any .go file under this package contains
// the literal "authorized_keys", "administrators_authorized_keys",
// "/etc/ssh", "C:\ssh" or "ProgramData". The basename of the key
// file is computed at runtime from filepath.Base(keyFile); error
// messages that need to refer to it use the runtime-derived
// basename.

package winkeys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// ─── seams used by unit tests ──────────────────────────────────────────

// The recording stubs themselves (installRecordingSeams, the
// chownFDCalls/chmodFDCalls slices) live in
// seams_record_unix.go — a non-test file, because internal/server's
// test binary installs the same stubs through the exported
// SetRecordingSeamsForTest hook and a _test.go file cannot be
// imported. This file's init() installs them for this package's
// own unit tests; the integration tests swap them to real impls.

func init() {
	// Default to recording seams — the unit tests want this.
	// Integration tests swap them to real impls.
	installRecordingSeams()
}

// installRealImplSeams swaps the seams to their production
// (real-syscall) versions for the duration of t. The defer'd
// restore brings the recording stubs back so a following unit
// test is not affected by side-effects of the integration test.
func installRealImplSeams(t *testing.T) {
	t.Helper()
	saved := swapSeams(Seams{
		ChmodFD: realChmodFnFD,
		ChownFD: realChownFnFD,
	})
	t.Cleanup(func() {
		saved()
		installRecordingSeams()
	})
}

func resetSeamLogs(t *testing.T) {
	t.Helper()
	seamMu.Lock()
	chownFDCalls = nil
	chmodFDCalls = nil
	seamMu.Unlock()
	t.Cleanup(func() {
		seamMu.Lock()
		chownFDCalls = nil
		chmodFDCalls = nil
		seamMu.Unlock()
	})
}

func seamChownCalls() []chownFDCall {
	seamMu.Lock()
	defer seamMu.Unlock()
	out := make([]chownFDCall, len(chownFDCalls))
	copy(out, chownFDCalls)
	return out
}

func seamChmodCalls() []chmodFDCall {
	seamMu.Lock()
	defer seamMu.Unlock()
	out := make([]chmodFDCall, len(chmodFDCalls))
	copy(out, chmodFDCalls)
	return out
}

// ─── helpers ───────────────────────────────────────────────────────────

// testUID/testGID are the ids the tests drive the door with — the ids of
// the process running them (IAMT-284/IAMT-294: the fixtures used to
// hardcode 1000/1000, which only matches a Linux container; see
// testOwnerUID in doors_test.go for the whole story). They are variables
// rather than constants precisely because they are now a fact of the runner.
var (
	testUID = testOwnerUID()
	testGID = testOwnerGID()
)

// newUnixDoor returns a Door with a sensible Unix-shaped
// DoorOptions: a LockPath in the same TempDir and the test
// uid/gid as the file owner. Tests that need different owners
// pass a custom opts to NewDoorWithOptions directly.
func newUnixDoor(t *testing.T, keyFile string) *Door {
	t.Helper()
	d, err := NewDoorWithOptions(keyFile, nil, DoorOptions{
		LockPath: keyFile + ".door.lock",
		OwnerUID: testUID,
		OwnerGID: testGID,
	})
	if err != nil {
		t.Fatalf("NewDoorWithOptions: %v", err)
	}
	return d
}

// ─── constructor / validation ─────────────────────────────────────────

// TestNewDoorWithOptions_RefusesEmptyLockPath pins the contract:
// a Linux/Darwin Door without a LockPath cannot be built.
func TestNewDoorWithOptions_RefusesEmptyLockPath(t *testing.T) {
	_, err := NewDoorWithOptions("/tmp/somewhere/auth_keys", nil, DoorOptions{OwnerUID: testUID, OwnerGID: testGID})
	if err == nil {
		t.Fatalf("NewDoorWithOptions without LockPath must error on linux/darwin")
	}
	if !strings.Contains(err.Error(), "LockPath is required") {
		t.Fatalf("error message must explain the requirement, got: %v", err)
	}
}

// TestNewDoorWithOptions_RefusesZeroZeroOwner pins the second
// half of the contract: opts.OwnerUID/OwnerGID both zero is the
// "not resolved" sentinel and is rejected.
func TestNewDoorWithOptions_RefusesZeroZeroOwner(t *testing.T) {
	_, err := NewDoorWithOptions("/tmp/x/auth_keys", nil, DoorOptions{LockPath: "/tmp/x/door.lock"})
	if err == nil {
		t.Fatalf("NewDoorWithOptions without owner must error")
	}
}

// TestValidateOptions_AcceptsSensibleValues is the happy path of
// the constructor's gate. The owner is the pair the tests above
// actually install for — this process's own uid and gid, which is
// the shape production resolves from the OS user database too
// (uid and gid are independent; only a Linux container makes them
// equal — IAMT-284).
func TestValidateOptions_AcceptsSensibleValues(t *testing.T) {
	if err := validateOptions(DoorOptions{
		LockPath: "/var/lib/iamtunnel-machine/door.lock",
		OwnerUID: testUID,
		OwnerGID: testGID,
	}); err != nil {
		t.Fatalf("validateOptions refused a sensible value: %v", err)
	}
}

// ─── flock-based file lock ────────────────────────────────────────────

// TestAcquireFileLock_RejectsEmptyPath guards the platform layer.
func TestAcquireFileLock_RejectsEmptyPath(t *testing.T) {
	if _, err := AcquireFileLock(""); err == nil {
		t.Fatalf("AcquireFileLock(\"\") must error")
	}
}

// TestAcquireFileLock_ExcludesSecondHolderInSameProcess pins
// rule 1 of SPEC §3.2.1: two Doors holding the same lockPath in
// the same process exclude each other.
func TestAcquireFileLock_ExcludesSecondHolderInSameProcess(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "door.lock")

	first, err := AcquireFileLock(lockPath)
	if err != nil {
		t.Fatalf("first AcquireFileLock: %v", err)
	}
	defer first.Release()

	second, err := AcquireFileLock(lockPath)
	if err == nil {
		_ = second.Release()
		t.Fatalf("second AcquireFileLock succeeded while first held the lock — flock is not excluding")
	}
	if !strings.Contains(err.Error(), "held by another writer") {
		t.Fatalf("error must name the cause, got: %v", err)
	}
}

// TestAcquireFileLock_ReleasesOnClose covers the half of rule 1
// that does not depend on a stuck second holder.
func TestAcquireFileLock_ReleasesOnClose(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "door.lock")

	first, err := AcquireFileLock(lockPath)
	if err != nil {
		t.Fatalf("first AcquireFileLock: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	second, err := AcquireFileLock(lockPath)
	if err != nil {
		t.Fatalf("second AcquireFileLock after Release: %v", err)
	}
	defer second.Release()
}

// TestAcquireFileLock_DifferentPathsCoexist is the
// counter-evidence: two Doors on DIFFERENT lock paths do not
// exclude each other.
func TestAcquireFileLock_DifferentPathsCoexist(t *testing.T) {
	dir := t.TempDir()
	a, err := AcquireFileLock(filepath.Join(dir, "a.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release()
	b, err := AcquireFileLock(filepath.Join(dir, "b.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release()
}

// ─── chownIfRoot (the only chown seam caller) ─────────────────────────

// TestFchownIfRoot_RejectsNegative guards the seam itself: a
// negative uid or gid must surface as an explicit error.
func TestFchownIfRoot_RejectsNegative(t *testing.T) {
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := fchownIfRoot(fd, -1, 1000); err == nil {
		t.Fatalf("fchown with negative uid must error")
	}
}

// TestFchownIfRoot_RejectsZeroZero guards the "not resolved"
// sentinel: OwnerUID=0 AND OwnerGID=0 is unset; chowning to
// 0:0 would silently land on root.
func TestFchownIfRoot_RejectsZeroZero(t *testing.T) {
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	err = fchownIfRoot(fd, 0, 0)
	if err == nil {
		t.Fatalf("fchown with uid/gid both 0 must error")
	}
	if !strings.Contains(err.Error(), "refusing to chown to uid=0,gid=0") {
		t.Fatalf("error must explain the sentinel, got: %v", err)
	}
}

// TestFchownIfRoot_RecordsCalls is the audit-trail check: when
// fchownIfRoot accepts (root path), the chownFnFD seam receives
// exactly one (fd, uid, gid) call. The test exercises the
// "root changes owner" hook from IAMT-269 — the seam is the
// only thing the door uses to change a file's owner. Skipped
// when the test process is not root (a non-root runner cannot
// chown to uid 1234 even at the seam level, since fchownIfRoot
// refuses the call before the seam; the integration test
// TestIntegrationDoorOnRealSyscalls_* covers the running-as-self
// path).
func TestFchownIfRoot_RecordsCalls(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skipf("fchownIfRoot refuses under non-root (current euid=%d) — integration test covers the running-as-self path", unix.Geteuid())
	}
	resetSeamLogs(t)
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := fchownIfRoot(fd, 1234, 5678); err != nil {
		t.Fatalf("fchown refused: %v", err)
	}
	calls := seamChownCalls()
	if len(calls) != 1 {
		t.Fatalf("chownFnFD recorded %d calls, want 1: %+v", len(calls), calls)
	}
	if calls[0].UID != 1234 || calls[0].GID != 5678 {
		t.Fatalf("chown saw %d:%d, want 1234:5678", calls[0].UID, calls[0].GID)
	}
}

// ─── chmodFn / chownFn (path-based — kept for LockDownFileACL etc) ──

// TestChmodFn_PathIsForwardedUntouched covers the path-based
// seam surface. With installRecordingSeams in init() now also
// replacing the path-based seam, calling chmodFn records a
// single (FD=-1, mode) entry in the chmodFDCalls slice — a
// negative fd is the convention for "this came from the
// path-based seam, not the fd-based one".
func TestChmodFn_PathIsForwardedUntouched(t *testing.T) {
	resetSeamLogs(t)
	if err := chmodFn("/some/path", 0o755); err != nil {
		t.Fatalf("chmodFn: %v", err)
	}
	calls := seamChmodCalls()
	if len(calls) != 1 {
		t.Fatalf("chmodFn recorded %d calls, want 1: %+v", len(calls), calls)
	}
	if calls[0].FD != -1 {
		t.Fatalf("chmodFn's path-based seam should record FD=-1 (the path-based-vs-fd-based marker); got %d", calls[0].FD)
	}
	if calls[0].Mode != 0o755 {
		t.Fatalf("chmodFn recorded mode %o, want 0o755", calls[0].Mode)
	}
}

// seamChmodFDCalls returns the fd-seam log specifically. The
// path-based and fd-based chmod seams share the same slice (FD=-1
// marks a path-based call, otherwise the fd is the literal); a
// separate getter is kept for callers that want to assert "only fd
// calls landed".
func seamChmodFDCalls() []chmodFDCall {
	return seamChmodCalls()
}

var _ = seamChmodFDCalls // keep referenced even when no test asserts on it today

// ─── lock + door serialisation across goroutines ──────────────────────

// TestConcurrentDoors_LockSerialisesAcrossGoroutines is the
// in-process analogue of the cross-process lock test: two
// goroutines hammer Install on Doors that share a lockPath.
// Under recording seams the door write succeeds; the test
// asserts that the file always contains exactly one door line
// (not zero, not two) after the storm.
func TestConcurrentDoors_LockSerialisesAcrossGoroutines(t *testing.T) {
	resetSeamLogs(t)
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("auth_keys")
	lockPath := filepath.Join(tree.Home, "door.lock")
	a, err := NewDoorWithOptions(keyFile, nil, DoorOptions{LockPath: lockPath, OwnerUID: testUID, OwnerGID: testGID})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDoorWithOptions(keyFile, nil, DoorOptions{LockPath: lockPath, OwnerUID: testUID, OwnerGID: testGID})
	if err != nil {
		t.Fatal(err)
	}

	id := "0123456789abcdef0123456789abcdef"
	var wg sync.WaitGroup
	var errA, errB error
	const cycles = 50
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < cycles; i++ {
			if err := a.Install(id, TestKey); err != nil {
				errA = err
				return
			}
			runtime.Gosched()
			if err := a.Remove(id); err != nil {
				errA = err
				return
			}
			runtime.Gosched()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < cycles; i++ {
			if err := b.Install(id, TestKey); err != nil {
				errB = err
				return
			}
			runtime.Gosched()
			if err := b.Remove(id); err != nil {
				errB = err
				return
			}
			runtime.Gosched()
		}
	}()
	wg.Wait()
	if errA != nil {
		t.Fatalf("writer A: %v", errA)
	}
	if errB != nil {
		t.Fatalf("writer B: %v", errB)
	}
	lines, err := readLinesLocked(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, l := range lines {
		if IsOursID(l, id) {
			count++
		}
	}
	if count != 0 {
		t.Fatalf("expected zero iamtunnel lines after interleaved Install/Remove, got %d", count)
	}
}

// TestInstallCallsChmodFDWithMode0600 is the audit story at the
// public-API level: Install goes through writeAtomicBytesPlatform
// which calls chmodFnFD with mode 0600 on the tmp fd. Under
// recording seams, every recorded chmod is 0600.
func TestInstallCallsChmodFDWithMode0600(t *testing.T) {
	resetSeamLogs(t)
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("auth_keys")
	d := newUnixDoor(t, keyFile)
	if err := d.Install("0123456789abcdef0123456789abcdef", TestKey); err != nil {
		t.Fatalf("Install: %v", err)
	}
	calls := seamChmodCalls()
	if len(calls) == 0 {
		t.Fatalf("chmodFnFD recorded zero calls — Install did not fchmod the tmp")
	}
	for _, c := range calls {
		if c.Mode != 0o600 {
			t.Fatalf("Install triggered fchmod with mode %o, want 0o600: %+v", c.Mode, c)
		}
	}
}

// TestInstallCallsChownFDWithOwnerUIDAndGID covers the second
// half: every Install must reach the chownFnFD seam with
// opts.OwnerUID/OwnerGID. Skipped under non-root: when the test
// process's euid equals OwnerUID (e.g. uid 1000), fchownIfRoot
// is a no-op (the file already has the right owner) and the
// seam is not called. The integration test covers the
// running-as-self path with real syscalls.
func TestInstallCallsChownFDWithOwnerUIDAndGID(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skipf("chownFnFD only fires when the test process is root (current euid=%d); the non-root integration test TestIntegrationDoorOnRealSyscalls_CanaryDoorID covers the running-as-self path", unix.Geteuid())
	}
	resetSeamLogs(t)
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("auth_keys")
	d := newUnixDoor(t, keyFile)
	if err := d.Install("0123456789abcdef0123456789abcdef", TestKey); err != nil {
		t.Fatalf("Install: %v", err)
	}
	calls := seamChownCalls()
	if len(calls) == 0 {
		t.Fatalf("chownFnFD recorded zero calls — Install did not fchown the tmp")
	}
	for _, c := range calls {
		if c.UID != testUID || c.GID != testGID {
			t.Fatalf("Install triggered fchown with %d:%d, want %d:%d", c.UID, c.GID, testUID, testGID)
		}
	}
}

// TestInstallSurfacesChownFailure makes sure the seam
// short-circuit returns up through writeAtomicBytes.
//
// The chownFnFD seam is reachable only under root: fchownIfRoot
// (the IAMT-269 hook) resolves the non-root case entirely on its
// own. The tmp file is created by this very process, so under
// non-root its owner already equals the requested owner and the
// function returns nil before the seam; a requested owner that
// differs fails with the explicit "non-root process cannot chown"
// refusal instead of the seam's error. No DoorOptions owner choice
// can therefore surface the seam's failure as non-root — the same
// root-only seam contract TestInstallCallsChownFDWithOwnerUIDAndGID
// skips on. The running-as-self path is covered by the integration
// tests with real syscalls.
func TestInstallSurfacesChownFailure(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skipf("chownFnFD is only reachable as root — fchownIfRoot returns before the seam under non-root (current euid=%d)", unix.Geteuid())
	}
	resetSeamLogs(t)
	saved := chownFnFD
	chownFnFD = func(int, int, int) error { return errors.New("fake chown failure") }
	t.Cleanup(func() { chownFnFD = saved })

	tree := testsupport.NewSSHTree(t)
	d := newUnixDoor(t, tree.KeyPath("auth_keys"))
	err := d.Install("0123456789abcdef0123456789abcdef", TestKey)
	if err == nil {
		t.Fatalf("Install did not surface chown failure")
	}
	if !strings.Contains(err.Error(), "fake chown failure") {
		t.Fatalf("Install error does not name the chown failure: %v", err)
	}
}

// TestSupported_TrueOnLinuxDarwin pins the production-support gate.
func TestSupported_TrueOnLinuxDarwin(t *testing.T) {
	if !Supported() {
		t.Fatalf("Supported() = false on %s; SPEC §12 puts linux in 1.1", runtime.GOOS)
	}
}

// TestReadDACL_ReturnsEmptyList is the cross-platform stub's
// promise: there is no DACL on Linux/Darwin.
func TestReadDACL_ReturnsEmptyList(t *testing.T) {
	out, err := ReadDACL(t.TempDir())
	if err != nil {
		t.Fatalf("ReadDACL: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("ReadDACL on Unix returned %v, want nil", out)
	}
}

// TestDACLProtected_ReturnsFalse is the cross-platform stub's
// promise.
func TestDACLProtected_ReturnsFalse(t *testing.T) {
	prot, err := DACLProtected(t.TempDir())
	if err != nil {
		t.Fatalf("DACLProtected: %v", err)
	}
	if prot {
		t.Fatalf("DACLProtected on Unix returned true, want false")
	}
}

// ─── cross-platform smoke ──────────────────────────────────────────────

// makeSSHTree sets up a fake `home/.ssh/auth_keys` tree for the
// strict-mode tests using testsupport.NewSSHTree (explicit 0700 modes,
// immune to process umask).
func makeSSHTree(t *testing.T) (home, sshDir, authKeys string) {
	t.Helper()
	tree := testsupport.NewSSHTree(t)
	return tree.Home, tree.SSHDir, tree.KeyPath("auth_keys")
}

// setMode sets the file's mode via real os.Chmod (no seam —
// these are test-data setup, not the door's production path).
func setMode(t *testing.T, path string, mode uint32) {
	t.Helper()
	if err := os.Chmod(path, os.FileMode(mode)); err != nil {
		t.Fatal(err)
	}
}

// ─── symlink / strict-mode tests via the openat-based preflight ──────

// TestStrictPreflight_RejectsSymlinkedSSHDir is rule 2's first
// half: a symlinked .ssh is refused.
func TestStrictPreflight_RejectsSymlinkedSSHDir(t *testing.T) {
	resetSeamLogs(t)
	home, _, _ := makeSSHTree(t)
	target := t.TempDir()
	if err := os.Remove(filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	err := writeAtomicBytesPlatform(
		filepath.Join(home, ".ssh", "auth_keys"),
		[]byte("seed"),
		DoorOptions{LockPath: filepath.Join(t.TempDir(), "door.lock"), OwnerUID: testUID, OwnerGID: testGID},
	)
	if err == nil {
		t.Fatalf("writeAtomicBytesPlatform accepted a symlinked .ssh — SPEC §3.2.1 rule 2 was bypassed")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("error must name the cause, got: %v", err)
	}
}

// TestStrictPreflight_RejectsSymlinkedAuthorizedKeys is rule 2's
// second half.
func TestStrictPreflight_RejectsSymlinkedAuthorizedKeys(t *testing.T) {
	resetSeamLogs(t)
	_, sshDir, _ := makeSSHTree(t)
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "realfile"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(target, "realfile"), filepath.Join(sshDir, "auth_keys")); err != nil {
		t.Fatal(err)
	}
	err := writeAtomicBytesPlatform(
		filepath.Join(sshDir, "auth_keys"),
		[]byte("seed"),
		DoorOptions{LockPath: filepath.Join(t.TempDir(), "door.lock"), OwnerUID: testUID, OwnerGID: testGID},
	)
	if err == nil {
		t.Fatalf("writeAtomicBytesPlatform accepted a symlinked auth_keys")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("error must name the cause, got: %v", err)
	}
}

// TestStrictPreflight_RefusesGroupWritableSSHDir is rule 4's
// first half.
func TestStrictPreflight_RefusesGroupWritableSSHDir(t *testing.T) {
	resetSeamLogs(t)
	_, sshDir, _ := makeSSHTree(t)
	setMode(t, sshDir, 0o770)
	err := writeAtomicBytesPlatform(
		filepath.Join(sshDir, "auth_keys"),
		[]byte("seed"),
		DoorOptions{LockPath: filepath.Join(t.TempDir(), "door.lock"), OwnerUID: testUID, OwnerGID: testGID},
	)
	if err == nil {
		t.Fatalf("writeAtomicBytesPlatform accepted group-writable .ssh")
	}
	if !strings.Contains(err.Error(), "group- or world-writable") || !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("error must name the cause and the fix, got: %v", err)
	}
}

// TestStrictPreflight_RefusesWorldWritableSSHDir is the
// world-writable half.
func TestStrictPreflight_RefusesWorldWritableSSHDir(t *testing.T) {
	resetSeamLogs(t)
	_, sshDir, _ := makeSSHTree(t)
	setMode(t, sshDir, 0o707)
	err := writeAtomicBytesPlatform(
		filepath.Join(sshDir, "auth_keys"),
		[]byte("seed"),
		DoorOptions{LockPath: filepath.Join(t.TempDir(), "door.lock"), OwnerUID: testUID, OwnerGID: testGID},
	)
	if err == nil {
		t.Fatalf("writeAtomicBytesPlatform accepted world-writable .ssh")
	}
}

// TestStrictPreflight_RefusesGroupWritableAuthorizedKeys covers
// the file variant.
func TestStrictPreflight_RefusesGroupWritableAuthorizedKeys(t *testing.T) {
	resetSeamLogs(t)
	_, _, authKeys := makeSSHTree(t)
	if err := os.WriteFile(authKeys, []byte("seed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setMode(t, authKeys, 0o660)
	err := writeAtomicBytesPlatform(authKeys, []byte("new content"), DoorOptions{LockPath: filepath.Join(t.TempDir(), "door.lock"), OwnerUID: testUID, OwnerGID: testGID})
	if err == nil {
		t.Fatalf("writeAtomicBytesPlatform accepted group-writable auth_keys")
	}
	if !strings.Contains(err.Error(), "group- or world-writable") {
		t.Fatalf("error must name the cause, got: %v", err)
	}
}

// TestStrictPreflight_CreatesMissingSSHDir covers rule 3's
// second half: a missing .ssh is created with mode 0700 by the
// door write.
func TestStrictPreflight_CreatesMissingSSHDir(t *testing.T) {
	resetSeamLogs(t)
	home := testsupport.NewFakeHome(t)
	authKeys := filepath.Join(home, ".ssh", "auth_keys")
	if err := writeAtomicBytesPlatform(authKeys, []byte("seed line\n"), DoorOptions{LockPath: filepath.Join(t.TempDir(), "door.lock"), OwnerUID: testUID, OwnerGID: testGID}); err != nil {
		t.Fatalf("writeAtomicBytesPlatform refused to create .ssh: %v", err)
	}
	info, err := os.Stat(filepath.Join(home, ".ssh"))
	if err != nil {
		t.Fatalf(".ssh was not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf(".ssh is not a directory")
	}
}

// TestStrictPreflight_PassesValidTree is the happy path.
func TestStrictPreflight_PassesValidTree(t *testing.T) {
	resetSeamLogs(t)
	_, _, authKeys := makeSSHTree(t)
	if err := writeAtomicBytesPlatform(authKeys, []byte("seed line\n"), DoorOptions{LockPath: filepath.Join(t.TempDir(), "door.lock"), OwnerUID: testUID, OwnerGID: testGID}); err != nil {
		t.Fatalf("writeAtomicBytesPlatform refused a valid tree: %v", err)
	}
	got, err := os.ReadFile(authKeys)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "seed line\n" {
		t.Fatalf("content: got %q, want %q", got, "seed line\n")
	}
}

// TestInstallOnUnix_ThirdPartyLinesByteForByte covers rule 5:
// stranger lines are preserved byte-for-byte and in their original
// relative order (PROTOCOL §5.1: "all other existing lines
// ... are preserved byte-for-byte and in the prior order"). The protocol
// pins preservation and order of the EXISTING lines only — it says
// nothing about where the added door line lands. On a file whose
// final stranger line has no terminator (this fixture)
// appendDoorLine deliberately PREPENDS the door line instead of
// manufacturing a line terminator the stranger never wrote: such a
// terminator would survive a later Remove and permanently alter the
// third-party bytes, which the protocol does forbid. The
// end-to-end invariants this test pins are therefore: the stranger
// bytes survive as one contiguous block in their original order,
// exactly one door line exists for the id, and Remove restores the
// file to its exact pre-install bytes.
func TestInstallOnUnix_ThirdPartyLinesByteForByte(t *testing.T) {
	resetSeamLogs(t)
	_, _, authKeys := makeSSHTree(t)
	preExisting := []byte("# stranger one\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRealForeignKey stranger@home\n# final without newline")
	if err := os.WriteFile(authKeys, preExisting, 0o600); err != nil {
		t.Fatal(err)
	}
	d := newUnixDoor(t, authKeys)
	id := "0123456789abcdef0123456789abcdef"
	if err := d.Install(id, TestKey); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, err := os.ReadFile(authKeys)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), string(preExisting)) {
		t.Fatalf("third-party bytes lost or reordered: got=%q want-contiguous-block=%q", got, preExisting)
	}
	count := strings.Count(string(got), "iamtunnel-door="+id)
	if count != 1 {
		t.Fatalf("expected exactly one door line for id, got %d", count)
	}
	// The strongest PROTOCOL §5.1 consequence: closing the door must
	// return the file to byte-for-byte what the stranger had, with
	// no leftover separator from the install.
	if err := d.Remove(id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	restored, err := os.ReadFile(authKeys)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(preExisting) {
		t.Fatalf("Remove did not restore the original bytes:\n got: %q\nwant: %q", restored, preExisting)
	}
}

// ─── INTEGRATION tests: real syscalls under t.TempDir ────────────────

// TestIntegrationDoorOnRealSyscalls_CanaryDoorID is the
// IAMT-269 lesson applied: real syscalls, real flock, real
// fchmod/fchown, with chdir OUTSIDE the .ssh directory the
// door operates on. The seam fchmodat(AT_FDCWD) bug the
// review flagged would be invisible to recording-seam tests;
// here we run the production seams and verify the on-disk
// outcome directly.
//
// Skipped when the test process is root (production chown to
// opts.OwnerUID would always succeed and not exercise the
// fchownIfRoot path); the production server is the same
// process the test runs in, so this matches reality.
func TestIntegrationDoorOnRealSyscalls_CanaryDoorID(t *testing.T) {
	if unix.Geteuid() == 0 {
		t.Skipf("integration test runs as root — chown is a no-op, gate 11 still satisfied via unit tests")
	}
	installRealImplSeams(t)
	resetSeamLogs(t)

	tree := testsupport.NewSSHTree(t)
	home := tree.Home
	authKeys := tree.KeyPath("auth_keys")
	lockPath := filepath.Join(home, "door.lock")

	// chdir to a totally unrelated directory so a Fchmodat(AT_FDCWD)
	// bug would surface as a chmod of this directory's path
	// instead of the door's.
	// t.Chdir, not os.Chdir: the process working directory is shared by
	// every test in this package, and a bare os.Chdir that leaves it in a
	// temp dir (or in "/") makes every later `go build` in the package run
	// outside the module — the full package run failed with "go.mod file not
	// found in current directory or any parent directory" while the
	// -run-filtered run stayed green (IAMT-305 round 3). t.Chdir restores
	// the previous directory and refuses to run in a parallel test.
	outside := t.TempDir()
	t.Chdir(outside)

	d, err := NewDoorWithOptions(authKeys, nil, DoorOptions{
		LockPath: lockPath,
		OwnerUID: unix.Geteuid(),
		OwnerGID: unix.Getegid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef0123456789abcdef"
	if err := d.Install(id, TestKey); err != nil {
		t.Fatalf("Install under real syscalls: %v", err)
	}

	// The key file must exist with the door line and no group/other write.
	// We mirror sshd StrictModes: only group/other WRITE matters; group/other
	// read on the key file (mode 0o600 itself, owner-only) is what we
	// verify by refusing group/other write bits (mask 0o022).
	info, err := os.Stat(authKeys)
	if err != nil {
		t.Fatalf("stat auth_keys: %v", err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		t.Fatalf("auth_keys has group/other write: mode %#04o", info.Mode().Perm())
	}

	// The .ssh dir must exist with mode 0700.
	sshInfo, err := os.Stat(filepath.Join(home, ".ssh"))
	if err != nil {
		t.Fatalf("stat .ssh: %v", err)
	}
	if sshInfo.Mode().Perm()&0o022 != 0 {
		t.Fatalf(".ssh has group/other write: mode %#04o", sshInfo.Mode().Perm())
	}
	if !sshInfo.IsDir() {
		t.Fatalf(".ssh is not a directory")
	}

	// Owner of auth_keys must be the running process's uid (the
	// "root changes owner" hook ran fchown; non-root path leaves
	// the owner unchanged, which is the test-process uid).
	var st unix.Stat_t
	if err := unix.Stat(authKeys, &st); err != nil {
		t.Fatal(err)
	}
	if int(st.Uid) != unix.Geteuid() || int(st.Gid) != unix.Getegid() {
		t.Fatalf("auth_keys owner=%d:%d, want %d:%d (test process uid/gid)",
			st.Uid, st.Gid, unix.Geteuid(), unix.Getegid())
	}
}

// TestIntegrationDoorOnRealSyscalls_RandomTmpName proves the
// tmp-name source is crypto-random, not PID-derived: write 8
// lines in a tight loop, observe the directory after each via
// the unix readdir syscall, and assert no tmp filename pattern
// is recoverable. A regression that returns the PID-derived
// shape would fail here.
func TestIntegrationDoorOnRealSyscalls_RandomTmpName(t *testing.T) {
	if unix.Geteuid() == 0 {
		t.Skipf("integration test runs as root")
	}
	installRealImplSeams(t)
	resetSeamLogs(t)

	tree := testsupport.NewSSHTree(t)
	authKeys := tree.KeyPath("auth_keys")
	lockPath := filepath.Join(tree.Home, "door.lock")
	d, err := NewDoorWithOptions(authKeys, nil, DoorOptions{
		LockPath: lockPath,
		OwnerUID: unix.Geteuid(),
		OwnerGID: unix.Getegid(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Each Install renames the tmp into place, so a subsequent
	// Install creates a new tmp. After the storm, no leftover
	// tmp may exist under .ssh.
	//
	// Door ids must be 32 hex characters: isDoorLine recognises a
	// line as ours only when the marker tail carries a full 32-hex
	// id (PROTOCOL §5.1 door.open verifies a UUID; the on-disk tail
	// is the UUID's 32-hex body — internal/server's winkeysID is
	// the inverse mapping). A shorter id would be written to disk
	// fine but would fail Install's own IsOursID read-back proof
	// with "line for door ... not present after install", so the
	// loop uses %032x.
	for i := 0; i < 8; i++ {
		if err := d.Install(fmt.Sprintf("%032x", i), TestKey); err != nil {
			t.Fatalf("Install %d: %v", i, err)
		}
	}

	// Walk .ssh and assert no tmp leftover.
	f, err := unix.Open(tree.SSHDir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(f)
	// We don't want a per-test dependency on golang.org/x/sys/unix
	// Getdents in this file's import block; do a minimal dirent
	// walk via ReadDirent (Linux-only). On Darwin this is a no-op
	// (ReadDirent may differ); the test runs only on linux in CI
	// because openbsd/amd64 is excluded by the build-tag-only
	// path. macOS supports ReadDirent on Darwin 17+, so this
	// branch is safe.
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		names, err := readDirNames(f)
		if err != nil {
			t.Fatalf("readDirNames: %v", err)
		}
		for _, n := range names {
			if strings.HasPrefix(n, ".winkeys.tmp.") {
				t.Fatalf("leftover tmp file in .ssh: %q", n)
			}
		}
	}

	// Also assert no PID-shaped tmp leaked (the pre-fix shape).
	entries, err := os.ReadDir(tree.SSHDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		// The pre-fix name was .authorized_keys.<pid>.tmp or
		// .auth_keys.<pid>.tmp. Any file with that suffix is a
		// regression. We have already ruled out .winkeys.tmp.*
		// above, but the explicit "<pid>" pattern is the canary.
		if strings.Contains(name, ".tmp") && !strings.HasPrefix(name, ".winkeys.tmp.") {
			t.Fatalf("unexpected tmp-shaped file: %q", name)
		}
	}
}

// readDirNames reads directory entries from dirfd using
// unix.ReadDirent. The returned slice contains only the file
// names (basename), not the "." / ".." entries.
func readDirNames(dirfd int) ([]string, error) {
	var (
		buf   [4096]byte
		names []string
	)
	for {
		n, err := unix.ReadDirent(dirfd, buf[:])
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return names, nil
		}
		var off int
		for off < n {
			// Linux dirent header layout (see getdents(2)):
			//   uint64  d_ino
			//   int64   d_off
			//   uint16  d_reclen
			//   uint8   d_type
			//   char    d_name[]
			const (
				offIno  = 0
				offOff  = 8
				offLen  = 16
				offType = 18
				offName = 19
			)
			reclen := int(*(*uint16)(unsafe.Pointer(&buf[off+offLen])))
			dtype := buf[off+offType]
			nameBytes := buf[off+offName : off+reclen]
			// Trim trailing NUL.
			for len(nameBytes) > 0 && nameBytes[len(nameBytes)-1] == 0 {
				nameBytes = nameBytes[:len(nameBytes)-1]
			}
			if dtype != unix.DT_DIR {
				names = append(names, string(nameBytes))
			}
			off += reclen
		}
	}
}

// unsafeSlice is no longer used (we go through unsafe.Pointer for
//// the dirent field reads instead). Kept as a comment-only marker
//// so future readers know the seam was considered.

// keep imports live when some references are only referenced on
// certain build tags.
var _ = time.Now
var _ atomic.Int64
var _ = filepath.Join

// TestInstall_Umask0002Canary proves that tempDoor is immune to process umask 0002
// (Ubuntu desktop default). Without the fix, Install fails with:
//
//	Install: winkeys: directory .ssh is group- or world-writable (mode 0775) — run: chmod go-w .ssh
//
// umask is process-wide: this test MUST NOT call t.Parallel().
func TestInstall_Umask0002Canary(t *testing.T) {
	old := syscall.Umask(0o002)
	t.Cleanup(func() {
		syscall.Umask(old)
	})

	d := tempDoor(t)
	id := randomDoorID(t)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatalf("Install under umask 0002 failed: %v", err)
	}
	lines, err := d.ReadLines()
	if err != nil {
		t.Fatalf("ReadLines: %v", err)
	}
	if len(lines) != 1 || !IsOursID(lines[0], id) {
		t.Fatalf("written line not recognised: %v", lines)
	}
}
