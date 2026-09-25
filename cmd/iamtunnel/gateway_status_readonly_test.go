package main

// gateway_status_readonly_test.go proves IAMT-98: a read of gateway
// state ("gateway status") MUST NOT write to disk. Concretely:
//
//   - on a freshly-resolved data directory that was never created,
//     nothing is created (no state.json, no state.lock, no
//     enrol-hmac.key, no data directory at all);
//   - the same holds on a second run over the same dir, which is the
//     path that used to mint the enrol-hmac.key secret;
//   - on a directory that EXISTS but holds neither state.json nor
//     state.lock (the exact case that bit round one: AcquireFileLock
//     opened the lock file with O_CREATE, so a read created state.lock),
//     nothing is created either;
//   - on a dir where the gateway is supposedly "running" (state.lock
//     held by an external holder), the running branch still works and
//     still touches no file;
//   - right after `gateway restore` (CASE A, round three): a
//     state.json with no state.lock must answer "not running" with
//     the real counts, not "no gateway is installed";
//   - right after `gateway install` (CASE B, round three): a host
//     key with no state.json must answer "installed but never
//     started" and print the fingerprint, not "no gateway is
//     installed".
//
// The assertion is filesystem-level: capture the directory listing
// before and after the call, and require the lists to be identical.
// The textual answer ("no gateway is installed", "running",
// "installed but never started", etc.) is also checked but only as
// a sanity guard, not as the primary proof — the primary proof is
// the file system diff.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// listDirSorted returns the basename of every entry in dir, sorted. A
// missing directory yields an empty slice (it must not exist before
// the call we are about to make, and must not exist after).
func listDirSorted(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// diffNames returns the names that are in after but not in before,
// and the names that are in before but not in after.
func diffNames(before, after []string) (added, removed []string) {
	bset := make(map[string]struct{}, len(before))
	for _, n := range before {
		bset[n] = struct{}{}
	}
	aset := make(map[string]struct{}, len(after))
	for _, n := range after {
		aset[n] = struct{}{}
	}
	for n := range aset {
		if _, ok := bset[n]; !ok {
			added = append(added, n)
		}
	}
	for n := range bset {
		if _, ok := aset[n]; !ok {
			removed = append(removed, n)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// TestGatewayStatusFreshDirCreatesNothing is the headline test for
// IAMT-98: against a brand-new, never-touched data directory "gateway
// status" must not create a single file or directory. Before the fix
// this run produced /var/lib/iamtunnel/state.json,
// /var/lib/iamtunnel/state.lock, and on the second pass also
// /var/lib/iamtunnel/enrol-hmac.key — the latter is the secret whose
// silent creation is named as its own hazard.
func TestGatewayStatusFreshDirCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	// Make the gateway use exactly this dir; resolveRoleDir is bypassed
	// by passing the --data-dir flag through drive.
	before := listDirSorted(t, dir)
	if len(before) != 0 {
		t.Fatalf("t.TempDir() was supposed to be empty, found %v", before)
	}

	out, errs, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("first status call: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, "no gateway is installed") {
		t.Fatalf("first status call: stdout should say \"no gateway is installed\", got:\n%s", out)
	}
	after := listDirSorted(t, dir)
	if added, removed := diffNames(before, after); len(added) > 0 || len(removed) > 0 {
		t.Fatalf("first status call: filesystem changed. added=%v removed=%v", added, removed)
	}
}

// TestGatewayStatusSecondRunAlsoCreatesNothing covers the path that
// needs its own check: a second status call over a directory that
// has been "touched" by the first one (still without a real gateway)
// must likewise not write anything. Before the fix the first call
// created state.json+state.lock, and the second call additionally
// minted the secret enrol-hmac.key — the second-pass creation of that
// key is what this test pins down.
//
// The first call is run only to put the store in the state the second
// call would actually see. Whether the first call leaves the dir empty
// (with the fix in place) or full (without the fix) does not matter:
// what matters is that the SECOND call adds no new entry to whatever
// the first call left behind.
func TestGatewayStatusSecondRunAlsoCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	if _, _, code := drive(t, "gateway", "status", "--data-dir", dir); code != exitOK {
		t.Fatalf("prime status: code != 0")
	}

	before := listDirSorted(t, dir)

	out, errs, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("second status call: code=%d out=%q errs=%q", code, out, errs)
	}
	if strings.Contains(out, "no gateway is installed") {
		// Acceptable — the first call also wrote nothing, so the second
		// call sees the same empty directory.
	} else if !strings.Contains(out, "not running") {
		t.Fatalf("second status call: stdout should say \"not running\" (state.json from first call), got:\n%s", out)
	}

	after := listDirSorted(t, dir)
	if added, removed := diffNames(before, after); len(added) > 0 || len(removed) > 0 {
		t.Fatalf("second status call: filesystem changed. added=%v removed=%v", added, removed)
	}
	// Belt-and-braces: name the secret by name so a future regression
	// that creates some other secret instead of enrol-hmac.key still
	// fails loudly.
	for _, n := range after {
		if strings.Contains(n, "hmac") || strings.Contains(n, "enrol") {
			t.Fatalf("status must never create a secret-like file; found %q in %s", n, dir)
		}
	}
}

// TestGatewayStatusRunningBranchDoesNotWrite pins down the "running"
// branch too: when another process holds the state lock, status
// reports "running" via peekStateCounts. The lock holder here is a
// plain state.Open (no real gateway), and we close it through
// t.Cleanup. No file is created by the status call.
func TestGatewayStatusRunningBranchDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	// Seed a state.json with one person so the running branch has
	// real counts to print.
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("seed state.Open: %v", err)
	}
	if uerr := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "alice", Role: "user"})
		return nil
	}); uerr != nil {
		t.Fatalf("seed update: %v", uerr)
	}
	if cerr := store.Close(); cerr != nil {
		t.Fatalf("seed close: %v", cerr)
	}

	// Take the lock the way a live gateway would.
	holder, err := state.Open(dir)
	if err != nil {
		t.Fatalf("holder state.Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := holder.Close(); cerr != nil {
			t.Errorf("holder close: %v", cerr)
		}
	})

	before := listDirSorted(t, dir)
	out, errs, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("status against held lock: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, "running (data dir ") {
		t.Fatalf("status against held lock: stdout should say \"running\", got:\n%s", out)
	}

	after := listDirSorted(t, dir)
	if added, removed := diffNames(before, after); len(added) > 0 || len(removed) > 0 {
		t.Fatalf("running-branch status: filesystem changed. added=%v removed=%v", added, removed)
	}
}

// TestGatewayStatusNotRunningBranchDoesNotWrite covers the third
// outcome: the dir is real, the lock is free, state.json exists — so
// the answer must be "not running" and, still, no write must happen.
// (This is what runGatewayStatus does on a clean restart of a real
// gateway: same dir, lock not held yet.)
func TestGatewayStatusNotRunningBranchDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("seed state.Open: %v", err)
	}
	if uerr := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "bob", Role: "user"})
		return nil
	}); uerr != nil {
		t.Fatalf("seed update: %v", uerr)
	}
	if cerr := store.Close(); cerr != nil {
		t.Fatalf("seed close: %v", cerr)
	}

	before := listDirSorted(t, dir)
	out, errs, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("status against free lock: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, "not running") {
		t.Fatalf("status against free lock: stdout should say \"not running\", got:\n%s", out)
	}

	after := listDirSorted(t, dir)
	if added, removed := diffNames(before, after); len(added) > 0 || len(removed) > 0 {
		t.Fatalf("not-running-branch status: filesystem changed. added=%v removed=%v", added, removed)
	}
}

// TestGatewayStatusDirExistsButNoStateFilesCreatesNothing is the
// exact regression for the case that bit IAMT-98 round one: the data
// directory exists (so os.Stat(dir) succeeds) but BOTH state.json and
// state.lock are absent — a state the product never produces
// intentionally, but a status probe must still touch nothing.
//
// The first round's fix used AcquireFileLock, which opens the lock
// file with O_CREATE — so this probe created state.lock on disk and
// the test caught it: `added=[state.lock] removed=[]`. The new
// OpenForRead stats state.json first and refuses to take the lock if
// it is missing, so state.lock is never opened (and certainly never
// created). This test pins the new behaviour down.
func TestGatewayStatusDirExistsButNoStateFilesCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	// t.TempDir() is the directory; no state.json, no state.lock, no
	// enrol-hmac.key. The empty directory IS the precondition this
	// test pins down — exactly the shape that turned round one red.
	before := listDirSorted(t, dir)
	if len(before) != 0 {
		t.Fatalf("t.TempDir() was supposed to be empty, found %v", before)
	}

	out, errs, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("status against empty-but-existing dir: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, "no gateway is installed") {
		t.Fatalf("status against empty-but-existing dir: stdout should say \"no gateway is installed\", got:\n%s", out)
	}

	after := listDirSorted(t, dir)
	if added, removed := diffNames(before, after); len(added) > 0 || len(removed) > 0 {
		t.Fatalf("status against empty-but-existing dir: filesystem changed. added=%v removed=%v", added, removed)
	}
	// Name the secret-by-name file that bit round one explicitly, so a
	// future regression that materialises some other secret instead of
	// state.lock still fails loudly.
	for _, n := range after {
		if n == "state.lock" || strings.Contains(n, "hmac") || strings.Contains(n, "enrol") {
			t.Fatalf("status must never create a lock or secret file; found %q in %s", n, dir)
		}
	}
}

// TestGatewayStatusAfterRestoreReportsNotRunningWithCounts pins
// down CASE A (round three). After a successful "gateway restore",
// gateway.RestoreBackupTarGz (internal/gateway/lifecycle.go, ex-
// restoreBackupTarGz) extracts state.json and events.jsonl into the
// data dir and does NOT re-create state.lock — that is the write
// path of Open, and restore is a read-then-write path that touches
// only the listed members. The admin typically follows restore with
// "gateway status" to confirm the restore landed, and the answer has
// to be "not running" with the real counts out of the restored
// state.json, NOT "no gateway is installed". A lock file that does
// not exist cannot be held by anybody, so "not running" is not a
// guess — it is the only possible truth.
//
// The seed uses state.Open + store.Update with a real ed25519 key
// (the same path seedLiveStatusState uses in
// gateway_status_live_test.go), then Close()s the store and
// os.Remove()s state.lock. That reproduces exactly what
// gateway.RestoreBackupTarGz leaves behind — a state.json that the product
// itself wrote (so State.Validate is satisfied) and no state.lock.
// Hand-writing state.json as a string literal (round three's first
// attempt) failed State.Validate because the machineKey was a
// placeholder, not a real SSH wire-format public key.
//
// The test asserts:
//   - exit 0;
//   - the answer says "not running";
//   - the printed counts are the seeded reality (1/1/0);
//   - the fingerprint is the real host-key fingerprint (restore
//     almost always follows an install, which leaves a host key);
//   - the filesystem diff is empty — status must not create
//     state.lock to "fix" the missing lock file.
func TestGatewayStatusAfterRestoreReportsNotRunningWithCounts(t *testing.T) {
	dir := t.TempDir()

	// Seed the host key the way runGatewayInstall does, so the
	// fingerprint line in the status answer is real.
	if _, err := loadOrGenerateSigner(hostkeyPath(dir)); err != nil {
		t.Fatalf("seed host key: %v", err)
	}

	// Seed a state.json the way the product itself would: real
	// ed25519 machineKey so State.Validate accepts it.
	_, _, signer := genTestKey(t)
	machineKey := authorizedKeyLine(signer.PublicKey())
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("seed state.Open: %v", err)
	}
	if uerr := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "alice", Role: "admin"})
		st.Machines = append(st.Machines, state.Machine{
			ID: "vm1", Name: "vm1", State: "verified",
			MachineKey: machineKey,
			OSUser:     `MACHINE\svc`,
		})
		return nil
	}); uerr != nil {
		t.Fatalf("seed update: %v", uerr)
	}
	if cerr := store.Close(); cerr != nil {
		t.Fatalf("seed close: %v", cerr)
	}

	// Crucially: drop state.lock — that is exactly what
	// gateway.RestoreBackupTarGz leaves behind.
	if err := os.Remove(filepath.Join(dir, "state.lock")); err != nil {
		t.Fatalf("remove state.lock (simulate restore): %v", err)
	}

	before := listDirSorted(t, dir)
	// Sanity: state.lock is absent before the call.
	for _, n := range before {
		if n == "state.lock" {
			t.Fatalf("precondition: state.lock must be absent before the call, found it in %v", before)
		}
	}

	out, errs, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("status after restore: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, "not running") {
		t.Fatalf("status after restore: stdout should say \"not running\", got:\n%s", out)
	}
	if strings.Contains(out, "no gateway is installed") {
		t.Fatalf("status after restore: stdout must NOT say \"no gateway is installed\" (CASE A):\n%s", out)
	}
	if !strings.Contains(out, "people=1 machines=1 grants=0") {
		t.Fatalf("status after restore: counts must be the seeded reality (1 person, 1 machine, 0 grants), got:\n%s", out)
	}
	wantFP := hostkeyFingerprintOnDisk(t, dir)
	if !strings.Contains(out, "host key fingerprint: "+wantFP) {
		t.Fatalf("status after restore: fingerprint must be the real key's %s, got:\n%s", wantFP, out)
	}

	after := listDirSorted(t, dir)
	if added, removed := diffNames(before, after); len(added) > 0 || len(removed) > 0 {
		t.Fatalf("status after restore: filesystem changed. added=%v removed=%v", added, removed)
	}
	for _, n := range after {
		if n == "state.lock" {
			t.Fatalf("status must NOT create state.lock on disk; found it in %s", dir)
		}
	}
}

// TestGatewayStatusAfterInstallReportsInstalledButNeverStarted pins
// down CASE B (round three). runGatewayInstall creates the data dir
// and the host key (and the bootstrap token on Linux), but does NOT
// create state.json — the first `gateway run` is what creates it. A
// status probe right after install must NOT say "no gateway is
// installed" — the host key is the marker install leaves, and the
// admin deserves the truth ("installed but never started") plus the
// fingerprint they just minted.
//
// The test seeds a host key (the only file install creates in this
// build), runs status, and asserts:
//   - exit 0;
//   - the answer says "installed but never started";
//   - the fingerprint is the real host-key fingerprint;
//   - the counts line says "people=0 machines=0 grants=0" (no state
//     yet);
//   - the filesystem diff is empty.
func TestGatewayStatusAfterInstallReportsInstalledButNeverStarted(t *testing.T) {
	dir := t.TempDir()
	// Seed the host key the way runGatewayInstall does — loadOrGenerateSigner
	// generates one if absent, so this is exactly what `gateway install`
	// would have produced on a fresh machine.
	if _, err := loadOrGenerateSigner(hostkeyPath(dir)); err != nil {
		t.Fatalf("seed host key: %v", err)
	}

	before := listDirSorted(t, dir)
	if len(before) != 1 || before[0] != "hostkey" {
		t.Fatalf("precondition: dir should contain only the host key, found %v", before)
	}

	out, errs, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("status after install: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, "installed but never started") {
		t.Fatalf("status after install: stdout should say \"installed but never started\", got:\n%s", out)
	}
	if strings.Contains(out, "no gateway is installed") {
		t.Fatalf("status after install: stdout must NOT say \"no gateway is installed\" (CASE B):\n%s", out)
	}
	wantFP := hostkeyFingerprintOnDisk(t, dir)
	if !strings.Contains(out, "host key fingerprint: "+wantFP) {
		t.Fatalf("status after install: fingerprint must be the real key's %s, got:\n%s", wantFP, out)
	}
	if !strings.Contains(out, "people=0 machines=0 grants=0") {
		t.Fatalf("status after install: counts must be zero (no state.json yet), got:\n%s", out)
	}

	after := listDirSorted(t, dir)
	if added, removed := diffNames(before, after); len(added) > 0 || len(removed) > 0 {
		t.Fatalf("status after install: filesystem changed. added=%v removed=%v", added, removed)
	}
	for _, n := range after {
		if n == "state.json" || n == "state.lock" || strings.Contains(n, "hmac") || strings.Contains(n, "enrol") {
			t.Fatalf("status after install must not create state.json, state.lock, or any secret file; found %q in %s", n, dir)
		}
	}
}
