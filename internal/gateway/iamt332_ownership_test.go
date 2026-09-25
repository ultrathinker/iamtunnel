package gateway

// iamt332_ownership_test.go — IAMT-332: the local verbs "gateway restore"
// and "gateway rotate-hostkey" replace files the unprivileged service
// account owns (state.json, events.jsonl, the host key and its .old
// copy). Run under sudo on the real Linux gateway, their atomic renames
// used to hand those files to root, and the service died on its next
// start. Every atomic replace in this package must therefore ask for the
// replacement's ownership to be adopted — on the open descriptor, and
// from a temporary whose name nothing could have pre-planted (round
// two). The real step is a POSIX chown — nothing a test may do for real
// — so the adoption tests record the request through the adoptOwnership
// seam (no root, no real ownership changes, on any platform). The
// planted-symlink test runs the real path instead: it needs no chown to
// observe a followed link.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// withOwnershipRecorder swaps the adoption seam for a recorder and
// restores it when the test finishes.
func withOwnershipRecorder(t *testing.T) func() []string {
	t.Helper()
	orig := adoptOwnership
	var requested []string
	adoptOwnership = func(f *os.File, replacedPath string) error {
		requested = append(requested, replacedPath)
		return nil
	}
	t.Cleanup(func() { adoptOwnership = orig })
	return func() []string { return requested }
}

func TestRestoreAdoptsTheOwnershipOfTheFilesItReplaces(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close state: %v", err)
	}
	eventsPath := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(eventsPath, []byte{}, 0o600); err != nil {
		t.Fatalf("seed events.jsonl: %v", err)
	}
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := WriteBackupTarGz(archive, dir); err != nil {
		t.Fatalf("WriteBackupTarGz: %v", err)
	}

	requested := withOwnershipRecorder(t)

	if _, err := RestoreBackupTarGz(archive, dir); err != nil {
		t.Fatalf("RestoreBackupTarGz: %v", err)
	}

	counts := map[string]int{}
	for _, replaced := range requested() {
		counts[replaced]++
	}
	wantState := filepath.Join(dir, state.StateFileName)
	if counts[wantState] != 1 {
		t.Errorf("restore asked to adopt the ownership of %q %d times, want exactly once — a root-run \"gateway restore\" would otherwise leave state.json owned by root and the service dead on its next start (IAMT-332)", wantState, counts[wantState])
	}
	if counts[eventsPath] != 1 {
		t.Errorf("restore asked to adopt the ownership of %q %d times, want exactly once", eventsPath, counts[eventsPath])
	}
	// The copy the restore keeps of the state.json it replaces (M-8) is a
	// file of the data directory like any other: a root-run restore must
	// not leave it owned by root either, or the operator reading it back
	// under the service account cannot open the way back it was kept for.
	copies := m8PreRestoreCopies(t, dir)
	if len(copies) != 1 {
		t.Fatalf("restore kept %v as copies of the state it replaced, want exactly one state.json.pre-restore-<label>", copies)
	}
	wantCopy := filepath.Join(dir, copies[0])
	if counts[wantCopy] != 1 {
		t.Errorf("restore asked to adopt the ownership of the copy it keeps (%q) %d times, want exactly once (IAMT-332, M-8)", copies[0], counts[wantCopy])
	}
	for replaced := range counts {
		if replaced != wantState && replaced != eventsPath && replaced != wantCopy {
			t.Errorf("restore asked to adopt the ownership of unexpected %q", replaced)
		}
	}
}

func TestRotateHostKeyAdoptsTheOwnershipItReplaces(t *testing.T) {
	dir := t.TempDir()
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer func() { _ = log.Close() }()

	requested := withOwnershipRecorder(t)

	if _, _, err := RotateHostKey(dir, log, time.Now()); err != nil {
		t.Fatalf("RotateHostKey: %v", err)
	}

	hk := filepath.Join(dir, HostKeyFileName)
	counts := map[string]int{}
	for _, replaced := range requested() {
		counts[replaced]++
	}
	if counts[hk+".old"] != 1 {
		t.Errorf("rotation asked to adopt the ownership of %q %d times, want exactly once — a root-run \"gateway rotate-hostkey\" would otherwise leave hostkey owned by root and the service unable to load its key (IAMT-332)", hk+".old", counts[hk+".old"])
	}
	if counts[hk] < 1 {
		t.Errorf("rotation never asked to adopt the ownership of %q — the fresh key would carry the running account's owner", hk)
	}
	for replaced := range counts {
		if replaced != hk && replaced != hk+".old" {
			t.Errorf("rotation asked to adopt the ownership of unexpected %q", replaced)
		}
	}
}

// Round two, finding 1: a symlink planted at the old predictable
// temporary name (path+".tmp") must not be followed. The pre-round-two
// writer opened that name with O_CREATE|O_TRUNC — straight through the
// link — so the directory's owner could aim the write, and the adoption,
// at any file on the system. This test runs the REAL writer (no
// recorder): observing a followed link needs no chown, and the ownership
// step's same-owner fast path keeps the run chown-free even on POSIX.
func TestRotateHostKeyDoesNotFollowASymlinkPlantedAtTheOldTempName(t *testing.T) {
	dir := t.TempDir()
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer func() { _ = log.Close() }()

	target := filepath.Join(t.TempDir(), "victim")
	const canary = "the file a planted symlink points at"
	if err := os.WriteFile(target, []byte(canary), 0o600); err != nil {
		t.Fatalf("write the symlink target: %v", err)
	}
	planted := hostKeyPath(dir) + ".tmp"
	if err := os.Symlink(target, planted); err != nil {
		t.Skipf("this platform refuses the symlink the scenario needs (usually an unprivileged Windows): %v", err)
	}

	if _, _, err := RotateHostKey(dir, log, time.Now()); err != nil {
		t.Fatalf("RotateHostKey: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("re-read the symlink target: %v", err)
	}
	if string(got) != canary {
		t.Errorf("the planted symlink at %q was followed: its target now holds %q — a hostile directory owner must not be able to aim the key write at an arbitrary file; the temporary must be a random O_EXCL creation (IAMT-332 round 2)", planted, got)
	}
}
