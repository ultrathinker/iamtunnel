package state

// iamt332_ownership_test.go — IAMT-332: a root-run maintenance command
// ("gateway pair", "install --rebootstrap") rewrites the gateway data
// directory's files, and the unprivileged service account then dies on
// its next start reading files it owns («failed to read state file ...
// permission denied» on the real Linux gateway).
//
// Round two sharpened the mechanism after review: the adoption is asked
// about the OPEN file (the real step fchowns the descriptor, so nothing
// follows a path), the temporaries carry random O_EXCL names instead of
// the old predictable path+".tmp..." shapes, and the files that are
// merely CREATED on a maintenance run — enrol-hmac.key, state.lock — are
// adopted at creation too.
//
// The real step is a chown on POSIX: no test may chown for real, and
// only root could. These tests record the request through the
// adoptOwnership seam instead; nothing touches real ownership and no
// privilege is needed, on any platform. The real POSIX owner selection
// (ownerToCarry, the same-owner fast path) is exercised without a
// recorder in iamt332_ownership_posix_test.go.

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// adoptionRequest is one ask of the seam: the open file whose owner
// should be adopted, and the file it is about to replace ("" when the
// file was created where nothing stood).
type adoptionRequest struct {
	newFile  string
	replaced string
}

// withAdoptionRecorder swaps the seam for a recorder and restores it
// when the test finishes.
func withAdoptionRecorder(t *testing.T) func() []adoptionRequest {
	t.Helper()
	orig := adoptOwnership
	var requested []adoptionRequest
	adoptOwnership = func(f *os.File, replacedPath string) error {
		requested = append(requested, adoptionRequest{newFile: f.Name(), replaced: replacedPath})
		return nil
	}
	t.Cleanup(func() { adoptOwnership = orig })
	return func() []adoptionRequest { return requested }
}

func TestSaveAdoptsTheReplacedStateFileOwnership(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	requested := withAdoptionRecorder(t)

	if err := s.Update(func(st *State) error {
		st.PairingPending = &PairingPending{Expires: NewZonedTime(time.Now().Add(time.Minute))}
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got := requested()
	if len(got) == 0 {
		t.Fatal("the atomic save never asked for the replacement's ownership to be adopted — a root-run \"gateway pair\" would rename its own root-owned temporary file over state.json and the service would die on its next start (IAMT-332)")
	}
	want := filepath.Join(dir, StateFileName)
	if len(got) != 1 || got[0].replaced != want {
		t.Errorf("ownership adoption was asked about %+v, want exactly one request for the state file %q", got, want)
	}
}

func TestSaveRefusesWhenOwnershipCannotBeAdopted(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()
	statePath := filepath.Join(dir, StateFileName)
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}

	orig := adoptOwnership
	adoptOwnership = func(f *os.File, replacedPath string) error {
		return errFakeChownDenied
	}
	defer func() { adoptOwnership = orig }()

	if err := s.Update(func(st *State) error {
		st.PairingPending = &PairingPending{Expires: NewZonedTime(time.Now().Add(time.Minute))}
		return nil
	}); err == nil {
		t.Fatal("a save whose ownership adoption failed reported success — the rename would hand state.json to an account the service cannot read it under")
	}

	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("re-read state.json: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("state.json changed even though the ownership adoption failed — the refusal must happen before the rename, leaving the old file (content and owner) in place")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), StateFileName+".tmp.") {
			t.Errorf("abandoned temporary file %s left behind by the refused save", e.Name())
		}
	}
}

// Round two, finding 1: the temporary must not carry the old predictable
// shape. The pre-round-two save named its temporary
// state.json.tmp.<pid>.<nanotime> — both guessable by anyone able to
// watch the data directory, which is what made the name plantable. The
// save must create a random O_EXCL temporary instead (os.CreateTemp), so
// the captured temporary name must not match the pid-tagged shape. (The
// planted-canary version of this test — a pre-planted symlink at the
// old name, its target left untouched — lives with the writers whose
// temporary really was the flat path+".tmp": the gateway lifecycle and
// CLI writers.)
func TestSaveCreatesItsTemporaryUnderARandomUnpredictableName(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	var tmpPath string
	SetBeforeRenameHook(s, func(p string) error { tmpPath = p; return nil })

	if err := s.Update(func(st *State) error {
		st.PairingPending = &PairingPending{Expires: NewZonedTime(time.Now().Add(time.Minute))}
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if tmpPath == "" {
		t.Fatal("the save never reached the rename — no temporary name was captured")
	}

	pidTagged := StateFileName + ".tmp." + strconv.Itoa(os.Getpid()) + "."
	if strings.HasPrefix(filepath.Base(tmpPath), pidTagged) {
		t.Errorf("the save's temporary %q carries the old pid-tagged shape state.json.tmp.<pid>.<nanotime>: a hostile directory owner knows the live pid and the wall clock and can pre-plant a file or symlink at the guessed name — the temporary must be a random O_EXCL creation (IAMT-332 round 2)", tmpPath)
	}
}

// Round two, finding 3: enrol-hmac.key is created on the run too — a root
// run over a directory where the key was missing used to leave it
// root-owned, and the service could never hash another enrol secret.
func TestEnrolHMACCreationAdoptsTheDataDirOwner(t *testing.T) {
	dir := t.TempDir()

	requested := withAdoptionRecorder(t)

	if _, err := LoadOrCreateEnrolHMACKey(dir); err != nil {
		t.Fatalf("LoadOrCreateEnrolHMACKey: %v", err)
	}

	got := requested()
	if len(got) != 1 {
		t.Fatalf("creating enrol-hmac.key asked for ownership adoption %d times (%+v), want exactly once — a root run would leave the fresh key owned by root and the service unable to hash enrol secrets (IAMT-332 round 2)", len(got), got)
	}
	if got[0].replaced != "" {
		t.Errorf("the creation asked to adopt the owner of %q, want the empty replacement (the fresh file takes the data directory's owner)", got[0].replaced)
	}
	if filepath.Base(got[0].newFile) != EnrolHMACKeyFileName {
		t.Errorf("the adoption was asked about %q, want the fresh key file", got[0].newFile)
	}

	if _, err := LoadOrCreateEnrolHMACKey(dir); err != nil {
		t.Fatalf("second LoadOrCreateEnrolHMACKey: %v", err)
	}
	if got = requested(); len(got) != 1 {
		t.Errorf("reading the existing key asked for adoption again (%+v) — the seam is for creations, not reads", got)
	}
}

// Round two, finding 3: state.lock is created on the run too — the lock
// the service takes on every start.
func TestAcquireFileLockAdoptsTheDataDirOwner(t *testing.T) {
	dir := t.TempDir()

	requested := withAdoptionRecorder(t)

	fl, err := AcquireFileLock(filepath.Join(dir, LockFileName))
	if err != nil {
		t.Fatalf("AcquireFileLock: %v", err)
	}
	defer func() { _ = fl.Unlock() }()

	got := requested()
	if len(got) != 1 {
		t.Fatalf("acquiring the state lock asked for ownership adoption %d times (%+v), want exactly once — a root run that finds state.lock missing would leave it root-owned and the service could never take its lock again (IAMT-332 round 2)", len(got), got)
	}
	if got[0].replaced != "" {
		t.Errorf("the lock adoption was asked about %q, want the empty replacement (the fresh file takes the data directory's owner)", got[0].replaced)
	}

	// Releasing and re-acquiring goes through the existing-file leg of the
	// open — the adoption must run there too: it is what heals a pre-fix
	// root-owned lock, and what the round-three no-symlink open must
	// preserve.
	if err := fl.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	fl2, err := AcquireFileLock(filepath.Join(dir, LockFileName))
	if err != nil {
		t.Fatalf("second AcquireFileLock: %v", err)
	}
	defer func() { _ = fl2.Unlock() }()
	if got = requested(); len(got) != 2 {
		t.Errorf("re-acquiring an existing lock asked for adoption %d times (%+v), want exactly once more — the existing-file leg adopts the same as the creation leg", len(got), got)
	}
}

// Round three: state.lock is a LONG-LIVED file reused across restarts, so
// its creation cannot be O_EXCL-unconditionally — but a symlink planted at
// its real name must be refused, not opened through (the pre-round-three
// open followed the link, and the ownership adoption then Fchowned
// whatever the directory's owner had pointed it at).
func TestAcquireFileLockRefusesASymlinkAtTheLockFilesName(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, LockFileName)

	target := filepath.Join(t.TempDir(), "victim")
	const canary = "the file a planted symlink points at"
	if err := os.WriteFile(target, []byte(canary), 0o600); err != nil {
		t.Fatalf("write the symlink target: %v", err)
	}
	if err := os.Symlink(target, lockPath); err != nil {
		t.Skipf("this platform refuses the symlink the scenario needs (usually an unprivileged Windows): %v", err)
	}

	requested := withAdoptionRecorder(t)

	fl, err := AcquireFileLock(lockPath)
	if err == nil {
		_ = fl.Unlock()
		t.Fatal("AcquireFileLock opened a symlink planted at the lock file's name — the service account can point a root-run command's descriptor (and its ownership adoption) at any file on the system; a symlink at a gateway data file's name must be refused (IAMT-332 round 3)")
	}
	if got := requested(); len(got) != 0 {
		t.Errorf("the refused open still asked for ownership adoption (%+v) — nothing at the end of a planted symlink may be touched", got)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("re-read the symlink target: %v", err)
	}
	if string(got) != canary {
		t.Errorf("the symlink target changed (%q) — the refusal must leave everything behind the planted link untouched", got)
	}
	if st, err := os.Lstat(lockPath); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the planted symlink did not survive the refused open (Lstat: %v, %#v) — the refusal must leave the name as it found it", err, st)
	}
}

// TestOpenDataFileReopensAnExistingRegularFile pins the second leg of the
// two-legged open against over-rejection: a REGULAR file at the name must
// come back open through both entries — the create-or-refuse pair (whose
// first leg lost the EEXIST race to the pre-existing file) and the
// existing-file leg the repair/read paths use directly. The round-three
// no-follow guarantee must refuse symlinks, never ordinary files.
func TestOpenDataFileReopensAnExistingRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.dat")
	const canary = "regular data"
	if err := os.WriteFile(path, []byte(canary), 0o600); err != nil {
		t.Fatalf("write the existing file: %v", err)
	}

	for _, tt := range []struct {
		name string
		open func() (*os.File, error)
	}{
		{"OpenDataFile", func() (*os.File, error) { return OpenDataFile(path, os.O_RDWR, 0o600) }},
		{"OpenExistingDataFile", func() (*os.File, error) { return OpenExistingDataFile(path, os.O_RDWR) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, err := tt.open()
			if err != nil {
				t.Fatalf("%s refused an ordinary existing data file: %v", tt.name, err)
			}
			defer f.Close()
			got, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("read back through the reopened handle: %v", err)
			}
			if string(got) != canary {
				t.Errorf("the reopened handle sees %q, want %q", got, canary)
			}
		})
	}
}

// errFakeChownDenied stands for the chown a process is not allowed — the
// refusal branch the POSIX implementation reaches when a non-root run
// meets another account's file.
var errFakeChownDenied = errors.New("fake: chown denied")
