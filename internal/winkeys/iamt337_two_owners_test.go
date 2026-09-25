package winkeys

// iamt337_two_owners_test.go — two servers, one key file.
//
// Until 1.4 exactly one registration lived on a machine, so this
// package could assume it owned every iamtunnel line in the file it was
// given. SweepStale says so in as many words: "removes every line with
// the marker from the file", keeping only the door id it is told to
// keep. On a single-server machine that is exactly right — it is how a
// server cleans up after its own crash, where the ids it wrote are
// gone with the process that knew them.
//
// 1.4 puts two registrations on one machine, one per person, and on
// Windows they share `%ProgramData%\ssh\administrators_authorized_keys`
// because that is the one file sshd reads for administrators. Two
// servers now sweep the same file. Under the old rule the second one to
// start deletes the first one's LIVE door line — and the person working
// through it is disconnected mid-session, with nothing in any log
// saying why: from the gateway's side the target simply stopped
// accepting the key.
//
// So a door line now carries WHO wrote it, and a sweep removes only its
// own owner's lines. Everything else in the file — another owner's
// lines, and anything that is not ours at all — is left byte for byte.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// twoOwnerFile is one key file with a door from each of two servers.
// It returns the file path and the two live door ids.
func twoOwnerFile(t *testing.T) (path, danaDoor, erikDoor string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "administrators_authorized_keys")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed key file: %v", err)
	}

	danaDoor = strings.Repeat("a", 32)
	erikDoor = strings.Repeat("b", 32)

	dana := newOwnedDoor(t, path, "office-pc")
	if err := dana.Install(danaDoor, TestKey); err != nil {
		t.Fatalf("install dana's door: %v", err)
	}
	erik := newOwnedDoor(t, path, "lab-pc")
	if err := erik.Install(erikDoor, TestKey); err != nil {
		t.Fatalf("install erik's door: %v", err)
	}
	return path, danaDoor, erikDoor
}

func newOwnedDoor(t *testing.T, keyFile, owner string) *Door {
	t.Helper()
	// The lock path is derived from the key file (the same shape
	// newUnixDoor uses), so every Door on one key file shares one lock —
	// the two owners here model two servers sharing a file, and they
	// must share its serialization. On linux/darwin the constructor
	// refuses a Door without an explicit LockPath and an unresolved
	// owner (SPEC §3.2.1), which is what the MAC round's first darwin
	// run tripped over: the options below say everything that call
	// demands. On Windows LockPath is consulted (an explicit path is as
	// good as the derived one — beside the key file, inside the test's
	// own TempDir) and OwnerUID/OwnerGID are ignored.
	d, err := NewDoorWithOptions(keyFile, nil, DoorOptions{
		LockPath: keyFile + ".door.lock",
		OwnerUID: testOwnerUID(),
		OwnerGID: testOwnerGID(),
		Owner:    owner,
	})
	if err != nil {
		t.Fatalf("NewDoorWithOptions(owner=%q): %v", owner, err)
	}
	return d
}

// TestIAMT337_ASweepLeavesTheOtherOwnersLiveDoor is the defect itself.
// Dana restarts his server, which sweeps before it installs. Erik is
// working through his door at that moment.
//
// Canary: make sweepLocked's predicate ignore the owner again — that is
// the one-registration-per-machine rule — and this goes red on "Erik's
// live door was swept away".
func TestIAMT337_ASweepLeavesTheOtherOwnersLiveDoor(t *testing.T) {
	path, danaDoor, erikDoor := twoOwnerFile(t)

	// Dana's server starts again: it sweeps everything of its own
	// that is not the door it is about to use.
	dana := newOwnedDoor(t, path, "office-pc")
	if _, err := dana.SweepStale(""); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	lines := readDoorLines(t, path)
	if hasDoor(lines, danaDoor) {
		t.Error("the sweep kept Dana's own stale door — a sweep with no current id must remove every line it owns")
	}
	if !hasDoor(lines, erikDoor) {
		t.Fatal("Erik's live door was swept away by Dana's server starting. He is disconnected mid-session, and nothing anywhere says why: from the gateway's side his machine simply stopped accepting the key.")
	}
}

// TestIAMT337_ASweepKeepsItsOwnCurrentDoor is the other half of the
// same predicate, and the reason it cannot simply be "leave everything
// with an owner": a server restarting with its door already open must
// keep that one line and drop its own older ones.
func TestIAMT337_ASweepKeepsItsOwnCurrentDoor(t *testing.T) {
	path, danaDoor, erikDoor := twoOwnerFile(t)

	// A second, older door of Dana's — the kind a crash leaves behind.
	stale := strings.Repeat("c", 32)
	if err := newOwnedDoor(t, path, "office-pc").Install(stale, TestKey); err != nil {
		t.Fatalf("install the stale door: %v", err)
	}

	dana := newOwnedDoor(t, path, "office-pc")
	if _, err := dana.SweepStale(danaDoor); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	lines := readDoorLines(t, path)
	if !hasDoor(lines, danaDoor) {
		t.Error("the sweep removed the door it was told to keep")
	}
	if hasDoor(lines, stale) {
		t.Error("the sweep kept Dana's own stale door")
	}
	if !hasDoor(lines, erikDoor) {
		t.Error("the sweep removed Erik's door")
	}
}

// TestIAMT337_RemoveOnlyTouchesItsOwnDoor. Remove already takes an id,
// so it was never going to delete the wrong LINE — but an id is 128
// bits of somebody else's randomness, and "the id matches" is a weaker
// claim than "the id matches and it is mine". Closing the door of a
// registration that is not yours is not something this package should
// be able to do by accident.
func TestIAMT337_RemoveOnlyTouchesItsOwnDoor(t *testing.T) {
	path, danaDoor, erikDoor := twoOwnerFile(t)

	// Dana's server asks to remove, by id, a door that is Erik's.
	dana := newOwnedDoor(t, path, "office-pc")
	_ = dana.Remove(erikDoor)

	lines := readDoorLines(t, path)
	if !hasDoor(lines, erikDoor) {
		t.Error("one registration removed another's door by naming its id")
	}
	if !hasDoor(lines, danaDoor) {
		t.Error("the attempt also took out the caller's own door")
	}
}

// TestIAMT337_AnUntaggedLegacyLineIsSwept is the case that decided the
// shape of ownsLine, and it decided it against my first answer.
//
// A line written by a build from before 1.4 carries no owner, and the
// first rule here was "leave it alone — this package cannot tell whose
// it is, and cannot-tell must not mean delete". IAMT-194 refused that:
// sweeping the stale door of a server that is gone, before the first
// dial, is the whole subject of that test, and under the careful rule
// an orphaned door line survived on every upgraded machine forever.
//
// A build older than 1.4 held exactly ONE registration per machine, so
// an untagged line is by construction the leftover of a server that no
// longer exists. The cost is a window during a mixed-version upgrade,
// while an old binary and a new one run side by side; that window ends
// when the old binary is replaced, and a door nobody ever closes does
// not.
//
// Canary: make ownsLine refuse an untagged line for an owned Door and
// this goes red here, and IAMT-194 goes red in internal/server.
func TestIAMT337_AnUntaggedLegacyLineIsSwept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "administrators_authorized_keys")
	legacy := Options + " ssh-ed25519 " + TestKey + " " + Marker + strings.Repeat("d", 32)
	if err := os.WriteFile(path, []byte(legacy+"\n"), 0o600); err != nil {
		t.Fatalf("seed legacy line: %v", err)
	}

	if _, err := newOwnedDoor(t, path, "office-pc").SweepStale(""); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if hasDoor(readDoorLines(t, path), strings.Repeat("d", 32)) {
		t.Error("a door line left by a build from before 1.4 survived the sweep — that is an orphaned open door on every upgraded machine, which is what IAMT-194 exists to prevent")
	}
}

func readDoorLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Split(string(raw), "\n")
}

func hasDoor(lines []string, doorID string) bool {
	for _, l := range lines {
		if strings.Contains(l, Marker+doorID) {
			return true
		}
	}
	return false
}
