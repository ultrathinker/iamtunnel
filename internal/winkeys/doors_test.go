package winkeys

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// memorySink records every Action.OnDoor call in order so tests
// can assert on audit behaviour.
type memorySink struct {
	mu      sync.Mutex
	actions []Action
}

func (m *memorySink) OnDoor(a Action) {
	m.mu.Lock()
	m.actions = append(m.actions, a)
	m.mu.Unlock()
}

func (m *memorySink) snapshot() []Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Action, len(m.actions))
	copy(out, m.actions)
	return out
}

// tempKeyFile returns a fresh path under a fake ~/.ssh directory tree
// created with explicit 0700 permissions (immune to process umask).
func tempKeyFile(t *testing.T) string {
	t.Helper()
	tree := testsupport.NewSSHTree(t)
	return tree.KeyPath("testkeys")
}

// randomDoorID returns a 32-hex id (matching the SPEC format).
func randomDoorID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// tempDoor returns a *Door configured with platform-correct
// DoorOptions: LockPath is a sibling path inside t.TempDir() so
// the file-lock layer has a real file to flock on every GOOS, and
// OwnerUID/OwnerGID are zero (the "not resolved" sentinel) on
// windows but valid integers on linux/darwin so
// validateOptionsPlatform's two gates both pass.
//
// On linux/darwin this is the only constructor the cross-platform
// tests in this file are allowed to reach for: NewDoor(path, nil)
// would refuse with "LockPath is required" (validateOptionsPlatform
// in doors_unix.go). On windows NewDoor(path, nil) and this
// helper produce a functionally identical Door; the helper is the
// cross-platform shape because tests share a single _test.go file.
func tempDoor(t *testing.T) *Door {
	t.Helper()
	return tempDoorWithSink(t, nil)
}

// tempDoorWithSink is the sink-aware twin of tempDoor. Tests
// that need to inspect audit events use this; tests that do not
// care use tempDoor.
func tempDoorWithSink(t *testing.T, sink Sink) *Door {
	t.Helper()
	d, err := NewDoorWithOptions(tempKeyFile(t), sink, testDoorOptions(t))
	if err != nil {
		t.Fatalf("tempDoorWithSink: %v", err)
	}
	return d
}

// tempDoorWithPath returns a *Door for the given explicit key
// file path (some tests in doors_iamt128_test.go need to reuse a
// path they prepared earlier). Sink and DoorOptions follow the
// same rules as tempDoor.
func tempDoorWithPath(t *testing.T, path string) *Door {
	t.Helper()
	d, err := NewDoorWithOptions(path, nil, testDoorOptions(t))
	if err != nil {
		t.Fatalf("tempDoorWithPath(%s): %v", path, err)
	}
	return d
}

// tempDoorWithSinkPath is the path-aware, sink-aware twin. Tests
// that both need a custom path and a sink reach for this.
func tempDoorWithSinkPath(t *testing.T, path string, sink Sink) *Door {
	t.Helper()
	d, err := NewDoorWithOptions(path, sink, testDoorOptions(t))
	if err != nil {
		t.Fatalf("tempDoorWithSinkPath(%s): %v", path, err)
	}
	return d
}

// testOwnerUID and testOwnerGID are the ids the *testing process itself*
// runs as — the one pair that is true on every runner this suite has:
//
//   - on a developer's real machine (uid 501, gid 20 on macOS; uid 1000,
//     gid 1000 on most Linux desktops) the tests then say "install this
//     door into my own tree", which is exactly what they do: every path a
//     test touches lives under its t.TempDir(), owned by this process;
//   - under the docker root lane both come back as the fixed 1000/1000
//     pair instead, because OwnerUID=0,OwnerGID=0 is winkeys' *unset*
//     sentinel (validateOptionsPlatform refuses it) and the root runner's
//     temp tree passes the strict-mode preflight through its "or root"
//     branch anyway;
//   - on windows the value is unused (windows' validateOptionsPlatform
//     ignores it and sshd's Match Group administrators owns the file), so
//     os.Getuid()'s -1 there falls into the same fixed pair as root.
//
// IAMT-284 is why this pair exists at all: the fixtures used to hardcode
// 1000/1000 for both, which is a Linux-container coincidence (first user,
// private group). On a real macOS account uid=501 but gid=20 (staff) —
// uid is never the gid — so the strict-mode preflight compared the temp
// directory's real owner (501) against the fixture's expectation (1000)
// and every door test failed with "is owned by uid 501, expected uid
// 1000", while fchownIfRoot refused to chown the temp file to "501:501"
// (a group this user is not in). Nothing about the production checks was
// wrong; only the fixture's idea of who the test user is.
//
// The two helpers are deliberately separate functions rather than one
// uid used twice: uid and gid are independent facts of an account, and
// assuming they are equal is precisely the bug being fixed.
func testOwnerUID() int {
	if uid := os.Getuid(); uid > 0 {
		return uid
	}
	return 1000
}

func testOwnerGID() int {
	if gid := os.Getgid(); gid > 0 {
		return gid
	}
	return 1000
}

// testDoorOptions returns platform-correct DoorOptions: on linux/darwin
// a fresh t.TempDir() LockPath (so the flock file does not sit beside the
// user's key file) and this process's own uid/gid as the owner this door
// will be installed for. On windows LockPath is unused (the platform
// layer derives the path itself from keyFile) and OwnerUID/OwnerGID are
// ignored — the fixed pair from the helpers above is as good as any.
func testDoorOptions(t *testing.T) DoorOptions {
	t.Helper()
	dir := t.TempDir()
	return DoorOptions{
		LockPath: filepath.Join(dir, "testkeys.lock"),
		OwnerUID: testOwnerUID(),
		OwnerGID: testOwnerGID(),
	}
}

// TestFormatLine pins the wire format. The protocol (PROTOCOL §5.1
// and SPEC §6.3) requires this exact shape.
func TestFormatLine(t *testing.T) {
	id := "deadbeefcafebabe1234567890abcdef"
	got := FormatLine(id, TestKey)
	want := `restrict,pty,from="127.0.0.1" ssh-ed25519 ` + TestKey + ` iamtunnel-door=deadbeefcafebabe1234567890abcdef`
	if got != want {
		t.Fatalf("FormatLine:\n got=%q\nwant=%q", got, want)
	}
}

// TestIsOurs covers the strict IsOurs predicate: a leading space
// is required, then 32 hex digits of door-id, then only whitespace
// or end-of-line. A bare marker-bearing comment is not ours; a
// similar-shaped marker with non-hex tail is not ours.
func TestIsOurs(t *testing.T) {
	ours := FormatLine("00000000000000000000000000000000", TestKey)
	if !IsOurs(ours) {
		t.Errorf("IsOurs failed on %q", ours)
	}
	if !IsOursID(ours, "00000000000000000000000000000000") {
		t.Errorf("IsOursID failed on %q with own doorID", ours)
	}
	if IsOursID(ours, "00000000000000000000000000000001") {
		t.Errorf("IsOursID matched a different doorID")
	}
	if IsOurs(`ssh-ed25519 something`) {
		t.Errorf("IsOurs misidentified a markerless line")
	}
	if IsOurs(`# iamtunnel-door=short`) {
		t.Errorf("IsOurs misidentified a short tail")
	}
	if IsOurs(`# iamtunnel-door=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz`) {
		t.Errorf("IsOurs misidentified a non-hex tail")
	}
	// Our line starts with the options prefix, so there IS a
	// leading space before the marker. A bare-marker comment with
	// no preceding space must not be picked up.
	if IsOurs(`#iamtunnel-door=00000000000000000000000000000000`) {
		t.Errorf("IsOurs misidentified a no-leading-space comment")
	}
}

// TestIsOursRequiresOwnOptionsPrefix is IAMT-71's central assertion
// at the unit level: a line a human wrote by hand, whose free-text
// comment happens to end in something shaped exactly like our
// marker plus a well-formed 32-hex door-id, must NOT be recognised
// as ours unless it also starts with our own options prefix.
// The suffix alone used to be enough — that was the bug.
func TestIsOursRequiresOwnOptionsPrefix(t *testing.T) {
	sameID := "deadbeefcafebabe1234567890abcdef"

	// Foreign prefix, otherwise a byte-perfect marker+id tail: this
	// is the false friend that used to be swept.
	foreign := `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpretendKeyMaterial admin@example.com backup key iamtunnel-door=` + sameID
	if IsOurs(foreign) {
		t.Errorf("IsOurs must reject a foreign-prefix line even with a well-formed marker tail: %q", foreign)
	}
	if IsOursID(foreign, sameID) {
		t.Errorf("IsOursID must reject a foreign-prefix line even when doorID matches: %q", foreign)
	}

	// Same door-id, but written with our own options prefix: this
	// one really is ours and must still match (our prefix + our
	// marker).
	genuine := FormatLine(sameID, TestKey)
	if !IsOurs(genuine) {
		t.Errorf("IsOurs must accept a line with both our prefix and our marker: %q", genuine)
	}

	// Our prefix, but no marker at all (our prefix + a
	// foreign/absent marker).
	ourPrefixNoMarker := Options + ` ssh-ed25519 ` + TestKey + ` someone-elses-comment`
	if IsOurs(ourPrefixNoMarker) {
		t.Errorf("IsOurs must reject our prefix without our marker: %q", ourPrefixNoMarker)
	}
}

// TestIsOursRejectsCorruptedOwnMarker keeps IsOurs a predicate for a valid
// id. SweepStale additionally uses the immutable line frame to recognise
// and remove this same line as a damaged owned door.
func TestIsOursRejectsCorruptedOwnMarker(t *testing.T) {
	corrupted := Options + ` ssh-ed25519 ` + TestKey + ` iamtunnel-door=deadbeefcafebabe1234567890abcdeZ`
	if IsOurs(corrupted) {
		t.Errorf("IsOurs must reject our own prefix with a non-hex door-id tail: %q", corrupted)
	}
	tooShort := Options + ` ssh-ed25519 ` + TestKey + ` iamtunnel-door=deadbeef`
	if IsOurs(tooShort) {
		t.Errorf("IsOurs must reject our own prefix with a truncated door-id tail: %q", tooShort)
	}
}

func TestNewDoorRejectsEmptyKeyFile(t *testing.T) {
	if _, err := NewDoor("", nil); err == nil {
		t.Fatalf("NewDoor with empty keyFile must error")
	}
}

func TestNewDoorNilSinkIsOK(t *testing.T) {
	if _, err := NewDoorWithOptions(tempKeyFile(t), nil, testDoorOptions(t)); err != nil {
		t.Fatalf("NewDoorWithOptions with nil sink must not error: %v", err)
	}
}

// TestInstallAndReadback is the layer-0 happy path: under the file
// lock, atomically, the line appears and read-back sees it.
func TestInstallAndReadback(t *testing.T) {
	d := tempDoor(t)
	id := randomDoorID(t)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatalf("Install: %v", err)
	}
	lines, err := d.ReadLines()
	if err != nil {
		t.Fatalf("ReadLines: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d: %v", len(lines), lines)
	}
	if !IsOursID(lines[0], id) {
		t.Fatalf("written line not recognised: %q", lines[0])
	}
}

// TestInstallRequiresNonEmptyDoorID guards against an empty id
// silently producing a line nobody can sweep later.
func TestInstallRequiresNonEmptyDoorID(t *testing.T) {
	d := tempDoor(t)
	if err := d.Install("", TestKey); err == nil {
		t.Fatal("Install with empty doorID must error")
	}
}

// TestSweepStalePreservesThirdParty is the heart of "stranger keys
// preserved byte-for-byte": pre-existing stranger lines, an empty
// line, and a comment containing the marker (false friend) — they
// all survive the sweep, in order.
func TestSweepStalePreservesThirdParty(t *testing.T) {
	path := tempKeyFile(t)
	preExisting := []string{
		`# ssh-rsa AAAAB3Nz... user@laptop`,
		`ssh-ed25519 AAAAC3Nza... friend@home`,
		``, // empty line — preserved
		`# some program left iamtunnel-door=foo here as a comment`, // not ours
	}
	if err := os.WriteFile(path, []byte(strings.Join(preExisting, "\r\n")+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	id1 := randomDoorID(t)
	id2 := randomDoorID(t)
	d := tempDoorWithPath(t, path)
	if err := d.Install(id1, TestKey); err != nil {
		t.Fatal(err)
	}
	// Add a second line via raw write. door.open's Install does NOT
	// sweep pre-existing iamtunnel lines (PROTOCOL §5.1, PROTOCOL.md:243,248:
	// "atomically replace the file" means only the same-marker line is touched),
	// so a second Install would just append. We simulate the realistic case
	// — a foreign process dropped a stale line — by writing it directly with
	// os.WriteFile. SweepStale must still drop both ours and leave strangers
	// alone.
	stale := FormatLine(id2, TestKey)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(stale + "\r\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	n, err := d.SweepStale("")
	if err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 removed, got %d", n)
	}

	got, err := d.ReadLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(preExisting) {
		t.Fatalf("expected %d lines after sweep, got %d: %v", len(preExisting), len(got), got)
	}
	for _, l := range got {
		if IsOurs(l) {
			t.Errorf("SweepStale left an ours line behind: %q", l)
		}
	}
	for _, p := range preExisting {
		found := false
		for _, g := range got {
			if g == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("third-party line vanished: %q", p)
		}
	}
}

// TestSweepStaleDoesNotTouchForeignLookalike is IAMT-71's main
// assertion at the operation level: a foreign line
// whose human-written comment happens to end exactly like our
// marker plus a well-formed 32-hex door-id is not removed by
// SweepStale, and every other line — including it — survives
// byte-for-byte and in order.
func TestSweepStaleDoesNotTouchForeignLookalike(t *testing.T) {
	path := tempKeyFile(t)
	lookalike := `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpretendKeyMaterial admin@example.com backup key iamtunnel-door=deadbeefcafebabe1234567890abcdef`
	preExisting := []string{
		`# ssh-rsa AAAAB3Nz... user@laptop`,
		lookalike,
		``,
		`ssh-ed25519 AAAAC3Nza... friend@home`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(preExisting, "\r\n")+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := tempDoorWithPath(t, path)

	n, err := d.SweepStale("")
	if err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 removed (the lookalike line is not ours), got %d", n)
	}

	got, err := d.ReadLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(preExisting) {
		t.Fatalf("expected %d lines untouched, got %d: %v", len(preExisting), len(got), got)
	}
	for i, want := range preExisting {
		if got[i] != want {
			t.Errorf("line %d changed: got %q, want %q", i, got[i], want)
		}
	}
}

// TestSweepStaleRemovesCorruptedOwnMarker covers the corruption-aware path
// and verifies raw preservation of every foreign physical line.
func TestSweepStaleRemovesCorruptedOwnMarker(t *testing.T) {
	path := tempKeyFile(t)
	corrupted := Options + ` ssh-ed25519 ` + TestKey + ` iamtunnel-door=deadbeef!`
	foreignBefore := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRealForeignKey iamtunnel-door=deadbeef`
	foreignAfter := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIxyziamtunnel-door=00000000000000000000000000000000`
	want := []byte(foreignBefore + "\r\n\r\n# iamtunnel-door=not-ours\r\n" + foreignAfter)
	input := []byte(foreignBefore + "\r\n\r\n" + corrupted + "\r\n# iamtunnel-door=not-ours\r\n" + foreignAfter)
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	sink := &memorySink{}
	d := tempDoorWithSinkPath(t, path, sink)

	n, err := d.SweepStale("")
	if err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected one corrupt own line removed, got %d", n)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("foreign bytes changed:\n got: %q\nwant: %q", got, want)
	}
	actions := sink.snapshot()
	if len(actions) != 1 || actions[0].CorruptRemoved != 1 || actions[0].Removed != 1 {
		t.Fatalf("corrupt removal was not audit-visible: %+v", actions)
	}
}

// TestSweepStaleOwnershipBoundary enumerates the ambiguous inputs from
// IAMT-86 and IAMT-94. Damage after the precisely located marker, or an
// unreadable/corrupt key with our marker, belongs to our line; damage to the
// marker itself, or an ordinary comment merely mentioning the marker text,
// never authorises deleting a third-party line.
func TestSweepStaleOwnershipBoundary(t *testing.T) {
	path := tempKeyFile(t)
	ownedCorrupt := []string{
		Options + ` ssh-ed25519 ` + TestKey + ` iamtunnel-door=`,
		Options + ` ssh-ed25519 ` + TestKey + ` iamtunnel-door=deadbeef`,
		Options + ` ssh-ed25519 ` + TestKey + ` iamtunnel-door=0000000000000000000000000000000Z`,
		Options + ` ssh-ed25519 ` + TestKey + ` iamtunnel-door=00000000000000000000000000000000 iamtunnel-door=second`,
		Options + ` ssh-ed25519 not-a-base64-key iamtunnel-door=deadbeef`,
	}
	foreign := []string{
		Options + ` ssh-ed25519 ` + TestKey + ` iamtunnel-door`, // marker itself is damaged
		Options + ` ssh-ed25519 ` + TestKey + ` ordinary-comment iamtunnel-door=deadbeef`,
		`# iamtunnel-door=deadbeef`,
	}
	input := append(append([]string{}, foreign[:1]...), ownedCorrupt...)
	input = append(input, foreign[1:]...)
	if err := os.WriteFile(path, []byte(strings.Join(input, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	d := tempDoorWithPath(t, path)
	n, err := d.SweepStale("")
	if err != nil {
		t.Fatal(err)
	}
	if n != len(ownedCorrupt) {
		t.Fatalf("removed %d corrupt owned lines; want %d", n, len(ownedCorrupt))
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(strings.Join(foreign, "\n"))
	if string(got) != string(want) {
		t.Fatalf("ownership boundary changed foreign bytes:\n got: %q\nwant: %q", got, want)
	}
}

// TestSweepStaleKeepsCurrentDoor verifies the "do not sweep the
// live door" branch: when a non-empty currentDoorID is passed,
// that one line is preserved while other iamtunnel lines go.
func TestSweepStaleKeepsCurrentDoor(t *testing.T) {
	path := tempKeyFile(t)
	d := tempDoorWithPath(t, path)
	keepID := randomDoorID(t)
	drop1 := randomDoorID(t)
	drop2 := randomDoorID(t)

	if err := d.Install(keepID, TestKey); err != nil {
		t.Fatal(err)
	}
	// Plant two extra lines via direct write — install-style
	// would consolidate into one.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{drop1, drop2} {
		if _, err := f.WriteString(FormatLine(id, TestKey) + "\r\n"); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	f.Close()

	n, err := d.SweepStale(keepID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("expected 2 removed, got %d", n)
	}
	got, _ := d.ReadLines()
	foundKeep := false
	for _, l := range got {
		if IsOursID(l, keepID) {
			foundKeep = true
		}
		if IsOursID(l, drop1) || IsOursID(l, drop2) {
			t.Errorf("door that should have been swept is still present: %q", l)
		}
	}
	if !foundKeep {
		t.Errorf("keep door vanished during sweep")
	}
}

// TestSweepStaleStillRemovesGenuineLine proves that
// after narrowing IsOurs, a real line this package wrote is still
// swept by SweepStale, and the surrounding stranger lines survive
// byte-for-byte and in the same order.
func TestSweepStaleStillRemovesGenuineLine(t *testing.T) {
	path := tempKeyFile(t)
	before := []string{`# stranger one`, `ssh-ed25519 AAAAC3Nza... friend@home`}
	after := []string{`# stranger one`, `ssh-ed25519 AAAAC3Nza... friend@home`}
	if err := os.WriteFile(path, []byte(strings.Join(before, "\r\n")+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := tempDoorWithPath(t, path)
	id := randomDoorID(t)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatal(err)
	}
	n, err := d.SweepStale("")
	if err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 removed (our genuine line), got %d", n)
	}
	got, err := d.ReadLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(after) {
		t.Fatalf("expected %d stranger lines left, got %d: %v", len(after), len(got), got)
	}
	for i, want := range after {
		if got[i] != want {
			t.Errorf("stranger line %d changed: got %q, want %q", i, got[i], want)
		}
	}
}

// TestRemoveStillDeletesGenuineLine proves that the
// targeted close path (Remove) still removes our real line, leaving
// stranger lines byte-for-byte and in order.
func TestRemoveStillDeletesGenuineLine(t *testing.T) {
	path := tempKeyFile(t)
	strangers := []string{`# stranger one`, `ssh-ed25519 AAAAC3Nza... friend@home`}
	if err := os.WriteFile(path, []byte(strings.Join(strangers, "\r\n")+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := tempDoorWithPath(t, path)
	id := randomDoorID(t)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove(id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got, err := d.ReadLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(strangers) {
		t.Fatalf("expected %d stranger lines left, got %d: %v", len(strangers), len(got), got)
	}
	for i, want := range strangers {
		if got[i] != want {
			t.Errorf("stranger line %d changed: got %q, want %q", i, got[i], want)
		}
	}
}

// TestRemoveIsIdempotent: removing an absent line is not an error.
// This guards the server's "Stop on a wire that died" path.
func TestRemoveIsIdempotent(t *testing.T) {
	d := tempDoor(t)
	id := randomDoorID(t)
	if err := d.Remove(id); err != nil {
		t.Fatalf("Remove on empty file must be a no-op, got %v", err)
	}
}

// TestRemoveRequiresNonEmptyDoorID pairs with TestInstallRequires
// — an empty id can produce a line nobody can sweep; same for
// remove.
func TestRemoveRequiresNonEmptyDoorID(t *testing.T) {
	d := tempDoor(t)
	if err := d.Remove(""); err == nil {
		t.Fatal("Remove with empty doorID must error")
	}
}

// TestInstallThenRemoveRoundTrip writes and then removes — the
// file should be empty again.
func TestInstallThenRemoveRoundTrip(t *testing.T) {
	d := tempDoor(t)
	id := randomDoorID(t)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove(id); err != nil {
		t.Fatal(err)
	}
	lines, _ := d.ReadLines()
	if len(lines) != 0 {
		t.Fatalf("expected empty file after Remove, got %v", lines)
	}
}

// TestReinstallSameIDCollapses is the "open exactly as needed"
// guarantee: calling Install twice with the same
// doorID does not leave two lines. The line must end up in the
// file exactly once.
func TestReinstallSameIDCollapses(t *testing.T) {
	d := tempDoor(t)
	id := randomDoorID(t)
	for i := 0; i < 5; i++ {
		if err := d.Install(id, TestKey); err != nil {
			t.Fatalf("Install iteration %d: %v", i, err)
		}
	}
	lines, _ := d.ReadLines()
	count := 0
	for _, l := range lines {
		if IsOursID(l, id) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one line for doorID, got %d (file: %v)", count, lines)
	}
}

// TestConcurrentInstallAndRemove reproduces the spike's race test
// in the product surface: two writers alternate Install + Remove
// on disjoint door IDs, and the file must remain valid (everyone
// sees complete lines, no ours leftover, all strangers intact).
// Run with the race detector enabled.
func TestConcurrentInstallAndRemove(t *testing.T) {
	path := tempKeyFile(t)
	strangers := []string{
		`# persistent-a`,
		`ssh-ed25519 AAAAPERS friend@elsewhere`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(strangers, "\r\n")+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := tempDoorWithPath(t, path)
	id1 := randomDoorID(t)
	id2 := randomDoorID(t)
	var errA, errB error
	done := make(chan struct{}, 2)

	doCycle := func(myID string, setErr *error) {
		for i := 0; i < 25; i++ {
			if err := d.Install(myID, TestKey); err != nil {
				*setErr = err
				done <- struct{}{}
				return
			}
			if err := d.Remove(myID); err != nil {
				*setErr = err
				done <- struct{}{}
				return
			}
		}
		done <- struct{}{}
	}
	go func() { doCycle(id1, &errA) }()
	go func() { doCycle(id2, &errB) }()
	<-done
	<-done
	if errA != nil {
		t.Fatalf("writer A: %v", errA)
	}
	if errB != nil {
		t.Fatalf("writer B: %v", errB)
	}

	got, err := d.ReadLines()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range strangers {
		found := false
		for _, l := range got {
			if l == s {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("stranger line vanished: %q", s)
		}
	}
	for _, l := range got {
		if IsOurs(l) {
			t.Errorf("leftover ours line: %q", l)
		}
	}
}

// TestAudit_OpenEmitsActionEvent asserts the guarantee:
// every open emits exactly one Sink.OnDoor event before Install
// returns.
func TestAudit_OpenEmitsActionEvent(t *testing.T) {
	sink := &memorySink{}
	d := tempDoorWithSink(t, sink)
	id := randomDoorID(t)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatal(err)
	}
	actions := sink.snapshot()
	if len(actions) != 1 {
		t.Fatalf("expected exactly 1 action, got %d: %+v", len(actions), actions)
	}
	if actions[0].Op != "open" {
		t.Errorf("expected Op=open, got %q", actions[0].Op)
	}
	if actions[0].DoorID != id {
		t.Errorf("expected DoorID=%q, got %q", id, actions[0].DoorID)
	}
	if actions[0].Err != nil {
		t.Errorf("expected nil Err, got %v", actions[0].Err)
	}
	if actions[0].At.IsZero() {
		t.Errorf("expected non-zero At")
	}
}

// TestAudit_CloseEmitsActionEvent is the close variant of the
// guarantee.
func TestAudit_CloseEmitsActionEvent(t *testing.T) {
	sink := &memorySink{}
	d := tempDoorWithSink(t, sink)
	id := randomDoorID(t)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove(id); err != nil {
		t.Fatal(err)
	}
	actions := sink.snapshot()
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions (open, close), got %d: %+v", len(actions), actions)
	}
	last := actions[1]
	if last.Op != "close" {
		t.Errorf("expected Op=close, got %q", last.Op)
	}
	if last.DoorID != id {
		t.Errorf("expected DoorID=%q, got %q", id, last.DoorID)
	}
	if last.Err != nil {
		t.Errorf("expected nil Err, got %v", last.Err)
	}
}

// TestAudit_SweepEmitsActionEvent is the sweep variant.
func TestAudit_SweepEmitsActionEvent(t *testing.T) {
	sink := &memorySink{}
	d := tempDoorWithSink(t, sink)
	id := randomDoorID(t)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatal(err)
	}
	n, err := d.SweepStale("")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 removed, got %d", n)
	}
	actions := sink.snapshot()
	var sweep *Action
	for i := range actions {
		if actions[i].Op == "sweep" {
			sweep = &actions[i]
			break
		}
	}
	if sweep == nil {
		t.Fatalf("expected a sweep audit event: %+v", actions)
	}
	if sweep.Removed != 1 {
		t.Errorf("expected Removed=1, got %d", sweep.Removed)
	}
	if sweep.Err != nil {
		t.Errorf("expected nil Err, got %v", sweep.Err)
	}
}

// TestAudit_ErrorPathEmitsAuditEvent proves that the audit
// "every action leaves a record" guarantee holds on failure paths
// too. We force an Install to fail by pointing it at a directory
// (not a file), which makes the underlying open fail. The audit
// sink must still receive exactly one event with the error
// recorded — otherwise a failed install disappears from the
// journal and the operator never knows.
func TestAudit_ErrorPathEmitsAuditEvent(t *testing.T) {
	dirPath := filepath.Join(t.TempDir(), "not-a-file")
	if err := os.Mkdir(dirPath, 0o700); err != nil {
		t.Fatal(err)
	}
	sink := &memorySink{}
	d, err := NewDoorWithOptions(dirPath, sink, testDoorOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	id := randomDoorID(t)
	if err := d.Install(id, TestKey); err == nil {
		t.Fatalf("Install on a directory must fail, got nil")
	}
	actions := sink.snapshot()
	if len(actions) != 1 {
		t.Fatalf("expected 1 audit event on error, got %d: %+v", len(actions), actions)
	}
	if actions[0].Op != "open" {
		t.Errorf("expected Op=open, got %q", actions[0].Op)
	}
	if actions[0].Err == nil {
		t.Errorf("audit event must carry the failure cause")
	}
}

// TestAudit_OnIdempotentRemoveStillEmits guards "every close
// leaves a record" even when there is nothing to close: the
// server might issue a Remove on a door that already vanished,
// and the journal still records that attempt.
func TestAudit_OnIdempotentRemoveStillEmits(t *testing.T) {
	sink := &memorySink{}
	d := tempDoorWithSink(t, sink)
	id := randomDoorID(t)
	if err := d.Remove(id); err != nil {
		t.Fatal(err)
	}
	actions := sink.snapshot()
	if len(actions) != 1 || actions[0].Op != "close" {
		t.Fatalf("expected 1 close event, got %+v", actions)
	}
}

// TestParseWatchdogArgs guards the argv contract the watchdog
// subprocess speaks. PROTOCOL §5.2 and the helper binary depend
// on this exact shape; a wrong parse hands the watchdog a wrong
// parent PID or a wrong max-wait.
func TestParseWatchdogArgs(t *testing.T) {
	pid, doorID, keyFile, journalPath, maxWait, err := ParseWatchdogArgs([]string{
		"iamtunnel.exe", "server", "doorwatch", "0123456789abcdef0123456789abcdef", "12345", "C:\\path\\keys", "28800000", "C:\\path\\journal.jsonl",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pid != 12345 || doorID != "0123456789abcdef0123456789abcdef" || keyFile != "C:\\path\\keys" {
		t.Fatalf("unexpected parse: pid=%d doorID=%q keyFile=%q", pid, doorID, keyFile)
	}
	if maxWait != 28800000*time.Millisecond {
		t.Fatalf("maxWait: got %s, want 8h", maxWait)
	}
	if journalPath != "C:\\path\\journal.jsonl" {
		t.Fatalf("journalPath: got %q, want %q", journalPath, "C:\\path\\journal.jsonl")
	}
	if _, _, _, _, _, err := ParseWatchdogArgs([]string{"only"}); err == nil {
		t.Fatalf("expected error on too few args")
	}
	if _, _, _, _, _, err := ParseWatchdogArgs([]string{"x", "wrong", "doorwatch", "d", "1", "k", "1", "j"}); err == nil {
		t.Fatalf("expected error when args[1] != 'server'")
	}
	if _, _, _, _, _, err := ParseWatchdogArgs([]string{"x", "server", "wrong", "d", "1", "k", "1", "j"}); err == nil {
		t.Fatalf("expected error when args[2] != 'doorwatch'")
	}
	if _, _, _, _, _, err := ParseWatchdogArgs([]string{"x", "server", "doorwatch", "d", "abc", "k", "1", "j"}); err == nil {
		t.Fatalf("expected error on non-numeric pid")
	}
	if _, _, _, _, _, err := ParseWatchdogArgs([]string{"x", "server", "doorwatch", "d", "1", "k", "abc", "j"}); err == nil {
		t.Fatalf("expected error on non-numeric max-wait-ms")
	}
}

// TestAtomicContentSnapshot is the property we actually need to
// prove: at any moment a successful reader opens the file, the
// content is either the old version or the new version, never a
// half-written one. writeAtomic does that by writing the new
// version to a sibling tmp file and renaming it over. The reader
// may see brief ERROR_ACCESS_DENIED during the rename (Windows
// file-handle semantics — that is documented in MoveFileEx's
// "If the destination file is open for normal I/O" caveat), but
// the file is never observed empty.
func TestAtomicContentSnapshot(t *testing.T) {
	d := tempDoor(t)
	idA := randomDoorID(t)
	idB := randomDoorID(t)
	if err := d.Install(idA, TestKey); err != nil {
		t.Fatal(err)
	}
	// 100 alternating reinstalls on a single Door. Each successful
	// read must yield either the A-line or the B-line, never
	// neither and never partial.
	readCoherent := 0
	readTotal := 0
	for i := 0; i < 100; i++ {
		id := idA
		if i%2 == 1 {
			id = idB
		}
		if err := d.Install(id, TestKey); err != nil {
			t.Fatalf("Install iter %d: %v", i, err)
		}
		lines, err := d.ReadLines()
		if err != nil {
			continue
		}
		readTotal++
		foundOurs := false
		for _, l := range lines {
			if IsOursID(l, id) {
				foundOurs = true
				break
			}
		}
		if foundOurs {
			readCoherent++
		} else {
			t.Errorf("read after Install(%d) did not find our line (file: %v)", i, lines)
		}
	}
	if readCoherent != readTotal {
		t.Fatalf("read coherence dropped: %d/%d", readCoherent, readTotal)
	}
}

// TestEnsureDirCreatesMissingParent is a small guard: server
// role's install on a fresh machine needs EnsureDir to make
// C:\ProgramData\ssh on the first run.
func TestEnsureDirCreatesMissingParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newdir", "subdir", "testkeys")
	d, err := NewDoorWithOptions(path, nil, testDoorOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	created, err := d.EnsureDir()
	if err != nil {
		t.Fatal(err)
	}
	if created == "" {
		t.Fatalf("expected non-empty directory name")
	}
	if _, err := os.Stat(created); err != nil {
		t.Fatalf("EnsureDir did not create %s: %v", created, err)
	}
}
