// Package winkeys owns administrators_authorized_keys on a Windows
// target: the door line (SPEC §6.3 layer 0), the ACL lockdown (layer 1),
// the server-side live removal (layer 2) and the doorwatch fallback
// (layer 3). It must never touch a line it did not write, must not
// talk to the gateway or know about sessions.
//
// Path discipline: every function that touches the file takes the
// path as a parameter. There is no constant that names a real
// authorized_keys file, and the package never resolves
// C:\ProgramData\ssh or opens the sshd service. All tests operate
// on paths inside t.TempDir(). The real Windows authorised_keys on
// this machine is the production sshd's configuration file; it is
// outside this package and outside these tests by design.
//
// Audit discipline: the Sink passed to New is the only audit surface.
// Every Install/Remove/SweepStale path emits one event through the
// Sink. The Sink is set at construction and there is no exported
// way to mutate or disable it after — there is no setter, no
// package-level variable, no environment lookup, and no build tag.
// This is the only way to ensure the "every action leaves a record"
// guarantee without leaving a kill switch in the binary.
package winkeys

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Marker is appended to every line this package writes. Matching on
// it (with a non-empty 32-hex door-id tail) is what SweepStale and
// Remove use. The format mirrors the spike and SPEC §6.3 table row 0.
const Marker = "iamtunnel-door="

// TestKey is a deterministic, syntactically valid ed25519 public-key blob
// with an all-zero public half. It has no corresponding test private key and
// is used only as inert text in files rooted at t.TempDir().
const TestKey = "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// Options is the authorized_keys options prefix required by SPEC
// §6.3 table row 0. `restrict,pty,from="127.0.0.1"` is what we put
// before every key. The package documents the format but does not
// generate a different prefix per call: server-side policy lives
// in the server role, not here.
const Options = `restrict,pty,from="127.0.0.1"`

// OwnerMarker tags a door line with the registration that wrote it
// (1.4). It is the second comment token, after the door id.
//
// Until 1.4 a machine held one registration, so every iamtunnel line in
// the file belonged to the one server and a sweep could take them all.
// A machine now holds one registration per person, and on Windows they
// share the single file sshd reads for administrators, so a sweep that
// could not tell whose line it was looking at would disconnect a
// colleague mid-session. The tag is what makes "mine" answerable.
const OwnerMarker = "iamtunnel-owner="

// FormatLine returns one line in the exact shape SPEC §6.3 table
// row 0 calls for. CRLF is not appended — the writer is responsible
// for the separator.
//
// An empty owner writes the pre-1.4 shape, which is what a file written
// by an older build already contains.
func FormatLine(doorID, pubKey string) string {
	return FormatLineOwned(doorID, pubKey, "")
}

// FormatLineOwned is FormatLine with the owner tag of 1.4.
func FormatLineOwned(doorID, pubKey, owner string) string {
	line := fmt.Sprintf(`%s ssh-ed25519 %s %s%s`, Options, pubKey, Marker, doorID)
	if owner != "" {
		line += " " + OwnerMarker + owner
	}
	return line
}

// IsOurs reports whether line has the complete, valid door-line shape.
// Ownership is established by the immutable portion that Install writes:
// our exact options, ssh-ed25519 key field and marker as the first comment
// token. The id is then validated separately. See isDoorLine for why a
// malformed id is still an owned (but corrupt) door line.
func IsOurs(line string) bool {
	_, _, valid, _ := isDoorLine(line)
	return valid
}

// OwnerOf returns the registration that wrote this door line, or "" for
// a line written before 1.4 — and for a line that is not ours at all,
// so callers pair it with IsOurs.
func OwnerOf(line string) string {
	_, owner, _, _ := isDoorLine(line)
	return owner
}

// DoorLineID returns the door id (the bare 32-hex form Install was given)
// and the owner tag of a valid door line - the same reading IsOurs and
// OwnerOf make, for a caller that needs the id itself. ok is false for a
// corrupt line and for a line that is not ours at all; owner is "" for a
// line written before 1.4.
func DoorLineID(line string) (id, owner string, ok bool) {
	id, owner, valid, _ := isDoorLine(line)
	return id, owner, valid
}

// IsOursID is like IsOurs but verifies the door-id matches. An
// empty doorID is rejected so the function stays a usable
// "this specific line is mine" predicate.
func IsOursID(line, doorID string) bool {
	if doorID == "" {
		return false
	}
	id, _, valid, _ := isDoorLine(line)
	return valid && id == doorID
}

// LooksLikeDoorLine reports whether line is syntactically shaped like
// a door line written by this package: our exact options prefix, an
// ssh-ed25519 key field, and the iamtunnel-door= marker as the first
// token of the comment field. The validity of the key and the
// 32-hex shape of the marker tail are NOT checked — that is what
// IsOurs / IsOursID are for. Use LooksLikeDoorLine where the question
// is "did we ever write anything here, even if it got corrupted later
// on disk" (door.sanitize, SweepStale, corruption detection, the
// stale/foreign-line sanity check the gateway runs before a door
// status reply). Use IsOursID where the question is "is this the
// specific line I just installed" (Remove(doorID), Install's read-back
// proof, SweepStale's preserve branch).
//
// The two predicates deliberately do not share their tail check
// (PROTOCOL §5.1 still demands a valid 32-hex door id where the
// line is matched against a specific expected id — IAMT-246 fix5
// finding 4: "isOursID requires an exact match on a valid 32-hex
// id"); a corrupted tail is still an owned door line for the
// corruption-detector, and "not the one I'm looking at" for the
// specific-id matcher.
func LooksLikeDoorLine(line string) bool {
	prefix := Options + " ssh-ed25519 "
	if !strings.HasPrefix(line, prefix) {
		return false
	}
	rest := line[len(prefix):]
	keyEnd := strings.IndexByte(rest, ' ')
	if keyEnd <= 0 {
		return false
	}
	comment := rest[keyEnd+1:]
	return strings.HasPrefix(comment, Marker)
}

// isDoorLine recognises the non-negotiable format written by FormatLine.
// It returns (id, valid, corrupt). Ownership is established by our options
// prefix, ssh-ed25519 key token and the iamtunnel-door= marker as the first
// token in the comment field.
//
// A line is valid if its key is a valid base64 token AND its marker tail is
// exactly one 32-hex door id (plus optional horizontal whitespace).
//
// A line is corrupt (but owned, and therefore subject to removal by SweepStale
// and door.sanitize per PROTOCOL §5.1 / SPEC §8 / IAMT-94) if it carries our
// options and marker prefix, but its key token is unreadable/invalid base64
// or its marker tail is malformed.
//
// A foreign line (different options prefix, no options prefix, hash comment,
// or an ordinary third-party comment merely containing "iamtunnel-door=" later
// in prose) has no ownership signature and is deliberately left untouched.
func isDoorLine(line string) (id, owner string, valid, corrupt bool) {
	prefix := Options + " ssh-ed25519 "
	if !strings.HasPrefix(line, prefix) {
		return "", "", false, false
	}
	rest := line[len(prefix):]
	keyEnd := strings.IndexByte(rest, ' ')
	if keyEnd <= 0 {
		return "", "", false, false
	}
	key := rest[:keyEnd]
	comment := rest[keyEnd+1:]
	if !strings.HasPrefix(comment, Marker) {
		return "", "", false, false
	}
	tail := comment[len(Marker):]
	if !isBase64Token(key) {
		return "", "", false, true
	}
	if len(tail) < 32 {
		return "", "", false, true
	}
	for i := 0; i < 32; i++ {
		if !isHex(tail[i]) {
			return "", "", false, true
		}
	}
	// What follows the id is either nothing — a line from before 1.4 —
	// or the owner tag. Anything else is a line we wrote and can no
	// longer read, which is corrupt: the same verdict as a malformed
	// id, for the same reason. This package must not guess about its
	// own lines.
	after := strings.TrimLeft(tail[32:], " \t")
	if after == "" {
		return tail[:32], "", true, false
	}
	if !strings.HasPrefix(after, OwnerMarker) {
		return "", "", false, true
	}
	owner = strings.TrimRight(after[len(OwnerMarker):], " \t")
	if owner == "" || strings.ContainsAny(owner, " \t") {
		return "", "", false, true
	}
	return tail[:32], owner, true, false
}

func isBase64Token(s string) bool {
	if s == "" {
		return false
	}
	if _, err := base64.StdEncoding.DecodeString(s); err == nil {
		return true
	}
	_, err := base64.RawStdEncoding.DecodeString(s)
	return err == nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// Sink accepts audit events from Door operations. Implementations
// decide WHERE to write (file, journal, event bus). Set at
// construction time; the API does not expose any way to swap the
// sink after the Door is built. Pass nil to Open to disable
// auditing — tests do this when audit is not the subject.
type Sink interface {
	OnDoor(a Action)
}

// Action is the audit payload emitted by Sink.OnDoor. The Err
// field is non-nil on failure paths; removed and lines hold
// counts from sweep operations.
type Action struct {
	Op             string    // "open" | "close" | "sweep"
	DoorID         string    // empty for unconditional sweep
	At             time.Time // moment the file op returned
	Removed        int       // sweep: number of door lines removed
	CorruptRemoved int       // sweep: owned lines whose marker tail was invalid
	Err            error     // nil on success
}

// noopSink is the Sink used when the caller passes nil to New.
type noopSink struct{}

func (noopSink) OnDoor(Action) {}

// DoorOptions carries the platform-specific knobs a Door needs on
// non-Windows targets. On Windows the zero value is sufficient:
// the lock path is derived from the key file and the file's owner
// is whoever sshd's Match Group administrators block names. On
// Linux and Darwin every field has a meaning:
//
//   - LockPath: the cross-process lock file the server role keeps
//     in its own data directory (SPEC §3.2.1: "lock — flock on the
//     door.lock file in the server's directory (the user cannot
//     hold it)"). It must differ from keyFile — keeping the
//     lock alongside the user's authorized_keys would let the
//     owner hold it and freeze the door. NewDoor refuses an empty
//     LockPath on linux/darwin.
//   - OwnerUID / OwnerGID: the uid/gid of the user whose
//     authorized_keys the door line lives in. The server resolves
//     them via os/user.Lookup at start time and threads them here;
//     tests pass fixed integers. The Door writes the tmp file
//     with these values via fchown(2) under a seam so a test
//     binary never touches the real user database.
//
// On platforms that are not linux/darwin the zero value is the
// right answer; the platform layer there rejects every operation
// explicitly rather than running with platform defaults that might
// silently bypass the strict-mode checks (SPEC §3.2.1).
type DoorOptions struct {
	LockPath string
	OwnerUID int
	OwnerGID int
	// Owner names the REGISTRATION whose doors this Door may touch
	// (1.4) — the machine id, in practice. It is not a filesystem owner
	// and has nothing to do with OwnerUID/OwnerGID; it is the tag
	// written into each line, and the only thing that lets a sweep tell
	// one server's doors from another's on a machine that now holds
	// several registrations.
	//
	// An empty Owner means "the only server on this machine", the
	// pre-1.4 shape. Such a Door writes untagged lines and sweeps only
	// untagged ones, so an old file keeps working and a tagged line is
	// never touched by a caller that could not say whose it was.
	Owner string
}

// NewDoor constructs a Door for the given key file. The sink is
// the audit destination; passing nil is equivalent to passing a
// sink that drops every event.
//
// On Windows this is the only constructor the server role needs:
// the lock path is derived from the key file and the door's owner
// is sshd's Match Group administrators identity. On Linux and
// Darwin the same call refuses with a clear message: the server
// role must use NewDoorWithOptions so the lock path and the
// owner uid/gid are explicit. This split keeps the existing
// Windows server logic untouched — Windows behavior and
// tests do not change — and forces the Linux/Darwin path to surface
// the choices it has to make.
//
// The keyFile path is REQUIRED to be non-empty. The Door does not
// touch the filesystem at construction — it does that lazily
// inside Install / SweepStale / Remove. This keeps New cheap and
// makes it safe to call before checking other prerequisites.
func NewDoor(keyFile string, sink Sink) (*Door, error) {
	return NewDoorWithOptions(keyFile, sink, DoorOptions{})
}

// NewDoorWithOptions constructs a Door with explicit platform
// options. On Windows the only field consulted is LockPath; if it
// is empty the platform layer derives the lock path from keyFile
// the same way the Windows-only NewDoor always did. On Linux and
// Darwin LockPath must be non-empty; OwnerUID/OwnerGID are passed
// through to fchown(2) under the chown seam.
//
// NewDoorWithOptions is the constructor cmd/iamtunnel's server
// role reaches for on every GOOS that is not Windows (cmd/iamtunnel
// knows the GOOS via runtime.GOOS at the call site — see server.go).
func NewDoorWithOptions(keyFile string, sink Sink, opts DoorOptions) (*Door, error) {
	if keyFile == "" {
		return nil, errors.New("winkeys: keyFile must not be empty")
	}
	if sink == nil {
		sink = noopSink{}
	}
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	return &Door{keyFile: keyFile, sink: sink, opts: opts, owner: opts.Owner}, nil
}

// validateOptions is the platform-layer hook that decides whether
// a given Options value is usable on the current GOOS. On linux/
// darwin LockPath is mandatory; on Windows it stays optional. The
// stub on other platforms refuses rather than silently producing
// a Door whose Install would later no-op.
func validateOptions(opts DoorOptions) error { return validateOptionsPlatform(opts) }

// Door owns the file-level operations for a single key file. The
// server role creates one Door at process start; all subsequent
// Install / Remove / SweepStale calls go through it.
//
// Door is safe to use from multiple goroutines in the same
// process: mu serialises every file-touching method. The
// cross-process file lock at opts.LockPath is acquired under that
// mu, inside each method.
type Door struct {
	keyFile string
	sink    Sink
	opts    DoorOptions
	// owner is DoorOptions.Owner, kept beside the file path because
	// every predicate below asks "is this line mine", and this string
	// is the answer.
	owner string
	mu    sync.Mutex
}

// KeyFile returns the path this Door was constructed with. The
// path is informational; callers must not depend on it for I/O.
func (d *Door) KeyFile() string { return d.keyFile }

// lockPath returns the cross-process lock path the platform layer
// will use for every Install / Remove / SweepStale of this Door.
// On Windows the historical "keyFile.lock" shape is preserved so
// existing tooling and tests do not have to learn a new path. On
// Linux and Darwin opts.LockPath is mandatory (NewDoorWithOptions
// refused an empty value at construction time).
func (d *Door) lockPath() string {
	if d.opts.LockPath != "" {
		return d.opts.LockPath
	}
	return d.keyFile + ".lock"
}

// EnsureDir creates the directory of the key file if it is
// missing. Returns the directory it created (or "" if it already
// existed). Failures bubble up as is. Production callers may use
// it once at install; tests rarely need it.
func (d *Door) EnsureDir() (string, error) {
	dir := pathDir(d.keyFile)
	if dir == "" || dir == "." {
		return "", nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return dir, nil
}

// Install appends or rewrites the line for doorID into the key
// file. The semantic is:
//
//   - if the file contains zero iamtunnel lines today, the line is
//     appended. Third-party lines stay byte-for-byte;
//   - if the file contains one or more iamtunnel lines already,
//     they are removed and the new line is appended; third-party
//     lines stay byte-for-byte.
//
// The operation runs under the cross-process file lock, then
// read-back is performed: if the file does not contain a line
// matched by IsOursID(doorID), the call returns an error. On
// Windows the file's DACL ends up as {Administrators FullControl,
// SYSTEM FullControl} with SE_DACL_PROTECTED set: writeAtomicBytes
// applies that DACL to the tmp file BEFORE the rename (IAMT-214), so
// the file is never visible under its real name with a wider ACL —
// there is no separate after-the-fact lockdown step left. On Linux
// and Darwin writeAtomicBytes works relative to the parent
// directory's file descriptor (SPEC §3.2.1): the tmp file is
// created with O_NOFOLLOW inside .ssh so a symlink swap mid-write
// cannot redirect the write to a stranger's path; ownership is
// fchowned to opts.OwnerUID/OwnerGID; the rename goes through the
// parent dir fd so a TOCTOU rename of .ssh cannot land the line
// in a stranger's authorized_keys. Every observable state change
// emits one Sink.OnDoor event before Install returns.
//
// If Audit is required, the sink is the only source of truth for
// "an open happened" — there is no separate log file.
func (d *Door) Install(doorID, pubKey string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	lock, err := AcquireFileLock(d.lockPath())
	if err != nil {
		emit(d.sink, Action{Op: "open", DoorID: doorID, At: time.Now(), Err: err})
		return err
	}
	defer lock.Release()

	if err := d.installLocked(doorID, pubKey); err != nil {
		emit(d.sink, Action{Op: "open", DoorID: doorID, At: time.Now(), Err: err})
		return err
	}
	emit(d.sink, Action{Op: "open", DoorID: doorID, At: time.Now()})
	return nil
}

// installLocked must be called with d.mu held AND while the file
// lock is held.
func (d *Door) installLocked(doorID, pubKey string) error {
	if doorID == "" {
		return errors.New("winkeys: doorID must not be empty")
	}
	// Per PROTOCOL §5.1, "atomically replace the file" (PROTOCOL.md:248) means
	// adding/deleting ONLY the line with exact iamtunnel-marker; everything
	// else in administrators_authorized_keys stays byte-for-byte and in
	// order. The same-doorID collapse below is the one deletion door.open
	// is allowed: a previous install for the very same doorID is replaced.
	// Damage that belongs to our line (corrupt marker, non-base64 key) is
	// NOT removed here — that is door.sanitize's / SweepStale's job
	// (PROTOCOL.md:246, IAMT-94). Removing it here would silently turn
	// door.open into a sweep, which §5.1 does not authorise.
	//
	// Code-rev (rall_codex round, major): the previous shape read
	// the existing file via os.ReadFile, then computed next, then
	// handed next to writeAtomicBytes — which on Linux opens its
	// own sshFD and writes. A TOCTOU swap of ~/.ssh between the
	// path-based read and the openat-based write could let us
	// compute next off stale bytes. modifyKeyFile runs the whole
	// read+transform+write+readback through ONE fd on Unix, so the
	// transform sees exactly the bytes the write lands on top of.
	line := FormatLineOwned(doorID, pubKey, d.owner)
	err := modifyKeyFile(d.keyFile, func(raw []byte) ([]byte, error) {
		sameID := false
		for _, l := range splitKeyLines(raw) {
			if IsOursID(l.text, doorID) {
				sameID = true
				break
			}
		}
		if sameID {
			kept, _, _ := filterDoorLines(raw, func(line string, valid, _ bool) bool {
				return valid && IsOursID(line, doorID)
			})
			return appendDoorLine(kept, line), nil
		}
		return appendDoorLine(raw, line), nil
	}, d.opts)
	if err != nil {
		return err
	}
	// modifyKeyFile's platform layer already verified the
	// post-write content on both Unix (verifyWriteBack, byte-
	// for-byte) and Windows (read-back via readLinesLocked plus
	// the existing IsOursID walk for Install). No second pass is
	// needed here.
	return nil
}

// Remove removes the line for doorID. Returns nil if no line for
// that door was present (idempotent). Acquires the cross-process
// file lock, rewrites the file, read-backs, and emits exactly one
// audit event before returning. The audit event is emitted even on
// errors so the journal records the failed attempt. The rewrite goes
// through writeAtomicBytes, so on Windows a close leaves the file's
// protected {SYSTEM, Administrators} DACL in place instead of the
// directory's inherited entries (IAMT-214).
func (d *Door) Remove(doorID string) error {
	if doorID == "" {
		err := errors.New("winkeys: doorID must not be empty")
		emit(d.sink, Action{Op: "close", DoorID: doorID, At: time.Now(), Err: err})
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	lock, err := AcquireFileLock(d.lockPath())
	if err != nil {
		emit(d.sink, Action{Op: "close", DoorID: doorID, At: time.Now(), Err: err})
		return err
	}
	defer lock.Release()

	if err := d.removeLocked(doorID); err != nil {
		emit(d.sink, Action{Op: "close", DoorID: doorID, At: time.Now(), Err: err})
		return err
	}
	emit(d.sink, Action{Op: "close", DoorID: doorID, At: time.Now()})
	return nil
}

func (d *Door) removeLocked(doorID string) error {
	// Code-rev (rall_codex round, major): previous code read the
	// file via os.ReadFile, computed kept/removed, then wrote
	// through writeAtomicBytes — separate path-based read and
	// openat-relative write, which on Linux is a TOCTOU window.
	// modifyKeyFile closes that window by running read +
	// filterDoorLines + write + readback through ONE sshFD on
	// Unix (and the read+write are still permitted to be
	// path-based on Windows, where the openat discipline is not
	// in scope).
	err := modifyKeyFile(d.keyFile, func(raw []byte) ([]byte, error) {
		kept, _, _ := filterDoorLines(raw, func(line string, valid, _ bool) bool {
			// An OWNED Door removes only its own lines. An id is 128
			// bits of somebody's randomness, so it was never going to
			// hit the wrong line by accident — but since 1.4 a caller
			// can name another registration's id, and closing a door
			// that is not yours is not something this package should be
			// able to do, accident or not.
			//
			// An UNOWNED Door may remove any line whose id it can name,
			// and that asymmetry is deliberate. It is the watchdog
			// (doorwatch_unix.go's removeOnceAndAudit): the last-resort
			// cleanup that runs when the server process is already gone,
			// re-exec'd with the door id on its command line and nothing
			// else. Refusing it would leave the door of a crashed server
			// open — layer 3 exists precisely for the case where the
			// layers that knew the owner are dead.
			//
			// The asymmetry is safe because Remove names ONE line the
			// caller must already know the id of. The operation that
			// actually caused the 1.4 defect is the sweep, which matches
			// by pattern, and that one is owned with no exception.
			return valid && IsOursID(line, doorID) && (d.owner == "" || OwnerOf(line) == d.owner)
		})
		return kept, nil
	}, d.opts)
	return err
}

// SweepStale removes every line with the marker from the file,
// leaving every other line byte-for-byte intact. Returns the number
// of iamtunnel lines removed. If currentDoorID is non-empty, that
// one line is preserved (the server role uses this on Start so an
// open door survives a restart). Acquires the cross-process file
// lock and emits exactly one audit event. Like Remove, the rewrite
// goes through writeAtomicBytes, so a sweep (and door.sanitize, which
// is SweepStale("")) leaves the Windows file with the protected
// {SYSTEM, Administrators} DACL (IAMT-214).
func (d *Door) SweepStale(currentDoorID string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	lock, err := AcquireFileLock(d.lockPath())
	if err != nil {
		emit(d.sink, Action{Op: "sweep", DoorID: currentDoorID, At: time.Now(), Err: err})
		return 0, err
	}
	defer lock.Release()

	n, corrupt, err := d.sweepLocked(currentDoorID)
	emit(d.sink, Action{
		Op:             "sweep",
		DoorID:         currentDoorID,
		At:             time.Now(),
		Removed:        n,
		CorruptRemoved: corrupt,
		Err:            err,
	})
	return n, err
}

func (d *Door) sweepLocked(currentDoorID string) (int, int, error) {
	// Code-rev (rall_codex round, major): same TOCTOU fix as
	// removeLocked — read+filter+write+readback all go through
	// modifyKeyFile's single-fd Unix path (path-based on Windows,
	// where the openat discipline is not in scope).
	var removed, corrupt int
	err := modifyKeyFile(d.keyFile, func(raw []byte) ([]byte, error) {
		kept, n, c := filterDoorLines(raw, func(line string, valid, corrupt bool) bool {
			if !valid && !corrupt {
				return false
			}
			// MINE only (1.4). With two registrations sharing one file,
			// a line this Door cannot claim is left exactly where it
			// is: "cannot tell whose it is" must not resolve to
			// "delete", because the other side of that guess is a
			// colleague disconnected mid-session.
			if !d.ownsLine(line, valid) {
				return false
			}
			return !(currentDoorID != "" && valid && IsOursID(line, currentDoorID))
		})
		removed, corrupt = n, c
		if n == 0 {
			// No-op write: do not rewrite the file just to keep
			// the same bytes on disk — that would churn the
			// inode and trigger unrelated watchers.
			return raw, nil
		}
		return kept, nil
	}, d.opts)
	return removed, corrupt, err
}

// ownsLine answers the one question every predicate in this file turns
// on: may THIS Door touch that line?
//
// The rule is: another owner's line, never. Anything else, yes.
//
//   - a line carrying MY tag is mine;
//   - a line carrying SOMEBODY ELSE'S tag is not, and is left exactly
//     where it is. This is the whole point of the tag: on a machine
//     with several registrations, a wrong guess here disconnects a
//     colleague mid-session;
//   - an UNTAGGED line — written by a build from before 1.4, or corrupt
//     past the point where an owner can be read — is claimable by
//     anyone. It has to be.
//
// That last case was the hard one, and the first answer was the other
// one: leave untagged lines alone, since this package cannot tell whose
// they are. IAMT-194 is what settled it. A build older than 1.4 held
// exactly ONE registration on a machine, so an untagged line is by
// construction the leftover of a server that no longer exists — and
// sweeping stale lines left by a dead server, before the first dial, is
// the entire subject of IAMT-194. Refusing to sweep them leaves an
// orphaned door line on every upgraded machine, permanently, which is
// precisely the state that test was written to prevent.
//
// What it costs is a window during a MIXED-version upgrade: while an
// old binary and a new one both run on one machine, the new one's
// sweep can take the old one's live line. That window is brief, needs
// somebody to run two versions at once, and ends the moment the old
// binary is replaced. A door line nobody ever removes does not end.
func (d *Door) ownsLine(line string, valid bool) bool {
	if !valid {
		// Corrupt but ours-shaped: no owner can be read out of it, so
		// it falls in the untagged case above.
		return true
	}
	owner := OwnerOf(line)
	return owner == "" || owner == d.owner
}

// ReadLines returns the file's lines (without trailing CR/LF),
// without acquiring the file lock. This is a read-only diagnostic
// helper used by tests; production callers should not depend on
// its concurrency story.
func (d *Door) ReadLines() ([]string, error) {
	return readLinesLocked(d.keyFile)
}

// keyLine keeps one physical line exactly as it appeared on disk. raw includes
// its line ending (if any); text has neither LF nor a preceding CR.
type keyLine struct {
	text string
	raw  []byte
}

func splitKeyLines(raw []byte) []keyLine {
	if len(raw) == 0 {
		return nil
	}
	lines := make([]keyLine, 0, 8)
	for start := 0; start < len(raw); {
		end := start
		for end < len(raw) && raw[end] != '\n' {
			end++
		}
		if end < len(raw) {
			end++
		}
		segment := raw[start:end]
		textEnd := len(segment)
		if textEnd > 0 && segment[textEnd-1] == '\n' {
			textEnd--
			if textEnd > 0 && segment[textEnd-1] == '\r' {
				textEnd--
			}
		}
		lines = append(lines, keyLine{text: string(segment[:textEnd]), raw: segment})
		start = end
	}
	return lines
}

// filterDoorLines removes only complete physical lines chosen by drop. Every
// retained segment is copied verbatim, so CRLF/LF choice, blank lines and a
// missing final newline remain byte-for-byte unchanged.
func filterDoorLines(raw []byte, drop func(line string, valid, corrupt bool) bool) (kept []byte, removed, corruptRemoved int) {
	kept = make([]byte, 0, len(raw))
	for _, line := range splitKeyLines(raw) {
		_, _, valid, corrupt := isDoorLine(line.text)
		if drop(line.text, valid, corrupt) {
			removed++
			if corrupt {
				corruptRemoved++
			}
			continue
		}
		kept = append(kept, line.raw...)
	}
	return kept, removed, corruptRemoved
}

// appendDoorLine keeps existing bytes untouched. A file without a trailing
// newline gets the door line prepended: doing so avoids manufacturing a line
// terminator for a third-party final line that could not be removed later
// without changing that line's original bytes.
func appendDoorLine(raw []byte, line string) []byte {
	door := []byte(line + "\r\n")
	if len(raw) == 0 || raw[len(raw)-1] == '\n' {
		out := make([]byte, 0, len(raw)+len(door))
		out = append(out, raw...)
		return append(out, door...)
	}
	out := make([]byte, 0, len(raw)+len(door))
	out = append(out, door...)
	return append(out, raw...)
}

// readLinesLocked opens the file (which may not yet exist), reads
// its lines, returns them. It does not acquire the cross-process
// file lock; the caller is responsible.
func readLinesLocked(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return lines, nil
}

// writeAtomic writes lines to a sibling tmp file, fsyncs, renames
// into place. On Windows it uses MoveFileEx with REPLACE_EXISTING
// so a target may be atomically swapped; on Linux and Darwin the
// rename goes through renameat(2) anchored at the parent
// directory's open file descriptor so a TOCTOU swap of the
// authorised_keys parent cannot land the line anywhere but the
// real path. A truncated key file locks the account out of SSH
// entirely, so we write aside and only then move.
//
// IAMT-214: this is the ONLY path through which the key file is ever
// rewritten — Install (open), removeLocked (close, doorwatch close)
// and sweepLocked (SweepStale, door.sanitize) all end here — so it is
// where the ACL guarantee lives. On Windows the tmp file's DACL is
// narrowed to the protected {SYSTEM, Administrators} pair BEFORE the
// rename: a freshly created tmp file inherits the containing
// directory's entries (ProgramData\ssh grants Authenticated Users
// read), and after the rename the content is already visible under
// the real name — too late to fix the ACL without a window in which
// everyone can read it. protectTmpBeforeReplace explains why the
// rename carries exactly that protected DACL onto the final file. On
// Linux and Darwin the tmp file's mode is narrowed to 0600 and the
// owner is fchowned to opts.OwnerUID/OwnerGID before the rename;
// without those steps an open parent dir's default group-writable
// mode would leak the line on a freshly-created file. On
// unsupported Unixes writeAtomicBytes refuses with an explicit
// "not supported" rather than silently dropping the protection.
// modifyKeyFile is the read-modify-write counterpart of writeAtomicBytes
// (Code-rev rall_codex round, major). It is the only sanctioned way for
// the public Door.Install / Remove / SweepStale methods to rewrite the
// authorized_keys file: the read of the existing bytes, the
// application of `transform` to those bytes, the atomic write of the
// result and the post-write read-back all run inside one platform
// call. On Linux the whole sequence is anchored at a single
// ssh-directory file descriptor opened via unix.Openat under the
// already-validated homeFD — a TOCTOU swap of ~/.ssh (or the home
// itself) between the read and the write cannot redirect the write to
// a stranger's file. On Windows the read and write still go by path
// (Windows does not have the openat-style strict-mode discipline
// SPEC §3.2.1 prescribes for Linux/Darwin, so the TOCTOU concern is
// scoped to the Unix side). Windows-only is permitted for the path-based
// read+write here: the path-based code stays only for the Windows layer.
//
// transform must be pure (operate on raw bytes, return next bytes). It
// runs under the cross-process file lock and the door-level mutex
// just like writeAtomicBytes did.
//
// Returns nil on success (Unix: includes the post-write verifyWriteBack
// pass; Windows: includes a path-based read-back that names the line
// the caller expects to be on disk for Install/Remove, or simply
// "the iamtunnel lines are gone" for SweepStale).
func modifyKeyFile(path string, transform func(raw []byte) ([]byte, error), opts DoorOptions) error {
	return modifyKeyFilePlatform(path, transform, opts)
}

// chownAndRename was the cross-platform wrapper that
// sequentially called chownTmpBeforeReplace + renameForReplace;
// the unix write path now does both inside atomicWriteInSSHDir
// (via fd, with no path traversal possible), and the windows
// write path does both inside writeAtomicBytesPlatform. The
// function has no remaining caller; the cross-platform write
// surface is writeAtomicBytesPlatform alone.
//
// pathDir is filepath.Dir without importing filepath — kept here
// so the package layout is obvious and test build tags do not have
// to think about it.
func pathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[:i]
		}
	}
	return ""
}

func emit(s Sink, a Action) {
	// Sink.OnDoor must not panic; we still feed Action.At if the
	// caller left it zero.
	if a.At.IsZero() {
		a.At = time.Now()
	}
	s.OnDoor(a)
}
