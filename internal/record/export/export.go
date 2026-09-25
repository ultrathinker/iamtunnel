package export

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// EventSink receives the journal event the exporter writes after the
// files are on disk. *events.Log satisfies it; the sink is an
// interface because which journal to open is the caller's decision —
// the export runs in the window's role, and the window's caller wires
// the journal, not this package (there is no admin command that
// appends to a gateway journal, and the window holds no journal of
// its own).
type EventSink interface {
	Append(events.Event) error
}

// Request is one export. The window fills it from what it already
// holds in memory: the transcript text and the recording it watched —
// the exporter never dials the gateway for either.
type Request struct {
	// Root is the directory the export tree is created under, e.g. the
	// folder the human picked on their own machine. Required.
	Root string

	// Transcript is the finished session text. Required even when
	// empty: an empty transcript exports as one empty 0001.txt, and a
	// nil reader is refused rather than guessed about.
	Transcript io.Reader

	// Cast is the session recording, byte for byte as it was made; it
	// streams straight to session.cast under a running sha256 and is
	// never held whole in memory. Nil means the session has no
	// recording: no session.cast is written and about.txt says
	// "cast file: none" (no fabricated zero-bytes hash, PROTOCOL §8).
	Cast io.Reader

	// Person and Machine name the session and land in the folder name
	// verbatim. Both must pass the PROTOCOL §2.1 name grammar — a
	// value that cannot appear in a folder name is refused loudly,
	// never silently rewritten.
	Person  string
	Machine string

	// SessionID goes into the folder name verbatim and into about.txt.
	SessionID string

	// StartedAt is the session start; it carries the zone the date
	// folder and the HHMMSS stamp are formatted in. Required: there is
	// no honest default for a start that never happened.
	StartedAt time.Time

	// EndedAt is the session end; zero means the session is still
	// running and about.txt says so.
	EndedAt time.Time

	// Exporter is who asked for the export — the journal event's
	// Actor. Required: an export without a who is exactly the fact
	// the recording.export event exists to keep.
	Exporter string

	// PartLimit caps one text part in bytes; zero — DefaultPartLimit.
	PartLimit int

	// Version is the product version, written to about.txt verbatim.
	Version string

	// Now is the moment of the export; zero — time.Now(). The
	// recording.export event's Time is built from it, which keeps the
	// exporter deterministic under a test clock.
	Now time.Time

	// Journal receives the recording.export event. Required.
	Journal EventSink
}

// Result reports what was written. It comes back even when the error
// is non-nil: if the journal refused the event after every file is
// already on disk, the caller must be able to tell the human both
// facts — where the export is and that the journal missed the event.
type Result struct {
	// Dir is the session folder that was created, claimed name
	// included (a taken name advances to name_1, name_2, …).
	Dir string

	// Parts are the text file names, in order: 0001.txt, 0002.txt, …
	Parts []string

	// CastFile is "session.cast", or "" when the session had none.
	CastFile string

	// TranscriptBytes is the exact transcript size that was split.
	TranscriptBytes int64

	// CastBytes and CastSHA256 describe session.cast; both zero/empty
	// when the session had no recording.
	CastBytes  int64
	CastSHA256 string
}

const (
	castName        = "session.cast"
	aboutName       = "about.txt"
	aboutTimeFormat = "2006-01-02 15:04:05 -07:00"
	maxNameLen      = 32 // PROTOCOL §2.1: name = (lower / digit) *31name-char

	// maxSessionIDLen bounds the session id, which is NOT a §2.1 name
	// and must not be checked as one. The gateway mints it as
	// "<UnixNano>-<person>-<machine>": nineteen digits, two separators
	// and two names of up to 32 — eighty-three characters for the
	// longest legal pair, where a name may be thirty-two. The first
	// version of this file ran the id through the §2.1 name rule and so
	// refused EVERY real export, because every real id is over thirty-two
	// characters long; the tests that pinned it used a real id and went
	// red the first time they were run. Ninety-six leaves slack over the
	// eighty-three without letting the id push the session folder name
	// anywhere near a path limit.
	maxSessionIDLen = 96
)

// Export writes the session out and journals the fact. All or
// nothing is not promised: a failure in the middle leaves the honest
// remains — the files that made it to disk before the error — exactly
// the way an interrupted session recording does, and nothing is
// removed behind the error. The journal event goes last, after
// about.txt, so a folder that carries about.txt is a folder whose
// every other file already landed.
func Export(req Request) (Result, error) {
	if req.Root == "" {
		return Result{}, errors.New("export: Root is empty: the human's chosen folder is not guessable")
	}
	if req.Transcript == nil {
		return Result{}, errors.New("export: Transcript is nil: hand over the text the window holds, even when it is empty")
	}
	if req.Exporter == "" {
		return Result{}, errors.New("export: Exporter is empty: the recording.export event needs a who")
	}
	if req.Journal == nil {
		return Result{}, errors.New("export: Journal is nil: an export that leaves no journal event is a silent copy")
	}
	if req.StartedAt.IsZero() {
		return Result{}, errors.New("export: StartedAt is zero: the session start names the date folder")
	}
	if err := checkNameComponent("Person", req.Person); err != nil {
		return Result{}, err
	}
	if err := checkNameComponent("Machine", req.Machine); err != nil {
		return Result{}, err
	}
	if err := checkSessionID(req.SessionID); err != nil {
		return Result{}, err
	}

	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}

	transcript, err := io.ReadAll(req.Transcript)
	if err != nil {
		return Result{}, fmt.Errorf("export: read transcript: %w", err)
	}
	parts, err := Split(transcript, req.PartLimit)
	if err != nil {
		return Result{}, err
	}

	dayDir := filepath.Join(req.Root, req.StartedAt.Format("2006-01-02"))
	if err := os.MkdirAll(dayDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("export: create %s: %w", dayDir, err)
	}
	base := filepath.Join(dayDir, sessionDirName(req))
	dir, err := claimSessionDir(base)
	if err != nil {
		return Result{}, err
	}

	res := Result{
		Dir:             dir,
		Parts:           make([]string, 0, len(parts)),
		TranscriptBytes: int64(len(transcript)),
	}

	if req.Cast != nil {
		name, size, sum, cerr := writeCast(dir, req.Cast)
		if cerr != nil {
			// Only a partial session.cast may exist so far; the Result
			// still names the folder of the remains.
			return res, cerr
		}
		res.CastFile, res.CastBytes, res.CastSHA256 = name, size, sum
	}

	for i, part := range parts {
		name := partName(i + 1)
		if werr := datafile.WriteFileAtomic(filepath.Join(dir, name), part, datafile.WithMode(0o600), datafile.WithSync()); werr != nil {
			// Parts reports only the parts that made it to disk.
			return res, fmt.Errorf("export: write %s: %w", name, werr)
		}
		res.Parts = append(res.Parts, name)
	}

	about := aboutText(req, res)
	if werr := datafile.WriteFileAtomic(filepath.Join(dir, aboutName), about, datafile.WithMode(0o600), datafile.WithSync()); werr != nil {
		return res, fmt.Errorf("export: write %s: %w", aboutName, werr)
	}

	if jerr := req.Journal.Append(recordingExportEvent(req, res, now)); jerr != nil {
		// The files are written; only the journal entry failed. Both
		// facts travel: the Result carries the folder so the caller
		// can still tell the human where the export is, the error
		// says the journal missed the event.
		return res, fmt.Errorf("export: the files are in %s, but the journal refused the %s event: %w", dir, events.EventRecordingExport, jerr)
	}
	return res, nil
}

// sessionDirName builds the folder name from the contract's example:
// office-pc_alice_141205_<id> — machine, person, session clock, full
// session id. Every component is grammar-checked before it gets here.
func sessionDirName(req Request) string {
	return req.Machine + "_" + req.Person + "_" + req.StartedAt.Format("150405") + "_" + req.SessionID
}

// claimSessionDir creates the session folder, advancing to name_1,
// name_2, … while the name is taken — the take-next-name rule
// internal/gateway/record/sessionname.go applies to session names,
// for the same reason: a name derived from a clock repeats whenever
// the clock stands still, and a repeat must not refuse the human
// their export. os.Mkdir, unlike a file create, cannot be talked into
// following a planted entry: it either makes the directory or refuses.
func claimSessionDir(base string) (string, error) {
	dir := base
	for attempt := 1; attempt <= maxNameAttempts; attempt++ {
		if err := os.Mkdir(dir, 0o700); err == nil {
			return dir, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("export: create %s: %w", dir, err)
		}
		dir = base + "_" + strconv.Itoa(attempt)
	}
	return "", fmt.Errorf("export: %s: %d suffixes are taken, refusing to guess further", base, maxNameAttempts)
}

// writeCast streams the recording into session.cast under a running
// sha256, so a multi-gigabyte cast never sits whole in memory. The
// fresh O_EXCL create is datafile.Create — the same door every
// recorder-side recording goes through.
func writeCast(dir string, cast io.Reader) (string, int64, string, error) {
	f, err := datafile.Create(filepath.Join(dir, castName), 0o600)
	if err != nil {
		return "", 0, "", fmt.Errorf("export: create %s: %w", castName, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), cast)
	if err != nil {
		f.Close()
		return "", 0, "", fmt.Errorf("export: write %s: %w", castName, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", 0, "", fmt.Errorf("export: sync %s: %w", castName, err)
	}
	if err := f.Close(); err != nil {
		return "", 0, "", fmt.Errorf("export: close %s: %w", castName, err)
	}
	return castName, n, hex.EncodeToString(h.Sum(nil)), nil
}

// aboutText builds the human-readable front page of the export: who,
// whose machine, when it started, when it ended (or that it has not
// ended yet), how many bytes, the sha256 of the .cast, the product
// version. Every promised fact, plain English, key: value.
func aboutText(req Request, res Result) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "person: %s\n", req.Person)
	fmt.Fprintf(&b, "machine: %s\n", req.Machine)
	fmt.Fprintf(&b, "session: %s\n", req.SessionID)
	fmt.Fprintf(&b, "started: %s\n", req.StartedAt.Format(aboutTimeFormat))
	if req.EndedAt.IsZero() {
		b.WriteString("ended: still running\n")
	} else {
		fmt.Fprintf(&b, "ended: %s\n", req.EndedAt.Format(aboutTimeFormat))
	}
	fmt.Fprintf(&b, "transcript bytes: %d\n", res.TranscriptBytes)
	fmt.Fprintf(&b, "parts: %d\n", len(res.Parts))
	if res.CastFile == "" {
		// No recording, no hash: a made-up all-zero sha256 would tell
		// the reader nothing but would look like one (PROTOCOL §8:
		// no fabricated zero-bytes hash).
		b.WriteString("cast file: none\n")
	} else {
		fmt.Fprintf(&b, "cast file: %s\n", res.CastFile)
		fmt.Fprintf(&b, "cast bytes: %d\n", res.CastBytes)
		fmt.Fprintf(&b, "cast sha256: %s\n", res.CastSHA256)
	}
	fmt.Fprintf(&b, "product version: %s\n", req.Version)
	return []byte(b.String())
}

// recordingExportEvent builds the journal fact about this export: who
// exported, whose session, where it went. The write site of the
// recording.export type in this build.
func recordingExportEvent(req Request, res Result, now time.Time) events.Event {
	return events.Event{
		Time:   state.NewZonedTime(now),
		Type:   events.EventRecordingExport,
		Actor:  req.Exporter,
		Object: req.Person + " -> " + req.Machine,
		Result: "ok",
		Details: map[string]any{
			"session": req.SessionID,
			"path":    res.Dir,
			"bytes":   res.TranscriptBytes,
			"parts":   len(res.Parts),
		},
	}
}

// checkNameComponent refuses any folder-name ingredient that cannot
// appear there unmodified. The grammar is PROTOCOL §2.1:
// name = (lower / digit) *31name-char over [a-z0-9._-]. A value that
// does not pass is refused loudly, never silently rewritten — the
// folder name is how the human finds the session again, and a mangled
// name points at a session that is not there.
// checkSessionID accepts the gateway's session id. It shares the
// character rules with a §2.1 name — the id is built out of names and
// digits, and the whole string becomes part of a folder name, so a
// separator or a parent-directory dot must be as impossible here as
// there — but not the length rule: see maxSessionIDLen.
func checkSessionID(value string) error {
	if value == "" {
		return errors.New("export: SessionID is empty")
	}
	if len(value) > maxSessionIDLen {
		return fmt.Errorf("export: SessionID %q is longer than %d characters", value, maxSessionIDLen)
	}
	if c := value[0]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9') {
		return fmt.Errorf("export: SessionID %q must start with a lowercase letter or a digit", value)
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return fmt.Errorf("export: SessionID %q contains a character outside [a-z0-9._-]", value)
		}
	}
	return nil
}

func checkNameComponent(field, value string) error {
	if value == "" {
		return fmt.Errorf("export: %s is empty", field)
	}
	if len(value) > maxNameLen {
		return fmt.Errorf("export: %s %q is longer than %d characters (PROTOCOL §2.1)", field, value, maxNameLen)
	}
	if c := value[0]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9') {
		return fmt.Errorf("export: %s %q must start with a lowercase letter or a digit (PROTOCOL §2.1)", field, value)
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return fmt.Errorf("export: %s %q contains a character outside [a-z0-9._-] (PROTOCOL §2.1)", field, value)
		}
	}
	return nil
}
