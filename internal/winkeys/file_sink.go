// File-backed Sink for winkeys audit actions.
//
// Why it exists. The watchdog subprocess (doorwatch) lives in its own
// process, but its layer-3 cleanup still has to reach the same
// journal as the server's layer-2 cleanup — otherwise the "remove by
// the watcher" event vanishes into noopSink and an operator cannot
// tell a server-controlled close from a watcher-controlled close.
// internal/server carries a Sink in its Config; the parent passes the
// journal path to the watchdog via argv, and the watchdog opens this
// file sink on its end.
//
// Concurrency. fileSink serialises OnDoor calls under fs.mu so two
// goroutines inside the same process cannot interleave bytes into the
// JSONL record. Two different PROCESSES writing this file (the server
// and its watchdog child, IAMT-307) is a different problem: O_APPEND
// alone keeps their individual Write calls from tearing each other's
// line, but rotation needs its own cross-process exclusion. rotateLockPath
// is a small cross-process flock (the same primitive AcquireFileLock
// already gives the door layer) taken around every OnDoor call, turning
// "check size, rotate if past the cap, then write" into one atomic step
// no matter which process is doing it.
//
// Rotation is copy-then-truncate, not rename-then-reopen. A rename would
// need every other open handle on the file to have granted delete/rename
// sharing — Windows refuses to rename a file that a SECOND process (or
// this one's own earlier NewFileSink call) has open without that sharing,
// with "the process cannot access the file because it is being used by
// another process", which is exactly what production has: the server and
// its watchdog child both hold long-lived handles on the same path.
// Truncating the file in place, after copying its bytes out to the
// archive, changes no path and needs no sharing flags neither side
// controls — every open handle, in either process, keeps working, and the
// next append from whichever process writes next simply lands at the
// (now empty) end of the same file. This is the same reasoning
// logrotate's "copytruncate" mode is for: a writer that cannot be told to
// reopen its handle.
//
// Persistence. Every OnDoor call fsyncs the file. The journal's
// contract is append-only and tamper-evident; a torn-tail recovery
// (closing newline appended on next open) belongs to a higher-level
// audit tool, not to this sink.
//
// Crash safety (IAMT-307 round 7 F-307-2, round 8 F-307-4/F-307-5 —
// reviews round15/round16). Copy-then-truncate is not itself
// atomic across a crash: rotateLocked writes the archive under a
// ".partial" name and only publishes it under its final name with an
// atomic os.Rename once it is fully on disk, and a durable-looking
// rotation marker (rotationMarkerPath) records the target archive
// before any of that starts. Round 7 tried to use that marker plus
// "does the archive's final name exist" to FINISH an interrupted
// truncate automatically on the next open. Round 8 removes that: on a
// platform without a supported way to fsync a directory entry through
// this package's tools (Windows, notably — see syncDirBestEffort), an
// os.Rename that appears to have succeeded is not a durable fact after
// a crash, so "the archive's name exists" can no longer be trusted as
// proof the truncate is safe to perform. Trusting it anyway risks
// exactly the wrong failure mode for an audit trail: destroying events
// the live file picked up AFTER the crash, the moment recovery
// mistakenly re-triggers a truncate the original rotation never
// finished.
//
// recoverRotationOnOpen therefore never performs a destructive
// truncate. Finding a marker on open means, at most, that this
// implementation reports the situation (OnError) and cleans up the
// bookkeeping (the marker itself, and any stray ".partial" staging file
// — never trusted as a data source, so always safe to discard); it
// never touches the live file's content. The accepted cost is
// duplication, not loss: a crash between a published archive and its
// truncate can leave the same lines counted twice — once there, once
// still in the live file — until the next successful, UNINTERRUPTED
// rotation (which performs its own copy+rename+truncate synchronously,
// within one process's single execution, and is not subject to any
// cross-restart durability question) copies and empties the live file
// again. This journal's actual promise has always been "the line is
// never lost", not "the line is never duplicated" (compare OnDoor's own
// silence-vs-retry tradeoff below); F-307-4/F-307-5 is precisely
// review catching an earlier version of this file promising the
// stronger, undeliverable-on-every-platform guarantee instead.
//
// Round 9 (F-307-6, F-307-7, F-307-8, F-307-9 — review round17)
// corrects three consequences round 8 introduced or left unfinished:
//
//   - F-307-6: a truncate that keeps failing must not turn every
//     subsequent OnDoor call into ANOTHER full copy+rename+archive
//     attempt against the (still growing, still not truncated) live
//     file - that multiplies archives without bound and defeats
//     retention. writeLocked instead remembers, in memory,
//     that THIS process instance has one specific archive still
//     waiting on its truncate (pendingArchive) and retries only that
//     truncate on later calls instead of starting a fresh rotation;
//     pruneArchivesLocked also now runs immediately once an archive is
//     durably published, before the truncate is even attempted, so
//     retention is not skipped just because that truncate then fails.
//     pendingArchive was, at this round, only ever set by an in-process
//     rotateLocked failure - see round 11 below for why that alone left
//     a related gap open across a restart.
//   - F-307-7/F-307-9: since recovery performs no destructive action at
//     all (see above), an inability to read, stat or remove the marker
//     or a stray ".partial" no longer justifies refusing to open the
//     journal - round 8's F-307-4 fix over-corrected by keeping the
//     hard-refusal shape from before recovery became non-destructive.
//     Every recoverRotationOnOpen failure is now reported through
//     OnError and otherwise ignored; NewJournalSink only still refuses
//     outright when the journal FILE ITSELF cannot be opened.
//   - F-307-8: OnError must never run while this sink still holds
//     either s.mu or the cross-process rotation lock - a caller-supplied
//     callback can block for an unbounded time (in production, opening
//     and writing a file, or writing to a process's stderr), and doing
//     that while still holding the rotation lock would let a hung
//     callback stall the OTHER process's own journalling too, not just
//     this call. writeLocked collects every error from one locked
//     critical section into a slice and returns it; OnDoor invokes
//     OnError only after writeLocked has fully returned, both locks
//     already released by its own defers.
//
// Round 10 (F-307-10 — review round19) found that F-307-6's own
// fix was still incomplete: pendingArchive lives in ONE fileSink, but
// the journal is normally opened by TWO independent processes (the
// server and its watchdog child), each with its own *fileSink and its
// own pendingArchive. If both may rotate, a stuck truncate is never
// resolved "exactly once" by an author who remembers trying: process A
// publishes an archive, its truncate fails, A remembers pendingArchive
// - but process B (a fresh watchdog spawn, or a server restart) opens
// the SAME journal with an EMPTY pendingArchive, sees the still-oversized
// live file, and starts its OWN rotation, publishing a second duplicate
// archive; if ITS truncate also fails, B's own memory of the attempt is
// lost the moment B exits. Every process that ever opens the journal
// republishes one more archive, unbounded - exactly the F-307-6 failure
// mode, just moved from "every write" to "every process that opens the
// file", which is not actually bounded either in a system whose whole
// point is a watchdog that gets spawned and re-spawned.
//
// The fix narrows WHO MAY ROTATE instead of inventing a cross-process
// ownership protocol for pendingArchive: JournalOptions.Role marks
// exactly one sink per journal path as the RotatorRole (the server, in
// production - the zero value, so every existing caller that does not
// set Role keeps today's behaviour unchanged); every other sink
// (the watchdog) opens as AppenderRole and never checks maxBytes, never
// starts or retries a rotation, and its own recoverRotationOnOpen only
// REPORTS a marker it finds - it never removes it, never touches a
// ".partial", never acts on it in any way (see JournalRole's and
// AppenderRole's own doc comments). The cross-process rotation lock
// still serialises an appender's writes against a concurrent rotator's
// copy, exactly as before.
//
// Consequence, stated plainly rather than left implied: if the server
// is down while the watchdog is still running (SPEC §6.3's whole
// reason to exist - outliving a dead parent for the minutes it takes to
// clean up a door line), nobody rotates, and the live file grows until
// the server comes back. That is a bounded, understandable state - a
// watchdog lives minutes, not months - and it is a far smaller problem
// than the unbounded duplicate-archive growth this round removes.
//
// NewJournalSink refuses to hand back a sink only when the journal FILE
// ITSELF cannot be opened - not for any recovery-cleanup failure, all of
// which are now reported (OnError) rather than fatal (F-307-7).
//
// Round 11 (the acceptance run caught this against round
// 10, on this file's own new canary) found round 10 still incomplete in
// two ways:
//
//   - Round 10's F-307-10 fix only covered the WATCHDOG side of "every
//     process that opens the journal republishes a duplicate archive" -
//     recoverRotationOnOpen still unconditionally removed a marker it
//     found even for the ROTATOR, so a restarted SERVER (not just a
//     fresh watchdog spawn) would forget a pending rotation and start a
//     brand new one on top of it, the exact failure mode F-307-10 named,
//     just for "every rotator restart" instead of "every watchdog
//     spawn". Fixed by having a rotator's recovery, on finding an
//     archive that is already durably visible, SEED pendingArchive
//     instead of removing the marker - the SAME retry-on-next-write path
//     an in-process truncate failure already uses (F-307-6) now also
//     handles a rotation inherited from a restart, and the marker is
//     removed only once that retried truncate actually succeeds, never
//     by recovery itself. This does not weaken F-307-5: recovery still
//     performs zero destructive action on any path - seeding a field
//     that only causes a LATER write to retry a truncate is not
//     recovery truncating anything itself.
//   - writeLocked's own pendingArchive-resolution branch fell through
//     into the ordinary maxBytes check on the SAME call once a pending
//     truncate succeeded: with the live file freshly emptied, the check
//     used the size AFTER adding the very record this call was about to
//     write, which - against a MaxBytes set close to one record's own
//     size - could look "oversized" on its own and trigger a SECOND,
//     spurious rotation in the same call that had just finished the
//     first one, publishing two archives where round 10's own new test
//     expected one. Fixed by making resolution and the maxBytes check
//     mutually exclusive within one call (if/else, not if/if): finishing
//     a pending rotation stops there; whether the live file is still (or
//     again) oversized afterwards is the NEXT call's question, exactly
//     like any other write.
//
// Round 13 (F-307-11 — review round22, High, confirmed) found the
// remaining path that could still delete a pending rotation's own
// archive: pruneArchivesLocked picked deletion candidates by
// lexicographic sort order alone, which silently assumes archive names
// (built from the wall clock) only ever grow. A clock moved backward -
// NTP, an operator - makes a JUST-published archive sort BEFORE an
// older one, and the plain "delete the oldest name" rule would then
// delete exactly the archive pendingArchive still points at; if a later
// truncate then succeeds, the records that archive was supposed to hold
// are gone outright, not merely duplicated - the one guarantee this
// entire design exists to keep. pruneArchivesLocked now takes the
// archive the current rotation just published as a mandatory `keep`
// argument and excludes it from every deletion candidate regardless of
// where sorting would place it; retention deletes enough OTHER archives
// instead, capped so it never runs out of candidates to delete if `keep`
// itself is somehow not among them.
//
// Every other removeFn/os.Remove call site in this file was re-checked
// against the same question, "can this ever delete the pending
// rotation's own archive or its marker": writeRotationMarkerLocked and
// recoverRotationOnOpen's tmpMarker cleanup only ever touch the DRAFT
// marker (a different path from the final one); recoverRotationOnOpen's
// ".partial" cleanup only ever touches the STAGING copy (a different
// path from the final archive name); rotateLocked's own failure-path
// cleanup (copy or rename failing) runs only when writeLocked called it
// with pendingArchive already empty, so there is no OTHER pending
// rotation's marker or archive in scope to disturb; every unconditional
// marker removal (after a successful truncate, in writeLocked's pending-
// resolution branch, and in rotateLocked's own success path) removes
// ONLY the marker for the rotation that call itself just finished.
// pruneArchivesLocked was the one path that could name and delete a
// FILE it did not itself just create or fail to create.
//
// Retention (IAMT-307). This file has no natural ceiling on its own —
// every SweepStale, door.open and door.close appends a line for as
// long as the machine lives, and a machine that reconnects for years
// never stops. NewFileSink now caps the current file at MaxBytes
// (rotating it out to a timestamped archive) and prunes archives beyond
// MaxArchives, so the journal's own growth cannot fill the disk the
// machine's own data lives on — as long as truncate itself keeps
// working; see F-307-6 above for the (bounded-archive-count, but not
// bounded-live-file-size) behaviour while it does not.
//
// Errors. A failed write, sync or rotation is no longer silent: OnDoor
// still cannot fail the layer-2/layer-3 cleanup itself (PROTOCOL §5.2:
// the invariant that matters is "the line is gone", not "the line is
// journalled"), but every JournalOptions.OnError callback now hears
// about it — a silent hole in the machine's own audit trail is exactly
// what the THREATS.md model this journal is part of assumes an
// attacker wants. cmd/iamtunnel wires OnError to the process's stderr;
// NewFileSink's short-hand form (unchanged production callers, and the
// doorwatch test binaries under testdata/) leaves it nil, which keeps
// the previous swallow-everything behaviour for anyone not yet passing
// one. OnError runs after every lock this call took has been released
// (F-307-8) - see JournalOptions.OnError's own doc comment for the
// exact contract.
package winkeys

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// DefaultJournalMaxBytes is the size at which NewFileSink's default
// construction rotates the current journal file out to an archive.
// Door lifecycle events are small and infrequent (open/close/sweep,
// not a per-byte data firehose), so even a machine that reconnects
// constantly takes a very long time to reach this; it exists as a
// ceiling, not a number tuned to be hit in ordinary operation.
const DefaultJournalMaxBytes int64 = 8 * 1024 * 1024

// DefaultJournalMaxArchives is the number of rotated archives
// NewFileSink's default construction keeps before deleting the
// oldest. Together with DefaultJournalMaxBytes this bounds the
// journal's total footprint to a small, fixed multiple of the cap
// instead of leaving retention to whoever remembers to clean the
// directory by hand.
const DefaultJournalMaxArchives = 5

// JournalRole controls whether a sink may perform rotation (copy the
// live file out to an archive, rename it into place, truncate the live
// file) or must only ever append (IAMT-307 round 10, F-307-10 —
// review round19). The journal is normally written by TWO independent
// processes (the server and its watchdog child) that each open their
// own *fileSink against the same path; each has its own in-memory
// pendingArchive, so if both may rotate, a truncate that keeps failing
// is never resolved "exactly once" by an author who remembers trying -
// every process that ever opens the journal (every watchdog spawn,
// every server restart) publishes one more duplicate archive of an
// ever-larger live file, unbounded, because each one's own memory of
// the attempt is lost the moment it exits. Narrowing rotation to a
// single role per journal path removes the ambiguity at its root
// instead of inventing a cross-process ownership protocol for
// pendingArchive itself.
type JournalRole int

const (
	// RotatorRole is JournalOptions.Role's zero value: this sink may
	// check MaxBytes and rotate (copy, rename, truncate, prune) - the
	// behaviour every fileSink had before this field existed, so any
	// existing caller that does not set Role keeps rotating exactly as
	// before. Exactly one process for a given journal path should hold
	// the rotating sink - in production, the server.
	RotatorRole JournalRole = iota
	// AppenderRole marks a sink that must never start a rotation of its
	// own: it only ever appends lines, and its own recoverRotationOnOpen
	// only reports a rotation marker it finds through OnError and
	// leaves every file alone - deleting or acting on a marker it did
	// not create would erase the one durable record of an unfinished
	// rotation while that rotation's actual author (the rotator) still
	// remembers it in memory and intends to retry. In production, the
	// watchdog opens its sink with this role explicitly (cmd/iamtunnel's
	// doorwatch call sites) - there is no automatic way to tell which of
	// several sinks on the same path "owns" rotation, so this is a
	// construction-time decision by the caller, never inferred.
	AppenderRole
)

// JournalOptions configures the production journal sink
// (NewJournalSink) two independent processes — the server and its
// watchdog child — write concurrently.
type JournalOptions struct {
	// MaxBytes is the size at which the current file is rotated out to
	// a timestamped archive before the next line is written. Zero
	// means DefaultJournalMaxBytes; a negative value disables
	// rotation entirely (the file grows without bound — the pre-
	// IAMT-307 behaviour, kept only as an explicit opt-out, never a
	// default).
	MaxBytes int64
	// MaxArchives is how many rotated archives are kept before the
	// oldest is deleted. Zero means DefaultJournalMaxArchives; a
	// negative value keeps every archive forever.
	MaxArchives int
	// OnError, if non-nil, is called instead of silently discarding a
	// write, sync, rotation, lock or recovery-cleanup failure. It runs
	// on whatever goroutine called OnDoor (or, for a failure found while
	// opening the journal, on whatever goroutine called NewJournalSink),
	// in either the server or the watchdog process, and — this is the
	// actual contract, not merely a recommendation (F-307-8,
	// review round17: an earlier version of this comment claimed the
	// callback never runs while a lock is held, but the code called it
	// while still holding both s.mu and the cross-process rotation lock)
	// — strictly after every lock that call took has already been
	// released. It should still not block indefinitely or panic: a
	// single OnDoor call can report more than one error (e.g. a rotation
	// failure followed by a write failure), and a hung callback delays
	// every one of them from being observed, plus every OTHER call
	// queued behind this one on s.mu.
	OnError func(error)
	// Role selects whether this sink may rotate the journal (RotatorRole,
	// the zero value - today's behaviour, unchanged) or must only append
	// (AppenderRole) - IAMT-307 round 10, F-307-10. See JournalRole's own
	// doc comment for why exactly one sink per journal path should ever
	// hold RotatorRole.
	//
	// A caller that opens a SECOND sink on the same path without setting
	// this field gets a SECOND rotator by default, not an error (
	// review round22's remark, not itself a finding): production is safe
	// today because both cmd/iamtunnel call sites set this explicitly
	// (RotatorRole for the server, AppenderRole for both doorwatch
	// entry points), but nothing in this package's own API stops a
	// future caller from forgetting to. Flipping the zero value to
	// AppenderRole so a forgotten Role fails safe was considered and
	// rejected: round 10's own explicit requirement was that no EXISTING
	// caller silently loses rotation when this field was introduced,
	// and Go's zero-value struct semantics mean any change to what the
	// zero value means is exactly that kind of silent behaviour change
	// for whoever does not set it - trading "a future caller can forget
	// to opt out of rotating" for "a future caller can forget to opt
	// INTO rotating and silently get an ever-growing, never-rotated
	// journal" is not a net improvement, only a different silent
	// failure mode. The unit is a single struct field precisely so
	// every construction site can be grepped and Role checked next to
	// the path, which is what this file's own two production callers
	// already demonstrate.
	Role JournalRole
}

// fileSink is the production write target of the server's and the
// watchdog's audit events. Use NewFileSink or NewJournalSink to
// construct one; the zero value is not usable.
type fileSink struct {
	mu          sync.Mutex
	path        string
	f           *os.File
	maxBytes    int64
	maxArchives int
	onError     func(error)
	// role is JournalOptions.Role, fixed at construction. Only a sink
	// with role == RotatorRole ever checks maxBytes or starts a
	// rotation; see JournalRole's own doc comment for why (F-307-10).
	role JournalRole
	// pendingArchive is the final name of an archive whose truncate has
	// not completed yet, set either by an in-process rotateLocked call
	// whose own truncate failed (F-307-6, review round17) or by
	// recoverRotationOnOpen finding one already durably published at
	// construction time (round 11, review round19/round21 - see
	// that function's own doc comment for why THIS is safe when a
	// destructive truncate performed directly BY recovery is not: this
	// field only ever causes writeLocked to RETRY a truncate on a later,
	// ordinary write, ordering it exactly like an in-process failure's
	// retry - it never causes recovery itself to touch the live file).
	// While set, writeLocked retries only that truncate on the next
	// OnDoor call instead of starting a brand new copy+rename+archive
	// rotation against the meanwhile-still-growing live file - doing the
	// latter on every single write, or on every process that happens to
	// (re)open the journal, is what turned a stuck truncate into an
	// unbounded pile of archives (F-307-6, then F-307-10 for the same
	// failure mode across process restarts). The rotation marker is
	// removed only once this field's truncate actually succeeds -
	// finishing a pending rotation is the ONLY thing that ever removes
	// it now, whether the field was set in this process or inherited
	// from recovery. Guarded by mu, like everything else OnDoor touches.
	pendingArchive string
}

// NewFileSink opens path for append and returns a Sink with
// NewJournalSink's default rotation policy and no error callback —
// the historical, still-supported short-hand every existing caller
// (cmd/iamtunnel's doorwatch subcommand, the testdata/ watchdog test
// binaries) already uses. NewJournalSink is the form cmd/iamtunnel's
// own long-lived "server start" uses, so a failed write is not silent
// there.
func NewFileSink(path string) (Sink, error) {
	return NewJournalSink(path, JournalOptions{})
}

// NewJournalSink is NewFileSink with an explicit rotation/retention/
// error-reporting policy. If path is empty an error is returned —
// there is no implicit "stdout" or "/dev/null" fallback, because the
// only reason to construct a fileSink is to bind it to an explicit
// journal path that the operator can later inspect.
//
// The file is created if it does not exist. fsync is performed on
// every record: the journal is the source of truth for "the watcher
// cleaned up this line", and a power-cut between an OnDoor call and a
// sync must not lose the record.
//
// The open goes through state.OpenAppendDataFile (IAMT-332 round
// seven): events.jsonl is a machine data file in the server data
// directory, and the privileged "server start" that opens it must
// refuse a symlink or FIFO planted at the name — not hang on the FIFO
// inside open(2) — exactly like the read side has since rounds five
// and six. Every name-based re-open below (ensureOpenLocked,
// truncateToZero, copyCurrentToLocked) is under the same contract, and
// the rotation marker's draft is created O_EXCL rather than opened
// through whatever a predictable temp name holds.
func NewJournalSink(path string, opts JournalOptions) (Sink, error) {
	if path == "" {
		return nil, errors.New("winkeys: file sink path must not be empty")
	}
	f, err := datafile.OpenAppend(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	maxBytes := opts.MaxBytes
	if maxBytes == 0 {
		maxBytes = DefaultJournalMaxBytes
	}
	maxArchives := opts.MaxArchives
	if maxArchives == 0 {
		maxArchives = DefaultJournalMaxArchives
	}
	s := &fileSink{path: path, f: f, maxBytes: maxBytes, maxArchives: maxArchives, onError: opts.OnError, role: opts.Role}
	// F-307-7 (review round17): recoverRotationOnOpen performs no
	// destructive action on any outcome (see the file's crash-safety
	// doc comment), so a failure here - a marker this process cannot
	// read, stat or remove - governs nothing about whether the journal
	// itself is safe to open or write to. Round 8's F-307-4 fix refused
	// to open at all on any such failure; that was sound while recovery
	// could still destructively truncate on a wrong guess, and became an
	// over-correction once round 8 removed that destructive path
	// entirely - it left a harmless leftover file able to stop the
	// server from starting. Report it and open anyway; only the journal
	// FILE ITSELF failing to open (above) still refuses outright.
	if err := s.recoverRotationOnOpen(); err != nil {
		s.reportError(err)
	}
	return s, nil
}

// Path returns the journal path this sink writes to. Diagnostic.
func (s *fileSink) Path() string { return s.path }

// rotateLockPath is the cross-process advisory lock every OnDoor call
// (from either the server or the watchdog) takes before touching the
// journal file, so "check size, rotate if past the cap, then write"
// runs as one step no matter which process is doing it. It is a
// sibling of the journal file, not door.lock — rotating the audit
// trail and installing a door key are unrelated critical sections, and
// serialising them against each other would only make an unrelated
// operation wait on this one.
func (s *fileSink) rotateLockPath() string { return s.path + ".rotate.lock" }

// journalLockWait bounds acquireRotateLock's total retrying, deliberately
// far past AcquireFileLock's own lockContentionWait (~2s). That bound
// exists so a single call cannot hang forever on a holder that is stuck
// FOREVER; it is sized for the door layer's own short Install/Remove
// critical sections between exactly two processes, not for however many
// of one process's own goroutines happen to call OnDoor at once (a busy
// machine's own event volume can produce more than two contenders on
// this same lock; IAMT-307's own concurrency test found writes silently
// dropped at the 2s bound under moderate concurrent load, purely from
// ordinary contention, not from anything stuck). Retrying here trades a
// slower write for never losing an audit line to ordinary contention;
// a peer that is stuck for the full 30s, not just busy, still surfaces
// through OnError once this budget is spent.
const journalLockWait = 30 * time.Second

// acquireRotateLock retries AcquireFileLock across ordinary contention
// ("held by another writer") until journalLockWait is spent, and returns
// immediately on any other error (a lock file that cannot be opened at
// all is not something retrying fixes).
func (s *fileSink) acquireRotateLock() (*FileLock, error) {
	deadline := time.Now().Add(journalLockWait)
	for {
		lock, err := AcquireFileLock(s.rotateLockPath())
		if err == nil {
			return lock, nil
		}
		if !strings.Contains(err.Error(), "held by another writer") || !time.Now().Before(deadline) {
			return nil, err
		}
	}
}

// reportError calls onError if set; safe when it is nil (every
// existing NewFileSink caller).
func (s *fileSink) reportError(err error) {
	if s.onError != nil {
		s.onError(err)
	}
}

// OnDoor serialises a JSON line for a into the underlying file,
// rotating first if the file has grown past maxBytes. Every error the
// locked critical section produces is reported through OnError only
// AFTER that section (writeLocked) has fully returned and released both
// locks it took (F-307-8, review round17) - see
// JournalOptions.OnError's own doc comment for why that ordering is
// part of the contract, not an implementation detail.
func (s *fileSink) OnDoor(a Action) {
	if s == nil {
		return
	}
	if a.At.IsZero() {
		a.At = time.Now()
	}
	raw, err := json.Marshal(a)
	if err != nil {
		// A marshal failure on a fixed struct shape is a programmer
		// error, not an audit concern; ignore rather than block the
		// cleanup.
		return
	}
	raw = append(raw, '\n')

	for _, werr := range s.writeLocked(raw) {
		s.reportError(werr)
	}
}

// writeLocked performs the write/rotate critical section under s.mu and
// the cross-process rotation lock, and returns every error it produced
// WITHOUT invoking OnError itself. See OnDoor's and JournalOptions.
// OnError's doc comments for why the callback must run only after this
// function - and therefore both locks - has fully returned.
func (s *fileSink) writeLocked(raw []byte) []error {
	// s.mu first, the cross-process lock second: AcquireFileLock's
	// contention wait is bounded (lockContentionWait, ~2s) so that a
	// stuck holder cannot hang a caller forever, but that same bound
	// means it must never be the thing several of THIS PROCESS's own
	// goroutines queue up on - under enough concurrent callers within
	// one process, the flock's bounded wait can itself be the timeout
	// that quietly drops a write. Serialising this process's own
	// callers on s.mu first (an ordinary, unbounded mutex - no data
	// loss possible from queuing on it) means only one goroutine per
	// process ever contends for the cross-process lock at a time,
	// which is the "two writers' short critical sections" case
	// AcquireFileLock's own doc comment says its bound is sized for -
	// not eight goroutines hammering the same flock at once.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil // Close already ran; nothing left to write to.
	}

	lock, lerr := s.acquireRotateLock()
	if lerr != nil {
		return []error{fmt.Errorf("winkeys: acquire journal rotation lock for %s: %w", s.path, lerr)}
	}
	defer lock.Release()

	if err := s.ensureOpenLocked(); err != nil {
		return []error{fmt.Errorf("winkeys: reopen journal %s: %w", s.path, err)}
	}

	var errs []error
	// Only the rotator ever checks maxBytes or starts/retries a rotation
	// (F-307-10): an appender (the watchdog) must never publish its own
	// archive or touch pendingArchive - it has none, and never will,
	// since this whole block simply does not run for it. It still
	// writes and syncs below, unconditionally, under the same
	// cross-process rotation lock a concurrent rotator's copy holds.
	if s.role == RotatorRole {
		if s.pendingArchive != "" {
			// F-307-6: this process instance already durably published
			// an archive whose truncate then failed - retry only that
			// truncate here instead of starting a brand new rotation
			// against the meanwhile-still-growing live file, which is
			// what would turn every single write into one more archive.
			// See pendingArchive's own doc comment.
			//
			// This is an "if", not something that falls through into
			// the maxBytes check below on the same call (round 11,
			// review round21's own canary against round 10: a
			// single write that both finished a pending rotation AND
			// immediately re-checked size - with the just-truncated
			// live file already back near empty, but the very raw
			// line about to be appended sometimes large enough on its
			// own to look "oversized" against a small MaxBytes -
			// started a SECOND, spurious rotation in the very same
			// call, publishing two archives instead of one). Finishing
			// a pending rotation and stop there for this call; if the
			// live file is still (or again) oversized afterwards, the
			// NEXT OnDoor call notices exactly like any other write
			// would.
			if terr := truncateFn(s.path); terr != nil {
				errs = append(errs, fmt.Errorf("winkeys: journal %s still needs a truncate after archiving to %s: %w", s.path, s.pendingArchive, terr))
			} else {
				if rerr := removeFn(s.rotationMarkerPath()); rerr != nil && !os.IsNotExist(rerr) {
					errs = append(errs, fmt.Errorf("winkeys: remove rotation marker after finishing a delayed truncate for %s: %w", s.path, rerr))
				}
				syncDirBestEffort(filepath.Dir(s.path))
				s.pendingArchive = ""
			}
		} else if s.maxBytes > 0 {
			if info, statErr := s.f.Stat(); statErr == nil && info.Size()+int64(len(raw)) > s.maxBytes {
				if err := s.rotateLocked(&errs); err != nil {
					errs = append(errs, fmt.Errorf("winkeys: rotate journal %s: %w", s.path, err))
					// Fall through and still try to write: a failed
					// rotation must not also lose the event that
					// triggered it.
				}
			}
		}
	}
	if _, err := s.f.Write(raw); err != nil {
		errs = append(errs, fmt.Errorf("winkeys: write journal event to %s: %w", s.path, err))
		return errs
	}
	if err := s.f.Sync(); err != nil {
		errs = append(errs, fmt.Errorf("winkeys: sync journal event to %s: %w", s.path, err))
	}
	return errs
}

// ensureOpenLocked reopens s.f if the path has been deleted out from
// under it (an operator clearing the directory by hand, or a stray
// external tool) — rotation itself never renames or removes s.path
// (see the file's doc comment on why it truncates in place instead),
// so this is a defensive fallback, not the normal path. Called under
// s.mu with the rotation lock already held.
func (s *fileSink) ensureOpenLocked() error {
	if _, err := os.Stat(s.path); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		_ = s.f.Close()
		f, oerr := datafile.OpenAppend(s.path)
		if oerr != nil {
			s.f = nil
			return oerr
		}
		s.f = f
	}
	return nil
}

// journalStemSuffix splits a journal's base name into the stem and
// suffix an archive name is built from — "events.jsonl" becomes
// ("events", ".jsonl") the same way internal/gateway/events.ArchiveName
// derives an archive name for the gateway's own log, just computed
// from whatever base name this journal actually has rather than a
// hardcoded "events".
func journalStemSuffix(path string) (stem, suffix string) {
	base := filepath.Base(path)
	suffix = filepath.Ext(base)
	stem = strings.TrimSuffix(base, suffix)
	return stem, suffix
}

// partialSuffix marks an archive copy that is still (or was left)
// in-flight — appended to the archive's own final name while
// copyCurrentToLocked is writing it, so a crash mid-copy leaves a file
// pruneArchivesLocked's suffix match (which requires the name to END in
// plain suffix, e.g. ".jsonl") never counts as a real archive (F-307-2).
const partialSuffix = ".partial"

// rotationMarkerPath is the "a rotation is or was in progress" record
// (IAMT-307 round 7 F-307-2, round 8 F-307-4/F-307-5). archive.Sync()
// alone only makes the ARCHIVE FILE's bytes durable; it says nothing
// about the directory entry that names it, and a power loss can drop
// that entry even after a successful fsync of the file's content — on a
// platform without a supported way to fsync a directory entry (Windows),
// this package cannot even claim the marker's own create/rename/remove
// is durable across a crash. The marker's job is therefore no longer
// "let recovery finish an interrupted truncate" (round 7's design,
// found unsound by F-307-5): it is written before the archive is ever
// renamed into its final name purely so a later open can, at most,
// report that this specific rotation was interrupted and clean up its
// bookkeeping — never so a later open can decide the live file's
// content is safe to destroy. See the file's crash-safety doc comment.
func (s *fileSink) rotationMarkerPath() string { return s.path + ".rotate.marker" }

// syncDirBestEffort fsyncs dir's own directory entry, so a rename or
// remove inside it survives a crash and not merely the file content
// those operations touched. Best-effort: some platforms and filesystems
// reject fsync on a directory handle outright (notably Windows, and
// some network filesystems), and a failure here only widens the crash
// window recovery already tolerates by describing state through a
// marker file rather than trusting the mtime/order of raw renames — it
// must never turn an ordinary rotation into a reported failure.
func syncDirBestEffort(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// writeRotationMarkerLocked durably records archivePath as the target
// of a rotation about to start, before anything about that rotation is
// otherwise observable on disk. See rotationMarkerPath's doc comment
// for what this buys recovery.
//
// Published by write-temp-then-rename, not by writing the marker path
// directly with O_TRUNC (F-307-5, review round16): an O_TRUNC
// write leaves a window where the marker exists but holds only a
// PREFIX of its intended content if the process dies mid-write, and a
// reader has no way to tell that torn content apart from a short but
// genuine archive path. A rename that replaces an existing destination
// is atomic on every platform this package targets — including
// Windows, where os.Rename uses MoveFileEx with the replace-existing
// flag — so recoverRotationOnOpen only ever observes the marker fully
// absent or fully written, never torn.
func (s *fileSink) writeRotationMarkerLocked(archivePath string) error {
	markerPath := s.rotationMarkerPath()
	tmpMarker := markerPath + partialSuffix
	// The draft lives at a fixed, predictable temp name — the round-2
	// symlink class — so it is CREATED, never opened through whatever
	// the name holds: any existing entry is discarded first (Remove
	// deletes a planted link, FIFO or stale draft, never its target),
	// and the O_EXCL create below is then safe by construction — a
	// name that reappears in between fails the create instead of being
	// followed (IAMT-332 round seven). Recovery already treats a
	// leftover draft as bookkeeping to discard, so discarding it here
	// changes nothing recovery relies on.
	_ = os.Remove(tmpMarker)
	f, err := os.OpenFile(tmpMarker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(archivePath); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpMarker)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpMarker)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpMarker)
		return err
	}
	if err := os.Rename(tmpMarker, markerPath); err != nil {
		_ = os.Remove(tmpMarker)
		return err
	}
	syncDirBestEffort(filepath.Dir(s.path))
	return nil
}

// recoverRotationOnOpen discards the bookkeeping of a rotation an
// earlier process instance left interrupted (IAMT-307 round 7 F-307-2,
// round 8 F-307-4/F-307-5, round 9 F-307-7/F-307-8/F-307-9), before this
// sink accepts any new write. It never touches the live file's CONTENT
// — see the file's crash-safety doc comment for why a round-7 version
// that finished an interrupted truncate automatically was unsafe on a
// platform without durable directory metadata. It is safe to call
// whether or not a rotation was ever interrupted: with neither the
// marker nor its own temporary staging name present, it is two stat
// calls and nothing more.
//
// The unlocked read first, then a locked re-read, avoids taking
// journalLockWait's full cross-process lock on every ordinary open (the
// overwhelmingly common case has no marker at all) while still being
// correct when the server and its watchdog child both call
// NewJournalSink around the same time at startup: whichever one gets
// there first performs the recovery under the lock, and the second
// finds the marker already gone.
//
// Every failure this function can hit — a stat/read/remove that is not
// "the file is simply gone", a lock that will not clear, an interrupted
// rotation's archive turning out to already be visible — is collected
// and returned as one combined error (errors.Join), NEVER invoked
// through OnError directly from inside this function (F-307-8: this
// function still holds the cross-process rotation lock at the point
// each of these is discovered; the caller reports the combined result
// only after this function has returned and that lock's own deferred
// Release has already run). NewJournalSink treats every such failure as
// non-fatal (F-307-7, review round17): since this function never
// destructively touches the live file's content on any path, a marker
// or ".partial" this process cannot read, stat or remove is a leftover
// worth reporting, not a reason to refuse opening an otherwise-healthy,
// append-only journal.
func (s *fileSink) recoverRotationOnOpen() error {
	markerPath := s.rotationMarkerPath()
	tmpMarker := markerPath + partialSuffix
	_, markerErr := os.Stat(markerPath)
	_, tmpMarkerErr := os.Stat(tmpMarker)
	if os.IsNotExist(markerErr) && os.IsNotExist(tmpMarkerErr) {
		return nil
	}
	if markerErr != nil && !os.IsNotExist(markerErr) {
		return fmt.Errorf("stat rotation marker %s: %w", markerPath, markerErr)
	}

	if s.role != RotatorRole {
		// F-307-10 (review round19): only the rotator may act on a
		// rotation marker or its ".partial" staging file. An appender
		// (the watchdog) that "cleaned up" a marker it merely found
		// would erase the one durable, cross-process record of an
		// unfinished rotation while that rotation's actual author (the
		// rotator) still remembers it in its own pendingArchive and
		// intends to retry the very truncate the marker names - the
		// appender has no way to know that, and no business resolving a
		// rotation it never started. Report what markerPath currently
		// names, if anything, and leave every file - the marker, any
		// ".partial", the live journal itself - exactly as found.
		if markerErr != nil { // os.IsNotExist(markerErr): nothing to report
			return nil
		}
		// The marker is a data-directory file like any other: the read
		// goes through the no-follow regular-file-only contract
		// (IAMT-332 round seven), so a FIFO planted at the marker's
		// name is refused promptly instead of hanging recovery — and
		// the failure stays best-effort here, exactly as before.
		raw, _ := datafile.ReadFile(markerPath)
		return fmt.Errorf("winkeys: found a rotation marker for %s naming archive %q on open by a non-rotating sink - left untouched; only the rotating sink may resolve it", s.path, strings.TrimSpace(string(raw)))
	}

	lock, lerr := s.acquireRotateLock()
	if lerr != nil {
		return fmt.Errorf("acquire rotation lock to recover %s: %w", markerPath, lerr)
	}
	defer lock.Release()

	var errs []error

	// A marker that never finished being published (writeRotationMarkerLocked
	// itself crashed between writing tmpMarker and renaming it into place)
	// names nothing recovery can act on - discard the draft and move on.
	// This can coexist with a fully published markerPath from an EARLIER,
	// separate rotation attempt that is handled below; removing this one
	// first keeps that handling simple regardless of which order they
	// are found in.
	if err := removeFn(tmpMarker); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove draft rotation marker %s: %w", tmpMarker, err))
	}

	raw, err := datafile.ReadFile(markerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.Join(errs...) // a sibling process instance already recovered it
		}
		errs = append(errs, fmt.Errorf("read rotation marker %s: %w", markerPath, err))
		return errors.Join(errs...)
	}
	// A marker's own publish is now atomic (writeRotationMarkerLocked
	// renames it into place), but content that does not name one of this
	// journal's OWN archive names is never used as a path at all. Round
	// nine (IAMT-332) sharpens F-307-5: the marker lives in the data
	// directory a privileged run can be aimed at, so its content is
	// attacker-choiceable up to a newline — the old code stat'ed and
	// ".partial"-removed whatever path the marker named, and a plant made
	// that removal land on somebody else's file. markerNamesOwnArchive
	// pins the name to what nextArchivePath can produce (a sibling of the
	// journal with the journal's own stem and suffix); anything else is
	// reported as corrupt, dropped, and never acted on.
	archivePath := strings.TrimSpace(string(raw))
	dir := filepath.Dir(s.path)
	archiveFound := false
	if markerNamesOwnArchive(s.path, archivePath) {
		if _, statErr := os.Stat(archivePath); statErr == nil {
			// The archive's name exists. On a platform with durable
			// directory metadata this would mean the rename that
			// published it is guaranteed to have fully happened before
			// the crash; this implementation deliberately does NOT
			// trust that inference on every platform (F-307-5) and so
			// takes no destructive action either way - only reports the
			// situation, so an operator knows this archive may already
			// duplicate lines the live file still also holds.
			archiveFound = true
			errs = append(errs, fmt.Errorf("winkeys: found an interrupted rotation on open for %s: archive %s was already visible; %s was left untouched and its lines may now be duplicated in %s - this sink will retry the pending truncate on its next write instead of starting a fresh rotation (see file_sink.go's crash-safety doc comment)", s.path, archivePath, s.path, archivePath))
		} else if !os.IsNotExist(statErr) {
			errs = append(errs, fmt.Errorf("stat interrupted rotation's archive %s: %w", archivePath, statErr))
		}
		// Whether or not the archive's name exists, any stray ".partial"
		// staging copy under it is always safe to discard: it is never
		// read as a data source by anything in this package, only ever
		// renamed whole (on success) or abandoned (on failure/crash),
		// and it must never be left where retention's suffix match
		// could mistake it for a finished archive. Its removal failing
		// is reported (F-307-9), not silently swallowed - the earlier
		// round left this file behind forever with no trace of why, on
		// nothing more than the observation that it could not lose live
		// data either way.
		if err := removeFn(archivePath + partialSuffix); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove leftover partial archive %s: %w", archivePath+partialSuffix, err))
		}
	} else if archivePath != "" {
		errs = append(errs, fmt.Errorf("winkeys: rotation marker for %s names %q, which is not one of this journal's own archive names - treating the marker as corrupt and dropping it without acting on the name", s.path, archivePath))
	}
	if archiveFound {
		// The marker disappears only when the rotation really completes
		// - a successful truncate - never on mere recovery (round 11,
		// following on from F-307-10, review round19/round21):
		// removing it here, just because THIS process happened to be the
		// one that opened the journal, would let a later restart of
		// this SAME rotator (or another instance) forget a rotation is
		// still pending and start a brand new one on top of it - the
		// exact "every new process republishes one more duplicate
		// archive" failure mode F-307-10 named, just moved from "every
		// watchdog spawn" to "every rotator restart". pendingArchive is
		// seeded here exactly the way an in-process truncate failure
		// already sets it (F-307-6): the next OnDoor call retries this
		// SAME truncate through the ordinary path in writeLocked, which
		// is now the ONLY place this marker is ever removed.
		s.pendingArchive = archivePath
	} else if err := removeFn(markerPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove rotation marker %s: %w", markerPath, err))
	}
	syncDirBestEffort(dir)
	return errors.Join(errs...)
}

// markerNamesOwnArchive reports whether archivePath is a name
// nextArchivePath could have produced for the journal at path: a
// sibling of the journal, with the journal's own stem and suffix. A
// marker's content is untrusted input (see recoverRotationOnOpen) —
// this is the one predicate that decides whether recovery may even
// stat the name it carries, let alone remove anything under it.
func markerNamesOwnArchive(journalPath, archivePath string) bool {
	if archivePath == "" {
		return false
	}
	if filepath.Dir(archivePath) != filepath.Dir(journalPath) {
		return false
	}
	stem, suffix := journalStemSuffix(journalPath)
	base := filepath.Base(archivePath)
	return strings.HasPrefix(base, stem+"-") && strings.HasSuffix(base, suffix)
}

// rotateLocked copies the current file's bytes out to a new,
// timestamped archive file, then truncates the current file to empty
// in place - see the file's doc comment for why this is copy+truncate
// and not rename+reopen. Called under s.mu with the rotation lock
// already held, immediately before the write that triggered it. Every
// non-fatal issue along the way (pruning, marker cleanup) is appended
// to errs rather than reported directly (F-307-8: the caller reports
// them only after releasing both locks).
//
// The copy itself is written under a temporary name and only published
// under its final archive name by an atomic rename once it is fully on
// disk (F-307-2): a reader (or the next rotation's pruning pass) must
// never be able to observe a partially written archive under the name
// retention treats as a complete one. rotationMarkerPath records which
// archive this rotation targets before any of this starts, so a crash at
// any point — before the copy, mid-copy, after the copy but before the
// rename, after the rename but before the truncate, or after the
// truncate but before the marker is removed — leaves a state
// recoverRotationOnOpen can safely clean up on the next open: it never
// loses a line, but (F-307-4/F-307-5) it also never trusts that state
// enough to finish an interrupted truncate itself, so a crash between a
// published archive and this call's own truncate can leave that
// archive's lines duplicated in the live file until this process's own
// next successful, uninterrupted rotation — see the file's crash-safety
// doc comment.
//
// Retention runs immediately once the archive is durably published,
// BEFORE the truncate that follows is even attempted (F-307-6,
// review round17): a truncate that then fails must not also skip
// pruning, or old archives pile up right alongside a live file that
// cannot be emptied either. A truncate failure sets s.pendingArchive
// instead of starting a fresh rotation on the very next OnDoor call -
// see that field's own doc comment for why repeating the full
// copy+rename+archive dance on every write while truncate stays broken
// is exactly the unbounded-archive-growth F-307-6 identified.
func (s *fileSink) rotateLocked(errs *[]error) error {
	stem, suffix := journalStemSuffix(s.path)
	dir := filepath.Dir(s.path)
	archivePath := nextArchivePath(dir, stem, suffix)
	tmpPath := archivePath + partialSuffix

	if err := s.writeRotationMarkerLocked(archivePath); err != nil {
		return fmt.Errorf("write rotation marker for %s: %w", archivePath, err)
	}
	if err := s.copyCurrentToLocked(tmpPath); err != nil {
		_ = removeFn(tmpPath)
		_ = removeFn(s.rotationMarkerPath())
		return fmt.Errorf("copy %s to archive %s: %w", s.path, archivePath, err)
	}
	if err := os.Rename(tmpPath, archivePath); err != nil {
		_ = removeFn(tmpPath)
		_ = removeFn(s.rotationMarkerPath())
		return fmt.Errorf("publish archive %s: %w", archivePath, err)
	}
	syncDirBestEffort(dir)
	s.pruneArchivesLocked(stem, suffix, dir, archivePath, errs)
	if err := truncateFn(s.path); err != nil {
		// The marker is deliberately left in place rather than removed,
		// and pendingArchive now remembers this rotation for writeLocked
		// (F-307-6): a later open cannot trust that archivePath existing
		// means this rename durably happened (F-307-4/F-307-5), so
		// recovery never retries this truncate itself, but THIS process
		// instance directly witnessed its own rename succeed moments ago
		// - no restart, no ambiguity - so retrying just the truncate on
		// its own next write is sound, and cheaper and safer than
		// re-copying the live file into yet another archive.
		s.pendingArchive = archivePath
		return fmt.Errorf("truncate %s after archiving to %s: %w", s.path, archivePath, err)
	}
	if err := removeFn(s.rotationMarkerPath()); err != nil && !os.IsNotExist(err) {
		*errs = append(*errs, fmt.Errorf("winkeys: remove rotation marker after archiving to %s: %w", archivePath, err))
	}
	syncDirBestEffort(dir)
	return nil
}

// truncateToZero opens a plain (non-append) handle on path and truncates
// it. s.f cannot do this itself: it is opened O_APPEND, and on Windows an
// O_APPEND handle carries FILE_APPEND_DATA access only, which
// SetEndOfFile (Truncate's Windows primitive) rejects with "Access is
// denied" - confirmed empirically, not merely suspected, since the
// alternative (silently failing to shrink the file) reads back as
// "every rotation duplicates all prior content into a new archive
// instead of ever actually emptying the current file", which is exactly
// what an untested truncate-on-an-append-handle produces. A second,
// separately opened handle has full write access and truncates
// correctly; the original O_APPEND handle's later writes are unaffected
// by ever having had this second handle open and closed.
func truncateToZero(path string) error {
	// A second, name-based handle on the live journal's name must obey
	// the same no-follow regular-file-only contract as every other
	// data-file open (IAMT-332 round seven): a symlink planted at the
	// name mid-life is refused here, not truncated through — the
	// rotation machinery already treats a failed truncate as a
	// reported, retryable state (F-307-6).
	f, err := datafile.OpenExisting(path, os.O_WRONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(0)
}

// truncateFn and removeFn are package-level indirections over
// truncateToZero and os.Remove, used at every call site rotateLocked,
// writeLocked and recoverRotationOnOpen otherwise call them at
// directly. Tests substitute these (and restore the original
// afterwards) to force a truncate or a removal to fail deterministically
// and PERMANENTLY on every platform (F-307-6, F-307-7, F-307-9,
// review round17) - real OS-level permission tricks do not portably
// model "this specific operation always fails from here on": POSIX
// directory write-permission removal has no Windows equivalent, and a
// read-only FILE attribute on Windows does not stop os.Remove or an
// already-open O_APPEND handle's own writes the way it might suggest.
// Always truncateToZero/os.Remove in production; never nil.
var (
	truncateFn = truncateToZero
	removeFn   = os.Remove
)

// nextArchivePath returns a timestamped archive path for stem/suffix in
// dir that does not already exist. The timestamp carries nanosecond
// precision, but a clock that does not advance between two rotations
// (a fake clock in a test, or two rotations scheduled within the same
// tick on a coarse platform clock) must still not silently overwrite
// an existing archive.
func nextArchivePath(dir, stem, suffix string) string {
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	build := func(n int) string {
		if n == 0 {
			return filepath.Join(dir, fmt.Sprintf("%s-%s%s", stem, stamp, suffix))
		}
		return filepath.Join(dir, fmt.Sprintf("%s-%s.%d%s", stem, stamp, n, suffix))
	}
	for i := 0; ; i++ {
		archivePath := build(i)
		// Both the final name and its ".partial" staging name must be
		// free: rotateLocked writes the copy under archivePath+partialSuffix
		// before it is ever renamed to archivePath itself (F-307-2), and a
		// leftover partial from an interrupted rotation that recovery has
		// not yet cleaned up must not collide with a fresh one.
		_, finalErr := os.Lstat(archivePath)
		_, partialErr := os.Lstat(archivePath + partialSuffix)
		if os.IsNotExist(finalErr) && os.IsNotExist(partialErr) {
			return archivePath
		}
	}
}

// copyCurrentToLocked copies s.path's full current content to a new file
// at tmpPath, fsyncing before it returns. tmpPath is the ".partial"
// staging name, not the archive's final name — the caller renames it
// into place only once this copy is complete and durable (F-307-2), so
// a reader or a pruning pass never sees a half-written archive under a
// name retention treats as finished. It reads through a separate,
// freshly opened read-only handle rather than s.f — s.f is O_WRONLY
// (append-only writers do not need read access, and Read on a
// write-only handle fails outright on every platform) — so this leaves
// s.f itself completely untouched: no seek, no position to restore
// before the Truncate that follows.
func (s *fileSink) copyCurrentToLocked(tmpPath string) error {
	// The read leg of the rotation re-opens the live journal's name;
	// like truncateToZero it goes through the no-follow
	// regular-file-only contract (IAMT-332 round seven): a symlink
	// planted at the name mid-life is refused, not read through into
	// the archive.
	src, err := datafile.OpenExisting(s.path, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer src.Close()

	archive, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer archive.Close()
	if _, err := io.Copy(archive, src); err != nil {
		return err
	}
	return archive.Sync()
}

// pruneArchivesLocked deletes rotated archives beyond s.maxArchives,
// oldest first by name - archive names sort chronologically as plain
// strings (the timestamp is a fixed-width, zero-padded RFC3339-like
// stamp) UNDER THE ASSUMPTION that the wall clock only moves forward.
// keep is the archive the CURRENT rotation just published (or, for a
// pending one being resolved elsewhere, is still waiting to be
// truncated) - it is EXCLUDED from every deletion candidate regardless
// of where sorting would place it (F-307-11, review round22): a
// clock moved backward (NTP, an operator) produces an archive name that
// sorts BEFORE existing ones even though it is the newest file on disk,
// and without this exclusion the plain "delete the lexicographically
// oldest name" rule would delete the archive a pending rotation still
// points at - if that archive is gone by the time its truncate finally
// succeeds, the records it was supposed to hold are lost outright, not
// merely duplicated (the one guarantee this whole crash-safety design
// exists to keep). A negative s.maxArchives means "keep every archive
// forever" and skips this entirely. Errors are appended to errs rather
// than reported directly (F-307-8: the caller reports them only after
// releasing both locks).
func (s *fileSink) pruneArchivesLocked(stem, suffix, dir, keep string, errs *[]error) {
	if s.maxArchives < 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("winkeys: list journal directory %s for archive pruning: %w", dir, err))
		return
	}
	prefix := stem + "-"
	var archives []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
			archives = append(archives, name)
		}
	}
	if len(archives) <= s.maxArchives {
		return
	}
	sort.Strings(archives)
	keepName := filepath.Base(keep)
	candidates := make([]string, 0, len(archives))
	for _, name := range archives {
		if name != keepName {
			candidates = append(candidates, name)
		}
	}
	// The total on disk (including keep) must come down to at most
	// s.maxArchives; keep itself is never a candidate, so the surplus to
	// delete is measured against the full count but only ever taken from
	// candidates (capped at len(candidates) in case keep itself is, for
	// whatever reason, not among archives - nothing to protect it from
	// in that case, and toDelete could otherwise overrun the slice).
	toDelete := len(archives) - s.maxArchives
	if toDelete > len(candidates) {
		toDelete = len(candidates)
	}
	for _, name := range candidates[:toDelete] {
		if err := removeFn(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			*errs = append(*errs, fmt.Errorf("winkeys: prune old journal archive %s: %w", name, err))
		}
	}
}

// Close flushes and closes the underlying file. Safe to call on a
// nil receiver.
func (s *fileSink) Close() error {
	if s == nil || s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
