package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

const (
	DefaultLogFileName = "events.jsonl"
	FilePerm           = 0600
	DirPerm            = 0700
)

// adoptOwnership is the ownership-adoption seam for the files this
// package creates in the gateway data directory (IAMT-332). A fresh
// events.jsonl carries the creating process's account, so a root-run
// "gateway pair" that finds the log missing would leave it owned by
// root, and the unprivileged service could never append another event.
// The default is the real platform step, state.PreserveOwnership (a
// no-op on Windows); tests swap in a recorder so nothing is chowned for
// real and root is never needed.
var adoptOwnership = state.PreserveOwnership

// openAfterRotate opens the fresh journal file a rotation creates. It is a
// seam like adoptOwnership above and for the same reason: no test can make
// a real create-or-refuse open fail on demand - a full disk or an
// unopenable file is not something a test can arrange in a temporary
// directory - and a rotation whose new file cannot be opened is exactly
// the case F-08 (round-1 review 24.09.2026) is about.
var openAfterRotate = state.OpenDataFile

// Log manages the append-only events.jsonl file.
type Log struct {
	path string
	mu   sync.Mutex
	file *os.File
	// lostWhy is how this log came to have no file while its owner never
	// closed it, in the words the errors use: "was rotated to <archive>"
	// when a rotation published the archive and then could not open a
	// fresh file, or "could not be rotated into <archive>" when the rename
	// itself failed and the file that stayed behind could not be opened
	// either. Non-empty, it is why l.file is nil - not the gateway closing
	// the log: every later write says so and tries once more to open a
	// file, so a disk that was full for a minute costs a minute of audit
	// rather than a gateway restart (IAMT-451's contract: failing until a
	// write succeeds). Cleared when a file is opened again, and by Close.
	lostWhy string
	// lostArchive is the archive the file was rotated into when the
	// rotation published it and could not open a fresh file - the one case
	// where the records of this journal are behind an archive the current
	// file does not name. It stays until a file is opened again, because
	// the recovery has to tie the chain to it (F-08, round-2 review
	// 24.09.2026); empty in the branch where the rename failed and the
	// file is still there, where nothing was published and there is
	// nothing to link.
	lostArchive string
	// openErr is why the last attempt to open a file after such a
	// rotation failed.
	openErr error
	// chain is set by OpenChainedLog: every line carries prev_hash
	// (IAMT-467, chain.go).
	chain bool
}

// The history of a gateway consists of exactly two kinds of file, and nothing else in
// the directory is history:
//
//	events.jsonl              the log being written right now
//	events-<label>.jsonl      an archive left behind by a rotation
//
// where <label> is one or more of [0-9A-Za-z_-] - in particular it holds no dot, so a
// name that has anything else glued into it is not an archive. The rule is a positive
// pattern, not a list of forbidden extensions: a "skip .tmp, .bak, .swp" list is
// incomplete the moment someone invents a fourth suffix, and reading a stray file as
// history means answering an audit question with somebody else's bytes. Rotate refuses
// to write an archive whose name this pattern would not find again.
const (
	logFileStem   = "events"
	logFileSuffix = ".jsonl"
)

// IsLogFileName reports whether name is the current log or one of its archives.
func IsLogFileName(name string) bool {
	if !strings.HasPrefix(name, logFileStem) || !strings.HasSuffix(name, logFileSuffix) {
		return false
	}
	label := name[len(logFileStem) : len(name)-len(logFileSuffix)]
	if label == "" {
		return true // exactly "events.jsonl"
	}
	if label[0] != '-' || len(label) == 1 {
		return false
	}
	for _, r := range label[1:] {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// ArchiveName returns the canonical name of an archive for a rotation happening at t.
func ArchiveName(t time.Time) string {
	return fmt.Sprintf("%s-%s%s", logFileStem, t.UTC().Format("20060102T150405Z"), logFileSuffix)
}

// ArchiveNameFor is ArchiveName with a tag of the caller's choosing after
// the moment: the name a rotation writes when two rotations can fall in
// the same second and each has to keep its own archive (F-09, round
// 1 24.09.2026 — "gateway restore" keeps the live journal aside, and two
// restores in one second used to land on one name). The tag is part of
// the label IsLogFileName accepts, so it must be [0-9A-Za-z_-] and must
// hold no dot, or the history stops finding the file.
func ArchiveNameFor(t time.Time, tag string) string {
	return fmt.Sprintf("%s-%s-%s%s", logFileStem, t.UTC().Format("20060102T150405Z"), tag, logFileSuffix)
}

// ParseArchiveTime reads the moment out of a name ArchiveName wrote, and
// says whether the name is exactly such an archive. It is the inverse the
// retention needs (R4 F-11): the timestamp in the name, not the file's
// mtime, is how old an archive is - a copy or a backup pass can move the
// mtime, and the name is the archive's identity. A tagged name
// (ArchiveNameFor) is not a rotation archive: its label carries the tag
// after the stamp, and the caller has no business ageing it.
func ParseArchiveTime(name string) (time.Time, bool) {
	label := strings.TrimSuffix(strings.TrimPrefix(name, logFileStem+"-"), logFileSuffix)
	// ArchiveName's stamp is <UTC date>T<UTC time>Z - fifteen layout
	// characters and the literal Z. The literal is matched by hand: in a
	// reference layout a Z belongs to a zone chunk (Z0700), and a bare
	// trailing Z must not be misread as one.
	if len(label) != 16 || label[15] != 'Z' {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102T150405", label[:15])
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// OpenLog opens or creates an append-only event log at path.
// It repairs a torn trailing line without newline by appending '\n' (Defect 5).
//
// The log handle is opened write-only and append-only. The one thing that needed
// reading - checking whether the previous run left a line without its newline - is done
// through a separate short-lived read handle before the writing one is opened. A single
// O_RDWR|O_APPEND handle would mix two access modes whose interaction differs between
// platforms: on Linux O_APPEND makes every write seek to the end atomically, on Windows
// the same flag is emulated and the position is per handle, so a handle that is also
// used for reading has a position that reading moves. Write-only plus append leaves
// nothing for that difference to bite.
func OpenLog(path string) (*Log, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, DirPerm); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	if err := repairTornTail(path); err != nil {
		return nil, err
	}

	// The log is a long-lived file reused across restarts, so the open
	// cannot be O_EXCL-unconditionally: create-or-refuse is the shape —
	// a fresh create is safe by construction, and an existing name is
	// reopened with the platform's no-follow guarantee, a symlink there
	// refused outright (IAMT-332 round three). state.OpenDataFile owns
	// that discipline.
	f, err := state.OpenDataFile(path, os.O_WRONLY|os.O_APPEND, FilePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to open event log %s: %w", path, err)
	}

	// A log this open CREATED carries the creating process's account
	// (IAMT-332): a root-run "gateway pair" that finds events.jsonl
	// missing would leave it owned by root, and the unprivileged service
	// could never append another event. The adoption runs on every open —
	// the common case finds the file already owned by the expected
	// account and skips (two stat calls), and a pre-fix root-owned log is
	// healed by the same step instead of staying unreadable.
	if aerr := adoptOwnership(f, ""); aerr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to adopt the owner of event log %s: %w", path, aerr)
	}

	return &Log{
		path: path,
		file: f,
	}, nil
}

// repairTornTail isolates a record whose write was cut short by a crash: if the file
// does not end with a newline, one is appended, so that the next event does not get
// glued onto the remains of the previous one (Defect 5). Neither leg creates the
// file, and both refuse a symlink planted at the log's name: the append is a WRITE,
// and no handle here may land behind a planted link (IAMT-332 round three).
func repairTornTail(path string) error {
	r, err := state.OpenExistingDataFile(path, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to inspect event log %s: %w", path, err)
	}
	fi, statErr := r.Stat()
	if statErr != nil || fi.Size() == 0 {
		_ = r.Close()
		return nil
	}
	lastByte := make([]byte, 1)
	_, readErr := r.ReadAt(lastByte, fi.Size()-1)
	_ = r.Close()
	if readErr != nil || lastByte[0] == '\n' {
		return nil
	}

	w, err := state.OpenExistingDataFile(path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return fmt.Errorf("failed to repair torn tail of %s: %w", path, err)
	}
	defer w.Close()
	if _, err := w.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("failed to repair torn tail of %s: %w", path, err)
	}
	return w.Sync()
}

// Append writes a single event as a JSON line followed by a newline.
//
// An event that fails validation is not written - a malformed record in an audit log is
// worse than none - and the validation error is returned. It is not swallowed: for an
// append-only journal, "written" and "lost" must not look the same to the caller.
// Use errors.Is(err, ErrInvalidEvent) to tell a rejected event from a broken log.
func (l *Log) Append(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.appendLocked(e)
}

// appendLocked is Append without taking the mutex. Must be called with l.mu held.
func (l *Log) appendLocked(e Event) error {
	if l.file == nil {
		if l.lostWhy == "" {
			return errors.New("log is closed")
		}
		// A rotation took this log's file and could not open a new one.
		// Try again: whatever refused the open may have let go, and a
		// journal that comes back by itself is worth more than one that
		// waits for a restart (F-08).
		if err := l.reopenAfterRotationLocked(); err != nil {
			return err
		}
	}

	if err := e.Validate(); err != nil {
		return fmt.Errorf("event not written to %s: %w", l.path, err)
	}
	if l.chain {
		unlock, err := l.lockChain()
		if err != nil {
			return fmt.Errorf("event not written to %s: the journal's append lock: %w", l.path, err)
		}
		defer unlock()
		return l.writeChainedLocked(e, "")
	}

	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("failed to serialize event: %w", err)
	}

	raw = append(raw, '\n')
	if _, err := l.file.Write(raw); err != nil {
		return fmt.Errorf("failed to append event to log: %w", err)
	}

	return l.file.Sync()
}

// Path is where the current log is written; its archives go beside it.
func (l *Log) Path() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.path
}

// Size is how many bytes the current log holds now - what a rotation by
// size is measured against (IAMT-452).
func (l *Log) Size() (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return 0, l.noFileErrLocked()
	}
	st, err := l.file.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// Rotate renames the current log file to archivePath and opens a fresh log file at the original path.
// Also performs fsync on the directory (Defect 11).
func (l *Log) Rotate(archivePath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return errors.New("log is closed")
	}

	// An archive ReadHistory would not recognise is an archive that silently drops out
	// of the history, so the name is checked before anything is moved.
	if !IsLogFileName(filepath.Base(archivePath)) {
		return fmt.Errorf("refusing to rotate into %q: an archive must be named %s-<label>%s (see ArchiveName), otherwise the history stops finding it",
			filepath.Base(archivePath), logFileStem, logFileSuffix)
	}

	// A chained journal (IAMT-467) goes on across the rotation: the fresh
	// file's first line names the archive's last one. The lock is held from
	// reading that line to writing the next, so no other writer can land a
	// line in between.
	prev := ""
	if l.chain {
		unlock, err := l.lockChain()
		if err != nil {
			return fmt.Errorf("rotation of %s: the journal's append lock: %w", l.path, err)
		}
		defer unlock()
		last, _, err := lastLine(l.path)
		if err != nil {
			return fmt.Errorf("rotation of %s: reading its last line: %w", l.path, err)
		}
		prev = genesisHash
		if last != nil {
			prev = LineHash(last)
		}
	}

	// Flush and close current file
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync log before rotate: %w", err)
	}
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("failed to close log before rotate: %w", err)
	}
	l.file = nil

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(archivePath), DirPerm); err != nil {
		return fmt.Errorf("failed to create archive directory: %w", err)
	}

	// Rename current log to archive path
	if err := os.Rename(l.path, archivePath); err != nil {
		// Reopen if rename failed. Same no-symlink open as everywhere
		// else in this file: the name exists (the rename failed), but a
		// link could have been planted in the gap (IAMT-332 round three).
		f, reopenErr := state.OpenDataFile(l.path, os.O_RDWR|os.O_APPEND, FilePerm)
		if reopenErr == nil {
			if aerr := adoptOwnership(f, ""); aerr == nil {
				l.file, l.lostWhy, l.openErr, l.lostArchive = f, "", nil, ""
			} else {
				_ = f.Close()
				l.openErr = aerr
			}
		} else {
			l.openErr = reopenErr
		}
		if l.file == nil {
			// The rename failed and the file it left behind could not be
			// opened either, so this log is now without one - and unlike
			// the rotation that published its archive, F-08's
			// self-healing never covered this branch: every later write
			// said the log was closed, which blames the gateway's own
			// stop for a rotation the disk refused, and nothing ever
			// opened the file again (F-19, round-1 review 24.09.2026).
			// The name of the archive it could not become is the only
			// thing that says what was being attempted.
			l.lostWhy = fmt.Sprintf("could not be rotated into %s", filepath.Base(archivePath))
		}
		return fmt.Errorf("failed to rotate log file: %w", err)
	}

	// Fsync directory entry after rename (Defect 11)
	_ = syncDir(filepath.Dir(archivePath))
	_ = syncDir(filepath.Dir(l.path))

	// Open fresh file at current path — same create-or-refuse open as
	// OpenLog (IAMT-332 round three).
	f, err := openAfterRotate(l.path, os.O_RDWR|os.O_APPEND, FilePerm)
	if err != nil {
		// The archive is published and there is no journal: the log
		// remembers the rotation, so every later write names it instead
		// of reporting the gateway's own shutdown as the cause (F-08,
		// round-1 review 24.09.2026).
		l.lostWhy, l.lostArchive, l.openErr = fmt.Sprintf("was rotated to %s", filepath.Base(archivePath)), archivePath, err
		return fmt.Errorf("failed to open new log file after rotation: %w", err)
	}
	// Same creation case as OpenLog: the fresh journal carries this
	// process's account (IAMT-332). The reopen on a failed rename above
	// is deliberately left alone — it reopens the very file that was
	// already this log, so nothing new is created there.
	if aerr := adoptOwnership(f, ""); aerr != nil {
		_ = f.Close()
		l.lostWhy, l.lostArchive, l.openErr = fmt.Sprintf("was rotated to %s", filepath.Base(archivePath)), archivePath, aerr
		return fmt.Errorf("failed to adopt the owner of event log %s: %w", l.path, aerr)
	}
	l.file = f
	l.lostWhy, l.lostArchive, l.openErr = "", "", nil

	// §3.5 counts rotation among the events the journal records. Written as the first
	// line of the new file, it tells a reader of the current log where the previous
	// records went - otherwise the history simply appears to begin out of nowhere.
	rotated := Event{
		Time:   state.NewZonedTime(time.Now().UTC()),
		Type:   EventLogRotate,
		Actor:  "gateway",
		Object: filepath.Base(l.path),
		Result: "ok",
		Details: map[string]interface{}{
			"archive": archivePath,
		},
	}
	var werr error
	if l.chain {
		werr = l.writeChainedLocked(rotated, prev)
	} else {
		werr = l.appendLocked(rotated)
	}
	if werr != nil {
		return fmt.Errorf("log rotated to %s, but the %s event was not recorded: %w", archivePath, EventLogRotate, werr)
	}

	return nil
}

// reopenAfterRotationLocked opens a file for a log that lost its own to a
// rotation attempt, and reports that attempt as the reason when it fails
// again. The file it opens is created and adopted exactly as the one a
// rotation creates (IAMT-332), because that is what it is - the same open
// that failed, tried again.
func (l *Log) reopenAfterRotationLocked() error {
	f, err := openAfterRotate(l.path, os.O_RDWR|os.O_APPEND, FilePerm)
	if err == nil {
		if aerr := adoptOwnership(f, ""); aerr != nil {
			_ = f.Close()
			err = aerr
		}
	}
	if err != nil {
		l.openErr = err
		return l.noFileErrLocked()
	}
	l.file = f
	// F-08 (round-2 review 24.09.2026): when the rotation published
	// an archive and could not open a file, the file opened here is the
	// first of a new journal, and the chain has to be tied to that archive
	// the way Rotate ties it - with a log.rotate line whose prev_hash is
	// the archive's last one. Rotate writes that line on the successful
	// path and only after the fresh file exists, so the recovery that
	// could not open the file at the time has to write it now; without it
	// the history reads as a gateway that rewrote its own journal (the
	// archive, then a file whose first line claims to begin it, and
	// VerifyChain says Broken).
	if l.chain && l.lostArchive != "" {
		empty := false
		if st, serr := f.Stat(); serr == nil {
			empty = st.Size() == 0
		}
		if empty {
			if werr := l.linkArchiveLocked(); werr != nil {
				l.openErr = werr
				return fmt.Errorf("the journal was rotated to %s and a new %s was opened, but the line that ties it to the archive could not be written (%v); nothing is recorded until it can be",
					filepath.Base(l.lostArchive), filepath.Base(l.path), werr)
			}
		}
	}
	l.lostWhy, l.lostArchive, l.openErr = "", "", nil
	return nil
}

// linkArchiveLocked writes the log.rotate line a rotation writes on its
// successful path, naming the archive this log published when it lost its
// file. It is called with l.mu held and l.file freshly opened and empty;
// the chain lock is taken here, because the hash of the archive's last
// line has to be read under it, exactly as Rotate reads it.
func (l *Log) linkArchiveLocked() error {
	unlock, err := l.lockChain()
	if err != nil {
		return fmt.Errorf("the journal's append lock: %w", err)
	}
	defer unlock()
	last, _, lerr := lastLine(l.lostArchive)
	if lerr != nil {
		return fmt.Errorf("reading the last line of %s: %w", filepath.Base(l.lostArchive), lerr)
	}
	prev := genesisHash
	if last != nil {
		prev = LineHash(last)
	}
	return l.writeChainedLocked(Event{
		Time:   state.NewZonedTime(time.Now().UTC()),
		Type:   EventLogRotate,
		Actor:  "gateway",
		Object: filepath.Base(l.path),
		Result: "ok",
		Details: map[string]interface{}{
			"archive": l.lostArchive,
			// The rotation this line records could not open its file when
			// it happened; the recovery writes the line late, and says so.
			"recovered": true,
		},
	}, prev)
}

// noFileErrLocked is what this log says when it has no file. A log its
// owner closed says exactly that; a log a rotation left without one names
// the rotation, the archive it published or could not publish, and the
// open that failed, so an operator reading gateway status (IAMT-451
// publishes this text) can tell a disk that is refusing work from a
// gateway that was stopped (F-08 and F-19, round-1 review 24.09.2026).
func (l *Log) noFileErrLocked() error {
	if l.lostWhy == "" {
		return errors.New("log is closed")
	}
	return fmt.Errorf("the journal %s and no new %s could be opened (%v); nothing is recorded until one can be",
		l.lostWhy, filepath.Base(l.path), l.openErr)
}

// ReadStats reports what a read had to step over. A torn trailing line after a power
// cut is expected and harmless; a damaged line in the middle of the file is a hole in
// the audit trail, and the caller has to be able to see that it happened rather than
// get a silently shorter slice.
type ReadStats struct {
	// Skipped counts lines that were present but could not be parsed as an event.
	Skipped int
	// BadLines holds the 1-based numbers of those lines, per file in read order.
	BadLines []int
}

// Add merges the stats of another file into these.
func (s *ReadStats) Add(other ReadStats) {
	s.Skipped += other.Skipped
	s.BadLines = append(s.BadLines, other.BadLines...)
}

// Read reads matching events from the current log file.
// It is resilient to ungraceful crashes: an incomplete/truncated trailing line
// does not abort reading of the preceding valid records - it is reported in ReadStats.
func (l *Log) Read(filter Filter) ([]Event, ReadStats, error) {
	l.mu.Lock()
	path := l.path
	l.mu.Unlock()

	return readLogFile(path, filter)
}

// ReadFile reads events from any log file (current or rotated archive).
func ReadFile(path string, filter Filter) ([]Event, ReadStats, error) {
	return readLogFile(path, filter)
}

// ReadFiles reads events across multiple log files in order.
func ReadFiles(filter Filter, paths ...string) ([]Event, ReadStats, error) {
	var all []Event
	var stats ReadStats
	for _, p := range paths {
		evts, st, err := readLogFile(p, filter)
		if err != nil {
			return nil, stats, err
		}
		stats.Add(st)
		all = append(all, evts...)
	}
	return all, stats, nil
}

// ReadHistory discovers and reads all event logs in dir (both current and archives) (Defect 12).
func ReadHistory(dir string, filter Filter) ([]Event, ReadStats, error) {
	names, err := historyNames(dir)
	if err != nil {
		return nil, ReadStats{}, err
	}
	files := make([]string, 0, len(names))
	for _, n := range names {
		files = append(files, filepath.Join(dir, n))
	}
	return ReadFiles(filter, files...)
}

// historyNames lists the journal's files in dir - archives, then the
// current log - in the order they were written; none when dir does not
// exist. ReadHistory and VerifyChain read the same files in the same order.
//
// The listing goes through os.Root (IAMT-333, closes the walk residual
// audit §3.4 deferred): the names come from the directory the Root holds
// open, so a swap of dir's own entry in its parent between this listing
// and the opens that follow cannot mix two directories, and a name that
// leads outside dir is refused rather than resolved. The opens themselves
// stay on the datafile primitive (create-or-refuse, no-follow, the
// regular-file contract) - a Root open would open a planted FIFO where
// the contract refuses it.
func historyNames(dir string) ([]string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && IsLogFileName(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func readLogFile(path string, filter Filter) ([]Event, ReadStats, error) {
	var stats ReadStats

	f, err := state.OpenExistingDataFile(path, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil, stats, nil
	} else if err != nil {
		return nil, stats, fmt.Errorf("failed to open log file %s: %w", path, err)
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	var events []Event
	lineNum := 0

	// One exit from this loop, at end of file. The last line of a log written by a
	// process that was killed has no '\n', so ReadBytes hands back the data *and*
	// io.EOF together: the data is processed first, and the next turn of the loop -
	// which reads zero bytes - is what ends it.
	for {
		lineNum++
		lineBytes, readErr := reader.ReadBytes('\n')

		if len(lineBytes) > 0 {
			if trimmed := bytes.TrimSpace(lineBytes); len(trimmed) > 0 {
				var ev Event
				if json.Unmarshal(trimmed, &ev) != nil {
					// Torn or corrupt line: keep reading, but do not pretend it was not there.
					stats.Skipped++
					stats.BadLines = append(stats.BadLines, lineNum)
				} else if filter.Matches(ev) {
					events = append(events, ev)
				}
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, stats, fmt.Errorf("read error at line %d: %w", lineNum, readErr)
		}
	}

	return events, stats, nil
}

// Close flushes and closes the log file.
// ReadAll reads this log AND its rotated archives.
//
// Read (above) opens only the current file, which is right for "what has
// happened lately" and wrong for a history. The review caught the difference
// on 21.09.2026 in the new History tab: a session whose start was written
// before a rotation and whose stop came after would be rebuilt from the
// stop alone -- appearing to have begun at the moment it ended, and as a
// shell session even when it was one exec command.
//
// The archives were always readable; ReadHistory has read them since
// Defect 12. What was missing was a method on the Log that knows its own
// directory, so a caller holding a *Log did not have to be told where its
// files live -- and the caller that was not told used the narrow read.
func (l *Log) ReadAll(filter Filter) ([]Event, ReadStats, error) {
	if l == nil {
		return nil, ReadStats{}, nil
	}
	return ReadHistory(filepath.Dir(l.path), filter)
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// A closed log is closed, whatever it lost on the way here: the
	// rotation a later write would have reported is not this log's state
	// any more (F-08 keeps the two apart).
	l.lostWhy, l.lostArchive, l.openErr = "", "", nil
	if l.file != nil {
		_ = l.file.Sync()
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}
