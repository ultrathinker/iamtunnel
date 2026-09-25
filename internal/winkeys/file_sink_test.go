package winkeys

// file_sink_test.go: IAMT-307 round 6 — the journal these tests exercise is
// written by two independent OS processes in production (cmd/iamtunnel's
// server and its watchdog child, both against the same
// /var/lib/iamtunnel-machine/events.jsonl). Every test here therefore
// constructs at least two independent *fileSink values against the SAME
// path rather than sharing one Go value, the same way two processes would
// never share memory: a bug that only shows up when writer B has not yet
// noticed writer A rotated the file cannot be caught by a single sink
// serialising itself under its own mutex.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// journalLines reads every line of every file in dir matching the given
// journal's stem/suffix (current file plus every archive), oldest first,
// and fails the test if any line is not valid JSON — a torn line would show
// up here as a json.Unmarshal error, not as a silently-dropped record.
func journalLines(t *testing.T, path string) []Action {
	t.Helper()
	stem, suffix := journalStemSuffix(path)
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read journal directory: %v", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == stem+suffix || (strings.HasPrefix(name, stem+"-") && strings.HasSuffix(name, suffix)) {
			names = append(names, name)
		}
	}
	// Archive names sort chronologically as plain strings (fixed-width
	// timestamp); the current file's bare name sorts before any archive
	// name that shares its stem plus "-", so a plain string sort already
	// puts everything in write order.
	sort.Strings(names)
	var out []Action
	for _, name := range names {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}
			var a Action
			if err := json.Unmarshal([]byte(line), &a); err != nil {
				t.Fatalf("torn or invalid JSON line in %s: %q: %v", name, line, err)
			}
			out = append(out, a)
		}
		if serr := scanner.Err(); serr != nil {
			t.Fatalf("scan %s: %v", name, serr)
		}
		_ = f.Close()
	}
	return out
}

// readSingleJSONLFile reads exactly one file (not the whole journal
// family journalLines reads) and fails the test on any invalid JSON
// line, same as journalLines. Used where a test needs to assert on the
// live file and an archive SEPARATELY - e.g. to pin an intentionally
// accepted duplication between the two, which journalLines' own combined
// count would hide.
func readSingleJSONLFile(t *testing.T, path string) []Action {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []Action
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var a Action
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatalf("torn or invalid JSON line in %s: %q: %v", path, line, err)
		}
		out = append(out, a)
	}
	if serr := scanner.Err(); serr != nil {
		t.Fatalf("scan %s: %v", path, serr)
	}
	return out
}

func archiveCount(t *testing.T, path string) int {
	t.Helper()
	stem, suffix := journalStemSuffix(path)
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read journal directory: %v", err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, stem+"-") && strings.HasSuffix(name, suffix) {
			n++
		}
	}
	return n
}

// TestJournalSink_RotatesAtMaxBytesAndKeepsEveryLineValid pins the size cap:
// enough small writes to force several rotations must leave every line, in
// the current file and in every archive, parseable JSON - no rotation may
// ever tear a line in half - and must not lose any of them, since
// MaxArchives here is large enough that nothing is pruned.
func TestJournalSink_RotatesAtMaxBytesAndKeepsEveryLineValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	sink, err := NewJournalSink(path, JournalOptions{MaxBytes: 512, MaxArchives: 1000})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	const n = 200
	for i := 0; i < n; i++ {
		sink.OnDoor(Action{Op: "open", DoorID: fmt.Sprintf("door-%04d", i), At: time.Now()})
	}

	if got := archiveCount(t, path); got == 0 {
		t.Fatalf("IAMT-307 canary: %d writes at a 512-byte cap produced no archives at all - rotation never triggered", n)
	}
	lines := journalLines(t, path)
	if len(lines) != n {
		t.Fatalf("IAMT-307 canary: wrote %d door.open actions, read back %d across current file + archives - rotation lost or duplicated lines", n, len(lines))
	}
	for i, a := range lines {
		want := fmt.Sprintf("door-%04d", i)
		if a.DoorID != want {
			t.Fatalf("IAMT-307 canary: line %d has DoorID %q, want %q - rotation reordered or dropped a record", i, a.DoorID, want)
		}
	}
}

// TestJournalSink_PrunesArchivesBeyondMaxArchives forces more rotations than
// the retention limit and checks the oldest archives - and only the oldest
// - are removed, keeping the journal's own disk footprint bounded.
func TestJournalSink_PrunesArchivesBeyondMaxArchives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	const maxArchives = 3
	sink, err := NewJournalSink(path, JournalOptions{MaxBytes: 200, MaxArchives: maxArchives})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	for i := 0; i < 400; i++ {
		sink.OnDoor(Action{Op: "close", DoorID: fmt.Sprintf("door-%04d", i), At: time.Now()})
	}

	if got := archiveCount(t, path); got != maxArchives {
		t.Fatalf("IAMT-307 canary: %d archives on disk, want exactly MaxArchives=%d - retention did not prune (or over-pruned)", got, maxArchives)
	}
	// The retained lines must be a CONTIGUOUS suffix of what was written -
	// pruning the oldest archives, not a random subset, and the newest
	// record (the last one written) must always survive.
	lines := journalLines(t, path)
	if len(lines) == 0 {
		t.Fatal("IAMT-307 canary: retention pruned every record, including the current file")
	}
	last := lines[len(lines)-1]
	if last.DoorID != "door-0399" {
		t.Fatalf("IAMT-307 canary: last retained record is %q, want the most recently written door-0399", last.DoorID)
	}
	for i := 1; i < len(lines); i++ {
		gotPrev, gotCur := lines[i-1].DoorID, lines[i].DoorID
		var prevN, curN int
		fmt.Sscanf(gotPrev, "door-%04d", &prevN)
		fmt.Sscanf(gotCur, "door-%04d", &curN)
		if curN != prevN+1 {
			t.Fatalf("IAMT-307 canary: retained records are not a contiguous run (gap between %q and %q) - pruning removed something other than the oldest archives", gotPrev, gotCur)
		}
	}
}

// TestJournalSink_SecondWriterSurvivesRotationByFirst is the two-process
// scenario by name: sinkA rotates the file several times over; sinkB - a
// second, independent *fileSink against the identical path, opened before
// any of sinkA's rotations and never touched since, standing in for a
// watchdog child that has been sitting idle - must still land its very
// next write in the current file afterwards. Rotation is copy+truncate,
// not rename (see the file's doc comment on why: Windows refuses to
// rename a file a second handle has open), so sinkB's original handle
// never actually goes stale the way a renamed-away file would leave it;
// this test is what proves that promise rather than assuming it.
func TestJournalSink_SecondWriterSurvivesRotationByFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	sinkA, err := NewJournalSink(path, JournalOptions{MaxBytes: 100, MaxArchives: 100})
	if err != nil {
		t.Fatalf("NewJournalSink A: %v", err)
	}
	defer sinkA.(*fileSink).Close()
	sinkB, err := NewJournalSink(path, JournalOptions{MaxBytes: 100, MaxArchives: 100})
	if err != nil {
		t.Fatalf("NewJournalSink B: %v", err)
	}
	defer sinkB.(*fileSink).Close()

	// Force sinkA to rotate the file several times over, entirely without
	// sinkB's participation - modelling the server rotating the journal
	// while the watchdog child idles.
	for i := 0; i < 30; i++ {
		sinkA.OnDoor(Action{Op: "open", DoorID: fmt.Sprintf("A-%02d", i), At: time.Now()})
	}
	if archiveCount(t, path) == 0 {
		t.Fatal("IAMT-307 canary precondition failed: sinkA's writes never rotated the file")
	}

	// sinkB has never rotated anything itself and has not looked at the
	// path since NewJournalSink opened it - exactly a watchdog process
	// that has been sitting idle. Its next write must still land in
	// CURRENT events.jsonl, not the archive its original handle now
	// silently points at.
	sinkB.OnDoor(Action{Op: "close", DoorID: "B-marker", At: time.Now()})

	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current journal: %v", err)
	}
	if !strings.Contains(string(cur), "B-marker") {
		t.Fatalf("IAMT-307 canary: sinkB's write after sinkA's rotation did not reach the current file %s (rotation lost the write instead of landing it after truncation); current file contents: %s", path, cur)
	}
	// And it must not have vanished into an old archive instead of really
	// being written at all.
	lines := journalLines(t, path)
	found := false
	for _, a := range lines {
		if a.DoorID == "B-marker" {
			found = true
		}
	}
	if !found {
		t.Fatal("IAMT-307 canary: sinkB's write after rotation is not present anywhere in the journal (current file or archives)")
	}
}

// TestJournalSink_ConcurrentTwoWriterStress is the stronger form of the
// above: two independent sinks (server + watchdog stand-ins), each driven
// by several goroutines (their own per-process concurrent OnDoor callers),
// hammering the same path while rotation is happening constantly. Every
// single write issued must be found somewhere afterwards, and every line
// must parse - no torn line survives concurrent rotation from either side.
func TestJournalSink_ConcurrentTwoWriterStress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	sinkA, err := NewJournalSink(path, JournalOptions{MaxBytes: 300, MaxArchives: -1})
	if err != nil {
		t.Fatalf("NewJournalSink A: %v", err)
	}
	defer sinkA.(*fileSink).Close()
	sinkB, err := NewJournalSink(path, JournalOptions{MaxBytes: 300, MaxArchives: -1})
	if err != nil {
		t.Fatalf("NewJournalSink B: %v", err)
	}
	defer sinkB.(*fileSink).Close()

	const perWriter = 150
	const goroutinesPerSink = 4
	var wg sync.WaitGroup
	write := func(sink Sink, tag string) {
		defer wg.Done()
		for i := 0; i < perWriter; i++ {
			sink.OnDoor(Action{Op: "sweep", DoorID: fmt.Sprintf("%s-%03d", tag, i), At: time.Now()})
		}
	}
	for g := 0; g < goroutinesPerSink; g++ {
		wg.Add(2)
		go write(sinkA, fmt.Sprintf("A%d", g))
		go write(sinkB, fmt.Sprintf("B%d", g))
	}
	wg.Wait()

	lines := journalLines(t, path) // fails the test itself on any torn line
	seen := make(map[string]int, len(lines))
	for _, a := range lines {
		seen[a.DoorID]++
	}
	var missing, duplicated []string
	for g := 0; g < goroutinesPerSink; g++ {
		for _, tag := range []string{fmt.Sprintf("A%d", g), fmt.Sprintf("B%d", g)} {
			for i := 0; i < perWriter; i++ {
				id := fmt.Sprintf("%s-%03d", tag, i)
				switch seen[id] {
				case 0:
					missing = append(missing, id)
				case 1:
				default:
					duplicated = append(duplicated, id)
				}
			}
		}
	}
	if len(missing) > 0 {
		t.Fatalf("IAMT-307 canary: %d of %d concurrent writes never reached the journal (e.g. %v) - concurrent rotation across two writers lost records", len(missing), goroutinesPerSink*2*perWriter, missing[:min(5, len(missing))])
	}
	if len(duplicated) > 0 {
		t.Fatalf("IAMT-307 canary: %d records appear more than once (e.g. %v)", len(duplicated), duplicated[:min(5, len(duplicated))])
	}
}

// TestJournalSink_OnErrorFiresOnLockContention proves a failed write is no
// longer silent (IAMT-307): holding the rotation lock out from under a
// sink's own OnDoor call - modelling a stuck or misbehaving peer holding
// the cross-process lock - must invoke JournalOptions.OnError instead of
// OnDoor just quietly doing nothing.
func TestJournalSink_OnErrorFiresOnLockContention(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	sink, err := NewJournalSink(path, JournalOptions{})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	held, err := AcquireFileLock(path + ".rotate.lock")
	if err != nil {
		t.Fatalf("acquire rotation lock directly: %v", err)
	}
	defer held.Release()

	errCh := make(chan error, 1)
	fs := sink.(*fileSink)
	fs.onError = func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sink.OnDoor(Action{Op: "open", DoorID: "blocked-by-test", At: time.Now()})
	}()

	// journalLockWait (30s), not a short guess: OnDoor now retries
	// ordinary contention across that whole budget on purpose (see its
	// own doc comment - a busy machine's own event volume must not
	// silently lose a line to a short lock-wait bound), so this held
	// lock, never released for the duration of the test, must still be
	// reported once that budget is actually spent.
	select {
	case gotErr := <-errCh:
		if gotErr == nil {
			t.Fatal("IAMT-307 canary: OnError fired with a nil error")
		}
	case <-time.After(journalLockWait + 5*time.Second):
		t.Fatalf("IAMT-307 canary: OnDoor never reported the held rotation lock through OnError within journalLockWait+5s - a failed write is still silent")
	}
	<-done
}

// seedRawJSONLLines writes n well-formed Action lines directly to path,
// bypassing OnDoor entirely, and returns them in write order. The crash-
// recovery tests below need a live file whose exact content they control
// without going through a real rotation first.
func seedRawJSONLLines(t *testing.T, path string, n int) []Action {
	t.Helper()
	var raw []byte
	actions := make([]Action, n)
	for i := 0; i < n; i++ {
		a := Action{Op: "open", DoorID: fmt.Sprintf("door-%04d", i), At: time.Now()}
		line, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("marshal seed action %d: %v", i, err)
		}
		raw = append(raw, line...)
		raw = append(raw, '\n')
		actions[i] = a
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
	return actions
}

// writeRawRotationMarker plants the durable "a rotation targeting
// archivePath is or was in progress" record directly, the way a real
// rotation's writeRotationMarkerLocked would have left it before a crash
// at any later step - the crash-recovery tests below use this to put a
// fileSink in each of rotateLocked's intermediate states without needing
// to actually interrupt a goroutine mid-rotation.
func writeRawRotationMarker(t *testing.T, path, archivePath string) {
	t.Helper()
	if err := os.WriteFile(path+".rotate.marker", []byte(archivePath), 0o600); err != nil {
		t.Fatalf("write rotation marker: %v", err)
	}
}

// TestJournalSink_RecoversFromCrashBeforeCopyBegins models a crash right
// after the rotation marker was written but before the copy that follows
// it ever started (F-307-2, review round15): no ".partial" staging
// file and no archive exist yet. Recovery must find nothing to finish,
// remove the now-meaningless marker, and leave the live file exactly as
// it was - it is the only copy of these lines that has ever existed.
func TestJournalSink_RecoversFromCrashBeforeCopyBegins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	seeded := seedRawJSONLLines(t, path, 5)

	stem, suffix := journalStemSuffix(path)
	archivePath := nextArchivePath(dir, stem, suffix)
	writeRawRotationMarker(t, path, archivePath)

	sink, err := NewJournalSink(path, JournalOptions{})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	if _, statErr := os.Stat(path + ".rotate.marker"); !os.IsNotExist(statErr) {
		t.Fatal("IAMT-307 canary: rotation marker still present after recovering from a crash before any copy began")
	}
	if _, statErr := os.Stat(archivePath); !os.IsNotExist(statErr) {
		t.Fatalf("IAMT-307 canary: an archive exists at %s after recovering from a crash that this test models as happening before any copy started", archivePath)
	}
	lines := journalLines(t, path)
	if len(lines) != len(seeded) {
		t.Fatalf("IAMT-307 canary: recovery from a crash before any copy began lost or duplicated lines: seeded %d, read back %d", len(seeded), len(lines))
	}
}

// TestJournalSink_RecoversFromCrashMidCopy models a crash while
// copyCurrentToLocked was still writing the ".partial" staging file
// (F-307-2): the marker names an archive that was never published (no
// rename ever happened, since rename only runs after a complete copy),
// and a partial file sits under the archive's staging name holding only
// a prefix of the live file's bytes. Recovery must discard that
// incomplete copy - it must never be visible under a name retention's
// suffix match would treat as a finished archive - and must leave the
// live file untouched, since this implementation never truncates before
// a successful rename publishes the archive.
func TestJournalSink_RecoversFromCrashMidCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	seeded := seedRawJSONLLines(t, path, 5)
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded live file: %v", err)
	}

	stem, suffix := journalStemSuffix(path)
	archivePath := nextArchivePath(dir, stem, suffix)
	writeRawRotationMarker(t, path, archivePath)
	if err := os.WriteFile(archivePath+partialSuffix, live[:len(live)/2], 0o600); err != nil {
		t.Fatalf("seed partial copy: %v", err)
	}

	sink, err := NewJournalSink(path, JournalOptions{})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	if _, statErr := os.Stat(path + ".rotate.marker"); !os.IsNotExist(statErr) {
		t.Fatal("IAMT-307 canary: rotation marker still present after recovering from a crash mid-copy")
	}
	if _, statErr := os.Stat(archivePath + partialSuffix); !os.IsNotExist(statErr) {
		t.Fatalf("IAMT-307 canary: the incomplete copy %s survived recovery from a crash mid-copy", archivePath+partialSuffix)
	}
	if _, statErr := os.Stat(archivePath); !os.IsNotExist(statErr) {
		t.Fatalf("IAMT-307 canary: archive %s exists after a crash mid-copy - the rename that would have published it never ran", archivePath)
	}
	lines := journalLines(t, path)
	if len(lines) != len(seeded) {
		t.Fatalf("IAMT-307 canary: recovery from a crash mid-copy lost or duplicated lines: seeded %d, read back %d - the live file must be untouched", len(seeded), len(lines))
	}
}

// TestJournalSink_CrashAfterPublishedArchiveNeverTruncatesLiveFile
// models a crash after the archive was renamed into its final name but
// before the live file's truncate - the exact window round 7's
// TestJournalSink_RecoversFromCrashAfterCopyBeforeTruncate (this test's
// predecessor) had recovery finish automatically by trusting "the
// archive's name exists" as proof the rename was durable. review
// round16, F-307-5: that trust does not hold on a platform without a
// supported way to fsync a directory entry (Windows, in particular —
// see syncDirBestEffort), so recovery must no longer perform ANY
// destructive action here. This test asserts the new, weaker but safe
// guarantee directly: the live file comes out of NewJournalSink
// byte-for-byte unchanged, on every platform this test runs on -
// duplication (this archive and the live file both holding these lines)
// is the accepted cost, not data loss.
//
// The rotation marker must still exist right after this call too (round
// 11, review round19/round21 follow-up on F-307-10): recovery
// finding the archive durably visible now seeds pendingArchive instead
// of removing the marker outright, so a restarted rotator resumes the
// SAME pending rotation on its next write instead of starting a fresh
// one - the marker disappears only once that retried truncate actually
// succeeds (see TestJournalSink_RecoveredPendingRotationRemovesMarker
// OnlyOnSuccessfulTruncate for that full lifecycle).
func TestJournalSink_CrashAfterPublishedArchiveNeverTruncatesLiveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	seeded := seedRawJSONLLines(t, path, 5)
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded live file: %v", err)
	}

	stem, suffix := journalStemSuffix(path)
	archivePath := nextArchivePath(dir, stem, suffix)
	writeRawRotationMarker(t, path, archivePath)
	if err := os.WriteFile(archivePath, live, 0o600); err != nil {
		t.Fatalf("seed published archive: %v", err)
	}

	var reported []error
	sink, err := NewJournalSink(path, JournalOptions{Role: RotatorRole, OnError: func(e error) { reported = append(reported, e) }})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	if _, statErr := os.Stat(path + ".rotate.marker"); statErr != nil {
		t.Fatalf("IAMT-307 canary (round 11): rotation marker removed by mere recovery - it must disappear only once a retried truncate actually succeeds: %v", statErr)
	}
	liveNow, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read live file after recovery: %v", err)
	}
	if string(liveNow) != string(live) {
		t.Fatalf("IAMT-307 canary (F-307-5): recovery changed the live file after a crash between a published archive and its truncate - it must never destructively act on marker/archive state it cannot prove is durable; got %d bytes, want the original %d untouched", len(liveNow), len(live))
	}
	// journalLines would double-count these 5 lines (both live and
	// archive now hold them) - the test asserts the specific, intended
	// duplication directly instead, so a regression that behaves
	// differently (e.g. silently dropping the archive, or the live
	// file) fails on ITS OWN mismatched count rather than this one.
	archiveLines := readSingleJSONLFile(t, archivePath)
	liveLines := readSingleJSONLFile(t, path)
	if len(archiveLines) != len(seeded) || len(liveLines) != len(seeded) {
		t.Fatalf("IAMT-307 canary: expected the accepted duplication (%d lines in both %s and %s), got %d in archive and %d in live", len(seeded), archivePath, path, len(archiveLines), len(liveLines))
	}
	if len(reported) == 0 {
		t.Fatal("IAMT-307 canary: recovery found a published archive from an interrupted rotation but never reported it through OnError")
	}
}

// TestJournalSink_RecoversFromCrashAfterTruncateBeforeMarkerRemoval
// models a crash after a rotation had fully completed - the archive
// published, the live file already truncated - with only the marker's
// own cleanup left to run. Recovery must be a no-op on both files and
// only remove the now-stale marker.
func TestJournalSink_RecoversFromCrashAfterTruncateBeforeMarkerRemoval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	seeded := seedRawJSONLLines(t, path, 5)
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded live file: %v", err)
	}

	stem, suffix := journalStemSuffix(path)
	archivePath := nextArchivePath(dir, stem, suffix)
	writeRawRotationMarker(t, path, archivePath)
	if err := os.WriteFile(archivePath, live, 0o600); err != nil {
		t.Fatalf("seed published archive: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed already-truncated live file: %v", err)
	}

	sink, err := NewJournalSink(path, JournalOptions{Role: RotatorRole})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	// Round 11 (review round19/round21 follow-up on F-307-10): the
	// marker must disappear only once a retried truncate actually
	// succeeds, never by mere recovery deciding on its own that the live
	// file already looks empty - so recovery seeds pendingArchive here
	// exactly as it would for an UN-truncated live file, and the marker
	// is still present immediately after NewJournalSink returns.
	if _, statErr := os.Stat(path + ".rotate.marker"); statErr != nil {
		t.Fatalf("IAMT-307 canary (round 11): rotation marker removed by mere recovery instead of by a retried, successful truncate: %v", statErr)
	}

	// The next write resolves it: truncating an already-empty file is a
	// harmless no-op, so this succeeds trivially and removes the marker.
	sink.OnDoor(Action{Op: "open", DoorID: "resolves-it", At: time.Now()})
	if _, statErr := os.Stat(path + ".rotate.marker"); !os.IsNotExist(statErr) {
		t.Fatalf("IAMT-307 canary: rotation marker survived a write whose retried truncate should have resolved it: %v", statErr)
	}

	lines := journalLines(t, path)
	if len(lines) != len(seeded)+1 {
		t.Fatalf("IAMT-307 canary: recovery from a crash after a completed rotation (before marker cleanup) lost or duplicated lines: seeded %d + 1 new write, read back %d", len(seeded), len(lines))
	}
}

// TestJournalSink_FailedRecoveryRefusesToOpen pins F-307-4 (review
// round16), and DELIBERATELY REVERSED in round 9 (F-307-7, review
// round17): this used to assert that NewJournalSink refuses to open at
// all when it cannot read a rotation marker. review round17 pointed out
// that round 8 already made recovery fully non-destructive (it never
// touches the live file's content on any path - see the file's crash-
// safety doc comment), so an unresolved marker/partial governs nothing
// about whether the journal itself is safe to open or write to. Refusing
// to start "server start" over a harmless leftover file was the actual
// defect this test now pins the fix for.
//
// Making rotationMarkerPath a DIRECTORY instead of a file keeps os.Stat
// succeeding (so recovery believes a marker exists) while os.ReadFile
// fails with something other than "does not exist" - modelling a marker
// recovery cannot read for any of the reasons F-307-4/F-307-7 name (a
// lock, an ACL, a transient I/O error), without needing a real
// 30-second lock-contention wait to force it.
func TestJournalSink_UnreadableStaleMarkerDoesNotBlockOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	seeded := seedRawJSONLLines(t, path, 3)

	if err := os.Mkdir(path+".rotate.marker", 0o700); err != nil {
		t.Fatalf("seed unreadable rotation marker: %v", err)
	}

	var reported []error
	sink, err := NewJournalSink(path, JournalOptions{OnError: func(e error) { reported = append(reported, e) }})
	if err != nil {
		t.Fatalf("IAMT-307 canary (F-307-7): NewJournalSink refused to open over an unreadable stale rotation marker: %v", err)
	}
	if sink == nil {
		t.Fatal("IAMT-307 canary (F-307-7): NewJournalSink returned a nil sink alongside a nil error")
	}
	defer sink.(*fileSink).Close()
	if len(reported) == 0 {
		t.Fatal("IAMT-307 canary: an unreadable stale rotation marker was not reported through OnError")
	}

	// The live file itself must be untouched...
	if got := len(readSingleJSONLFile(t, path)); got != len(seeded) {
		t.Fatalf("IAMT-307 canary: live file changed while opening over an unreadable stale marker; got %d lines, want %d", got, len(seeded))
	}
	// ...and the sink handed back must still be genuinely usable - the
	// leftover marker (which this process can never remove, since it is
	// a directory) must not wedge every future write either.
	sink.OnDoor(Action{Op: "close", DoorID: "after-recovery", At: time.Now()})
	if got := len(readSingleJSONLFile(t, path)); got != len(seeded)+1 {
		t.Fatalf("IAMT-307 canary: a sink returned despite an unreadable marker did not accept a new write; got %d lines, want %d", got, len(seeded)+1)
	}
}

// TestJournalSink_UnremovableStaleMarkerDoesNotBlockOpenOrWrites pins
// F-307-7 directly against the worked scenario found in review: the crash
// happened after a successful truncate but before the marker was
// removed, and now the marker cannot be deleted (its directory has gone
// read-only, in this example) even though the live journal itself is
// perfectly writable. removeFn is substituted rather than using a real
// read-only directory (F-307-6/F-307-7/F-307-9's shared seam - see its
// own doc comment for why a real permission trick does not portably
// model this on every platform) so this is deterministic and fast on
// Windows, Linux and macOS alike.
func TestJournalSink_UnremovableStaleMarkerDoesNotBlockOpenOrWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	seeded := seedRawJSONLLines(t, path, 3)
	// A marker naming an archive that does not exist - the "crash before
	// the rename ever happened" branch - is the simplest way to reach
	// the final os.Remove(markerPath) call without also depending on
	// recovery's archive-found branch.
	if err := os.WriteFile(path+".rotate.marker", []byte(filepath.Join(dir, "events-does-not-exist.jsonl")), 0o600); err != nil {
		t.Fatalf("seed stale rotation marker: %v", err)
	}

	orig := removeFn
	removeFn = func(name string) error {
		if name == path+".rotate.marker" {
			return fmt.Errorf("simulated permission denied removing marker (test)")
		}
		return orig(name)
	}
	t.Cleanup(func() { removeFn = orig })

	var reported []error
	sink, err := NewJournalSink(path, JournalOptions{OnError: func(e error) { reported = append(reported, e) }})
	if err != nil {
		t.Fatalf("IAMT-307 canary (F-307-7): NewJournalSink refused to open over an unremovable stale marker: %v", err)
	}
	defer sink.(*fileSink).Close()
	if len(reported) == 0 {
		t.Fatal("IAMT-307 canary: an unremovable stale marker was not reported through OnError")
	}
	if got := len(readSingleJSONLFile(t, path)); got != len(seeded) {
		t.Fatalf("IAMT-307 canary: live file changed while opening over an unremovable stale marker; got %d lines, want %d", got, len(seeded))
	}
	sink.OnDoor(Action{Op: "close", DoorID: "after-recovery", At: time.Now()})
	if got := len(readSingleJSONLFile(t, path)); got != len(seeded)+1 {
		t.Fatalf("IAMT-307 canary: a sink returned despite an unremovable marker did not accept a new write; got %d lines, want %d", got, len(seeded)+1)
	}
}

// TestJournalSink_TornRotationMarkerNeverTruncatesLiveFile pins F-307-5:
// a marker whose content is a torn, incomplete PREFIX of a real archive
// path - exactly what an interrupted write to the marker itself would
// have left before this round's write-temp-then-rename publish fix, or
// what a non-durable directory entry rolling back to an older
// generation after a Windows power loss could leave visible - must
// never be trusted enough to drive a destructive truncate. This
// guarantee is unconditional: it holds on every platform this package
// targets, including Windows, precisely because recovery no longer
// performs a destructive truncate on ANY marker content, trustworthy-
// looking or not (see file_sink.go's crash-safety doc comment). What is
// NOT claimed on every platform, and what this test does not assert, is
// exactly-once delivery across a crash — a platform without durable
// directory metadata can still end up with a line duplicated between
// the live file and an already-published archive; only losing a line is
// ruled out here.
func TestJournalSink_TornRotationMarkerNeverTruncatesLiveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	seeded := seedRawJSONLLines(t, path, 4)
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded live file: %v", err)
	}

	stem, suffix := journalStemSuffix(path)
	intended := nextArchivePath(dir, stem, suffix)
	torn := intended[:len(intended)/2] // a byte-prefix, not a real path
	if err := os.WriteFile(path+".rotate.marker", []byte(torn), 0o600); err != nil {
		t.Fatalf("seed torn rotation marker: %v", err)
	}

	sink, err := NewJournalSink(path, JournalOptions{})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	liveNow, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read live file after recovery: %v", err)
	}
	if string(liveNow) != string(live) {
		t.Fatalf("IAMT-307 canary (F-307-5): a torn/unrecognisable rotation marker changed the live file - got %d bytes, want the original %d untouched", len(liveNow), len(live))
	}
	if len(readSingleJSONLFile(t, path)) != len(seeded) {
		t.Fatalf("IAMT-307 canary: live file line count changed after recovering from a torn rotation marker")
	}
}

// TestJournalSink_PermanentTruncateFailureStopsMultiplyingArchives pins
// F-307-6 (review round17): once a truncate has failed once, later
// OnDoor calls must not each start a brand new copy+rename+archive
// rotation against the meanwhile-still-growing live file - that turns
// one stuck truncate into one new archive PER WRITE, defeating both the
// size cap and retention. truncateFn is substituted to fail forever
// (deterministic and portable - see its own doc comment for why a real
// permission trick does not model "permanently" on every platform);
// after many further writes, at most ONE archive may exist, and every
// line written must still be found somewhere (no loss, whether in the
// live file, the one archive, or - the accepted, documented cost -
// duplicated across both).
func TestJournalSink_PermanentTruncateFailureStopsMultiplyingArchives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	orig := truncateFn
	truncateFn = func(string) error { return fmt.Errorf("simulated permanent truncate failure (test)") }
	t.Cleanup(func() { truncateFn = orig })

	var reported []error
	sink, err := NewJournalSink(path, JournalOptions{MaxBytes: 200, MaxArchives: 5, OnError: func(e error) { reported = append(reported, e) }})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	const n = 150
	for i := 0; i < n; i++ {
		sink.OnDoor(Action{Op: "open", DoorID: fmt.Sprintf("door-%04d", i), At: time.Now()})
	}

	if got := archiveCount(t, path); got > 1 {
		t.Fatalf("IAMT-307 canary (F-307-6): %d archives exist after %d writes with truncate permanently failing - want at most 1 (a stuck truncate must not turn every write into a new archive)", got, n)
	}
	if len(reported) == 0 {
		t.Fatal("IAMT-307 canary: a permanently failing truncate was never reported through OnError")
	}
	// No loss: every DoorID from 0..n-1 must appear at least once,
	// whether in the live file, the one archive (if any), or duplicated
	// across both.
	seen := make(map[string]bool, n)
	for _, a := range readSingleJSONLFile(t, path) {
		seen[a.DoorID] = true
	}
	if archiveCount(t, path) == 1 {
		stem, suffix := journalStemSuffix(path)
		entries, rerr := os.ReadDir(dir)
		if rerr != nil {
			t.Fatalf("read journal dir: %v", rerr)
		}
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, stem+"-") && strings.HasSuffix(name, suffix) {
				for _, a := range readSingleJSONLFile(t, filepath.Join(dir, name)) {
					seen[a.DoorID] = true
				}
			}
		}
	}
	for i := 0; i < n; i++ {
		want := fmt.Sprintf("door-%04d", i)
		if !seen[want] {
			t.Fatalf("IAMT-307 canary: door id %q was lost while truncate kept failing - the accepted cost is duplication, never loss", want)
		}
	}
}

// TestJournalSink_RetentionStillRunsWhenTruncateFails pins the other
// half of F-307-6: pruneArchivesLocked must run as soon as an archive is
// durably published, even when the truncate that follows it then fails
// - otherwise every write past a stuck truncate also skips retention,
// and old archives pile up right alongside a live file that cannot be
// emptied either. MaxArchives=1 with two archives already on disk before
// the one rotation this test forces means retention has real pruning
// work to do on exactly the call whose truncate fails.
func TestJournalSink_RetentionStillRunsWhenTruncateFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	stem, suffix := journalStemSuffix(path)
	for i := 0; i < 2; i++ {
		old := filepath.Join(dir, fmt.Sprintf("%s-2020010%dT000000.000000000Z%s", stem, i+1, suffix))
		if err := os.WriteFile(old, []byte(`{"Op":"sweep"}`+"\n"), 0o600); err != nil {
			t.Fatalf("seed pre-existing archive %s: %v", old, err)
		}
	}
	seedRawJSONLLines(t, path, 1)

	orig := truncateFn
	truncateFn = func(string) error { return fmt.Errorf("simulated permanent truncate failure (test)") }
	t.Cleanup(func() { truncateFn = orig })

	sink, err := NewJournalSink(path, JournalOptions{MaxBytes: 1, MaxArchives: 1})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	// This single write is guaranteed to exceed MaxBytes=1 and trigger
	// exactly one rotation, whose truncate is forced to fail above.
	sink.OnDoor(Action{Op: "open", DoorID: "trigger", At: time.Now()})

	if got := archiveCount(t, path); got != 1 {
		t.Fatalf("IAMT-307 canary (F-307-6): %d archives remain after a rotation whose truncate failed, want exactly 1 (MaxArchives) - retention must still run when truncate does not", got)
	}
}

// TestJournalSink_UnremovablePartialIsReportedNotSilentlyIgnored pins
// F-307-9: a stray ".partial" staging file that recovery cannot delete
// used to be discarded with its error thrown away outright, leaving the
// draft on disk forever with no trace of why. removeFn is substituted so
// only that specific path fails, deterministically and portably.
func TestJournalSink_UnremovablePartialIsReportedNotSilentlyIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	seedRawJSONLLines(t, path, 2)

	stem, suffix := journalStemSuffix(path)
	archivePath := nextArchivePath(dir, stem, suffix)
	partialPath := archivePath + partialSuffix
	if err := os.WriteFile(partialPath, []byte("incomplete"), 0o600); err != nil {
		t.Fatalf("seed leftover partial: %v", err)
	}
	if err := os.WriteFile(path+".rotate.marker", []byte(archivePath), 0o600); err != nil {
		t.Fatalf("seed rotation marker: %v", err)
	}

	orig := removeFn
	removeFn = func(name string) error {
		if name == partialPath {
			return fmt.Errorf("simulated permission denied removing partial (test)")
		}
		return orig(name)
	}
	t.Cleanup(func() { removeFn = orig })

	var reported []error
	sink, err := NewJournalSink(path, JournalOptions{OnError: func(e error) { reported = append(reported, e) }})
	if err != nil {
		t.Fatalf("IAMT-307 canary (F-307-7): NewJournalSink refused to open over an unremovable partial: %v", err)
	}
	defer sink.(*fileSink).Close()
	if len(reported) == 0 {
		t.Fatal("IAMT-307 canary (F-307-9): an unremovable leftover partial archive was not reported through OnError")
	}
	if _, statErr := os.Stat(partialPath); statErr != nil {
		t.Fatalf("IAMT-307 canary: the leftover partial was supposed to remain (its removal was forced to fail), but it is now gone: %v", statErr)
	}
}

// TestJournalSink_AppenderNeverStartsItsOwnRotation pins F-307-10 (
// review round19): pendingArchive lives in ONE fileSink, but the journal
// is normally opened by TWO independent processes. A rotator (modelling
// the server) publishes one archive and gets stuck on its own truncate;
// a SEPARATE, non-rotating sink (modelling a fresh watchdog spawn, or
// any process that is not this journal's designated rotator) then opens
// the same path and serves several writes of its own. Before F-307-10,
// that second sink's own empty pendingArchive meant it saw the still-
// oversized live file and started ANOTHER rotation of its own - this
// test's red line, if the fix regresses, is the archive COUNT, not a
// setup failure: it must stay at exactly one no matter how many more
// writes the appender serves, and the rotation marker the rotator left
// behind must still be there afterwards - only the rotator may resolve
// it, and this second sink is not it.
func TestJournalSink_AppenderNeverStartsItsOwnRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	orig := truncateFn
	truncateFn = func(string) error { return fmt.Errorf("simulated permanent truncate failure (test)") }
	t.Cleanup(func() { truncateFn = orig })

	rotator, err := NewJournalSink(path, JournalOptions{MaxBytes: 100, MaxArchives: 5, Role: RotatorRole})
	if err != nil {
		t.Fatalf("NewJournalSink (rotator): %v", err)
	}
	defer rotator.(*fileSink).Close()
	// Force one rotation: this write, against a file already near
	// MaxBytes after a few more, triggers rotateLocked, whose truncate
	// is forced to fail above.
	for i := 0; i < 10; i++ {
		rotator.OnDoor(Action{Op: "open", DoorID: fmt.Sprintf("rotator-%d", i), At: time.Now()})
	}
	if got := archiveCount(t, path); got != 1 {
		t.Fatalf("test setup: rotator did not publish exactly one archive before the appender opened (got %d) - fix the setup, not the assertion below", got)
	}
	if _, statErr := os.Stat(path + ".rotate.marker"); statErr != nil {
		t.Fatalf("test setup: no rotation marker present before the appender opened (rotator's truncate must be stuck for this test to mean anything): %v", statErr)
	}

	appender, err := NewJournalSink(path, JournalOptions{MaxBytes: 100, MaxArchives: 5, Role: AppenderRole})
	if err != nil {
		t.Fatalf("NewJournalSink (appender): %v", err)
	}
	defer appender.(*fileSink).Close()

	for i := 0; i < 5; i++ {
		appender.OnDoor(Action{Op: "close", DoorID: fmt.Sprintf("appender-%d", i), At: time.Now()})
	}

	if got := archiveCount(t, path); got != 1 {
		t.Fatalf("IAMT-307 canary (F-307-10): %d archives exist after a non-rotating sink served 5 writes against a stuck rotation - want exactly 1 (an appender must never start its own rotation)", got)
	}
	if _, statErr := os.Stat(path + ".rotate.marker"); statErr != nil {
		t.Fatalf("IAMT-307 canary (F-307-10): the rotation marker is gone after only a non-rotating sink touched the journal - only the rotator may resolve it: %v", statErr)
	}
}

// TestJournalSink_AppenderRecoveryReportsMarkerAndLeavesItAlone pins the
// second half of F-307-10: a non-rotating sink's own recoverRotationOnOpen
// must report a rotation marker it finds through OnError, and must not
// remove it, read/act on any ".partial" beside it, or touch the live
// file - a rotation it never started is not its to resolve.
func TestJournalSink_AppenderRecoveryReportsMarkerAndLeavesItAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	seeded := seedRawJSONLLines(t, path, 3)

	stem, suffix := journalStemSuffix(path)
	archivePath := nextArchivePath(dir, stem, suffix)
	writeRawRotationMarker(t, path, archivePath)

	var reported []error
	sink, err := NewJournalSink(path, JournalOptions{Role: AppenderRole, OnError: func(e error) { reported = append(reported, e) }})
	if err != nil {
		t.Fatalf("NewJournalSink (appender): %v", err)
	}
	defer sink.(*fileSink).Close()

	if len(reported) == 0 {
		t.Fatal("IAMT-307 canary (F-307-10): a non-rotating sink's recovery found a rotation marker but never reported it through OnError")
	}
	if _, statErr := os.Stat(path + ".rotate.marker"); statErr != nil {
		t.Fatalf("IAMT-307 canary (F-307-10): a non-rotating sink removed the rotation marker it merely found: %v", statErr)
	}
	if got := len(readSingleJSONLFile(t, path)); got != len(seeded) {
		t.Fatalf("IAMT-307 canary: live file changed while a non-rotating sink recovered over a marker it does not own; got %d lines, want %d", got, len(seeded))
	}
}

// TestJournalSink_RotatorCompletesPendingRotationExactlyOnceTruncateWorks
// pins the third half of F-307-10: once the condition that made
// truncate fail clears, the rotator must finish the ONE pending
// rotation it already remembers (pendingArchive) and must not ALSO
// publish a further archive alongside it - retrying the remembered
// truncate, not starting over, is the whole point of pendingArchive.
func TestJournalSink_RotatorCompletesPendingRotationExactlyOnceTruncateWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	orig := truncateFn
	failing := true
	truncateFn = func(p string) error {
		if failing {
			return fmt.Errorf("simulated truncate failure (test)")
		}
		return orig(p)
	}
	t.Cleanup(func() { truncateFn = orig })

	rotator, err := NewJournalSink(path, JournalOptions{MaxBytes: 100, MaxArchives: 5, Role: RotatorRole})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer rotator.(*fileSink).Close()

	for i := 0; i < 10; i++ {
		rotator.OnDoor(Action{Op: "open", DoorID: fmt.Sprintf("before-%d", i), At: time.Now()})
	}
	if got := archiveCount(t, path); got != 1 {
		t.Fatalf("test setup: expected exactly one archive before truncate recovers, got %d", got)
	}

	// The condition clears: truncateFn now behaves like the real thing.
	failing = false
	rotator.OnDoor(Action{Op: "open", DoorID: "after-recovery", At: time.Now()})

	if got := archiveCount(t, path); got != 1 {
		t.Fatalf("IAMT-307 canary (F-307-10): %d archives exist once truncate started working again - want exactly 1 (the rotator must finish its ONE pending rotation, not also publish a new one)", got)
	}
	if _, statErr := os.Stat(path + ".rotate.marker"); !os.IsNotExist(statErr) {
		t.Fatalf("IAMT-307 canary: rotation marker still present after truncate recovered and the pending rotation should have completed: %v", statErr)
	}
	liveNow, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read live file: %v", err)
	}
	// The live file must hold exactly the ONE record written after
	// recovery: the pending rotation's own truncate finally succeeded
	// (emptying everything archived before it), and this write landed
	// after that.
	lines := readSingleJSONLFile(t, path)
	if len(lines) != 1 || lines[0].DoorID != "after-recovery" {
		t.Fatalf("IAMT-307 canary: live file after the pending rotation completed holds %d lines (%v), want exactly 1 (\"after-recovery\"); raw=%q", len(lines), lines, liveNow)
	}
}

// onlyArchiveName returns the single archive matching stem/suffix in
// dir, failing the test if there is not exactly one.
func onlyArchiveName(t *testing.T, dir, stem, suffix string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read journal dir: %v", err)
	}
	var found []string
	prefix := stem + "-"
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
			found = append(found, name)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one archive in %s, found %v", dir, found)
	}
	return found[0]
}

// TestJournalSink_RecoveredPendingRotationRemovesMarkerOnlyOnSuccessfulTruncate
// is round 11's own regression test (review round19/round21's
// acceptance run rejected round 10 on exactly this class of guarantee):
// it models a RESTARTED rotator - a fresh *fileSink opened on a journal
// left by an earlier rotator instance that published an archive and then
// crashed before its own truncate ran - and walks the full lifecycle
// through to resolution.
func TestJournalSink_RecoveredPendingRotationRemovesMarkerOnlyOnSuccessfulTruncate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	seedRawJSONLLines(t, path, 3)
	live, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded live file: %v", err)
	}

	stem, suffix := journalStemSuffix(path)
	archivePath := nextArchivePath(dir, stem, suffix)
	writeRawRotationMarker(t, path, archivePath)
	if err := os.WriteFile(archivePath, live, 0o600); err != nil {
		t.Fatalf("seed published archive: %v", err)
	}
	// Live file left un-truncated - models the crash landing between the
	// original rotator's rename and its own truncate.

	orig := truncateFn
	failing := true
	truncateFn = func(p string) error {
		if failing {
			return fmt.Errorf("simulated truncate failure (test)")
		}
		return orig(p)
	}
	t.Cleanup(func() { truncateFn = orig })

	// A FRESH *fileSink - the "restart" - opens the same journal.
	sink, err := NewJournalSink(path, JournalOptions{MaxBytes: 100, MaxArchives: 5, Role: RotatorRole})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	// Recovery alone (mere opening) must never be what removes the
	// marker - only a successful truncate does.
	if _, statErr := os.Stat(path + ".rotate.marker"); statErr != nil {
		t.Fatalf("IAMT-307 canary (round 11): rotation marker removed by recovery alone, before any truncate ever succeeded: %v", statErr)
	}

	// While truncate keeps failing, the restarted rotator must RESUME
	// the inherited pending rotation, not start a fresh one alongside
	// it - this is the deeper, restart-shaped case of F-307-10 round
	// 10's fix left open.
	sink.OnDoor(Action{Op: "open", DoorID: "still-stuck", At: time.Now()})
	if got := archiveCount(t, path); got != 1 {
		t.Fatalf("IAMT-307 canary (round 11): %d archives exist after a restarted rotator's write while truncate is still stuck - want exactly 1 (it must resume the recovered pending rotation, not start a fresh one)", got)
	}
	if _, statErr := os.Stat(path + ".rotate.marker"); statErr != nil {
		t.Fatalf("IAMT-307 canary: marker disappeared while the retried truncate is still failing: %v", statErr)
	}

	// Once truncate starts working, the next write must finish the
	// recovered pending rotation - and only then does the marker go.
	failing = false
	sink.OnDoor(Action{Op: "open", DoorID: "now-works", At: time.Now()})
	if _, statErr := os.Stat(path + ".rotate.marker"); !os.IsNotExist(statErr) {
		t.Fatalf("IAMT-307 canary: marker still present after the retried truncate succeeded: %v", statErr)
	}
	if got := archiveCount(t, path); got != 1 {
		t.Fatalf("IAMT-307 canary: %d archives exist after the recovered pending rotation finally completed - want exactly 1", got)
	}
}

// TestJournalSink_RetentionOnPendingBranchKeepsThePendingArchive pins
// the retention half of the round-11 checklist: pruning must not
// delete the archive a still-pending rotation is about, whether that
// archive was just published by THIS process or inherited from
// recovery, and must not run again (and misbehave) while resolution is
// still pending.
func TestJournalSink_RetentionOnPendingBranchKeepsThePendingArchive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	stem, suffix := journalStemSuffix(path)
	for i := 0; i < 2; i++ {
		old := filepath.Join(dir, fmt.Sprintf("%s-2020010%dT000000.000000000Z%s", stem, i+1, suffix))
		if err := os.WriteFile(old, []byte(`{"Op":"sweep"}`+"\n"), 0o600); err != nil {
			t.Fatalf("seed pre-existing archive %s: %v", old, err)
		}
	}
	seedRawJSONLLines(t, path, 1)

	orig := truncateFn
	failing := true
	truncateFn = func(p string) error {
		if failing {
			return fmt.Errorf("simulated truncate failure (test)")
		}
		return orig(p)
	}
	t.Cleanup(func() { truncateFn = orig })

	sink, err := NewJournalSink(path, JournalOptions{MaxBytes: 1, MaxArchives: 1, Role: RotatorRole})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	// This write exceeds MaxBytes=1 and triggers exactly one rotation,
	// which prunes the two pre-existing archives down to MaxArchives=1
	// (retention already runs before the truncate attempt - round 9,
	// F-307-6) and whose own truncate is then forced to fail.
	sink.OnDoor(Action{Op: "open", DoorID: "trigger", At: time.Now()})
	if got := archiveCount(t, path); got != 1 {
		t.Fatalf("test setup: expected exactly one archive to survive retention after the triggering rotation, got %d", got)
	}
	pendingName := onlyArchiveName(t, dir, stem, suffix)

	// Further writes while truncate stays stuck must not add, remove or
	// replace the pending rotation's own archive.
	for i := 0; i < 3; i++ {
		sink.OnDoor(Action{Op: "open", DoorID: fmt.Sprintf("stuck-%d", i), At: time.Now()})
	}
	if got := onlyArchiveName(t, dir, stem, suffix); got != pendingName {
		t.Fatalf("IAMT-307 canary: the pending rotation's own archive changed while truncate was stuck: was %q, now %q", pendingName, got)
	}

	// Once truncate resolves it, retention still has not touched it -
	// pendingArchive resolution does not re-run pruning against the
	// archive it is itself about.
	failing = false
	sink.OnDoor(Action{Op: "open", DoorID: "resolved", At: time.Now()})
	if got := onlyArchiveName(t, dir, stem, suffix); got != pendingName {
		t.Fatalf("IAMT-307 canary: retention removed the pending rotation's own archive %q once its truncate finally completed (now %q)", pendingName, got)
	}
}

// TestJournalSink_RetentionNeverDeletesThePendingArchiveEvenIfItSortsFirst
// pins F-307-11 (review round22, High, confirmed): pruneArchivesLocked
// used to pick deletion candidates by lexicographic sort order alone,
// which silently assumes the wall clock only ever moves forward (archive
// names are built from it). A clock moved BACKWARD (NTP, an operator) -
// modelled directly here, without touching the real clock, by seeding a
// pre-existing archive whose own name carries a timestamp far in the
// future relative to whatever a rotation started "now" will ever
// produce - makes the archive a rotation JUST published sort BEFORE an
// older one. TestJournalSink_RetentionOnPendingBranchKeepsThePendingArchive
// (round 11) did not catch this: its two pre-existing archives were both
// dated 2020, so the freshly published one was always lexicographically
// newest and survived by accident, not by rule. Without excluding the
// pending rotation's own archive from deletion candidates regardless of
// where sorting places it, retention deletes exactly that archive as
// "the oldest by name" - and once a later truncate succeeds, the records
// it was supposed to hold are gone outright, not merely duplicated: the
// one guarantee this entire crash-safety design exists to keep.
func TestJournalSink_RetentionNeverDeletesThePendingArchiveEvenIfItSortsFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	stem, suffix := journalStemSuffix(path)

	// A pre-existing archive whose name sorts AFTER anything a rotation
	// started "now" will ever produce.
	futureArchive := filepath.Join(dir, fmt.Sprintf("%s-99990101T000000.000000000Z%s", stem, suffix))
	if err := os.WriteFile(futureArchive, []byte(`{"Op":"sweep"}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed future-dated archive: %v", err)
	}

	seeded := seedRawJSONLLines(t, path, 3)

	orig := truncateFn
	failing := true
	truncateFn = func(p string) error {
		if failing {
			return fmt.Errorf("simulated truncate failure (test)")
		}
		return orig(p)
	}
	t.Cleanup(func() { truncateFn = orig })

	sink, err := NewJournalSink(path, JournalOptions{MaxBytes: 1, MaxArchives: 1, Role: RotatorRole})
	if err != nil {
		t.Fatalf("NewJournalSink: %v", err)
	}
	defer sink.(*fileSink).Close()

	// This write exceeds MaxBytes=1 and triggers exactly one rotation.
	// The archive it publishes sorts BEFORE futureArchive (a real "now"
	// timestamp is less than the seeded year-9999 one), so a naive
	// "delete the lexicographically oldest name" rule would delete the
	// archive this very rotation is still pending on, not the
	// pre-existing one that is the actual surplus.
	sink.OnDoor(Action{Op: "open", DoorID: "trigger", At: time.Now()})

	if _, statErr := os.Stat(futureArchive); !os.IsNotExist(statErr) {
		t.Fatalf("IAMT-307 canary (F-307-11): the pre-existing future-dated archive should have been pruned as the real surplus, but it is still present: %v", statErr)
	}
	pendingName := onlyArchiveName(t, dir, stem, suffix)
	if pendingName == filepath.Base(futureArchive) {
		t.Fatal("IAMT-307 canary (F-307-11): the surviving archive is the pre-existing future-dated one, not the pending rotation's own archive - it was deleted instead")
	}

	// Further writes while truncate stays stuck must not lose the
	// pending archive either.
	sink.OnDoor(Action{Op: "open", DoorID: "still-stuck", At: time.Now()})
	if got := onlyArchiveName(t, dir, stem, suffix); got != pendingName {
		t.Fatalf("IAMT-307 canary (F-307-11): the pending rotation's own archive changed while truncate was stuck: was %q, now %q", pendingName, got)
	}

	// Truncate finally succeeds: the surviving archive's own content
	// must still match what was actually archived, proving no records
	// were lost along the way.
	failing = false
	sink.OnDoor(Action{Op: "open", DoorID: "resolved", At: time.Now()})

	if got := onlyArchiveName(t, dir, stem, suffix); got != pendingName {
		t.Fatalf("IAMT-307 canary: the pending rotation's own archive %q is gone once its truncate finally completed (now %q)", pendingName, got)
	}
	archiveLines := readSingleJSONLFile(t, filepath.Join(dir, pendingName))
	if len(archiveLines) != len(seeded) {
		t.Fatalf("IAMT-307 canary (F-307-11): the surviving archive lost records - has %d lines, want the %d originally archived", len(archiveLines), len(seeded))
	}
}
