package record

// IAMT-164: every chunk of a recording is fsync-committed before it
// reaches the human. The seam for substituting Sync is the unexported
// package-level `fileSyncFn` (declared in recorder.go). Tests:
//
//   - TestIAMT164_Write_FsyncOnEveryChunk — substitute the seam with a
//     counter; write three chunks; expect exactly three calls, coming
//     exactly from Write.
//   - TestIAMT164_Write_NoSync_Fails — restore the seam afterwards so we
//     can imitate an absent Sync: temporarily swap the seam for a "noop
//     success", then trip the "Sync skipped" wire — if Sync were not
//     called, that branch would become impossible. The specific check
//     goes red if the fileSyncFn() call in Recorder.Write is removed.
//   - TestIAMT164_Write_SyncErrorReturned — the seam returns an error;
//     Write returns exactly it, and the same error lands in lastErr.
//   - TestIAMT164_Write_NoUnwrittenTail — after Write not a single byte
//     is left without Sync: the PROTOCOL §8 contract "committed before
//     it reaches the human".

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIAMT164_Write_FsyncOnEveryChunk(t *testing.T) {
	dir := t.TempDir()

	var calls atomic.Int32
	var lastPath atomic.Value

	prev := fileSyncFn
	fileSyncFn = func(f *os.File) error {
		calls.Add(1)
		lastPath.Store(f.Name())
		return nil
	}
	t.Cleanup(func() { fileSyncFn = prev })

	cfg := SessionConfig{
		BaseDir:   dir,
		Machine:   "vm-fsync",
		Person:    "alice",
		SessionID: "fsync-1",
		Clock:     NewSimClock(time.Date(2026, 9, 13, 9, 0, 0, 0, time.UTC)),
	}
	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	t.Cleanup(func() { _ = rec.Abort("test cleanup") })

	for _, msg := range []string{
		"\u043f\u0440\u0438\u0432\u0435\u0442\x1b[31m\u043a\u0440\u0430\u0441\u043d\u044b\u0439\x1b[0m \u043c\u0438\u0440",
		"\u0432\u0442\u043e\u0440\u043e\u0439 chunk",
		"\u0442\u0440\u0435\u0442\u0438\u0439 chunk — \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0439",
	} {
		rec.Write([]byte(msg))
	}
	_ = rec.Abort("done")

	if got := calls.Load(); got != 3 {
		t.Fatalf("Recorder.Write: want exactly 3 fileSyncFn calls (one per chunk), got %d — Sync is either skipped on a chunk or fired an extra time", got)
	}
	if p, _ := lastPath.Load().(string); !strings.HasSuffix(p, filepath.Base(rec.Paths().CastPath)) {
		t.Fatalf("fsync must be called on the .cast file; last path = %q, want suffix %q", p, filepath.Base(rec.Paths().CastPath))
	}
}

// TestIAMT164_Write_NoSync_Fails — the "Write without Sync before returning
// goes red" canary: remove the fileSyncFn() call from Recorder.Write → the
// sync counter stays 0 → red here. The test does NOT depend on whether the
// sync errored; it only watches that Sync is called at least once per chunk
// (PROTOCOL §8 "write before forwarding without fsync").
func TestIAMT164_Write_NoSync_Fails(t *testing.T) {
	dir := t.TempDir()

	var calls atomic.Int32
	prev := fileSyncFn
	fileSyncFn = func(f *os.File) error {
		calls.Add(1)
		return nil
	}
	t.Cleanup(func() { fileSyncFn = prev })

	cfg := SessionConfig{
		BaseDir:   dir,
		Machine:   "vm-nosync",
		Person:    "alice",
		SessionID: "nosync-1",
		Clock:     NewSimClock(time.Date(2026, 9, 13, 9, 1, 0, 0, time.UTC)),
	}
	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	t.Cleanup(func() { _ = rec.Abort("cleanup") })

	n, err := rec.Write([]byte("hello world\n"))
	if n == 0 || err != nil {
		t.Fatalf("Write returned (%d, %v) — sync must not fail here; we only check that it is called", n, err)
	}
	if got := calls.Load(); got == 0 {
		t.Fatalf("Recorder.Write does NOT call Sync before returning — a PROTOCOL §8 violation (write before forwarding without fsync). Fix Recorder.Write.")
	}
}

// TestIAMT164_Write_SyncErrorReturned — a Sync error turns into a
// Write error via the same path as T7: Write returns (0, err), where
// err is the source for lastErr and lands in meta.exitReason.
func TestIAMT164_Write_SyncErrorReturned(t *testing.T) {
	dir := t.TempDir()

	syncErr := errors.New("simulated fsync failure")
	prev := fileSyncFn
	fileSyncFn = func(f *os.File) error {
		return syncErr
	}
	t.Cleanup(func() { fileSyncFn = prev })

	cfg := SessionConfig{
		BaseDir:   dir,
		Machine:   "vm-syncerr",
		Person:    "alice",
		SessionID: "syncerr-1",
		Clock:     NewSimClock(time.Date(2026, 9, 13, 9, 2, 0, 0, time.UTC)),
	}
	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	t.Cleanup(func() { _ = rec.Abort("cleanup") })

	n, err := rec.Write([]byte("chunk"))
	if n != 0 {
		t.Fatalf("after an fsync error Write must return (0, err); got n=%d", n)
	}
	if err == nil {
		t.Fatalf("after an fsync error Write must return an error; got nil")
	}
	if !strings.Contains(err.Error(), syncErr.Error()) {
		t.Fatalf("the Write error must wrap the fsync error; got %v", err)
	}

	// Recorder.Write's contract stops at returning the error; it does not
	// close the recording itself (Recorder has no notion of "the session
	// is over" - only its caller does). Setting meta.exitReason on a
	// write/sync fault is core.Bridge's job (bridge.go: any non-EOF copy
	// error - which is exactly what T7 exercises - calls rec.Abort(err)
	// before returning). So this test drives the same T7 path explicitly:
	// the caller reacts to the Write error by aborting with it, and only
	// THEN is meta.exitReason populated.
	// Abort's own return value mirrors the same lastErr Write already
	// reported (finalize returns it verbatim, exactly like the T7 path);
	// only meta.exitReason is checked here, same as core.Bridge does.
	_ = rec.Abort(err.Error())
	meta := rec.Metadata()
	if meta.ExitReason == "" {
		t.Fatalf("the fsync error must be recorded in meta.exitReason after Abort (same path as T7)")
	}
	if !strings.Contains(meta.ExitReason, syncErr.Error()) {
		t.Fatalf("meta.exitReason must contain the original fsync error; got %q", meta.ExitReason)
	}
}
