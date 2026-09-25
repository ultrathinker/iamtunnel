package gateway

// F-06 of the round-1 review (24.09.2026), high: the host key
// rotation removed the working key file FIRST and generated the new one in
// its place, and recorded the moment afterwards.
//
//   - a failure between the remove and the new key left the gateway with
//     no host key at all: the next "gateway run" cannot speak SSH with the
//     identity every client pins;
//   - a failure to write the record left the new key installed and the
//     journal saying something else — the state and the audit disagreed,
//     silently, and the file is the one thing an operator hands out
//     connection strings for;
//   - nothing serialized two rotations, so the local verb and a live
//     gateway's remote command could both read one old key and both write
//     it, leaving one record describing a key that is not on disk.
//
// The test drives the two halves that can be arranged for real: a rotation
// whose record cannot be written (a closed journal), and a rotation asked
// for while another one holds the lock.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func r1cxHostKeyBytes(t *testing.T, dir string) []byte {
	t.Helper()
	data, err := state.ReadDataFile(hostKeyPath(dir))
	if err != nil {
		t.Fatalf("read the host key: %v", err)
	}
	return data
}

func TestR1CXF06_ARotationTheJournalRefusesPutsTheKeyBack(t *testing.T) {
	dir := t.TempDir()
	// A gateway with a key of its own, minted by the product itself.
	firstFP, _, err := RotateHostKey(dir, r1cxChainedLog(t, dir), time.Now())
	if err != nil {
		t.Fatalf("the first rotation: %v", err)
	}
	before := r1cxHostKeyBytes(t, dir)

	// The journal cannot take the record: a closed log is what any broken
	// journal looks like from here.
	closed := r1cxChainedLog(t, dir)
	if err := closed.Close(); err != nil {
		t.Fatalf("close the journal: %v", err)
	}
	oldFP, newFP, err := RotateHostKey(dir, closed, time.Now())
	if err == nil {
		t.Fatalf("the rotation reported success although the record could not be written (old=%s new=%s)", oldFP, newFP)
	}
	after := r1cxHostKeyBytes(t, dir)
	if string(after) != string(before) {
		t.Errorf("a rotation whose record was refused left a different host key on disk (was %s, now %s): the key every client pins changed while nothing recorded that it did — the file and the journal disagree (F-06)", firstFP, newFP)
	}
	if oldFP != "" || newFP != "" {
		t.Errorf("the failed rotation returned fingerprints (%q -> %q) for a rotation that did not happen", oldFP, newFP)
	}
}

func TestR1CXF06_ARotationRefusesToRunBesideAnotherOne(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := RotateHostKey(dir, r1cxChainedLog(t, dir), time.Now()); err != nil {
		t.Fatalf("the first rotation: %v", err)
	}
	before := r1cxHostKeyBytes(t, dir)

	// Another rotation is already running — the local verb beside a live
	// gateway's remote command is exactly this shape. The lock is the same
	// OS-level one the product takes; holding it here is what that other
	// rotation does.
	lock, lerr := state.AcquireFileLock(filepath.Join(dir, HostKeyRotateLockFile))
	if lerr != nil {
		t.Fatalf("take the rotation lock: %v", lerr)
	}
	defer func() { _ = lock.Unlock() }()

	if _, _, err := RotateHostKey(dir, r1cxChainedLog(t, dir), time.Now()); err == nil {
		t.Errorf("a second rotation ran while another one held the lock: two rotations read one old key, write hostkey.old and the active file under each other, and the journal ends up naming a key that is not on disk (F-06)")
	}
	if string(r1cxHostKeyBytes(t, dir)) != string(before) {
		t.Errorf("the refused second rotation changed the key anyway")
	}
}

// r1cxChainedLog opens the gateway's journal the way the gateway opens it.
func r1cxChainedLog(t *testing.T, dir string) *events.Log {
	t.Helper()
	log, err := events.OpenChainedLog(filepath.Join(dir, events.DefaultLogFileName))
	if err != nil {
		t.Fatalf("open the chained journal: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}
