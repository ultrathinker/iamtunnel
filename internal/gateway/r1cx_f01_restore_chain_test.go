package gateway

// F-01 of the round-1 review (24.09.2026): the restore opened the
// journal with events.OpenLog while the gateway's own journal is chained
// (events.OpenChainedLog, the IAMT-467 chain) — so the two lines the
// restore writes, log.rotate and the admin.op that records the restore
// itself, went in without prev_hash. From then on the chain, read across
// the archive and the fresh file as one history, meets lines it does not
// vouch for, and `gateway verify-journal` — the command whose whole job is
// to prove the journal was not rewritten — reports the gateway's own
// journal as tampered with.
//
// The gateway opens its journal chained everywhere else (cmd/iamtunnel's
// gateway run, rotate-hostkey, the GUI), so the restore has to as well.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// r1cxAppendChained writes one event the way the gateway itself writes
// them: through the chained journal, with prev_hash.
func r1cxAppendChained(t *testing.T, dir, marker string) {
	t.Helper()
	log, err := events.OpenChainedLog(filepath.Join(dir, events.DefaultLogFileName))
	if err != nil {
		t.Fatalf("open the chained journal: %v", err)
	}
	defer func() { _ = log.Close() }()
	if err := log.Append(events.Event{
		Time:   state.NewZonedTime(time.Now().UTC()),
		Type:   events.EventSessionStart,
		Actor:  "alice",
		Object: "win-vm",
		Result: "ok",
		Details: map[string]interface{}{
			"marker": marker,
		},
	}); err != nil {
		t.Fatalf("append the %s event: %v", marker, err)
	}
}

func TestR1CXF01_ARestoreKeepsTheJournalChainWhole(t *testing.T) {
	dir := t.TempDir()
	m8SeedState(t, dir)
	r1cxAppendChained(t, dir, "beforeBackup")
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := WriteBackupTarGz(archive, dir); err != nil {
		t.Fatalf("WriteBackupTarGz: %v", err)
	}
	r1cxAppendChained(t, dir, "afterBackup")

	before, err := events.VerifyChain(dir)
	if err != nil {
		t.Fatalf("VerifyChain before the restore: %v", err)
	}
	if !before.Intact() {
		t.Fatalf("precondition: the journal is not intact before the restore: %s", before.Summary())
	}

	if _, err := RestoreBackupTarGz(archive, dir); err != nil {
		t.Fatalf("RestoreBackupTarGz: %v", err)
	}

	rep, verr := events.VerifyChain(dir)
	if verr != nil {
		t.Fatalf("VerifyChain after the restore: %v", verr)
	}
	if !rep.Intact() {
		t.Errorf("after a restore the journal verifies as %q (unvouched=%d, chained=%d, legacy=%d): the restore wrote its own lines without the chain, so verify-journal — the command that exists to prove the journal was not rewritten — reports the gateway's own journal as tampered with (F-01)", rep.Summary(), rep.Unvouched, rep.Chained, rep.Legacy)
	}
	if rep.Unvouched != 0 {
		t.Errorf("the restore left %d line(s) without prev_hash, first at %s line %d: log.rotate and the admin.op recording the restore have to join the chain they land in", rep.Unvouched, rep.FirstUnvouchedFile, rep.FirstUnvouchedLine)
	}
	// The restore's own record has to be one of the chained lines: a
	// reader of the history must be able to see the rollback AND trust it.
	evs := m8History(t, dir)
	if !m8HasAdminOp(evs, "restore") {
		t.Errorf("the history does not hold the admin.op recording the restore: %+v", evs)
	}
	if rep.Chained <= before.Chained {
		t.Errorf("chained lines went from %d to %d across the restore, want the restore's own lines to be chained too", before.Chained, rep.Chained)
	}
}
