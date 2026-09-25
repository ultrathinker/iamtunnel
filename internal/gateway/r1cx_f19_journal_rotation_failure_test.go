package gateway

// F-19 of the round-1 review (24.09.2026), high: a rotation that
// cannot finish leaves the journal without a file, and nothing opens one
// again - every later write fails until the process is restarted, so a
// disk that refuses one rotation costs the audit trail until somebody
// notices.
//
// The half of it that the review is built around - the rename succeeds,
// opening the fresh file fails - is fixed in main already, by R1-MX F-08
// (commit 1d5f677): the log remembers the rotation, every later write
// names it instead of "log is closed", and the file is opened again on the
// next write (internal/gateway/events/r1mx_f08_rotation_open_failure_test.go
// holds that half).
//
// What F-19's own "Where" field points at is the other half, in Rotate itself
// (log.go:279-327): the branch that recovers a failed RENAME. It recovers
// only if reopening the file it left behind succeeds. When that fails too -
// and the review's own words are that "the recovery branch exists only for
// the failed Rename" - the log is left with file == nil and nothing
// recorded about why: every later write says "log is closed", which blames
// the gateway's own stop for a rotation the disk refused, and no write ever
// opens a file again. A gateway in that state keeps answering until the
// first write it has to journal, and then refuses everything, for good.
//
// This is that state, made through real code: a directory occupies the name
// the archive would take, so the rename fails, and the journal is
// read-only, so reopening it fails too. Nothing here is a seam.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestR1CXF19_ARotationThatCannotFinishDoesNotCloseTheJournalForGood(t *testing.T) {
	diag := &iamt451Lines{}
	f := newFixture(t, func(c *Config) { c.Diagnostics = diag })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	dir := filepath.Dir(f.logPath)
	archive := filepath.Join(dir, events.ArchiveName(time.Now()))
	if err := os.Mkdir(archive, 0o700); err != nil {
		t.Fatalf("could not put a directory where the archive would go: %v", err)
	}
	if err := os.Chmod(f.logPath, 0o400); err != nil {
		t.Fatalf("could not make the journal read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.logPath, 0o600) })
	if fh, err := os.OpenFile(f.logPath, os.O_RDWR|os.O_APPEND, 0); err == nil {
		_ = fh.Close()
		t.Skip("this platform opens a read-only file for writing anyway, so the reopen after the failed rename cannot be made to fail here")
	}

	// What the sweep does once a second while the journal is over its
	// limit (rotateJournalIfLarge calls exactly this). The rename cannot
	// happen, and the file the rename leaves behind cannot be reopened:
	// the journal is now without a file, and the log has to know it.
	if err := f.log.Rotate(archive); err == nil {
		t.Fatalf("Rotate reported success although its archive name was taken and its journal could not be reopened")
	}

	// The first write that has to be journaled is where the operator hears
	// about it - the audit state is what gateway status, the audit-health
	// file and the service log carry (IAMT-451).
	f.gw.appendEvent(events.Event{Type: events.EventDoorOpen, Actor: "gateway", Object: f.machineID, Result: "ok"})
	refusal := f.gw.auditRefusal()
	if refusal == nil {
		t.Fatalf("the gateway went on taking work after its journal lost its file: the write that failed was reported as fine")
	}
	if strings.Contains(refusal.message, "log is closed") {
		t.Errorf("the gateway's reason for refusing work is %q: the journal was never closed, its rotation could not finish, and this says the gateway stopped itself (F-19)", refusal.message)
	}
	if !strings.Contains(refusal.message, "could not be rotated into "+filepath.Base(archive)) {
		t.Errorf("the gateway's reason for refusing work is %q, want it to name the rotation that could not finish and the archive it could not become (%s)", refusal.message, filepath.Base(archive))
	}
	if !strings.Contains(diag.String(), "could not be rotated into "+filepath.Base(archive)) {
		t.Errorf("the service log does not carry the reason the journal stopped:\n%s", diag.String())
	}

	// And the journal comes back by itself: whatever refused the reopen may
	// let go, and IAMT-451's contract is that the gateway fails until a
	// write succeeds - not until somebody restarts it. No restart here, and
	// no new gateway: the same log, the same process.
	if err := os.Chmod(f.logPath, 0o600); err != nil {
		t.Fatalf("could not make the journal writable again: %v", err)
	}
	f.gw.appendEvent(events.Event{Type: events.EventDoorOpen, Actor: "gateway", Object: f.machineID, Result: "healed"})
	if r := f.gw.auditRefusal(); r != nil {
		t.Errorf("the journal did not write again once its file could be opened: the gateway still refuses work (%s) although the disk let go, and only a restart would have brought it back (F-19)", r.message)
	}
	raw, err := os.ReadFile(f.logPath)
	if err != nil {
		t.Fatalf("the journal is not there after the recovery: %v", err)
	}
	if !strings.Contains(string(raw), `"result":"healed"`) {
		t.Errorf("the journal came back but does not hold the write that came after the recovery:\n%s", raw)
	}
}
