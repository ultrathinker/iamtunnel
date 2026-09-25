package gateway

// lifecycle_restore_test.go — M-8 (code review 23.09.2026, round-4 F-11):
// "gateway restore" rolled an append-only journal back to the backup,
// ran under a live gateway, and installed whatever the archive held
// without validating it or keeping what it replaced.
//
// The three rows below are the three halves of the finding, and each one
// reddens on its own assertions against the old code: the journal is
// replaced by the archive's older copy (the events written after the
// backup are gone from the history), the state lock is not taken (a
// running gateway's next save silently undoes the restore), and an
// archive whose state.json does not validate — or whose member is not a
// regular file at all — is installed over the gateway's state with no
// copy taken.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// m8SeedState writes a valid state.json holding one admin, through the
// store itself, so the file is exactly what the product writes.
func m8SeedState(t *testing.T, dir string) {
	t.Helper()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	err = store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "alice", Role: "admin"})
		return nil
	})
	if err != nil {
		t.Fatalf("seed state: %v", err)
	}
	if cerr := store.Close(); cerr != nil {
		t.Fatalf("close store: %v", cerr)
	}
}

// m8AddPerson commits one more person, so a state differs from the
// backup's copy of it.
func m8AddPerson(t *testing.T, dir, name string) {
	t.Helper()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: name, Role: "admin"})
		return nil
	}); err != nil {
		t.Fatalf("add person %s: %v", name, err)
	}
}

// m8AppendEvent writes one event carrying a marker, the way any role
// writes to the journal.
func m8AppendEvent(t *testing.T, dir, marker string) {
	t.Helper()
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("open event log: %v", err)
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
		t.Fatalf("append %s event: %v", marker, err)
	}
}

// m8History reads the whole history the way the History tab does: the
// current journal AND its archives.
func m8History(t *testing.T, dir string) []events.Event {
	t.Helper()
	evs, _, err := events.ReadHistory(dir, events.Filter{})
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	return evs
}

// m8HasMarker reports whether an event carrying this marker is in the
// history.
func m8HasMarker(evs []events.Event, marker string) bool {
	for _, e := range evs {
		if got, _ := e.Details["marker"].(string); got == marker {
			return true
		}
	}
	return false
}

// m8HasAdminOp reports whether the history records an admin.op whose
// object or result names what happened.
func m8HasAdminOp(evs []events.Event, word string) bool {
	for _, e := range evs {
		if e.Type != events.EventAdminOp {
			continue
		}
		if e.Object == word || e.Result == word {
			return true
		}
	}
	return false
}

// m8Read reads a file that must exist.
func m8Read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// m8JournalArchives returns the journal archives (events-<label>.jsonl)
// in dir, name and bytes.
func m8JournalArchives(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	out := map[string][]byte{}
	for _, e := range entries {
		name := e.Name()
		if !events.IsLogFileName(name) || name == "events.jsonl" {
			continue
		}
		out[name] = m8Read(t, filepath.Join(dir, name))
	}
	return out
}

// m8PreRestoreCopies returns the names of the state.json copies a
// restore keeps beside the original.
func m8PreRestoreCopies(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), state.StateFileName+".pre-restore-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// m8WriteArchive builds a tar.gz at path from name -> content, every
// member a regular file.
func m8WriteArchive(t *testing.T, path string, members map[string][]byte) {
	t.Helper()
	m8WriteArchiveTyped(t, path, members, tar.TypeReg)
}

// m8WriteArchiveTyped is m8WriteArchive with the member type chosen by
// the caller: a foreign or hostile archive is input, not something this
// program writes.
func m8WriteArchiveTyped(t *testing.T, path string, members map[string][]byte, typeflag byte) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range members {
		hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: typeflag}
		if typeflag == tar.TypeSymlink {
			hdr.Linkname = "elsewhere"
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write(data); err != nil {
				t.Fatalf("write member %s: %v", name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if err := datafile.WriteFileAtomic(path, buf.Bytes(), datafile.WithMode(0o600)); err != nil {
		t.Fatalf("write archive %s: %v", path, err)
	}
}

// TestM8RestoreDoesNotRollBackTheJournal is (a): the journal is
// append-only, and "restore" was a supported command that rewound it —
// every auth.*, session.* and admin.op written after the backup vanished
// from the history, with the directory holding no copy of them at all.
func TestM8RestoreDoesNotRollBackTheJournal(t *testing.T) {
	dir := t.TempDir()
	m8SeedState(t, dir)
	m8AppendEvent(t, dir, "beforeBackup")
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := WriteBackupTarGz(archive, dir); err != nil {
		t.Fatalf("WriteBackupTarGz: %v", err)
	}
	m8AppendEvent(t, dir, "afterBackup")
	journalBefore := m8Read(t, filepath.Join(dir, "events.jsonl"))

	if _, err := RestoreBackupTarGz(archive, dir); err != nil {
		t.Fatalf("RestoreBackupTarGz: %v", err)
	}

	history := m8History(t, dir)
	if !m8HasMarker(history, "afterBackup") {
		t.Errorf("the event written AFTER the backup is not in the history any more — restore rolled an append-only journal back to the backup and the audit trail lost everything since (M-8a, round-4 F-11)")
	}
	if !m8HasMarker(history, "beforeBackup") {
		t.Errorf("the event written before the backup is gone from the history — a restore must not cost the journal anything at all")
	}

	// The journal as it was must still exist, under a name the history
	// reader finds (events-<label>.jsonl), byte for byte.
	archives := m8JournalArchives(t, dir)
	if len(archives) != 1 {
		t.Errorf("the directory holds %d journal archive(s) (%v), want exactly the one the restore kept — the journal the restore replaced must be preserved where the history can still read it (M-8a, round-4 F-11)", len(archives), archiveNames(archives))
	}
	for name, data := range archives {
		if !bytes.Equal(data, journalBefore) {
			t.Errorf("the journal archive %s does not hold the journal as it was before the restore (%d bytes, want %d) — a partial copy is not a kept journal", name, len(data), len(journalBefore))
		}
	}

	// And the restore itself is a journal fact.
	if !m8HasAdminOp(history, "restore") {
		t.Errorf("no admin.op event records the restore — an operator reading the journal later cannot tell that the state was rolled back to a backup (M-8a, round-4 F-11)")
	}
}

// TestM8RestoreRefusesWhileTheStateLockIsHeld is (b): restore took no
// lock, so it could run under a live gateway — which keeps its handle to
// the journal it just replaced and whose next save rewrites state.json
// from memory. The restore would be undone without a word.
func TestM8RestoreRefusesWhileTheStateLockIsHeld(t *testing.T) {
	dir := t.TempDir()
	m8SeedState(t, dir)
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := WriteBackupTarGz(archive, dir); err != nil {
		t.Fatalf("WriteBackupTarGz: %v", err)
	}
	before := m8Read(t, filepath.Join(dir, state.StateFileName))

	// A gateway that is running holds exactly this lock.
	running, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open (the running gateway): %v", err)
	}
	defer func() { _ = running.Close() }()

	_, rerr := RestoreBackupTarGz(archive, dir)
	if !errors.Is(rerr, state.ErrLockHeld) {
		t.Errorf("restore returned %v while another process held the state lock — it must refuse like \"gateway pair\" and \"install --rebootstrap\" do, because a live gateway keeps writing and its next save silently undoes the restore (M-8b, round-4 F-11)", rerr)
	}
	if after := m8Read(t, filepath.Join(dir, state.StateFileName)); !bytes.Equal(before, after) {
		t.Errorf("restore replaced state.json while a gateway held the state lock — the file it wrote belongs to a gateway that is still running (M-8b, round-4 F-11)")
	}
}

// TestM8RestoreValidatesBeforeItReplaces is (c): the archive is input —
// it arrives from a backup directory, a USB stick, another machine — and
// it was installed over the gateway's state with no validation and no
// copy of what it replaced.
func TestM8RestoreValidatesBeforeItReplaces(t *testing.T) {
	t.Run("a state.json that does not validate is refused, and the current one survives", func(t *testing.T) {
		dir := t.TempDir()
		m8SeedState(t, dir)
		before := m8Read(t, filepath.Join(dir, state.StateFileName))

		// Parses as JSON, fails state.Validate (an uppercase person name),
		// so the check under test is the state package's own rule.
		bad := []byte(`{"schema":1,"people":[{"name":"ALICE","role":"admin"}],"machines":[],"grants":[]}`)
		archive := filepath.Join(t.TempDir(), "foreign.tar.gz")
		m8WriteArchive(t, archive, map[string][]byte{state.StateFileName: bad, "events.jsonl": []byte("{}\n")})

		_, err := RestoreBackupTarGz(archive, dir)
		if err == nil {
			t.Errorf("restore installed a state.json that state.Validate refuses — a broken or foreign archive must be validated BEFORE it replaces the gateway's state (M-8c, round-4 F-11)")
		}
		if after := m8Read(t, filepath.Join(dir, state.StateFileName)); !bytes.Equal(before, after) {
			t.Errorf("the current state.json was replaced by an archive whose state.json does not validate — the gateway's state is now a file its own store refuses to open (M-8c, round-4 F-11)")
		}
	})

	t.Run("the state it replaces is kept as state.json.pre-restore-<label>", func(t *testing.T) {
		dir := t.TempDir()
		m8SeedState(t, dir)
		archive := filepath.Join(t.TempDir(), "backup.tar.gz")
		if err := WriteBackupTarGz(archive, dir); err != nil {
			t.Fatalf("WriteBackupTarGz: %v", err)
		}
		// The live state moves on after the backup was taken.
		m8AddPerson(t, dir, "bob")
		before := m8Read(t, filepath.Join(dir, state.StateFileName))

		if _, err := RestoreBackupTarGz(archive, dir); err != nil {
			t.Fatalf("RestoreBackupTarGz: %v", err)
		}

		copies := m8PreRestoreCopies(t, dir)
		if len(copies) != 1 {
			t.Fatalf("state.json copies kept before the restore = %v, want exactly one state.json.pre-restore-<label> (M-8c, round-4 F-11)", copies)
		}
		kept := m8Read(t, filepath.Join(dir, copies[0]))
		if !bytes.Equal(kept, before) {
			t.Errorf("the copy %s does not hold the state.json that was replaced (%d bytes, want %d) — the operator restoring the wrong backup has no way back", copies[0], len(kept), len(before))
		}
	})

	t.Run("an archive member that is not a regular file is refused", func(t *testing.T) {
		dir := t.TempDir()
		m8SeedState(t, dir)
		before := m8Read(t, filepath.Join(dir, state.StateFileName))

		archive := filepath.Join(t.TempDir(), "symlinked.tar.gz")
		m8WriteArchiveTyped(t, archive, map[string][]byte{state.StateFileName: nil}, tar.TypeSymlink)

		_, err := RestoreBackupTarGz(archive, dir)
		if err == nil {
			t.Errorf("restore accepted an archive whose state.json member is a symbolic link — only a regular file may be installed, and a link entry carries no bytes at all (M-8c, round-4 F-11)")
		}
		if after := m8Read(t, filepath.Join(dir, state.StateFileName)); !bytes.Equal(before, after) {
			t.Errorf("the current state.json was replaced by a link-shaped archive member — the gateway's state is now whatever that entry stood for (M-8c, round-4 F-11)")
		}
	})
}

// archiveNames lists a name -> bytes map's keys, for failure messages.
func archiveNames(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	return out
}
