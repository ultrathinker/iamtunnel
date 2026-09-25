package gateway

// F-22 of the round-1 review (24.09.2026): a backup read state.json
// and events.jsonl one after the other with no lock and no check, so an
// admin command that commits its state write now and its journal line a
// moment later could be caught in between: the archive then held a state
// from one version and an audit trail from another, and a restore of it
// put a gateway on disk whose grants and whose history disagree — both
// files valid, the archive accepted, the operator none the wiser.
//
// RUNBOOK §3 promises the opposite in as many words: the archive is packed
// under lock, and copying the directory of a running gateway by
// hand is forbidden for exactly this reason.
//
// The test parks an access command between its two writes — the
// accessPublishPause seam is that instant — and takes a backup while it is
// parked. The archive is allowed to contain the grant or not, but not to
// contain the state's half of it without the journal's.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func r1cxReadArchive(t *testing.T, path string) map[string][]byte {
	t.Helper()
	data := m8Read(t, path)
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s is not gzip: %v", path, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, terr := tr.Next()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			t.Fatalf("read the archive %s: %v", path, terr)
		}
		body, rerr := io.ReadAll(tr)
		if rerr != nil {
			t.Fatalf("read %s from %s: %v", hdr.Name, path, rerr)
		}
		out[hdr.Name] = body
	}
	return out
}

func TestR1CXF22_ABackupDoesNotPairAStateWithAJournalFromBeforeIt(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	addPerson(t, f, "bob", "user", genSigner(t))
	root := dialAdmin(t, f, "root", rootKey)

	// Park an access command between its state write and its journal line:
	// the state already carries the grant, the journal does not yet.
	parked, release := make(chan struct{}), make(chan struct{})
	accessPublishPause = func() {
		close(parked)
		<-release
	}
	defer func() { accessPublishPause = nil }()

	// The command's verdict comes back on a channel, not through a shared
	// variable: the backup finishing only means the command let the lock
	// go, and an unsynchronised read of the result here is a data race the
	// -race gate catches (it did).
	grantDone := make(chan error, 1)
	go func() {
		_, err := root.GrantsGrant("bob", f.machineID, futureRFC3339(f))
		grantDone <- err
	}()
	<-parked
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	done := make(chan error, 1)
	go func() { done <- WriteBackupTarGz(archive, f.gw.cfg.DataDir) }()

	// While the command is parked, the backup either waits for it (the
	// fix: the lock the command holds is the lock the backup takes) or
	// finishes without it (the defect).
	var backupErr error
	finished := false
	select {
	case backupErr = <-done:
		finished = true
	case <-time.After(250 * time.Millisecond):
	}
	close(release)
	if !finished {
		backupErr = <-done
	}
	if backupErr != nil {
		t.Fatalf("backup: %v", backupErr)
	}
	if cmdErr := <-grantDone; cmdErr != nil {
		t.Fatalf("the parked grant command: %v", cmdErr)
	}

	members := r1cxReadArchive(t, archive)
	stateBytes, ok := members[state.StateFileName]
	if !ok {
		t.Fatalf("the archive has no state.json: %v", keysOf(members))
	}
	journal := string(members["events.jsonl"])
	var st state.State
	if err := json.Unmarshal(stateBytes, &st); err != nil {
		t.Fatalf("the archive's state.json: %v", err)
	}
	inState := false
	for _, g := range st.Grants {
		if g.Person == "bob" && g.Machine == f.machineID {
			inState = true
		}
	}
	// The object is JSON-escaped ("bob -> vm1"), so the check is on
	// the result word and the person, not on the arrow.
	inJournal := strings.Contains(journal, `"grants.grant:ok"`) && strings.Contains(journal, `"bob -`)

	if inState != inJournal {
		t.Errorf("the archive pairs a state with a journal from another moment (grant in state=%v, grant in journal=%v): an operator restoring this gets a gateway whose grants and whose history disagree, and both files of the archive are valid (F-22)", inState, inJournal)
	} else if !inState {
		t.Errorf("the backup was taken before the parked command finished at all (state=%v journal=%v), so this test proves nothing about the pair", inState, inJournal)
	}
}
