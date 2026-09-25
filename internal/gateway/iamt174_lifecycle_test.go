package gateway

// iamt174_lifecycle_test.go — behavioral tests of the remote admin
// lifecycle commands (PROTOCOL §6 gateway.backup / gateway.rotate-hostkey,
// task IAMT-174, finding G3 from IAMT-162). Everything goes through the
// real harness_test.go fixture: a live gateway, a real admin.Conn over
// TCP+SSH, files only in t.TempDir().

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// openBackupArchive reads the tar.gz at path and returns its members as
// name -> contents, so a test can assert what a remote backup actually
// packed instead of trusting the response's metadata.
func openBackupArchive(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open backup archive %s: %v", path, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("%s is not a gzip file: %v", path, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	members := map[string][]byte{}
	for {
		hdr, terr := tr.Next()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			t.Fatalf("reading %s: %v", path, terr)
		}
		data, rerr := io.ReadAll(tr)
		if rerr != nil {
			t.Fatalf("reading member %s: %v", hdr.Name, rerr)
		}
		members[hdr.Name] = data
	}
	return members
}

// adminEvents reads one event type out of the fixture's journal.
func adminEvents(t *testing.T, f *fixture, typ events.EventType) []events.Event {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{typ}})
	if err != nil {
		t.Fatalf("read %s events: %v", typ, err)
	}
	return evs
}

func TestIAMT174_AdminBackupCreatesArchiveWithState(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	c := dialAdmin(t, f, "root", rootKey)

	id, created, size, sum, err := c.GatewayBackup()
	if err != nil {
		t.Fatalf("gateway.backup as admin: %v", err)
	}
	if id == "" {
		t.Fatal("gateway.backup returned an empty backup id")
	}
	if _, perr := time.Parse(time.RFC3339, created); perr != nil {
		t.Fatalf("gateway.backup created = %q is not an RFC 3339 time: %v", created, perr)
	}

	// The archive lives in the gateway's own local storage (PROTOCOL §6)
	// under the returned id as its file name, so an operator can feed
	// <data-dir>/backups/<id> straight to "iamtunnel gateway restore".
	path := filepath.Join(f.gw.cfg.DataDir, BackupArchiveDir, id)
	info, serr := os.Stat(path)
	if serr != nil {
		t.Fatalf("backup archive %s was not created in the gateway's local storage: %v", path, serr)
	}
	if info.Size() != size {
		t.Fatalf("gateway.backup size = %d, but the file on disk is %d bytes", size, info.Size())
	}
	if want, herr := fileSHA256Hex(path); herr != nil || want != sum {
		t.Fatalf("gateway.backup sha256 = %q, want the file's own %q (err %v)", sum, want, herr)
	}

	// The archive holds exactly the backup members, and state.json is the
	// real one — the person the fixture seeded is in it.
	members := openBackupArchive(t, path)
	if len(members) != 2 {
		t.Fatalf("backup archive members = %v, want exactly state.json and events.jsonl", memberNames(members))
	}
	if got, ok := members["state.json"]; !ok || !strings.Contains(string(got), f.person) {
		t.Fatalf("backup archive state.json missing or does not contain the seeded person %q: %v", f.person, memberNames(members))
	}
	if _, ok := members["events.jsonl"]; !ok {
		t.Fatalf("backup archive has no events.jsonl member: %v", memberNames(members))
	}

	// The operation is in the journal as an admin.op naming the id, like
	// every other admin operation (RUNBOOK event dictionary: admin.op).
	waitUntil(t, "gateway.backup never landed in the journal as admin.op", func() bool {
		for _, e := range adminEvents(t, f, events.EventAdminOp) {
			if e.Actor == "root" && e.Object == id && strings.HasPrefix(e.Result, "gateway.backup:") {
				return true
			}
		}
		return false
	})
}

func TestIAMT174_AdminRotateHostkeySwapsKeyAndKeepsOld(t *testing.T) {
	f := newFixture(t, nil)
	dir := f.gw.cfg.DataDir
	seedSigner, serr := loadOrGenerateHostKey(hostKeyPath(dir))
	if serr != nil {
		t.Fatalf("seed the on-disk host key: %v", serr)
	}
	fp0 := auth.Fingerprint(seedSigner.PublicKey())

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	c := dialAdmin(t, f, "root", rootKey)
	beforeFPs, ferr := c.GatewayFingerprint()
	if ferr != nil {
		t.Fatalf("gateway.fingerprint before rotation: %v", ferr)
	}

	oldFP, newFP, err := c.GatewayRotateHostkey()
	if err != nil {
		t.Fatalf("gateway.rotate-hostkey as admin: %v", err)
	}
	if oldFP != fp0 {
		t.Fatalf("gateway.rotate-hostkey oldFingerprint = %q, want the on-disk key's %q", oldFP, fp0)
	}
	if newFP == "" || newFP == oldFP {
		t.Fatalf("gateway.rotate-hostkey newFingerprint = %q, want a fresh key distinct from %q", newFP, oldFP)
	}

	// The new key is the one now on disk; the old one survived at
	// hostkey.old (RUNBOOK §4.3: the old key remains as
	// hostkey.old).
	newSigner, gerr := loadOrGenerateHostKey(hostKeyPath(dir))
	if gerr != nil {
		t.Fatalf("load rotated host key: %v", gerr)
	}
	if got := auth.Fingerprint(newSigner.PublicKey()); got != newFP {
		t.Fatalf("on-disk host key fingerprint after rotation = %q, want the reported new %q", got, newFP)
	}
	oldSigner, oerr := loadOrGenerateHostKey(hostKeyPath(dir) + ".old")
	if oerr != nil {
		t.Fatalf("hostkey.old was not kept: %v", oerr)
	}
	if got := auth.Fingerprint(oldSigner.PublicKey()); got != fp0 {
		t.Fatalf("hostkey.old fingerprint = %q, want the pre-rotation %q", got, fp0)
	}

	// The moment is in the journal as hostkey.rotate with both
	// fingerprints — the record RUNBOOK §4.3 greps for — and as admin.op.
	waitUntil(t, "hostkey.rotate never landed in the journal", func() bool {
		for _, e := range adminEvents(t, f, events.EventHostKeyRotate) {
			old, _ := e.Details["oldFingerprint"].(string)
			new, _ := e.Details["newFingerprint"].(string)
			if old == fp0 && new == newFP && e.Fingerprint == newFP {
				return true
			}
		}
		return false
	})
	foundAdminOp := false
	for _, e := range adminEvents(t, f, events.EventAdminOp) {
		if e.Actor == "root" && strings.HasPrefix(e.Result, "gateway.rotate-hostkey:") {
			foundAdminOp = true
		}
	}
	if !foundAdminOp {
		t.Fatal("gateway.rotate-hostkey never landed in the journal as admin.op")
	}

	// A rotation is not applied by the live process: the gateway keeps
	// presenting the OLD key until it is restarted (RUNBOOK §4.3 step 2),
	// so the fingerprint an admin is shown must be unchanged across the
	// rotation.
	afterFPs, aerr := c.GatewayFingerprint()
	if aerr != nil {
		t.Fatalf("gateway.fingerprint after rotation: %v", aerr)
	}
	if len(afterFPs) != len(beforeFPs) {
		t.Fatalf("gateway.fingerprint changed length across a disk-only rotation: %v -> %v", beforeFPs, afterFPs)
	}
	for i := range afterFPs {
		if afterFPs[i] != beforeFPs[i] {
			t.Fatalf("the live gateway swapped its presented key across a disk-only rotation: %v -> %v (RUNBOOK §4.3 step 2: rotation applies on restart)", beforeFPs, afterFPs)
		}
	}
}

func TestIAMT174_NonAdminRefusedLifecycleCommands(t *testing.T) {
	f := newFixture(t, nil)
	malloryKey := genSigner(t)
	addPerson(t, f, "mallory", "user", malloryKey)
	c := dialAdmin(t, f, "mallory", malloryKey)

	var cmdErr *admin.CommandError
	if _, _, _, _, err := c.GatewayBackup(); err == nil {
		t.Fatal("a non-admin person ran gateway.backup; want a refusal")
	} else if !errors.As(err, &cmdErr) || cmdErr.Code != "E_EXEC_UNKNOWN" {
		t.Fatalf("gateway.backup refusal for a non-admin = %v, want the E_EXEC_UNKNOWN refusal", err)
	}
	if _, _, err := c.GatewayRotateHostkey(); err == nil {
		t.Fatal("a non-admin person ran gateway.rotate-hostkey; want a refusal")
	} else if !errors.As(err, &cmdErr) || cmdErr.Code != "E_EXEC_UNKNOWN" {
		t.Fatalf("gateway.rotate-hostkey refusal for a non-admin = %v, want the E_EXEC_UNKNOWN refusal", err)
	}

	// A refusal must also refuse the side effects: no archive directory,
	// no rotated key, nothing on disk.
	if _, serr := os.Stat(filepath.Join(f.gw.cfg.DataDir, BackupArchiveDir)); !os.IsNotExist(serr) {
		t.Fatalf("a refused gateway.backup left %s behind: %v", BackupArchiveDir, serr)
	}
	if _, serr := os.Stat(filepath.Join(f.gw.cfg.DataDir, HostKeyFileName) + ".old"); !os.IsNotExist(serr) {
		t.Fatalf("a refused gateway.rotate-hostkey left hostkey.old behind: %v", serr)
	}

	// The wire itself is alive — a refusal is an answer, not a hang.
	if _, err := c.Whoami(); err != nil {
		t.Fatalf("whoami after the refusals: %v", err)
	}
}

func memberNames(m map[string][]byte) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	return names
}
