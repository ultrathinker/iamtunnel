package gateway

// R2-CX F-09 of the round-2 review (24.09.2026), medium: restore
// opened the state store before it had read or validated anything. A
// backup file is input - it comes from a share, a USB stick, another
// machine - and the store is not a read: state.Open creates the data
// directory, takes state.lock, creates enrol-hmac.key and, with no
// state.json there, writes a fresh one. So a restore that refused a
// malformed archive still left a directory that looks like an initialized
// gateway, while the refusals it printed promise "nothing here has been
// changed": the next run, the window and the operator all read an
// installed gateway that this command never installed.
//
// Everything an archive can be refused for is answerable from its bytes
// alone, so the answer now comes before the store is opened.

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// r2cxWriteArchive writes a gzip+tar with the given members, in order.
func r2cxWriteArchive(t *testing.T, path string, names []string, bodies [][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating %s: %v", path, err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for i, name := range names {
		hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(bodies[i])), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("writing the header of %s: %v", name, err)
		}
		if _, err := tw.Write(bodies[i]); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing the tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing the gzip: %v", err)
	}
}

func TestR2CXF09_ARefusedArchiveLeavesAnEmptyDirectoryEmpty(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(t.TempDir(), "not-a-backup.tar.gz")
	// A real gzip and a real tar member named state.json, whose content is
	// not a state - the archive is refused by the state package's own
	// validation, the last of the checks that need nothing but the bytes.
	r2cxWriteArchive(t, archive,
		[]string{state.StateFileName},
		[][]byte{[]byte("{ this is not the state of a gateway")})

	out, err := RestoreBackupTarGz(archive, dir)
	if err == nil {
		t.Fatalf("the restore accepted an archive whose state.json is not JSON: %+v", out)
	}

	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatalf("reading %s: %v", dir, rerr)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the restore refused %s and left %v in the data directory: state.Open creates the directory, %s, %s and a fresh %s before anything is validated (F-09) - so a failed restore from a bad backup file leaves what looks like an installed gateway, and the refusal it printed says nothing here has been changed",
			filepath.Base(archive), names, state.LockFileName, state.EnrolHMACKeyFileName, state.StateFileName)
	}
	if fileExists(filepath.Join(dir, state.StateFileName)) {
		t.Errorf("the refused restore wrote a %s: the directory now reads as an initialized gateway (F-09)", state.StateFileName)
	}
}
