package gateway

// R2-CX F-11 of the round-2 review (24.09.2026), low: the restore
// read every regular member of the archive with io.ReadAll and no limit
// of its own. The archive is input - a USB stick, a share, another
// machine - and its header decides how many bytes the command buffers: a
// member that says it carries gigabytes was unpacked into memory first
// and judged afterwards, so a bad backup file (or a hostile one) was a
// way to make the gateway's own administrator run the machine out of
// memory. A fixed set of member names is not a bound either: the same
// name twice decided the total by repetition.
//
// The fix refuses a member by what its header CLAIMS, before reading it,
// and refuses a name that appears twice.

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// r2cxTarHeader is the 512-byte POSIX header of one regular member with a
// declared size - which is the point: the header can claim any size, and
// the restore has to answer before it reads (archive/tar's own writer
// refuses to write a member it is not given, so the header is built here).
func r2cxTarHeader(name string, declared int64) []byte {
	b := make([]byte, 512)
	copy(b[0:100], name)
	copy(b[100:108], "0000644\x00")
	copy(b[108:116], "0000000\x00")
	copy(b[116:124], "0000000\x00")
	copy(b[124:136], fmt.Sprintf("%011o\x00", declared))
	copy(b[136:148], "00000000000\x00")
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	b[156] = '0' // a regular file
	copy(b[257:263], "ustar\x00")
	copy(b[263:265], "00")
	copy(b[265:297], "root")
	copy(b[297:329], "root")
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func TestR2CXF11_ARestoreRefusesAMemberByItsDeclaredSize(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(t.TempDir(), "huge.tar.gz")

	// A gzip holding one header that claims a terabyte of events.jsonl and
	// then a handful of bytes: what the command must not do is read it.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(r2cxTarHeader("events.jsonl", 1<<40)); err != nil {
		t.Fatalf("writing the header: %v", err)
	}
	if _, err := gz.Write([]byte("{}\n")); err != nil {
		t.Fatalf("writing the body: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing the gzip: %v", err)
	}
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("writing %s: %v", archive, err)
	}

	out, err := RestoreBackupTarGz(archive, dir)
	if err == nil {
		t.Fatalf("the restore accepted an archive whose journal member declares a terabyte: %+v", out)
	}
	if !strings.Contains(err.Error(), "declares") || !strings.Contains(err.Error(), "events.jsonl") {
		t.Errorf("the refusal is %q, want it to name the member and the size it declared: the answer is about what the header claims, and it comes before the bytes are read (F-11)", err)
	}
	if entries, rerr := os.ReadDir(dir); rerr == nil && len(entries) != 0 {
		t.Errorf("the refused archive left %d entries in the data directory", len(entries))
	}
}

func TestR2CXF11_ARestoreRefusesTheSameMemberTwice(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(t.TempDir(), "twice.tar.gz")
	// Both members hold a state the gateway would accept on its own, so
	// the only thing wrong with this archive is that the name is in it
	// twice - which is exactly what a limit per member cannot catch.
	body := r2cxSmallState(t)
	r2cxWriteArchive(t, archive,
		[]string{state.StateFileName, state.StateFileName},
		[][]byte{body, body})

	out, err := RestoreBackupTarGz(archive, dir)
	if err == nil {
		t.Fatalf("the restore accepted an archive holding state.json twice: %+v", out)
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("the refusal is %q, want it to say the member is in the archive twice: two members of one name are a way around a limit set per member (F-11)", err)
	}
}

// r2cxSmallState is a state.json the state package's own validation
// accepts (the fixture writes one the way the gateway does), so the
// archive below is refused for its repetition and for nothing else.
func r2cxSmallState(t *testing.T) []byte {
	t.Helper()
	f := newFixture(t, nil)
	raw, err := os.ReadFile(filepath.Join(f.gw.cfg.DataDir, state.StateFileName))
	if err != nil {
		t.Fatalf("reading the fixture's state.json: %v", err)
	}
	return raw
}
