package events

// IAMT-467: events.jsonl is the evidence of who came in and why somebody
// was refused, and anybody who could write the file could change it
// without a trace: a line edited, a line removed, a line added. Each line
// of the gateway's journal now carries prev_hash - the SHA-256 of the line
// before it, byte for byte as it lies in the file - so a change anywhere
// breaks the link of the line after it, across rotations too.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func iamt467Event(n int) Event {
	return Event{Time: state.NewZonedTime(time.Date(2026, 9, 23, 18, 0, n, 0, time.UTC)), Type: EventAdminOp, Actor: "root", Object: "iamt-467", Result: "ok",
		Details: map[string]interface{}{"n": n}}
}

func iamt467Lines(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		out = append(out, append([]byte(nil), sc.Bytes()...))
	}
	return out
}

func iamt467PrevHash(t *testing.T, line []byte) (string, bool) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("line %q: %v", line, err)
	}
	v, ok := m["prev_hash"].(string)
	return v, ok
}

func iamt467Sum(line []byte) string {
	s := sha256.Sum256(line)
	return "sha256:" + hex.EncodeToString(s[:])
}

func iamt467Write(t *testing.T, path string, from, to int, open func(string) (*Log, error)) {
	t.Helper()
	l, err := open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := from; i < to; i++ {
		if err := l.Append(iamt467Event(i)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIAMT467_EveryLineNamesTheOneBefore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	iamt467Write(t, path, 0, 3, OpenChainedLog)
	lines := iamt467Lines(t, path)
	if len(lines) != 3 {
		t.Fatalf("%d lines", len(lines))
	}
	if ph, ok := iamt467PrevHash(t, lines[0]); !ok || ph != "genesis" {
		t.Fatalf("the first line of a new journal has prev_hash %q (present=%v), want \"genesis\"", ph, ok)
	}
	for i := 1; i < len(lines); i++ {
		ph, _ := iamt467PrevHash(t, lines[i])
		if ph != iamt467Sum(lines[i-1]) {
			t.Errorf("line %d: prev_hash %q, want the hash of line %d (%s)", i+1, ph, i, iamt467Sum(lines[i-1]))
		}
	}
	if got := LineHash(lines[0]); got != iamt467Sum(lines[0]) {
		t.Errorf("LineHash = %q, want %q", got, iamt467Sum(lines[0]))
	}
	rep, err := VerifyChain(filepath.Dir(path))
	if err != nil || !rep.Intact() || rep.Chained != 3 || rep.Legacy != 0 {
		t.Errorf("a journal nobody touched verifies as %+v (err %v), want intact with 3 chained lines", rep, err)
	}
}

func TestIAMT467_AnEditedOrRemovedLineIsFound(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(lines [][]byte) [][]byte
		want   int // the line whose link breaks
	}{
		{"edited", func(l [][]byte) [][]byte {
			l[2] = bytes.Replace(l[2], []byte(`"result":"ok"`), []byte(`"result":"no"`), 1)
			return l
		}, 4},
		{"removed", func(l [][]byte) [][]byte { return append(l[:2], l[3:]...) }, 3},
		{"inserted", func(l [][]byte) [][]byte {
			forged := append([]byte(nil), l[1]...)
			return append(l[:2], append([][]byte{forged}, l[2:]...)...)
		}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "events.jsonl")
			iamt467Write(t, path, 0, 5, OpenChainedLog)
			lines := tc.change(iamt467Lines(t, path))
			if err := os.WriteFile(path, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			rep, err := VerifyChain(dir)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Intact() || !rep.Broken || rep.BreakLine != tc.want || rep.BreakFile != "events.jsonl" {
				t.Fatalf("a journal with a line %s verifies as %+v, want broken at events.jsonl line %d", tc.name, rep, tc.want)
			}
		})
	}
}

func TestIAMT467_TheChainGoesOnAcrossARotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	l, err := OpenChainedLog(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Append(iamt467Event(i)); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(dir, ArchiveName(time.Date(2026, 9, 23, 18, 1, 0, 0, time.UTC)))
	if err := l.Rotate(archive); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(iamt467Event(3)); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()

	old := iamt467Lines(t, archive)
	cur := iamt467Lines(t, path)
	if ph, _ := iamt467PrevHash(t, cur[0]); ph != iamt467Sum(old[len(old)-1]) {
		t.Fatalf("the fresh journal's first line has prev_hash %q, want the hash of the archive's last line", ph)
	}
	rep, err := VerifyChain(dir)
	if err != nil || !rep.Intact() || rep.Files != 2 || rep.Chained != 5 {
		t.Fatalf("across a rotation: %+v (err %v), want intact, 2 files, 5 chained lines", rep, err)
	}

	// Change the archive's last line: the break is at the first line of the
	// journal that followed it.
	old[len(old)-1] = bytes.Replace(old[len(old)-1], []byte(`"n":2`), []byte(`"n":9`), 1)
	if err := os.WriteFile(archive, append(bytes.Join(old, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err = VerifyChain(dir)
	if err != nil || !rep.Broken || rep.BreakFile != "events.jsonl" || rep.BreakLine != 1 {
		t.Fatalf("an archive changed after the rotation verifies as %+v (err %v), want broken at events.jsonl line 1", rep, err)
	}
}

func TestIAMT467_AJournalFromBeforeTheChainIsUnchainedNotBroken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	iamt467Write(t, path, 0, 4, OpenLog) // a gateway before 1.14
	iamt467Write(t, path, 4, 6, OpenChainedLog)
	lines := iamt467Lines(t, path)
	if _, ok := iamt467PrevHash(t, lines[3]); ok {
		t.Fatalf("an old line gained a prev_hash")
	}
	if ph, _ := iamt467PrevHash(t, lines[4]); ph != iamt467Sum(lines[3]) {
		t.Fatalf("the first chained line has prev_hash %q, want the hash of the last old line: the chain is anchored to what was already there", ph)
	}
	rep, err := VerifyChain(dir)
	if err != nil || !rep.Intact() || rep.Legacy != 4 || rep.Chained != 2 {
		t.Fatalf("an old journal carried on verifies as %+v (err %v), want intact with 4 unchained and 2 chained lines", rep, err)
	}
}

func TestIAMT467_ALineWrittenWithoutTheChainAfterItBeganIsNamed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	iamt467Write(t, path, 0, 2, OpenChainedLog)
	iamt467Write(t, path, 2, 3, OpenLog) // an older binary, or a forger
	rep, err := VerifyChain(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Intact() || rep.Unvouched != 1 || rep.FirstUnvouchedLine != 3 {
		t.Fatalf("an unchained line after the chain began verifies as %+v, want it named (line 3) and the journal not intact", rep)
	}
	if !strings.Contains(rep.FirstUnvouchedFile, "events.jsonl") {
		t.Errorf("the report does not name the file: %+v", rep)
	}
}

func TestIAMT467_TwoWritersKeepOneChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	a, err := OpenChainedLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenChainedLog(path) // the service and "gateway rotate-hostkey"
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	done := make(chan error, 2)
	for _, l := range []*Log{a, b} {
		go func(l *Log) {
			var err error
			for i := 0; i < 20 && err == nil; i++ {
				err = l.Append(iamt467Event(i))
			}
			done <- err
		}(l)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	rep, err := VerifyChain(dir)
	if err != nil || !rep.Intact() || rep.Chained != 40 {
		t.Fatalf("two writers on one journal: %+v (err %v), want one intact chain of 40", rep, err)
	}
}
