package main

// F-02 of the review round-1 review (24.09.2026), the CLI half: a journal
// with a line nobody can read printed "unreadable: 1" and still left the
// command with exit 0, so a script — or an operator reading only the exit
// code — was told the journal was whole. The line the command prints is
// the same line either way; the code is what scripts act on.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestR1CXF02_VerifyJournalFailsOnAJournalWithAnUnreadableLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	l, err := events.OpenChainedLog(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := l.Append(events.Event{Time: state.NewZonedTime(time.Now()), Type: events.EventAdminOp, Actor: "root", Object: "x", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()

	// A line cut in half by a crash, followed by the writes that came
	// after it: the chain still runs through the damage (the next line
	// names its hash), which is exactly why the verdict cannot rest on the
	// chain alone.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"time":"2026-09-24T12:00:00Z","type":"admin.op"`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	out, errs, code := drive(t, "gateway", "verify-journal", "--data-dir", dir)
	if code != exitEnv {
		t.Errorf("a journal with an unreadable line exits %d (out=%q errs=%q), want %d: an event is gone from it, and a script that reads only the code is told the journal is whole (F-02)", code, out, errs, exitEnv)
	}
	if !strings.Contains(out, "could not be read") {
		t.Errorf("the command does not say a line could not be read:\n%s", out)
	}
	if !strings.Contains(out, "unreadable") {
		t.Errorf("the counts line no longer reports the unreadable lines:\n%s", out)
	}
	// The help has to promise the code the command returns.
	help, _, _ := drive(t, "gateway", "verify-journal", "--help")
	if !strings.Contains(help, "cannot be read at all") {
		t.Errorf("the help does not name the unreadable case among the reasons for exit %d:\n%s", exitEnv, help)
	}
}
