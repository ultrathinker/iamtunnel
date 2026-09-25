package main

// IAMT-467, the command: "gateway verify-journal" reads the chain of the
// gateway's journal and says whether it holds, with the exit code a script
// can act on.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestIAMT467_VerifyJournalSaysWhetherTheChainHolds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	l, err := events.OpenChainedLog(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Append(events.Event{Time: state.NewZonedTime(time.Now()), Type: events.EventAdminOp, Actor: "root", Object: "x", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()

	out, errs, code := drive(t, "gateway", "verify-journal", "--data-dir", dir)
	if code != exitOK || !strings.Contains(out, "intact") {
		t.Fatalf("an untouched journal: code=%d out=%q errs=%q, want exit 0 and \"intact\"", code, out, errs)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Replace(raw, []byte(`"object":"x"`), []byte(`"object":"y"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errs, code = drive(t, "gateway", "verify-journal", "--data-dir", dir)
	if code != exitEnv || !strings.Contains(out, "BROKEN at events.jsonl line 2") {
		t.Fatalf("an edited journal: code=%d out=%q errs=%q, want exit %d and the line that breaks", code, out, errs, exitEnv)
	}
	// The help promises the code the command returns (it said 1 for a
	// day; exitEnv is 3).
	help, _, _ := drive(t, "gateway", "verify-journal", "--help")
	if !strings.Contains(help, "3 when a link is broken") {
		t.Errorf("the help does not name the exit code the command returns (%d):\n%s", exitEnv, help)
	}
}
