package main

// IAMT-451: on the gateway's own machine, `gateway status` is what the
// operator runs - and the window's Gateway tab reads the same things. The
// running gateway cannot be asked over its lock; what it knows about its
// audit journal has to be where status looks, in its data directory.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestIAMT451_GatewayStatusSaysTheAuditJournalIsNotWritten(t *testing.T) {
	dir := t.TempDir()
	seedLiveStatusState(t, dir)
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open (take the lock, as the running gateway does): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	health := `{"ok":false,"since":"2026-09-23T18:00:00Z","error":"write events.jsonl: no space left on device","lostWrites":3}`
	if err := os.WriteFile(filepath.Join(dir, "audit-health.json"), []byte(health), 0o600); err != nil {
		t.Fatal(err)
	}

	out, errs, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK || !strings.Contains(out, "audit: PROBLEM") || !strings.Contains(out, "no space left on device") {
		t.Fatalf("gateway status of a running gateway whose audit journal is not written does not say so (code=%d):\n%s%s", code, out, errs)
	}
}
