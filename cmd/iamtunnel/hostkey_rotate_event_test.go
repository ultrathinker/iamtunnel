package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// TestHostKeyRotate_WritesJournalEvent verifies that "gateway rotate-hostkey"
// records an EventHostKeyRotate entry in events.jsonl with old and new fingerprints.
func TestHostKeyRotate_WritesJournalEvent(t *testing.T) {
	dir := t.TempDir()

	// Perform rotation
	out, errs, code := drive(t, "gateway", "rotate-hostkey", "--data-dir", dir, "--yes")
	if code != exitOK {
		t.Fatalf("gateway rotate-hostkey failed: code=%d out=%q errs=%q", code, out, errs)
	}

	logPath := filepath.Join(dir, "events.jsonl")
	evs, stats, err := events.ReadFile(logPath, events.Filter{Types: []events.EventType{events.EventHostKeyRotate}})
	if err != nil {
		t.Fatalf("failed to read event log %s: %v", logPath, err)
	}
	if stats.Skipped > 0 {
		t.Fatalf("stats.Skipped = %d, want 0", stats.Skipped)
	}
	if len(evs) != 1 {
		t.Fatalf("len(evs) = %d, want 1", len(evs))
	}

	e := evs[0]
	if e.Type != events.EventHostKeyRotate {
		t.Fatalf("e.Type = %q, want %q", e.Type, events.EventHostKeyRotate)
	}
	if e.Actor != "gateway" {
		t.Fatalf("e.Actor = %q, want %q", e.Actor, "gateway")
	}
	if e.Object != "hostkey" {
		t.Fatalf("e.Object = %q, want %q", e.Object, "hostkey")
	}
	if e.Result != "ok" {
		t.Fatalf("e.Result = %q, want %q", e.Result, "ok")
	}
	if e.Fingerprint == "" {
		t.Fatalf("e.Fingerprint is empty, want non-empty new fingerprint")
	}
	oldFP, _ := e.Details["oldFingerprint"].(string)
	newFP, _ := e.Details["newFingerprint"].(string)
	if newFP == "" {
		t.Fatalf("details[newFingerprint] is empty, want valid fingerprint")
	}
	if oldFP == "" {
		t.Fatalf("details[oldFingerprint] is empty, want valid fingerprint")
	}
	if !strings.Contains(out, newFP) {
		t.Fatalf("stdout %q does not contain newFP %q", out, newFP)
	}
}
