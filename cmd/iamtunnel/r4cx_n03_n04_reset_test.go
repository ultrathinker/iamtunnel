package main

// r4cx_n03_n04_reset_test.go — review finding R4 N-03 and N-04, gateway reset.
//
// N-04: reset removed events.jsonl but left the journal's archives
// (events-<UTC>.jsonl) - the history and the verify-journal of the "clean"
// gateway went on reading the previous owner's events, and the chain check
// saw the fresh journal's first line as a break. The confirmation already
// promised to destroy "the event journal"; now it does, archives included.
//
// N-03: the wipe ran path-based os.Remove/os.RemoveAll in a privileged
// command. It now acts inside one os.Root on the data directory, so no
// name in the wipe can lead it outside that directory; the guard below
// pins that a link planted inside recordings/ is removed as a link and
// what it points at survives.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestR4CXN04_ResetLeavesNoArchiveOfTheOldJournal(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	dir := t.TempDir()
	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")
	if !gatewayInstallSucceedsOnThisHost() {
		t.Skip("this host has no service half")
	}
	archive := filepath.Join(dir, events.ArchiveName(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)))
	if err := os.WriteFile(archive, []byte(`{"time":"2026-01-02T03:04:05Z","type":"admin.op","actor":"old-owner","object":"gateway","result":"x"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, errs, code = drive(t, "gateway", "reset", "--data-dir", dir, "--public-host", "gw.example.test", "--yes")
	expectResetExit(t, out, errs, code, "reset --yes")

	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Fatalf("review finding R4 N-04: reset left the old journal's archive %s behind (stat err=%v) — the new owner's history still reads the previous owner's events", filepath.Base(archive), err)
	}
	rep, err := events.VerifyChain(dir)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !rep.Intact() {
		t.Fatalf("after reset the journal does not verify: %s", rep.Summary())
	}
}

func TestR4CXN03_ResetRemovesALinkInsideRecordingsNotItsTarget(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	dir := t.TempDir()
	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")
	if !gatewayInstallSucceedsOnThisHost() {
		t.Skip("this host has no service half")
	}
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("not the gateway's"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := filepath.Join(dir, "recordings")
	if err := os.MkdirAll(rec, 0o700); err != nil {
		t.Fatal(err)
	}
	if !plantDirLink(t, outside, filepath.Join(rec, "m-1")) {
		t.Skip("this host cannot create a directory link")
	}

	out, errs, code = drive(t, "gateway", "reset", "--data-dir", dir, "--public-host", "gw.example.test", "--yes")
	expectResetExit(t, out, errs, code, "reset --yes")

	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("review finding R4 N-03: reset followed a link planted in recordings/ and deleted %s (%v)", sentinel, err)
	}
}
