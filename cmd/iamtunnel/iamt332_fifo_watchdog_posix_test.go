//go:build !windows

package main

// iamt332_fifo_watchdog_posix_test.go — IAMT-332 round seven, the
// watchdog's own last-resort error file. When a journal write fails, the
// server appends one line to <journal>.watchdog.err beside the machine
// audit journal — opened by final pathname with plain
// O_CREATE|O_WRONLY|O_APPEND, so a FIFO planted at that name blocked the
// reporting path inside open(2) instead of giving up on a name it cannot
// open. Round seven routes the open through the same state contract.
//
// Verification note: this package's tests do not run in the Linux docker
// harness (the GUI-side packages need cgo/X11), so this file is exercised
// on a real POSIX host (the live checks). The seam's FIFO refusal itself
// is proven red-first in internal/winkeys and internal/gateway/state.

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestIAMT332Round7WatchdogErrorFileRefusesAFIFOAtTheName plants a FIFO
// at the watchdog error file's name and requires the reporter to give up
// PROMPTLY — the channel is best-effort by design (its own doc comment:
// if the filesystem is unwritable, so was the journal write it reports),
// so the only wrong behaviour is hanging, never a specific wording. The
// bounded-wait pattern is part of the test's meaning: a genuine hang
// fails the test naming the reader, it does not wedge the suite.
func TestIAMT332Round7WatchdogErrorFileRefusesAFIFOAtTheName(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "events.jsonl")
	errPath := journal + ".watchdog.err"
	if err := syscall.Mkfifo(errPath, 0o600); err != nil {
		t.Fatalf("plant the FIFO: %v", err)
	}
	report := watchdogAuditErrorReporter(journal)
	done := make(chan struct{})
	go func() {
		report(errors.New("iamt332 probe: a journal write failed"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("the watchdog audit-error reporter did not return within 3s — it is blocked on the FIFO planted at %s instead of giving up on a name it cannot open (IAMT-332 round 7)", errPath)
	}
	if st, serr := os.Lstat(errPath); serr != nil || st.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("the planted FIFO did not survive the refused open (Lstat: %v, %#v) — the refusal must leave the name as it found it", serr, st)
	}
}
