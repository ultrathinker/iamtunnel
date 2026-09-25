//go:build !windows

package main

// iamt332_fifo_enrolment_posix_test.go — IAMT-332 round six, the MACHINE
// role's half of the round-five sweep. enrolment.json is the machine data
// file "server start" reads back (serverStartConfig → loadGatewayRecord),
// and the startup config migration probes the legacy gateway.json name
// (migrateLegacyGatewayRecord) on the way there. Both reads went through
// plain os.ReadFile: a FIFO planted at either name by the owner of a
// custom --data-dir hung the privileged "server start" inside
// open(2) — the same class as state.json before round five. Both reads go
// through state.ReadDataFile now.
//
// Verification note: this package's tests do not run in the Linux docker
// harness (the GUI-side packages need cgo/X11), so this file is exercised
// on a real POSIX host (the live checks). The same seam's refusal wording
// is verified red-first on Windows by the directory-plant row for
// loadGatewayRecord in iamt332_readers_test.go, and the FIFO behaviour of
// state.ReadDataFile itself is proven in internal/gateway/state.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestIAMT332Round6MachineReadsRefuseAFIFOAtTheRecordNames plants a FIFO
// at each machine-record name in turn and requires the read to come back
// promptly: loadGatewayRecord with the actionable refusal,
// migrateLegacyGatewayRecord as a prompt no-op that moves nothing. The
// bounded-wait pattern is part of the test's meaning: a genuine hang
// fails the test naming the reader, it does not wedge the suite.
func TestIAMT332Round6MachineReadsRefuseAFIFOAtTheRecordNames(t *testing.T) {
	t.Run("loadGatewayRecord's read of enrolment.json (server start)", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, gatewayRecordName)
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatalf("plant the FIFO: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := loadGatewayRecord(dir)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("loadGatewayRecord read through a FIFO planted at %s — a machine data file's name must be refused when it is not a regular file (IAMT-332 round 6)", path)
			}
			if !strings.Contains(err.Error(), "not a regular file") {
				t.Errorf("loadGatewayRecord refused %s with %q — the error must say the name is not a regular file and what to do", path, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("loadGatewayRecord did not return within 3s — it is blocked on the FIFO planted at %s instead of refusing a non-regular file at a machine data file's name (IAMT-332 round 6)", path)
		}
		if st, serr := os.Lstat(path); serr != nil || st.Mode()&os.ModeNamedPipe == 0 {
			t.Errorf("the planted FIFO did not survive the refused read (Lstat: %v, %#v) — the refusal must leave the name as it found it", serr, st)
		}
	})

	t.Run("migrateLegacyGatewayRecord's probe of legacy gateway.json (startup migration)", func(t *testing.T) {
		dir := t.TempDir()
		legacy := filepath.Join(dir, legacyGatewayRecordName)
		enrolment := filepath.Join(dir, gatewayRecordName)
		if err := syscall.Mkfifo(legacy, 0o600); err != nil {
			t.Fatalf("plant the FIFO: %v", err)
		}
		done := make(chan error, 1)
		go func() { done <- migrateLegacyGatewayRecord(legacy, enrolment) }()
		select {
		case err := <-done:
			// The migration's contract is a NO-OP on any read error — the
			// settings parser owns the truth about that name later. What
			// round six buys is that the no-op is PROMPT instead of a hang,
			// and that it moves nothing.
			if err != nil {
				t.Errorf("migrateLegacyGatewayRecord returned %v for a name it cannot read — its contract is a silent no-op, config.Load reports the real reason", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("migrateLegacyGatewayRecord did not return within 3s — it is blocked on the FIFO planted at %s instead of no-op'ing on a non-regular file (IAMT-332 round 6)", legacy)
		}
		if st, serr := os.Lstat(legacy); serr != nil || st.Mode()&os.ModeNamedPipe == 0 {
			t.Errorf("the planted FIFO at the legacy name did not survive the probe (Lstat: %v, %#v) — migration must never touch a name it cannot read", serr, st)
		}
		if _, serr := os.Lstat(enrolment); !os.IsNotExist(serr) {
			t.Errorf("the probe created or moved something to %s (Lstat: %v) — a refused probe must be a no-op", enrolment, serr)
		}
	})
}
