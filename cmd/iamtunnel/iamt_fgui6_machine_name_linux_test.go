//go:build linux && !nogui

package main

// iamt_fgui6_machine_name_linux_test.go — F-GUI-6 (review round
// 25, MEDIUM, confirmed): reproduces the live shape with a real
// permission denial (chmod, no root needed) — the server data
// directory is root-owned 0700, exactly docs/RUNBOOK.md's own layout,
// so an ordinary user's os.Stat/os.ReadFile on machine.id both fail
// with a permission error, not "file not found". The window must carry
// that as Setup.MachineNameUnknown, not a silent empty MachineName that
// the Server tab draws as an ordinary dash.
//
// Run on the Linux host: go test -count=1 ./cmd/iamtunnel/

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// TestFGUI6_RunGUIMachineNameUnknownOnPermissionDenied is the canary.
//
// Canary: drop the !os.IsNotExist branches added to gui_linux.go's
// enrolment read (the round-3 shape, only setting MachineName on
// success and otherwise leaving it and MachineNameUnknown both at their
// zero values). This test goes red on:
//
//	runGUI on a permission-denied machine.id left MachineNameUnknown
//	false — the machine fact would draw a dash indistinguishable from a
//	genuinely absent name (F-GUI-6)
func TestFGUI6_RunGUIMachineNameUnknownOnPermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions — cannot reproduce the denial")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "machine.id"), []byte("lin-ubu-vm\n"), 0o644); err != nil {
		t.Fatalf("seeding fixture: %v", err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	var gotSnap ui.Snapshot
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		gotSnap = cfg.Snap
		return errors.New("stop here — the test only checks the snapshot")
	})

	env := testsupport.PlatformDataEnv(t)
	env["IAMTUNNEL_DATA_DIR"] = dir
	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &bytes.Buffer{}, env: env}

	run([]string{}, s)

	if !gotSnap.Setup.MachineNameUnknown {
		t.Fatalf("runGUI on a permission-denied machine.id left MachineNameUnknown=false — the machine fact would draw a dash indistinguishable from a genuinely absent name (F-GUI-6)")
	}
	if gotSnap.Setup.MachineName != "" {
		t.Fatalf("MachineName = %q, want empty when it could not be read at all", gotSnap.Setup.MachineName)
	}
}

// TestFGUI6_RunGUIMachineNameKnownWhenReadable proves the fix is scoped:
// an ordinary, readable enrolment still reports the name, not "unknown".
func TestFGUI6_RunGUIMachineNameKnownWhenReadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "machine.id"), []byte("lin-ubu-vm\n"), 0o644); err != nil {
		t.Fatalf("seeding fixture: %v", err)
	}

	seamSwap(t, &linuxSetenv, func(string, string) error { return nil })
	var gotSnap ui.Snapshot
	seamSwap(t, &linuxUIRun, func(cfg ui.FrameConfig, _ <-chan ui.LiveUpdate) error {
		gotSnap = cfg.Snap
		return errors.New("stop here — the test only checks the snapshot")
	})

	env := testsupport.PlatformDataEnv(t)
	env["IAMTUNNEL_DATA_DIR"] = dir
	s := &streams{in: strings.NewReader(""), out: &bytes.Buffer{}, errs: &bytes.Buffer{}, env: env}

	run([]string{}, s)

	if gotSnap.Setup.MachineNameUnknown {
		t.Fatal("a readable machine.id was reported as MachineNameUnknown")
	}
	if gotSnap.Setup.MachineName != "lin-ubu-vm" {
		t.Fatalf("MachineName = %q, want %q", gotSnap.Setup.MachineName, "lin-ubu-vm")
	}
}
