//go:build windows && !nogui

package main

// iamt181_wiring_test.go covers the four IAMT-181 actions the Server and
// Admin screens now call: guiServerStart, guiServerStop, guiGrant,
// guiRevoke. None of these tests opens a window or touches a network:
// guiServerStart's spawn is always a fake (a real one would start an
// actual "iamtunnel server start" child process, which touches the
// Windows OpenSSH authorized_keys file and the SCM — exactly what a
// test must never do), and guiServerStop/guiGrant/guiRevoke
// are exercised only on the paths that fail before any socket opens
// (t.TempDir() with no control.json / no saved connection string).

import (
	"errors"
	"strings"
	"testing"
)

// guiGrant preserves the historical shell-default helper used by callers
// that do not expose the capability selector. Production dials
// guiGrantWithCaps directly on every platform, and the only remaining
// caller is this file, so the wrapper lives here beside it: on darwin it
// sat unused in production sources, and staticcheck's U1000 said so
// (MAC, 24.09.2026).
func guiGrant(clientDir, person, machine, until string) (string, error) {
	return guiGrantWithCaps(clientDir, person, machine, until, "shell")
}

func TestGuiServerStartSpawnsWhenNotAlreadyRunning(t *testing.T) {
	dir := t.TempDir() // no control.json: sendControl reports "not running"
	var gotExe string
	spawned := false
	msg, err := guiServerStart(dir, func(exe string) error {
		spawned = true
		gotExe = exe
		return nil
	})
	if err != nil {
		t.Fatalf("guiServerStart: %v", err)
	}
	if !spawned {
		t.Fatalf("guiServerStart did not call spawn at all")
	}
	if gotExe == "" {
		t.Errorf("guiServerStart called spawn with an empty executable path")
	}
	if msg == "" {
		t.Errorf("guiServerStart returned an empty message on success")
	}
}

func TestGuiServerStartReportsASpawnFailure(t *testing.T) {
	dir := t.TempDir()
	wantErr := errors.New("access is denied")
	_, err := guiServerStart(dir, func(exe string) error { return wantErr })
	if err == nil {
		t.Fatalf("guiServerStart did not fail when spawn failed")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("guiServerStart error = %v, want it to wrap %v", err, wantErr)
	}
}

func TestGuiServerStopWhenNotRunning(t *testing.T) {
	dir := t.TempDir() // no control.json: sendControl reports "not running"
	msg, err := guiServerStop(dir)
	if err != nil {
		t.Fatalf("guiServerStop: %v", err)
	}
	if !strings.Contains(msg, "not running") {
		t.Errorf("guiServerStop message = %q, want it to say the server is not running", msg)
	}
}

func TestGuiGrantRefusesAnInvalidPersonName(t *testing.T) {
	// A name with a space is not a valid §4.3 name; this must be caught
	// before loadClientIdentity/dialAdmin are ever reached — the
	// directory has neither a saved connection string nor a network
	// reachable from it, so any attempt to go further would fail some
	// other, less specific way.
	_, err := guiGrant(t.TempDir(), "bad name", "win-srv01", "")
	if err == nil {
		t.Fatalf("guiGrant accepted an invalid person name")
	}
}

func TestGuiGrantRefusesAnInvalidUntil(t *testing.T) {
	_, err := guiGrant(t.TempDir(), "alice", "win-srv01", "not-a-timestamp")
	if err == nil {
		t.Fatalf("guiGrant accepted an invalid until value")
	}
}

func TestGuiGrantWithoutASavedConnectionSaysSo(t *testing.T) {
	_, err := guiGrant(t.TempDir(), "alice", "win-srv01", "")
	if err == nil {
		t.Fatalf("guiGrant with no saved connection did not fail")
	}
	if !strings.Contains(err.Error(), "connection") {
		t.Errorf("guiGrant error = %q, want it to mention the missing connection string", err.Error())
	}
}

func TestGuiRevokeWithoutASavedConnectionSaysSo(t *testing.T) {
	_, err := guiRevoke(t.TempDir(), "alice", "win-srv01")
	if err == nil {
		t.Fatalf("guiRevoke with no saved connection did not fail")
	}
	if !strings.Contains(err.Error(), "connection") {
		t.Errorf("guiRevoke error = %q, want it to mention the missing connection string", err.Error())
	}
}
