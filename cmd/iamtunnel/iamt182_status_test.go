//go:build windows && !nogui

package main

// iamt182_status_test.go: the window's live source of its own server
// state (IAMT-182) — the same path "iamtunnel server status" uses
// (control.json + the control port, sendControl), periodically re-asked
// and handed to the window through UpdateSnapshot. Every test here is a
// poddelny (fake) source: no control.json is ever written by hand, no
// real server.Run, no sleeping on business logic — only on the poll
// ticker's own short interval, bounded by time.After the same way round
// 3's guardWait pattern is.

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// TestServerStateFromControlReplyReportsASession is the exact canary
// for the session-reporting path: a fake source (a hand-built
// controlReplyMsg, nothing dialled) that reports a session gives a
// Snapshot whose Recording() is true.
func TestServerStateFromControlReplyReportsASession(t *testing.T) {
	got := serverStateFromControlReply(controlReplyMsg{Running: true, Connected: true, DoorOpen: true}, true)
	if !got.Waiting {
		t.Errorf("Waiting = false, want true (Connected was true)")
	}
	if !got.AccessOpen() {
		t.Fatalf("Recording() = false, want true — a fake source reporting DoorOpen must make the recording strip appear")
	}
	if got.Door.State != "open" {
		t.Errorf("Door.State = %q, want \"open\"", got.Door.State)
	}
}

func TestServerStateFromControlReplyNotContacted(t *testing.T) {
	got := serverStateFromControlReply(controlReplyMsg{Connected: true, DoorOpen: true}, false)
	if got.Waiting || got.AccessOpen() || got.Door.State != "" || len(got.Sessions) != 0 {
		t.Errorf("serverStateFromControlReply(_, contacted=false) = %+v, want the zero ServerState — an unreachable control port must never be drawn as a session in progress", got)
	}
}

func TestServerStateFromControlReplyConnectedWithoutDoor(t *testing.T) {
	got := serverStateFromControlReply(controlReplyMsg{Running: true, Connected: true, DoorOpen: false}, true)
	if !got.Waiting {
		t.Errorf("Waiting = false, want true")
	}
	if got.AccessOpen() {
		t.Fatalf("Recording() = true, want false — DoorOpen was false, there is nothing to record")
	}
}

// TestPollServerStatusWithNoControlFile exercises the REAL sendControl
// against an empty t.TempDir(): no control.json exists, so sendControl
// returns contacted=false without ever dialing a socket — this is the
// "not running" path, reached with neither a window nor a network.
func TestPollServerStatusWithNoControlFile(t *testing.T) {
	dir := t.TempDir()
	got := pollServerStatus(dir)
	if got.AccessOpen() {
		t.Errorf("pollServerStatus on an empty directory reports Recording() == true")
	}
	if got.Waiting {
		t.Errorf("pollServerStatus on an empty directory reports Waiting == true")
	}
}

// TestStartServerStatusPollSendsAndStops proves the poller's lifecycle:
// it sends at least one update carrying a freshly polled Server, and it
// stops sending the instant done is closed. The interval is a few
// milliseconds so the test does not wait real seconds; every wait in the
// test itself is a bounded channel receive, never a time.Sleep gating
// assertions.
//
// It used to also assert that the update carried a marker planted in a
// shadow snapshot, because the poller merged onto one. There is no
// shadow any more (21.09.2026): the poller says what it dialled for and
// nothing else, so there is no longer anything for it to carry across.
func TestStartServerStatusPollSendsAndStops(t *testing.T) {
	dir := t.TempDir() // no control.json: every poll reports "not running"
	updates := make(chan ui.LiveUpdate, 8)
	done := make(chan struct{})

	startServerStatusPoll(dir, t.TempDir(), 5*time.Millisecond, updates, done)

	var got ui.LiveUpdate
	select {
	case got = <-updates:
	case <-time.After(2 * time.Second):
		t.Fatalf("startServerStatusPoll did not send an update within 2s")
	}
	if got.Server.AccessOpen() {
		t.Errorf("update reports Recording() == true against an empty directory")
	}
	// No saved connection in that second temp dir, so the tick must say
	// so rather than leave the field at whatever it was.
	if got.Identity != nil {
		t.Errorf("update carried an identity %+v for a directory holding no connection", got.Identity)
	}
	if got.HeldKnown {
		t.Errorf("update claims the held list is known although there is no gateway to ask")
	}

	close(done)

	// Drain whatever was already queued, then prove nothing more arrives —
	// evidence the goroutine actually stopped, not that the buffered
	// channel merely ran dry on its own.
	drainUntil := time.After(50 * time.Millisecond)
drain:
	for {
		select {
		case <-updates:
		case <-drainUntil:
			break drain
		}
	}
	select {
	case <-updates:
		t.Fatalf("startServerStatusPoll kept sending after done was closed")
	case <-time.After(100 * time.Millisecond):
	}
}
