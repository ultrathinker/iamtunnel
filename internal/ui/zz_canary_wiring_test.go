//go:build windows || linux || darwin

package ui

// Canary for IAMT-346: the tab must ASK.
//
// Five items of the 1.5 wave were merged green while the Session tab was
// inert on every real window, because the three function fields it works
// through were never assigned. No test caught it: each test supplied the
// hooks itself, so every one of them tested a tab that was wired by the
// test and never the tab the product builds.
//
// This canary aims at the two halves of that failure which live in this
// package: a snapshot that carries no session id must not be turned into
// an invented one (the invented id kept the list non-empty, which is
// what stopped the real list from ever being requested), and a window
// with no ids of its own must reach for Actions.SessionList.

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestCanary_AnUnnamedSessionIsNotGivenAnInventedId.
//
// Canary: put back `id = fmt.Sprintf("session-%s", person)` in the
// server branch of activeSessions. This goes red on the invented id, and
// the test below goes red too — the fabricated entry is precisely what
// suppressed the real question.
func TestCanary_AnUnnamedSessionIsNotGivenAnInventedId(t *testing.T) {
	snap := Snapshot{}
	// Exactly what the machine's own status reply produces: somebody is
	// in, and the machine cannot say who or under which id.
	snap.Server.Sessions = []Session{{}}

	// The fixed theme source is the package's offscreen rule (MAC,
	// 24.09.2026): with the field unset NewFrame falls back to the
	// platform's live probe, which on darwin refuses to run in a test
	// binary by design.
	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Snap:        snap,
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	got := frame.sessionUI.activeSessions()

	for _, s := range got {
		if strings.HasPrefix(s.ID, "session-") {
			t.Fatalf("the window invented the session id %q: no such session exists on the gateway, so every tail asked with it comes back 'not live' and the owner watches an empty terminal over a session that is really running", s.ID)
		}
		if s.ID == "" {
			t.Fatalf("an entry with no id reached the watch list: it cannot be watched, and offering it promises something the window cannot do")
		}
	}
}

// TestCanary_AWindowWithNoIdsAsksTheGatewayForThem is the
// other half: having refused to invent, the window must go and get the
// real ids.
//
// Canary: restore the old `!s.listFetched` condition together with the
// invented id above — the list is then never empty, the branch is never
// reached, and this goes red with ask-count 0.
func TestCanary_AWindowWithNoIdsAsksTheGatewayForThem(t *testing.T) {
	var asked atomic.Int32
	snap := Snapshot{}
	snap.Server.Sessions = []Session{{}}

	cfg := FrameConfig{
		Enrolled:    true,
		InitialTab:  TabSession,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
		Snap:        snap,
	}
	cfg.Actions.SessionList = func(ctx context.Context) ([]SessionInfo, error) {
		asked.Add(1)
		return []SessionInfo{{
			ID:      "1758191525000000000-alice-pc1",
			Person:  "alice",
			Started: time.Now(),
		}}, nil
	}

	frame, err := NewFrame(cfg)
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	st := frame.sessionUI
	st.activeSessions()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && asked.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if asked.Load() == 0 {
		t.Fatal("the window never asked for the session list: with no id of its own it has nothing to watch, and this is exactly the state every real window was in while five items of this wave were called done")
	}

	// And the answer must actually reach the list.
	var found bool
	for i := 0; i < 100 && !found; i++ {
		for _, s := range st.activeSessions() {
			if s.ID == "1758191525000000000-alice-pc1" {
				found = true
			}
		}
		if !found {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !found {
		t.Fatal("the gateway's own session id never appeared in the watch list")
	}
}
