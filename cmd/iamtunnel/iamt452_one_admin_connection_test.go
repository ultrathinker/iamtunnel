//go:build (windows || linux || darwin) && !nogui

package main

// IAMT-452, the window's half. Every action of the window dialed the
// gateway afresh, and the Admin tab polls: a new SSH connection every one
// to three seconds, each one an auth.success in a journal that never
// rotates. An open window was a journal filling at a line a second.

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// iamt452AdminWindow is a client directory holding the identity of the
// test gateway's own admin, as a window on the admin's machine would.
func iamt452AdminWindow(t *testing.T, tg *testGateway, person string) string {
	t.Helper()
	_, portStr, err := net.SplitHostPort(tg.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeClientKeyPEM(t, dir, tg.adminPriv)
	if err := client.SaveConnection(dir, config.ConnString{Host: "127.0.0.1", Port: port, Person: person, Fingerprint: tg.hostFP}, false); err != nil {
		t.Fatal(err)
	}
	return dir
}

func iamt452AuthSuccesses(t *testing.T, tg *testGateway, person string) int {
	t.Helper()
	evs, _, err := events.ReadHistory(tg.dir, events.Filter{Types: []events.EventType{events.EventAuthSuccess}, Actor: person})
	if err != nil {
		t.Fatal(err)
	}
	return len(evs)
}

func TestIAMT452_TheWindowPollsOverOneConnection(t *testing.T) {
	tg := startTestGateway(t, "alice")
	dir := iamt452AdminWindow(t, tg, "alice")
	t.Cleanup(guiAdminLink.reset)
	for i := 0; i < 3; i++ {
		if _, err := guiAdminLists(context.Background(), dir); err != nil {
			t.Fatalf("poll %d: %v", i+1, err)
		}
	}
	if n := iamt452AuthSuccesses(t, tg, "alice"); n != 1 {
		t.Fatalf("three polls of the Admin tab left %d auth.success in the journal (%s), want one: the window logs in once", n, filepath.Join(tg.dir, "events.jsonl"))
	}
}

func TestIAMT452_TheWindowDialsAgainOnlyWhenItHasTo(t *testing.T) {
	tg := startTestGateway(t, "alice")
	dir := iamt452AdminWindow(t, tg, "alice")
	cs, signer, err := loadClientIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	var link adminLink
	t.Cleanup(link.reset)
	dials := 0
	link.dial = func(cs config.ConnString, s ssh.Signer) (*admin.Conn, error) {
		dials++
		return dialAdmin(cs, s)
	}

	c1, err := link.get(cs, signer)
	if err != nil {
		t.Fatal(err)
	}
	_ = c1.Close() // what every call site does when it is done
	c2, err := link.get(cs, signer)
	if err != nil {
		t.Fatal(err)
	}
	if dials != 1 || c1.Conn != c2.Conn {
		t.Fatalf("two actions dialed %d times, want one connection for both", dials)
	}
	if _, err := c2.Whoami(); err != nil {
		t.Fatalf("an action's Close closed the window's connection under the next one: %v", err)
	}

	// The connection goes: the next action dials again instead of failing.
	_ = c2.Conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for !c2.Conn.Broken() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	c3, err := link.get(cs, signer)
	if err != nil {
		t.Fatal(err)
	}
	if dials != 2 {
		t.Fatalf("after the connection went, the window dialed %d times in all, want 2", dials)
	}
	if _, err := c3.Whoami(); err != nil {
		t.Fatalf("the new connection does not work: %v", err)
	}

	// Another identity is another connection.
	other := cs
	other.Person = "bob"
	if _, err := link.get(other, signer); err == nil || dials != 3 {
		t.Fatalf("a changed connection string reused the old login (dials=%d err=%v)", dials, err)
	}
}
