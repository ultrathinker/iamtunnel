//go:build (windows || linux || darwin) && !nogui

package main

// IAMT-452 meets M-12 (merge of main affe89f). The window keeps one admin
// connection for everything it asks the gateway (IAMT-452); M-12 gave the
// recording reader a connection of its own, cached per client directory,
// with one retry and an idle close. One window, two logins, two caches of
// one idea. The reader now goes over the window's connection, and the
// window's connection keeps what M-12 promised: a refusal is an answer
// and is not asked again, a failure below it is retried exactly once, and
// the connection is let go once nothing uses it.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// iamt452Proxy stands between the window and the test gateway and counts
// the connections the window opens. The journal cannot count them: it
// folds repeated logins of one key from one host (IAMT-452).
type iamt452Proxy struct {
	ln     net.Listener
	mu     sync.Mutex
	opened int
	live   []net.Conn
}

func iamt452StartProxy(t *testing.T, target string) *iamt452Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &iamt452Proxy{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.opened++
			p.live = append(p.live, c, s)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(s, c); _ = s.Close() }()
			go func() { _, _ = io.Copy(c, s); _ = c.Close() }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); p.cut() })
	return p
}

// cut drops every connection through the proxy at once, as a gateway
// restart or a changed network does.
func (p *iamt452Proxy) cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.live {
		_ = c.Close()
	}
	p.live = nil
}

func (p *iamt452Proxy) connections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.opened
}

// iamt452ReaderWindow is the admin's window, pointed at the gateway
// through the proxy, and the id of one finished recording on the gateway.
func iamt452ReaderWindow(t *testing.T) (dir, id string, proxy *iamt452Proxy) {
	t.Helper()
	tg := startTestGateway(t, "alice")
	rec, err := record.NewRecorder(record.SessionConfig{
		BaseDir:      filepath.Join(tg.dir, "recordings"),
		Machine:      "box",
		Person:       "alice",
		SessionID:    "session:iamt452-read",
		SubdirLayout: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Several windows of recordingFetchWindow once written as a cast.
	if _, err := rec.Write(bytes.Repeat([]byte("iamt-452 reading a finished session\r\n"), 16*1024)); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	proxy = iamt452StartProxy(t, tg.addr.String())
	_, portStr, err := net.SplitHostPort(proxy.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	writeClientKeyPEM(t, dir, tg.adminPriv)
	if err := client.SaveConnection(dir, config.ConnString{Host: "127.0.0.1", Port: port, Person: "alice", Fingerprint: tg.hostFP}, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(guiAdminLink.reset)

	refs, err := guiAdminRecordings(context.Background(), dir, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if r.SessionID == "session:iamt452-read" {
			return dir, r.ID, proxy
		}
	}
	t.Fatalf("the gateway does not list the recording: %+v", refs)
	return "", "", nil
}

// iamt452ReadAll reads one part of a recording the way the transcript
// window does: window after window, until the gateway's total.
func iamt452ReadAll(t *testing.T, dir, id, part string) []byte {
	t.Helper()
	var got []byte
	for offset, reads := int64(0), 0; ; reads++ {
		raw, next, total, err := guiAdminRecordingFetch(context.Background(), dir, id, part, offset)
		if err != nil {
			t.Fatalf("reading %s at %d: %v", part, offset, err)
		}
		got = append(got, raw...)
		if next >= total {
			if reads == 0 {
				t.Fatalf("the %s part came in one window of %d bytes: the test reads nothing twice", part, total)
			}
			return got
		}
		offset = next
	}
}

func TestIAMT452_TheWindowReadsARecordingOverItsOneConnection(t *testing.T) {
	dir, id, proxy := iamt452ReaderWindow(t)
	if _, err := guiAdminLists(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	iamt452ReadAll(t, dir, id, "cast")
	if _, err := guiAdminLists(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if n := proxy.connections(); n != 1 {
		t.Fatalf("the window opened %d connections to list, read a recording window by window and list again, want one: the reader logs in on its own", n)
	}
}

func TestIAMT452_AReaderWhoseConnectionWentReadsOn(t *testing.T) {
	dir, id, proxy := iamt452ReaderWindow(t)
	first, next, _, err := guiAdminRecordingFetch(context.Background(), dir, id, "cast", 0)
	if err != nil || len(first) == 0 {
		t.Fatalf("first window: %d bytes, %v", len(first), err)
	}
	proxy.cut()
	if _, _, _, err := guiAdminRecordingFetch(context.Background(), dir, id, "cast", next); err != nil {
		t.Fatalf("the connection went between two windows of a transcript, and the next window failed instead of being read over a new one: %v", err)
	}
	if n := proxy.connections(); n != 2 {
		t.Fatalf("%d connections, want two: the one that went and one more", n)
	}
}

func TestIAMT452_ARefusalIsAnAnswerAndCostsNoConnection(t *testing.T) {
	dir, id, proxy := iamt452ReaderWindow(t)
	_, _, _, err := guiAdminRecordingFetch(context.Background(), dir, "no-such-recording", "cast", 0)
	var refused *admin.CommandError
	if !errors.As(err, &refused) {
		t.Fatalf("a recording the gateway does not have came back as %v, want the gateway's own refusal", err)
	}
	iamt452ReadAll(t, dir, id, "cast")
	if n := proxy.connections(); n != 1 {
		t.Fatalf("a refusal cost the window its connection: %d connections, want one", n)
	}
}

func TestIAMT452_AReadIsRetriedOnceAndARefusalNever(t *testing.T) {
	cut := errors.New("admin: open channel: EOF")
	refused := &admin.CommandError{Code: "E_NOT_FOUND", Message: "no such recording"}
	for _, tc := range []struct {
		name  string
		fails []error // what each attempt answers, in order
		calls int
		want  error
	}{
		{"answered", []error{nil}, 1, nil},
		{"refused", []error{refused, nil}, 1, refused},
		{"cut, then answered", []error{cut, nil}, 2, nil},
		{"cut twice", []error{cut, cut, nil}, 2, cut},
	} {
		calls := 0
		err := retryOnceUnlessRefused(context.Background(), func() error {
			calls++
			return tc.fails[calls-1]
		})
		if calls != tc.calls || !errors.Is(err, tc.want) {
			t.Errorf("%s: %d attempts ending in %v, want %d ending in %v", tc.name, calls, err, tc.calls, tc.want)
		}
	}

	// A reader that went away is not read for again.
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := retryOnceUnlessRefused(ctx, func() error { calls++; cancel(); return cut })
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled read was attempted %d times and ended in %v", calls, err)
	}
}

func TestIAMT452_TheWindowLetsItsConnectionGoWhenNothingUsesIt(t *testing.T) {
	tg := startTestGateway(t, "alice")
	cs, signer, err := loadClientIdentity(iamt452AdminWindow(t, tg, "alice"))
	if err != nil {
		t.Fatal(err)
	}
	link := adminLink{idleAfter: 100 * time.Millisecond}
	t.Cleanup(link.reset)
	dials := 0
	link.dial = func(cs config.ConnString, s ssh.Signer) (*admin.Conn, error) {
		dials++
		return dialAdmin(cs, s)
	}

	// Held by an action: not idle, however long the action takes. A
	// lease handed back twice is handed back once.
	held, err := link.get(cs, signer)
	if err != nil {
		t.Fatal(err)
	}
	other, err := link.get(cs, signer)
	if err != nil {
		t.Fatal(err)
	}
	_ = other.Close()
	_ = other.Close()
	time.Sleep(5 * link.idleAfter)
	if _, err := held.Whoami(); err != nil {
		t.Fatalf("the connection was closed under an action still holding it: %v", err)
	}

	// Let go: closed once idle, and the next action dials again.
	_ = held.Close()
	deadline := time.Now().Add(5 * time.Second)
	for !held.Conn.Broken() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !held.Conn.Broken() {
		t.Fatalf("the window kept its connection open 5s after the last action let it go, want it closed after %s idle", link.idleAfter)
	}
	again, err := link.get(cs, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if dials != 2 {
		t.Fatalf("%d dials, want two: the first connection and one after it idled out", dials)
	}
	if _, err := again.Whoami(); err != nil {
		t.Fatalf("the connection after the idle close does not work: %v", err)
	}
}
