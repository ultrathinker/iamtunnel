package sshx

// chanconn_test.go: tests for the net.Conn wrapper over ssh.Channel.
//
// A helper fake-sshd starts on 127.0.0.1, accepts "session" and
// echoes traffic. This lets us check the real behavior of
// Read/Write/Close/SetDeadline on a live ssh.Channel with no dependencies.

import (
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// echoFarewell — the echo server appends this AFTER it has seen EOF
// from the client. These bytes arrive after the half-close, so a swap
// of CloseWrite for a full Close fails to deliver them: that is
// exactly what catches the swap.
const echoFarewell = "BYE"

// --- helpers ---------------------------------------------------------------

// startEchoSSHD starts a TCP listener and serves an arbitrary number
// of connections and channels: every accepted session channel echoes
// bytes. No need to wait for "readiness": OpenChannel only returns
// after the server has accepted the channel.
func startEchoSSHD(t *testing.T) net.Listener {
	t.Helper()
	signer := mustSigner(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				cfg := &ssh.ServerConfig{NoClientAuth: true, ServerVersion: "SSH-2.0-echo"}
				cfg.AddHostKey(signer)
				conn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				for n := range chans {
					if n.ChannelType() != "session" {
						_ = n.Reject(ssh.UnknownChannelType, "only session")
						continue
					}
					ch, chReqs, err := n.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(chReqs)
					go func() {
						defer ch.Close()
						_, _ = io.Copy(ch, ch)
						// The client closed its half; our half is still alive.
						_, _ = ch.Write([]byte(echoFarewell))
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return ln
}

func dialEchoSession(t *testing.T, addr string) ssh.Channel {
	t.Helper()
	conn, err := ssh.Dial("tcp", addr, insecureClientConfig("u"))
	if err != nil {
		t.Fatal(err)
	}
	ch, reqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	go ssh.DiscardRequests(reqs)
	t.Cleanup(func() {
		_ = ch.Close()
		_ = conn.Close()
	})
	return ch
}

// echoConn — a ready wrapper over a live echo channel.
func echoConn(t *testing.T) *ChannelConn {
	t.Helper()
	ln := startEchoSSHD(t)
	return NewChannelConn(dialEchoSession(t, ln.Addr().String()))
}

// --- the net.Conn contract ---------------------------------------------------

// TestChannelConn_ImplementsNetConn — the type is declared as net.Conn and handed to
// ssh.NewClientConn; the check must be in the tests, not just in a comment.
func TestChannelConn_ImplementsNetConn(t *testing.T) {
	var c net.Conn = NewChannelConn(nil)
	_ = c
}

// TestErrDeadlineExceededIsNetError — io.Copy over network wrappers,
// http.Transport, and bufio recognize a timeout via net.Error.Timeout().
// It used to be a plain errors.New, and every such caller saw the
// timeout as a fatal error.
func TestErrDeadlineExceededIsNetError(t *testing.T) {
	var err error = ErrDeadlineExceeded
	ne, ok := err.(net.Error)
	if !ok {
		t.Fatalf("ErrDeadlineExceeded (%T) does not implement net.Error", err)
	}
	if !ne.Timeout() {
		t.Fatal("net.Error.Timeout() == false")
	}
	wrapped := &net.OpError{Op: "read", Err: ErrDeadlineExceeded}
	if !errors.Is(wrapped, ErrDeadlineExceeded) {
		t.Fatal("errors.Is does not find ErrDeadlineExceeded inside the wrapper")
	}
}

// TestChannelConn_ExpiredReadDeadlineReturnsTimeout — an expired
// deadline yields exactly ErrDeadlineExceeded, which is itself a net.Error.
func TestChannelConn_ExpiredReadDeadlineReturnsTimeout(t *testing.T) {
	cc := echoConn(t)
	if err := cc.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := cc.Read(make([]byte, 1))
	if !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("not ErrDeadlineExceeded: %v", err)
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("read error is not a Timeout: %T %v", err, err)
	}
}

func TestChannelConn_ExpiredWriteDeadlineReturnsTimeout(t *testing.T) {
	cc := echoConn(t)
	if err := cc.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := cc.Write([]byte{1})
	if !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("not ErrDeadlineExceeded: %v", err)
	}
}

func TestChannelConn_SetDeadlineExpired(t *testing.T) {
	cc := echoConn(t)
	if err := cc.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Read(make([]byte, 1)); !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("read after expired SetDeadline: %v", err)
	}
	if _, err := cc.Write([]byte{1}); !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("write after expired SetDeadline: %v", err)
	}
}

// TestChannelConn_ReadDeadlineDoesNotAffectWrite — a direct requirement
// of net.Conn: read and write deadlines are independent. The expired
// flag used to be a single one for both directions, and an expired
// read deadline used to kill Write.
func TestChannelConn_ReadDeadlineDoesNotAffectWrite(t *testing.T) {
	cc := echoConn(t)
	if err := cc.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Write([]byte("still writable")); err != nil {
		t.Fatalf("read deadline killed Write: %v", err)
	}
	if _, err := cc.Read(make([]byte, 1)); !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("read deadline did not fire: %v", err)
	}
}

// TestChannelConn_WriteDeadlineDoesNotAffectRead — the reverse side of the same.
func TestChannelConn_WriteDeadlineDoesNotAffectRead(t *testing.T) {
	cc := echoConn(t)
	if _, err := cc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := cc.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(cc, buf); err != nil {
		t.Fatalf("write deadline killed Read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo corrupted: %q", buf)
	}
	if _, err := cc.Write([]byte{1}); !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("write deadline did not fire: %v", err)
	}
}

// TestChannelConn_SoftDeadlineIsRecoverable — the ordinary net.Conn
// idiom for any heartbeat loop: short deadline, timeout, clear the
// deadline, keep working. The timer used to close the channel for
// good, destroying the connection.
func TestChannelConn_SoftDeadlineIsRecoverable(t *testing.T) {
	cc := echoConn(t)
	if err := cc.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if _, err := cc.Read(make([]byte, 1)); !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("soft timeout did not fire: %v", err)
	}
	// Clear the deadline — the connection must remain usable.
	if err := cc.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Write([]byte("alive")); err != nil {
		t.Fatalf("Write does not work after the deadline was cleared: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(cc, buf); err != nil || string(buf) != "alive" {
		t.Fatalf("Read does not work after the deadline was cleared: %v %q", err, buf)
	}
}

// TestChannelConn_BlockedReadIsInterruptedWithTimeout — if someone is
// blocked in Read when the deadline expires, the only way to interrupt
// it is by closing the channel. The caller must see a timeout, not an
// anonymous close error.
func TestChannelConn_BlockedReadIsInterruptedWithTimeout(t *testing.T) {
	cc := echoConn(t)
	done := make(chan error, 1)
	go func() {
		_, err := cc.Read(make([]byte, 1))
		done <- err
	}()
	// Let the read block.
	time.Sleep(20 * time.Millisecond)
	if err := cc.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrDeadlineExceeded) {
			t.Fatalf("blocked Read returned %v, want ErrDeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked Read did not return after the timer fired")
	}
}

// TestChannelConn_NoTimerAfterClose — SetDeadline on a closed
// connection is allowed (http.Transport does this when returning a
// connection to the pool) and must not arm a timer: there would be no
// way left to cancel it, and it holds a reference to the channel for
// the whole deadline period.
func TestChannelConn_NoTimerAfterClose(t *testing.T) {
	cc := echoConn(t)
	if err := cc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cc.SetDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := cc.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := cc.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.rtimer != nil || cc.wtimer != nil {
		t.Fatalf("SetDeadline armed a timer after Close(): rtimer=%v wtimer=%v", cc.rtimer != nil, cc.wtimer != nil)
	}
}

// TestChannelConn_CloseIsIdempotent — a repeated call returns nil.
func TestChannelConn_CloseIsIdempotent(t *testing.T) {
	cc := echoConn(t)
	for i := 0; i < 3; i++ {
		if err := cc.Close(); err != nil {
			t.Fatalf("Close #%d returned %v", i+1, err)
		}
	}
}

// TestChannelConn_CloseWriteDoesNotFullyClose — a half-close: after
// CloseWrite, reading keeps delivering data. The previous test only
// checked that LocalAddr/RemoteAddr were not nil, and stayed green
// even if CloseWrite were swapped for a full Close.
func TestChannelConn_CloseWriteDoesNotFullyClose(t *testing.T) {
	cc := echoConn(t)
	msg := []byte("half-close payload")
	if _, err := cc.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := cc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(cc)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("reading after CloseWrite did not deliver data: %v", err)
	}
	// The echo of what was sent plus the bytes the peer appended AFTER
	// our EOF: if CloseWrite closed the whole channel, the second half
	// would not be there.
	want := string(msg) + echoFarewell
	if string(got) != want {
		t.Fatalf("after CloseWrite got %q, want %q", got, want)
	}
}

// TestChannelConn_LocalAndRemoteAddr — the addresses are dummies, but
// stable: the caller writes them into the session log.
func TestChannelConn_LocalAndRemoteAddr(t *testing.T) {
	cc := echoConn(t)
	l, r := cc.LocalAddr(), cc.RemoteAddr()
	if l.Network() != "ssh" || l.String() != channelLocal {
		t.Fatalf("LocalAddr = %s/%s, want ssh/%s", l.Network(), l.String(), channelLocal)
	}
	if r.Network() != "ssh" || r.String() != channelRemote {
		t.Fatalf("RemoteAddr = %s/%s, want ssh/%s", r.Network(), r.String(), channelRemote)
	}
	if l.String() == r.String() {
		t.Fatal("LocalAddr and RemoteAddr are equal")
	}
}

// TestChannelConn_CloseRacesWithReadAndDeadline — Read ‖ SetDeadline ‖ Close
// under -race.
func TestChannelConn_CloseRacesWithReadAndDeadline(t *testing.T) {
	ln := startEchoSSHD(t)
	for i := 0; i < 20; i++ {
		ch := dialEchoSession(t, ln.Addr().String())
		cc := NewChannelConn(ch)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); _, _ = cc.Read(make([]byte, 16)) }()
		go func() { defer wg.Done(); _ = cc.SetDeadline(time.Now().Add(time.Millisecond)) }()
		go func() { defer wg.Done(); _ = cc.Close() }()
		wg.Wait()
	}
}

// TestChannelConn_NoGoroutineLeak — a hundred open-work-close cycles
// leave no goroutines behind: deadline timers are cancelled, channels are closed.
func TestChannelConn_NoGoroutineLeak(t *testing.T) {
	ln := startEchoSSHD(t)
	cycle := func() {
		conn, err := ssh.Dial("tcp", ln.Addr().String(), insecureClientConfig("u"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ch, reqs, err := conn.OpenChannel("session", nil)
		if err != nil {
			t.Fatal(err)
		}
		go ssh.DiscardRequests(reqs)
		cc := NewChannelConn(ch)
		_ = cc.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := cc.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(cc, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		_ = cc.Close()
	}
	for i := 0; i < 5; i++ {
		cycle()
	}
	settle := func() int {
		for i := 0; i < 50; i++ {
			runtime.GC()
			time.Sleep(10 * time.Millisecond)
		}
		return runtime.NumGoroutine()
	}
	before := settle()
	for i := 0; i < 100; i++ {
		cycle()
	}
	after := settle()
	if after > before+10 {
		t.Fatalf("goroutines before 100 cycles: %d, after: %d", before, after)
	}
}
