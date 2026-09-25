package gateway

// iamt273_serve_close_race_test.go — the Serve/Close race (IAMT-273): a
// Close that managed to run before the Serve goroutine registered the
// listener had no right to leave Accept parked forever (the closed flag
// was already up, the second Close is a no-op, nobody was left to
// interrupt ln.Accept(); that is exactly how cmd/iamtunnel hung on
// timeout in TestIAMT258_ServiceHandlerStopsViaSCMStop).
//
// Both tests here reproduce this interleaving and do not hang together
// with the code they check: waiting for Serve to exit runs under its
// own timeout with t.Fatal -- a regression turns red within seconds
// instead of jamming the package for 10 minutes (the same rule as in
// shutdown_test.go).
//
// Before the fix TestServeAfterCloseReturnsAndClosesListener hung
// deterministically (Close finished entirely BEFORE Serve was entered --
// the limiting case of that same window) and
// TestServeAndCloseRaceNeverParksAccept hung in most interleavings.
// After the fix both are green; the maintainer additionally runs the
// package repeatedly (-race -count=20) -- the race is not caught on the
// first try.

import (
	"errors"
	"net"
	"testing"
	"time"
)

// serveWithin runs gw.Serve(ln) in a goroutine and fails the test by its OWN
// timeout if Serve does not return within limit.
func serveWithin(t *testing.T, gw *Gateway, ln net.Listener, limit time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- gw.Serve(ln) }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatal("Gateway.Serve did not return within " + limit.String() + " — Accept is parked forever (IAMT-273)")
		return nil
	}
}

// closeGatewayWithin runs gw.Close in a goroutine and fails the test by its
// OWN timeout if it does not return within limit (same guard as closeWithin
// in shutdown_test.go, for a gateway built without the full fixture).
func closeGatewayWithin(t *testing.T, gw *Gateway, limit time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- gw.Close() }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatal("Gateway.Close did not return within " + limit.String())
		return nil
	}
}

// TestServeAfterCloseReturnsAndClosesListener — the deterministic half
// of the IAMT-273 race: Close ran IN FULL before the first step of
// Serve (it saw g.ln == nil and could not close the listener), and only
// then does Serve receive ln. Before the fix such a Serve set g.ln and
// hung forever in ln.Accept(); after the fix Serve sees closed under
// the same mutex, closes the listener itself (otherwise the fd would
// leak) and returns with a non-nil error.
func TestServeAfterCloseReturnsAndClosesListener(t *testing.T) {
	store, log, hostKey := bareStoreAndLog(t, t.TempDir())
	gw, err := New(Config{Store: store, Log: log, HostKey: hostKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := closeGatewayWithin(t, gw, 5*time.Second); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := serveWithin(t, gw, ln, 5*time.Second); err == nil {
		t.Fatal("Serve after a completed Close must return a non-nil error, got nil")
	}

	// Serve must have closed the abandoned listener: a fresh Accept
	// answers exactly "use of closed network connection", the fd does not
	// leak.
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept on the listener Serve walked away from = %v, want net.ErrClosed -- the listener is not closed", err)
	}
}

// TestServeAndCloseRaceNeverParksAccept — the combat shape of the call
// (the same one as in gatewayServeWithSettings and in the IAMT-258
// Windows-service test): go Serve -- and immediately Close. Either
// side may win; Accept must finish in both orders. The loop catches
// the window many times in one run.
func TestServeAndCloseRaceNeverParksAccept(t *testing.T) {
	for i := 0; i < 25; i++ {
		store, log, hostKey := bareStoreAndLog(t, t.TempDir())
		gw, err := New(Config{Store: store, Log: log, HostKey: hostKey})
		if err != nil {
			t.Fatalf("iter %d: New: %v", i, err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("iter %d: listen: %v", i, err)
		}

		serveDone := make(chan error, 1)
		go func() { serveDone <- gw.Serve(ln) }()
		// Close races the listener registration in Serve -- the very
		// production window of "Stop arrived in the first milliseconds".
		if err := closeGatewayWithin(t, gw, 5*time.Second); err != nil {
			t.Fatalf("iter %d: Close: %v", i, err)
		}
		// Serve returns an error in either order: either its own Accept
		// error on the listener Closed underneath it, or (Close won) the
		// "gateway already closed" refusal.
		select {
		case err := <-serveDone:
			if err == nil {
				t.Fatalf("iter %d: Serve after Close must return a non-nil error, got nil", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iter %d: Serve did not return within 5s -- Accept parked forever (IAMT-273)", i)
		}
	}
}
