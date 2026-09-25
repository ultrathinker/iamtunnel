package client

// bridge_test.go is an internal (white-box) test: it calls the
// unexported bridgeFirstThenForward directly so the ordering guarantee
// is pinned at the exact function it lives in, with no SSH, no network
// and no timing flakiness beyond one short, generous window.

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe for concurrent Write/String, needed
// because the keyboard-forwarding goroutine writes to it from its own
// goroutine while the test reads it from the main one.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestBannerReachesScreenBeforeAnyInputIsForwarded is written to break if
// the banner ever moves to after input: the "keyboard" is ready with a
// byte from the very first instant, and
// the "gateway" side (toGateway) is watched for that byte arriving before
// the banner is ever sent. A correct implementation cannot let that
// happen because it has not even looked at the keyboard reader yet.
func TestBannerReachesScreenBeforeAnyInputIsForwarded(t *testing.T) {
	fromGatewayR, fromGatewayW := io.Pipe()
	toGateway := &syncBuffer{}
	screen := &syncBuffer{}
	// bytes.Reader is ready from the first Read, just as a person who has
	// already typed a byte would be, but ends after that byte. The finite
	// input is important: bridgeFirstThenForward copies keyboard input in a
	// goroutine, and an endless source would leave that goroutine appending to
	// syncBuffer forever after this test finishes.
	keyboard := bytes.NewReader([]byte("X"))

	done := make(chan error, 1)
	go func() {
		done <- bridgeFirstThenForward(screen, fromGatewayR, toGateway, keyboard)
	}()

	// Give a broken implementation (one that starts forwarding the
	// keyboard concurrently with the first gateway read) a generous
	// window to leak a byte into toGateway before the banner is even
	// sent. A correct implementation cannot write here at all yet: it is
	// blocked on the single Read from fromGatewayR below.
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		if toGateway.String() != "" {
			t.Fatalf("input reached the gateway before the banner was ever sent: toGateway=%q", toGateway.String())
		}
		time.Sleep(2 * time.Millisecond)
	}

	const banner = "This session is recorded. Machine win01, until 2026-09-12T12:00:00Z.\r\n"
	if _, err := fromGatewayW.Write([]byte(banner)); err != nil {
		t.Fatalf("write banner: %v", err)
	}

	waitFor(t, "banner did not reach the screen", func() bool {
		return screen.String() == banner
	})
	waitFor(t, "keyboard input was never forwarded once the banner had shown", func() bool {
		return toGateway.String() != ""
	})

	_ = fromGatewayW.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bridgeFirstThenForward: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bridgeFirstThenForward did not return after the gateway side closed")
	}
}

func TestBridgeReturnsCleanlyOnImmediateEOF(t *testing.T) {
	fromGateway := io.NopCloser(bytes.NewReader(nil)) // immediate EOF, no bytes
	toGateway := &syncBuffer{}
	screen := &syncBuffer{}
	keyboard := bytes.NewReader([]byte("X"))

	err := bridgeFirstThenForward(screen, fromGateway, toGateway, keyboard)
	if err != nil {
		t.Fatalf("bridgeFirstThenForward on immediate EOF: %v", err)
	}
	if screen.String() != "" {
		t.Fatalf("screen got bytes from an empty gateway side: %q", screen.String())
	}
}

func waitFor(t *testing.T, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}
