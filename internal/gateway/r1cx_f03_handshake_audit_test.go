package gateway

// F-03 (round-1 review, 24.09.2026): a connection that failed the SSH
// handshake before offering a single key - a scanner that drops after the
// version exchange, a client speaking only an auth method the gateway does
// not - reached AuthDenied with an empty fingerprint, and AuthDenied dropped
// it: the auth.failure validator demands a fingerprint, and none exists.
// The attempt left no trace in events.jsonl. Pre-key refusals are exactly
// what the opening move of a brute-force sweep looks like, and the journal
// that misses them records every key that was guessed but none of the
// sweeping.

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestR1CX_F03_AHandshakeFailureBeforeAnyKeyIsJournaled(t *testing.T) {
	f := newFixture(t, nil)

	// The scanner: a bare version exchange, then gone - no KEXINIT, no
	// userauth, no key. The gateway's handshake fails with nothing offered.
	raw, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := raw.Write([]byte("SSH-2.0-r1cx-f03-scan\r\n")); err != nil {
		t.Fatalf("write version: %v", err)
	}
	buf := make([]byte, 256)
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = raw.Read(buf) // the server's banner; the close below is the point
	_ = raw.Close()

	// The type is matched by its string literal, not by a constant: the
	// constant is what the fix adds, and this test must fail on the missing
	// journal fact, not on a compile error.
	want := events.EventType("auth.handshake_failure")
	var got *events.Event
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && got == nil {
		evs, _, rerr := f.log.Read(events.Filter{})
		if rerr == nil {
			for i := range evs {
				if evs[i].Type == want {
					got = &evs[i]
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got == nil {
		t.Fatalf("a connection that failed the handshake before offering any key left no trace in the journal: AuthDenied received an empty fingerprint and dropped the attempt because the auth.failure validator demands a fingerprint none exists to give - the sweep's opening move is invisible (F-03)")
	}
	if !strings.Contains(got.Address, "127.0.0.1") {
		t.Fatalf("handshake_failure address = %q, want the loopback address the scan came from (F-03)", got.Address)
	}
	if got.Fingerprint != "" {
		t.Fatalf("handshake_failure fingerprint = %q, want none: no key was ever offered, and inventing one to satisfy a validator would be fabrication (F-03)", got.Fingerprint)
	}
	if !strings.Contains(got.Result, "handshake") {
		t.Fatalf("handshake_failure result = %q, want the handshake failure reason (F-03)", got.Result)
	}
}
