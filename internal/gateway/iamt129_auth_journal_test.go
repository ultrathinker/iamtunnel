package gateway

// iamt129_auth_journal_test.go verifies IAMT-129 requirement 129-3:
// When a client with a valid registered person key attempts an SSH login
// with the reserved username "machine", the SSH handshake is refused and
// the event journal records an auth.failure event whose result field
// explicitly carries the protocol rejection code E_NAME_RESERVED.

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestAuthDenied_ReservedUsernameProducesE_NAME_RESERVEDInJournal(t *testing.T) {
	f := newFixture(t, nil)

	aliceFP := fingerprintOf(t, f.personKey.PublicKey())

	cfg := &ssh.ClientConfig{
		User:            "machine",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(f.personKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// Dial with alice's registered key but reserved username "machine": handshake MUST fail.
	client, err := ssh.Dial("tcp", f.addr, cfg)
	if err == nil {
		client.Close()
		t.Fatal("dial with reserved username 'machine' unexpectedly succeeded")
	}

	waitUntil(t, "journal did not record auth.failure event", func() bool {
		evs, _, rerr := f.log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
		if rerr != nil {
			return false
		}
		return len(evs) >= 1
	})

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
	if err != nil {
		t.Fatalf("failed reading journal: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected exactly 1 auth.failure event in journal, got %d", len(evs))
	}

	e := evs[0]
	if e.Fingerprint != aliceFP {
		t.Fatalf("journal auth.failure fingerprint = %q, want alice key %q", e.Fingerprint, aliceFP)
	}
	if e.Actor != "machine" {
		t.Fatalf("journal auth.failure actor = %q, want 'machine'", e.Actor)
	}
	if e.Object != "machine" {
		t.Fatalf("journal auth.failure object = %q, want 'machine'", e.Object)
	}
	if !strings.Contains(e.Result, "E_NAME_RESERVED") {
		t.Fatalf("journal auth.failure result = %q, want containing 'E_NAME_RESERVED'", e.Result)
	}
}
