package gateway

// IAMT-447: the SSH username of a login that failed went into the journal
// as it came - into auth.failure's actor, its object, and its result,
// where most refusals quote it again. Nothing had authenticated at that
// point: whoever could reach the port chose the size of the entry, up to
// an SSH packet (256 KiB), once per key offered, and events.jsonl is
// append-only and fsynced per entry. The enrol role has bounded its
// caller-supplied strings with clipForJournal since 1.3; auth did not.

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestIAMT447_AFailedLoginsUsernameIsBoundedInTheJournal(t *testing.T) {
	f := newFixture(t, nil)

	huge := strings.Repeat("a", 100*1024) + ":" + f.machineID
	cfg := &ssh.ClientConfig{
		User:            huge,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(genSigner(t))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	if c, err := dialHumanClient(f.addr, cfg); err == nil {
		c.Close()
		t.Fatal("a login with an unknown key was accepted")
	}

	var evs []events.Event
	waitUntil(t, "no auth.failure entry for the refused login", func() bool {
		var err error
		evs, _, err = f.log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
		return err == nil && len(evs) > 0
	})
	// 65 bytes is the longest username PROTOCOL §2.1 accepts (two 32-byte
	// parts and the colon); what a refusal says around it stays short.
	for _, e := range evs {
		if len(e.Actor) > 128 || len(e.Object) > 128 {
			t.Errorf("auth.failure carries the %d-byte username as it came: actor %d bytes, object %d bytes", len(huge), len(e.Actor), len(e.Object))
		}
		if len(e.Result) > 512 {
			t.Errorf("auth.failure's result is %d bytes: the refusal quotes the username unbounded", len(e.Result))
		}
	}
}
