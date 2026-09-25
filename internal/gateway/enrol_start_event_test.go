package gateway

// enrol_start_event_test.go covers the enrol.start part of IAMT-119:
// When a machine connects to the gateway with username "enrol" and its ephemeral key,
// the gateway must record an enrol.start event in events.jsonl marking the beginning
// of the registration process (PROTOCOL §7, §1.7).
//
// 1.3 (IAMT-336) changed who that event names, and the change is the
// whole point of the assertions below. The test used to seed a
// Machine.EnrolPending — an invitation bound to a machine — and require
// the event to name that machine as both actor and object. There is no
// bound machine any more: an invitation names nobody, and the machine
// does not say what it is called until the exec body arrives, which is
// after this event is written. Written unchanged, the event would carry
// an empty actor and an empty object, and an auditor would find a row
// of blanks for every enrol session ever opened.
//
// So the actor is now the invitation's own key fingerprint: the single
// fact the handshake actually established, shared with the
// machines.enrol-code entry that minted it, and different for every
// invitation — which is what makes one session tellable from another.

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestEnrolStartWritesJournalEvent(t *testing.T) {
	f := newFixture(t, nil)

	const secret = "test-enrol-secret-1234567890"
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}
	ephPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(eph.PublicKey())))
	wantActor, err := state.ComputeFingerprint(ephPub)
	if err != nil {
		t.Fatalf("fingerprint the ephemeral key: %v", err)
	}

	// One unbound invitation, exactly as machines.enrol-code mints it.
	err = f.store.Update(func(st *state.State) error {
		st.PendingEnrolments = append(st.PendingEnrolments, state.PendingEnrolment{
			SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(secret)),
			PublicKey:  ephPub,
			Expires:    state.NewZonedTime(f.clock.Now().Add(time.Hour)),
		})
		return nil
	})
	if err != nil {
		t.Fatalf("seed pending enrolment: %v", err)
	}

	cfg := &ssh.ClientConfig{
		User:            "enrol",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(eph)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", f.addr, cfg)
	if err != nil {
		t.Fatalf("dial as enrol: %v", err)
	}
	defer client.Close()

	waitUntil(t, "journal did not record enrol.start event", func() bool {
		evs, _, rerr := f.log.Read(events.Filter{Types: []events.EventType{events.EventEnrolStart}})
		if rerr != nil {
			return false
		}
		return len(evs) >= 1
	})

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventEnrolStart}})
	if err != nil {
		t.Fatalf("failed reading journal: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected exactly 1 enrol.start event, got %d", len(evs))
	}

	e := evs[0]
	if e.Type != events.EventEnrolStart {
		t.Fatalf("event.Type = %q, want %q", e.Type, events.EventEnrolStart)
	}
	if e.Actor != wantActor {
		t.Fatalf("event.Actor = %q, want the invitation's key fingerprint %q — with no machine name in existence yet, this is the only thing that tells one enrol session from another", e.Actor, wantActor)
	}
	if e.Object != "" {
		t.Fatalf("event.Object = %q, want \"\": nothing has been enrolled at this point and naming an object here would be inventing one", e.Object)
	}
	if e.Result != "started" {
		t.Fatalf("event.Result = %q, want 'started'", e.Result)
	}
}
