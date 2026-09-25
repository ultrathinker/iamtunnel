package gateway

// hostkey_mismatch_event_test.go covers the first part of IAMT-119:
// When the gateway connects to a target machine's sshd over iamtunnel-target
// and the presented host key does not match the pinned SSHDHostKey, the gateway
// must refuse the session and record an event of type hostkey.mismatch in events.jsonl
// (PROTOCOL §5, §1.7).

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestHostKeyMismatchWritesJournalEvent(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// Replace the fake sshd signer with a different one to simulate a machine host key mismatch.
	differentSigner := genSigner(t)
	f.sshd.setSigner(differentSigner)
	observedFP := auth.Fingerprint(differentSigner.PublicKey())

	// Read the original pinned fingerprint from state.
	st := f.store.Get()
	m, ok := st.MachineByID(f.machineID)
	if !ok || m.SSHDHostKey == nil {
		t.Fatalf("machine %s or its SSHDHostKey not found in state", f.machineID)
	}
	pinnedFP, err := state.ComputeFingerprint(*m.SSHDHostKey)
	if err != nil {
		t.Fatalf("compute pinned fingerprint: %v", err)
	}

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer client.Close()

	// Opening the session will trigger the gateway to open the door and perform the nested
	// SSH handshake to sshd, where HostKeyCallback detects the mismatch and rejects it.
	ch, _, err := client.OpenChannel("session", nil)
	if err == nil {
		ch.Close()
	}

	waitUntil(t, "journal did not record hostkey.mismatch event", func() bool {
		evs, _, rerr := f.log.Read(events.Filter{Types: []events.EventType{events.EventHostKeyMismatch}})
		if rerr != nil {
			return false
		}
		return len(evs) >= 1
	})

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventHostKeyMismatch}})
	if err != nil {
		t.Fatalf("failed reading journal: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected exactly 1 hostkey.mismatch event for %s, got %d", f.machineID, len(evs))
	}

	e := evs[0]
	if e.Type != events.EventHostKeyMismatch {
		t.Fatalf("event.Type = %q, want %q", e.Type, events.EventHostKeyMismatch)
	}
	if e.Object != f.machineID {
		t.Fatalf("event.Object = %q, want %q", e.Object, f.machineID)
	}
	if e.Actor != f.person {
		t.Fatalf("event.Actor = %q, want %q", e.Actor, f.person)
	}
	if e.Result != "mismatch" {
		t.Fatalf("event.Result = %q, want 'mismatch'", e.Result)
	}
	if e.Fingerprint != observedFP {
		t.Fatalf("event.Fingerprint = %q, want %q", e.Fingerprint, observedFP)
	}
	if e.Details["observed"] != observedFP {
		t.Fatalf("event.Details[observed] = %v, want %q", e.Details["observed"], observedFP)
	}
	if e.Details["pinned"] != pinnedFP {
		t.Fatalf("event.Details[pinned] = %v, want %q", e.Details["pinned"], pinnedFP)
	}
}
