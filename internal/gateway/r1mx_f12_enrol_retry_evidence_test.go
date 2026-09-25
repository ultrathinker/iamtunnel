package gateway

// F-12 of the round-1 review (24.09.2026) says an already
// registered machine that tries to enrol again is answered
// E_ENROL_SECRET_USED with nothing in the journal to tell "our machine
// came back" from "somebody stole the one-shot code".
//
// Neither half of that is how the code behaves, and this test is the
// evidence:
//
//   - a spent invitation cannot reach the exec at all. The enrol-login
//     handshake resolves the ephemeral key against the pending entry
//     (lookup.go), so once the entry is redeemed the retry is refused at
//     the handshake and recorded as auth.failure for the login literal
//     "enrol" with the offered key's fingerprint - not as E_ENROL_SECRET_USED
//     and not as the replay alarm;
//   - E_ENROL_SECRET_USED is reachable only when the entry WAS there for
//     the handshake and is gone by the time the body is read (a race
//     between two holders of one invitation, or a revocation in between),
//     which is what its Result "replay" means;
//   - a machine that really is already registered meets the name
//     collision, and that refusal is journaled with the collision and its
//     remedy in the entry (enrol_role.go: "the name %q is already
//     registered ... must remove the old record first").
//
// Nothing was changed for this finding.

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func r1mxF12Pending(t *testing.T, f *fixture, name, secret string) ssh.Signer {
	t.Helper()
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive the ephemeral signer: %v", err)
	}
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(eph.PublicKey())))
	if err := f.store.Update(func(st *state.State) error {
		st.PendingEnrolments = append(st.PendingEnrolments, state.PendingEnrolment{
			Name:       name,
			SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(secret)),
			PublicKey:  pub,
			Expires:    state.NewZonedTime(f.clock.Now().Add(time.Hour)),
		})
		return nil
	}); err != nil {
		t.Fatalf("mint the pending enrolment: %v", err)
	}
	return eph
}

func TestR1MXF12_ARetriedInvitationIsRecordedAsAFailedLoginNotAsAReplay(t *testing.T) {
	f := newFixture(t, nil)
	const secret = "r1mx-f12-invitation"
	eph := r1mxF12Pending(t, f, "pc-f12", secret)
	machineKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))

	first := doEnrolViaWire(t, f, eph, secret, "", `MACHINE\svc`, machineKey)
	if !strings.Contains(first, `"enrolled"`) {
		t.Fatalf("the first enrol was not accepted: %q", first)
	}

	machinesAfterFirst := len(f.store.Get().Machines)

	// The same invitation, again: the machine key is the same, the secret
	// is the same, and the entry is gone.
	second := doEnrolViaWire(t, f, eph, secret, "", `MACHINE\svc`, machineKey)
	if second != "" {
		t.Fatalf("the retry reached the exec and answered %q; a spent invitation cannot pass the handshake", second)
	}

	// What the retry left behind: a failed login for the enrol literal,
	// carrying the offered key. That is the line an operator reads to see
	// a machine trying an invitation that has already been used.
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
	if err != nil {
		t.Fatalf("read the auth.failure journal: %v", err)
	}
	fp := fingerprintOf(t, eph.PublicKey())
	found := false
	for _, e := range evs {
		if e.Actor == "enrol" && e.Fingerprint == fp {
			found = true
		}
	}
	if !found {
		t.Errorf("the retried invitation left no auth.failure naming the enrol login and the offered key (%s); the journal is where the leak question is answered: %+v", fp, evs)
	}

	// And it is not the replay alarm: that word belongs to the race the
	// code documents, where the entry was live for the handshake and gone
	// for the body. No second machine came of it either.
	replays, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventEnrolFailed}})
	if err != nil {
		t.Fatalf("read the enrol.failed journal: %v", err)
	}
	for _, e := range replays {
		if e.Result == "replay" {
			t.Errorf("a retried invitation was journaled as a replay (%+v): the replay is the leak indicator, and a machine asking twice is not a leak", e)
		}
	}
	if machines := f.store.Get().Machines; len(machines) != machinesAfterFirst {
		t.Errorf("the retried invitation produced %d machine records, want the %d the first attempt left: %+v", len(machines), machinesAfterFirst, machines)
	}
}

func TestR1MXF12_AnAlreadyRegisteredNameIsRefusedInWordsThatSaySo(t *testing.T) {
	f := newFixture(t, nil)
	const secret = "r1mx-f12-first"
	eph := r1mxF12Pending(t, f, "pc-f12b", secret)
	machineKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
	if first := doEnrolViaWire(t, f, eph, secret, "", `MACHINE\svc`, machineKey); !strings.Contains(first, `"enrolled"`) {
		t.Fatalf("the first enrol was not accepted: %q", first)
	}

	// A NEW invitation for the name that is now taken - the reinstalled
	// machine's ordinary path (enrol_role.go).
	const second = "r1mx-f12-second"
	eph2 := r1mxF12Pending(t, f, "pc-f12b", second)
	otherKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
	resp := doEnrolViaWire(t, f, eph2, second, "", `MACHINE\svc`, otherKey)
	if !strings.Contains(resp, "E_ENROL_SECRET_INVALID") {
		t.Fatalf("an invitation for a name that is already registered answered %q, want E_ENROL_SECRET_INVALID", resp)
	}

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventEnrolFailed}})
	if err != nil {
		t.Fatalf("read the enrol.failed journal: %v", err)
	}
	named := ""
	for _, e := range evs {
		if e.Result != "invalid" {
			continue
		}
		if msg, _ := e.Details["errMsg"].(string); strings.Contains(msg, "already registered") {
			named = msg
		}
	}
	if named == "" {
		t.Errorf("the journal does not say a name was already registered, so an operator cannot tell this from a mistyped secret: %+v", evs)
	}
	if !strings.Contains(named, "machines remove") {
		t.Errorf("the entry names the collision but not the remedy the machine's owner needs: %q", named)
	}
}
