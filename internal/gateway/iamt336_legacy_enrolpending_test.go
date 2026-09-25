package gateway

// iamt336_legacy_enrolpending_test.go — the half of the 1.3 enrol
// rework that the rework itself left behind.
//
// Before 1.3 an invitation was stored on the machine it was minted for,
// in Machine.EnrolPending, and stateView.Resolve admitted that entry's
// ephemeral public key to the SSH handshake with role "enrol". 1.3
// moved every invitation to the unbound state.PendingEnrolments list
// and rewrote runEnrol to read ONLY that list ("runEnrol therefore
// always takes the PendingEnrolments path" — enrol_role.go).
//
// The reading half moved; the admitting half did not. Resolve still
// walks st.Machines and still hands out role "enrol" for any
// Machine.EnrolPending public key it finds — and the comment above it
// still says, correctly for 1.2 and wrongly for 1.3, that "the SSH
// handshake itself does not consult EnrolPending.Expires ... that
// expiry is enforced atomically when the exec body runs". Nothing
// enforces it now. Nothing consumes the entry, either: no code path in
// 1.3 clears Machine.EnrolPending.
//
// So a state.json written by 1.2 — an upgrade, which is the ordinary
// case, not a contrived one — leaves a key that authenticates to this
// gateway as role "enrol" forever, long past the expiry it was given.
// It cannot enrol anything (runEnrolFromPending finds no entry by
// secret hash and refuses) and the enrol role can run no other command
// (TestE2E_EnrolRoleCannotRunAnyOtherCommand), so this is not a way in.
// It is a credential that outlives its own expiry date and cannot be
// revoked by waiting, which is exactly the property the 15-minute TTL
// exists to guarantee, and it should not survive an upgrade.
//
// The fix is to stop admitting it: an invitation the gateway cannot
// redeem must not open a session. The dead field stays readable in
// state.json — validate.go still checks its shape, so a 1.2 file still
// loads — it is simply never honoured again.

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestIAMT336_LegacyEnrolPendingKeyIsNotAdmitted is the red-first test
// for the above. It seeds the state a 1.2 gateway would have written —
// a machine carrying an unconsumed Machine.EnrolPending — and requires
// the SSH handshake to refuse that ephemeral key.
//
// Canary: put the
//
//	if m.EnrolPending != nil { ... return Subject{m.ID, RoleEnrol} }
//
// branch back into stateView.Resolve's st.Machines loop (lookup.go) and
// this test goes red at "the legacy enrolPending key still
// authenticates".
func TestIAMT336_LegacyEnrolPendingKeyIsNotAdmitted(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.PublicHost = "127.0.0.1"
		cfg.PublicPort = 2222
	})

	const legacySecret = "a-1-2-era-invitation-secret-0123456789ab"
	eph, err := config.DeriveEphemeralSigner(legacySecret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("DeriveEphemeralSigner: %v", err)
	}
	ephPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(eph.PublicKey())))

	// Exactly what a 1.2 `machines.enrol-code vm1 MACHINE\svc` left on
	// disk — and still unexpired, so the refusal below cannot be
	// mistaken for an expiry check doing the work.
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			st.Machines[i].EnrolPending = &state.EnrolPending{
				SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(legacySecret)),
				PublicKey:  ephPub,
				Expires:    state.NewZonedTime(f.clock.Now().Add(time.Hour)),
			}
			return nil
		}
		t.Fatal("fixture seeded no machine to hang a legacy enrolPending on")
		return nil
	}); err != nil {
		t.Fatalf("seed legacy enrolPending: %v", err)
	}

	conn, derr := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            "enrol",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(eph)},
		HostKeyCallback: ssh.FixedHostKey(f.gw.HostKey().PublicKey()),
		Timeout:         5 * time.Second,
	})
	if derr == nil {
		_ = conn.Close()
		t.Fatal("the legacy enrolPending key still authenticates as role enrol — 1.3 can never redeem it and never clears it, so it is an invitation that outlives its own expiry and cannot be revoked by waiting")
	}
}

// TestIAMT336_AnUnboundInvitationIsStillAdmitted is the other side of
// the same coin, and the reason the fix has to be surgical rather than
// "stop resolving enrol keys". The live 1.3 path — an invitation in
// state.PendingEnrolments — must keep authenticating, or nothing can
// enrol at all.
//
// Canary: delete the st.PendingEnrolments loop from stateView.Resolve
// and this test goes red at "a freshly minted invitation was refused".
func TestIAMT336_AnUnboundInvitationIsStillAdmitted(t *testing.T) {
	f, c := iamt336Fixture(t)

	secret, _ := c.mint(t, "vm-invited")
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("DeriveEphemeralSigner: %v", err)
	}

	conn, derr := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            "enrol",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(eph)},
		HostKeyCallback: ssh.FixedHostKey(f.gw.HostKey().PublicKey()),
		Timeout:         5 * time.Second,
	})
	if derr != nil {
		t.Fatalf("a freshly minted invitation was refused at the handshake: %v", derr)
	}
	_ = conn.Close()
}
