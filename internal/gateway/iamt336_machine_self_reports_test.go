package gateway

// iamt336_machine_self_reports_test.go — IAMT-336 / 1.3 phase 3.
//
// The gateway half of the new enrol flow:
//
//   1. `machines.enrol-code` takes no arguments. The invitation is not
//      bound to a machine name or to an OS user. Its TTL is 15 minutes.
//   2. The enrolling machine dials as "enrol", sends the secret
//      together with its own hostname and the OS account its server
//      process is running as, and the gateway records those as the
//      new machine's name and as requestedOsUser.
//   3. Nothing else about trust changes: the secret is still burned
//      in the same atomic state write as the result; requestedOsUser
//      is still never used for login or for admitting a person; the
//      machine still goes to state "enrolled" with osUserStatus
//      "pending", and only the gateway's own SSH public-key user-auth
//      probe on the target sshd (SPEC §3.4 step 3) may set
//      verifiedOsUser and osUserStatus="verified".
//   4. A claimed name that collides with an existing machine must
//      not silently take that machine's identity.
//
// Each behaviour of the machine self-report has its own test below. The
// canary comments name the precise
// change that turns the test red — so a future regression is localised
// to one line in runEnrolFromPending or its helpers.

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// iamt336Fixture wires a fresh gateway with the public-host/port
// properties cmdMachinesEnrolCode's enrol-code URL needs to parse
// (the test dials f.addr directly, so the values only have to render
// a valid URL). It also returns the dialed admin.Conn the rest of the
// IAMT-336 tests share.
func iamt336Fixture(t *testing.T) (*fixture, *adminClient) {
	t.Helper()
	f := newFixture(t, func(cfg *Config) {
		cfg.PublicHost = "127.0.0.1"
		cfg.PublicPort = 2222
	})
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)
	return f, &adminClient{root: root, f: f}
}

// adminClient is the small bundle a single test needs to drive
// both ends of the enrol flow: the admin wire (for `machines.enrol-
// code`) and the SSH handshake (for the actual `enrol` exec).
type adminClient struct {
	root *admin.Conn
	f    *fixture
}

// mint dials `machines.enrol-code` and returns (secret, expires, error).
func (c *adminClient) mint(t *testing.T, name string) (string, string) {
	t.Helper()
	code, expires, err := c.root.MachinesInvite(name)
	if err != nil {
		t.Fatalf("machines.enrol-code: %v", err)
	}
	parsed, err := config.ParseEnrolCode(code)
	if err != nil {
		t.Fatalf("ParseEnrolCode(%q): %v", code, err)
	}
	return parsed.Secret, expires
}

// TestIAMT336_MintNoArgs_ProducesUsableCode exercises requirement 1:
//
// "The invitation carries no machine name and no OS user. Minting one
// takes no arguments at all. Its TTL becomes 15 minutes."
//
// We mint a code via the no-arg admin command, parse it back through
// the same wire shape the CLI parses, and assert that the only
// authoritative inputs the gateway kept were a 32-byte secret hash, an
// ephemeral public key, and an expiry — no machine name, no osUser.
//
// Canary: revert cmdMachinesEnrolCode to require `machine` and
// `osUser` body fields (with `omitempty` removed) — and this test goes
// red at the MachinesInvite call (wire refusal).
func TestIAMT336_MintNoArgs_ProducesUsableCode(t *testing.T) {
	f, c := iamt336Fixture(t)

	_, expires := c.mint(t, "vm-invited")
	gotExpiry, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		t.Fatalf("expires %q is not RFC3339: %v", expires, err)
	}
	wantExpiry := f.clock.Now().Add(15 * time.Minute)
	delta := gotExpiry.Sub(wantExpiry)
	if delta < -time.Second || delta > time.Second {
		t.Fatalf("enrol-code expires = %s, want ~%s (15 minutes from now)", gotExpiry, wantExpiry)
	}

	// The pending entry carries the NAME the administrator chose and
	// NO osUser. That split is the 1.4 design: he could name the
	// registration, he could not have known the machine's account.
	st := f.store.Get()
	if len(st.PendingEnrolments) != 1 {
		t.Fatalf("state.PendingEnrolments len = %d, want 1", len(st.PendingEnrolments))
	}
	pe := st.PendingEnrolments[0]
	if pe.Name != "vm-invited" {
		t.Fatalf("PendingEnrolment.Name = %q, want the name the administrator minted it under", pe.Name)
	}
	if pe.OSUser != "" {
		t.Fatalf("PendingEnrolment.OSUser = %q, want \"\" — the account is the machine's own report, not a binding", pe.OSUser)
	}
	if pe.PublicKey == "" || pe.SecretHash == [32]byte{} {
		t.Fatalf("PendingEnrolment missing publicKey or secretHash: %+v", pe)
	}
	if pe.Expires.IsZero() {
		t.Fatalf("PendingEnrolment.Expires is zero: %+v", pe)
	}
}

// TestIAMT336_Consume_RecordsMachineOwnFacts exercises requirement 2
// end-to-end: a machine dials as "enrol", sends the secret + its
// hostname + the OS user its server runs as, and the gateway records
// those as the new machine's name and as requestedOsUser.
//
// Canary: revert runEnrolFromPending to "use the binding" (i.e. read
// pe.OSUser into the new Machine.OSUser / RequestedOSUser instead of
// req.OSUser) and this test goes red on the RequestedOSUser
// assertion.
func TestIAMT336_Consume_RecordsMachineOwnFacts(t *testing.T) {
	f, c := iamt336Fixture(t)

	secret, _ := c.mint(t, "vm-win-01")
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("DeriveEphemeralSigner: %v", err)
	}

	// The name is the administrator's, carried by the invitation.
	const claimedName = "vm-win-01"
	const claimedOSUser = `DESKTOP-I3FL2S5\Admin`
	machineKeyPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))

	resp := doEnrolViaWire(t, f, eph, secret, "", claimedOSUser, machineKeyPubLine)
	if !strings.Contains(resp, `"state":"enrolled"`) {
		t.Fatalf("enrol response missing state=enrolled: %q", resp)
	}
	if !strings.Contains(resp, `"machine":"`+claimedName+`"`) {
		t.Fatalf("enrol response missing machine id %q: %q", claimedName, resp)
	}

	// The machine record carries EXACTLY the values the machine sent.
	st := f.store.Get()
	m, ok := st.MachineByID(claimedName)
	if !ok {
		t.Fatalf("machine %q not in state after enrol", claimedName)
	}
	if m.ID != claimedName {
		t.Fatalf("machine.ID = %q, want %q", m.ID, claimedName)
	}
	if m.Name != claimedName {
		t.Fatalf("machine.Name = %q, want %q", m.Name, claimedName)
	}
	if m.RequestedOSUser != claimedOSUser {
		t.Fatalf("machine.RequestedOSUser = %q, want %q", m.RequestedOSUser, claimedOSUser)
	}
	// requestedOsUser is NOT yet verifiedOsUser: the gateway's own
	// login step (SPEC §3.4 step 3) is what sets verifiedOsUser, and
	// that step has not happened here.
	if m.VerifiedOSUser != nil {
		t.Fatalf("machine.VerifiedOSUser = %v, want nil (the gateway's own login step has not run)", *m.VerifiedOSUser)
	}
	if m.OSUserStatus != state.OSUserStatusPending {
		t.Fatalf("machine.OSUserStatus = %q, want %q", m.OSUserStatus, state.OSUserStatusPending)
	}
	if m.State != "enrolled" {
		t.Fatalf("machine.State = %q, want %q", m.State, "enrolled")
	}
	if m.MachineKey != machineKeyPubLine {
		t.Fatalf("machine.MachineKey does not match what the enrol body sent")
	}

	// Secret burned in the same atomic write.
	if len(st.PendingEnrolments) != 0 {
		t.Fatalf("state.PendingEnrolments len = %d after a successful enrol, want 0", len(st.PendingEnrolments))
	}

	// The success enrol.verified event names the new machine id so
	// an audit reader sees the freshly-recorded name right away.
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventEnrolVerified}})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if len(evs) != 1 || evs[0].Object != claimedName {
		t.Fatalf("journal enrol.verified = %+v, want exactly one event with Object=%q", evs, claimedName)
	}
}

// TestIAMT336_SecretSingleUse exercises requirement 3: "the secret is
// still single-use, a second attempt with the same invitation is
// refused." A successful enrol leaves the pending entry gone; here we
// explicitly verify that a second dial with the SAME secret cannot
// register a second machine.
//
// Canary: remove `st.PendingEnrolments = removePendingByHash(...)` in
// runEnrolFromPending — and this test goes red on the second-machine
// assertion: a second machine is registered on the reused secret.
func TestIAMT336_SecretSingleUse(t *testing.T) {
	f, c := iamt336Fixture(t)

	secret, _ := c.mint(t, "vm-invited")
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("DeriveEphemeralSigner: %v", err)
	}

	pubLine1 := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
	resp1 := doEnrolViaWire(t, f, eph, secret, "", `MACHINE\svc`, pubLine1)
	if !strings.Contains(resp1, `"state":"enrolled"`) {
		t.Fatalf("first enrol did not succeed: %q", resp1)
	}

	// Second dial with the SAME secret: refused. Either the SSH
	// handshake layer reports "unknown key" (no JSON response body
	// at all, since the ephemeral key is gone) or runEnrol's body
	// path returns E_ENROL_SECRET_USED.
	pubLine2 := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
	resp2 := doEnrolViaWire(t, f, eph, secret, "", `MACHINE\svc`, pubLine2)
	if strings.Contains(resp2, `"state":"enrolled"`) {
		t.Fatalf("second enrol with the same secret succeeded; the secret was not single-use: %q", resp2)
	}

	st := f.store.Get()
	if _, dup := st.MachineByID("vm-second"); dup {
		t.Fatalf("second enrol created machine vm-second; the secret was reused: %+v", st.Machines)
	}
	count := 0
	for _, m := range st.Machines {
		if strings.HasPrefix(m.Name, "vm-") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("state has %d machines starting with vm-, want 1 (only the first enrol should have created one): %+v", count, st.Machines)
	}
}

// TestIAMT336_ExpiredInvitation_Refused exercises requirement 3's TTL
// half: "an invitation older than 15 minutes is refused." A pending
// entry whose expiry is in the past is refused at exec time, even
// though the SSH handshake accepted the ephemeral key (the lookup by
// fingerprint is unaware of expiry — that's the whole point of the
// pure-callback discipline in §6.1).
//
// Canary: drop the `!pe.Expires.After(now)` check in
// runEnrolFromPending and this test goes red: the body succeeds and
// the assertion sees `"state":"enrolled"`.
func TestIAMT336_ExpiredInvitation_Refused(t *testing.T) {
	f := newFixture(t, nil)

	const secret = "test-secret-already-expired"
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("DeriveEphemeralSigner: %v", err)
	}
	ephPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(eph.PublicKey())))

	// Hand-plant an expired PendingEnrolment directly in the store:
	// the gateway clock will read this Expiry and the check inside
	// runEnrolFromPending will reject. Using the injected clock keeps
	// the test fast — no real 15-minute wait.
	err = f.store.Update(func(st *state.State) error {
		st.PendingEnrolments = append(st.PendingEnrolments, state.PendingEnrolment{
			SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(secret)),
			PublicKey:  ephPub,
			Expires:    state.NewZonedTime(f.clock.Now().Add(-time.Minute)),
		})
		return nil
	})
	if err != nil {
		t.Fatalf("update store with expired PendingEnrolment: %v", err)
	}

	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
	resp := doEnrolViaWire(t, f, eph, secret, "", `MACHINE\svc`, pubLine)
	if !strings.Contains(resp, "E_ENROL_SECRET_EXPIRED") {
		t.Fatalf("expired invitation must be refused with E_ENROL_SECRET_EXPIRED, got %q", resp)
	}

	st := f.store.Get()
	if _, ok := st.MachineByID("vm-stale"); ok {
		t.Fatalf("an expired invitation still created a machine record")
	}
}

// TestIAMT336_ClaimedOSUser_DoesNotBecomeVerified exercises requirement 3:
//
// "requestedOsUser is still never used for login or for admitting a
// person; the machine still goes to state enrolled with osUserStatus
// pending, and only the gateway's own real login on step 3 may set
// verifiedOsUser / verified."
//
// We can't drive the gateway's own SSH public-key user-auth probe here
// (that lives in sshd_probe.go and is exercised by other tests), so
// the strongest claim this test can make is about the enrol-time
// result: after a successful enrol, verifiedOsUser is nil and
// osUserStatus is "pending". A future regression that bumps either
// up at enrol time would fail this test.
//
// Canary: in runEnrolFromPending's success branch, set
//
//	st.Machines[idx].OSUserStatus = state.OSUserStatusVerified
//	st.Machines[idx].VerifiedOSUser = &osUser
//
// — and this test goes red on the OSUserStatus assertion.
func TestIAMT336_ClaimedOSUser_DoesNotBecomeVerified(t *testing.T) {
	f, c := iamt336Fixture(t)

	secret, _ := c.mint(t, "vm-claim-osu")
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("DeriveEphemeralSigner: %v", err)
	}

	const claimedOSUser = `MACHINE\admin`
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
	resp := doEnrolViaWire(t, f, eph, secret, "", claimedOSUser, pubLine)
	if !strings.Contains(resp, `"state":"enrolled"`) {
		t.Fatalf("enrol did not succeed: %q", resp)
	}

	st := f.store.Get()
	m, ok := st.MachineByID("vm-claim-osu")
	if !ok {
		t.Fatalf("machine vm-claim-osu not in state")
	}
	if m.OSUserStatus != state.OSUserStatusPending {
		t.Fatalf("machine.OSUserStatus = %q after enrol, want %q (the gateway's own login has not run)",
			m.OSUserStatus, state.OSUserStatusPending)
	}
	if m.VerifiedOSUser != nil {
		t.Fatalf("machine.VerifiedOSUser = %v after enrol, want nil (a claimed osUser is not a verified one)",
			*m.VerifiedOSUser)
	}
	if m.RequestedOSUser != claimedOSUser {
		t.Fatalf("machine.RequestedOSUser = %q, want %q", m.RequestedOSUser, claimedOSUser)
	}
}

// TestIAMT336_NameCollision_Refused exercises requirement 4:
//
// "A name that collides with an existing machine must not silently
// take over that machine's identity. Decide what happens, do the
// safe thing, and write down what you chose and why."
//
// We chose: refuse the enrol with E_ENROL_SECRET_INVALID, the same
// error as a wrong secret. The reasoning is in
// runEnrolFromPending's own comment: refusing with a generic
// "invalid" error prevents a probe from confirming the existence of
// the colliding machine.
//
// Since 1.4 the ordinary way to meet this is at MINT time, where
// cmdMachinesEnrolCode refuses the name in front of the administrator
// who typed it (TestMachinesEnrolCodeReservesTheLoginLiterals covers
// the shape of that refusal). The check below it, in
// runEnrolFromPending, is what is left when the mint check cannot have
// seen the collision: a state.json edited by hand, or a name that
// became taken between minting and redeeming. That is why both
// sub-tests forge the pending entry's name directly — through the API
// the second invitation could not be minted at all, which is the
// point.
//
// Canary: drop the for-loop collision check in runEnrolFromPending —
// and this test goes red on the wire refusal: the second enrol
// overwrites the first machine record.
func TestIAMT336_NameCollision_Refused(t *testing.T) {
	f, c := iamt336Fixture(t)

	// renamePending rewrites a live invitation's name to one the mint
	// command would have refused. It stands for the two things that
	// reach runEnrolFromPending's check in practice — an edited state
	// file, and a name taken after the invitation went out.
	renamePending := func(t *testing.T, secret, to string) {
		t.Helper()
		hash := state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(secret))
		if err := f.store.Update(func(st *state.State) error {
			pe, ok := st.FindPendingEnrolmentBySecretHash(hash)
			if !ok {
				t.Fatalf("no pending invitation carries the secret under test")
			}
			pe.Name = to
			return nil
		}); err != nil {
			t.Fatalf("rename pending invitation: %v", err)
		}
	}

	t.Run("collision-by-id", func(t *testing.T) {
		// Two independent codes for two independent dials.
		secret1, _ := c.mint(t, "first")
		secret2, _ := c.mint(t, "first-again")
		eph1, err := config.DeriveEphemeralSigner(secret1, config.EnrolKeySalt)
		if err != nil {
			t.Fatalf("DeriveEphemeralSigner (1): %v", err)
		}
		eph2, err := config.DeriveEphemeralSigner(secret2, config.EnrolKeySalt)
		if err != nil {
			t.Fatalf("DeriveEphemeralSigner (2): %v", err)
		}

		pubA := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
		resp1 := doEnrolViaWire(t, f, eph1, secret1, "", `MACHINE\svc`, pubA)
		if !strings.Contains(resp1, `"state":"enrolled"`) {
			t.Fatalf("first enrol did not succeed: %q", resp1)
		}

		st := f.store.Get()
		m, ok := st.MachineByID("first")
		if !ok {
			t.Fatalf("machine %q not in state after first enrol", "first")
		}
		originalKey := m.MachineKey

		renamePending(t, secret2, "first")

		pubB := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
		resp2 := doEnrolViaWire(t, f, eph2, secret2, "", `MACHINE\svc`, pubB)
		if strings.Contains(resp2, `"state":"enrolled"`) {
			t.Fatalf("second enrol with the colliding id succeeded and overwrote the machine record: %q", resp2)
		}
		if !strings.Contains(resp2, "E_ENROL_SECRET_INVALID") {
			t.Fatalf("collision-by-id must be refused with E_ENROL_SECRET_INVALID, got %q", resp2)
		}

		st = f.store.Get()
		m, ok = st.MachineByID("first")
		if !ok {
			t.Fatalf("machine %q disappeared after a refused collision attempt", "first")
		}
		if m.MachineKey != originalKey {
			t.Fatalf("machine.MachineKey was overwritten by the refused collision attempt: was %q, now %q", originalKey, m.MachineKey)
		}
	})

	t.Run("collision-by-name", func(t *testing.T) {
		// Two machines with different ids but the same claimed name.
		// The §4.3 "names are labels" rule means a name in the id
		// space and a name in the label space are the same slot, so
		// the collision check looks at BOTH m.ID and m.Name.
		secretA, _ := c.mint(t, "label-claim-a")
		ephA, err := config.DeriveEphemeralSigner(secretA, config.EnrolKeySalt)
		if err != nil {
			t.Fatalf("DeriveEphemeralSigner (A): %v", err)
		}

		// First enrol under id="label-claim-a".
		pubA := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
		resp1 := doEnrolViaWire(t, f, ephA, secretA, "", `MACHINE\svc`, pubA)
		if !strings.Contains(resp1, `"state":"enrolled"`) {
			t.Fatalf("first enrol (label-claim-a) did not succeed: %q", resp1)
		}
		// Mutate the machine's Name so the next enrol collides on the
		// Name field instead of ID (model.go's validation rejects id
		// == name unless they coincide, so we need to take it
		// through a Store.Update).
		err = f.store.Update(func(st *state.State) error {
			for i := range st.Machines {
				if st.Machines[i].ID == "label-claim-a" {
					st.Machines[i].Name = "label-claim"
					return nil
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("update machine name: %v", err)
		}

		// Second dial: fresh code, fresh machineKey. The invitation is
		// minted under a free name and then forged to the taken one —
		// minting "label-claim" outright is exactly what the mint-time
		// check now refuses.
		secretB, _ := c.mint(t, "label-claim-b")
		ephB, err := config.DeriveEphemeralSigner(secretB, config.EnrolKeySalt)
		if err != nil {
			t.Fatalf("DeriveEphemeralSigner (B): %v", err)
		}
		renamePending(t, secretB, "label-claim")

		pubB := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genSigner(t).PublicKey())))
		resp2 := doEnrolViaWire(t, f, ephB, secretB, "", `MACHINE\svc`, pubB)
		if strings.Contains(resp2, `"state":"enrolled"`) {
			t.Fatalf("second enrol with a colliding NAME succeeded: %q", resp2)
		}
		if !strings.Contains(resp2, "E_ENROL_SECRET_INVALID") {
			t.Fatalf("collision-by-name must be refused with E_ENROL_SECRET_INVALID, got %q", resp2)
		}

		// Identity of the first machine unchanged.
		st := f.store.Get()
		if m, ok := st.MachineByID("label-claim-a"); !ok {
			t.Fatalf("machine label-claim-a disappeared after a refused collision attempt")
		} else if m.Name != "label-claim" {
			t.Fatalf("machine label-claim-a.Name = %q, want %q", m.Name, "label-claim")
		}
		if _, ok := st.MachineByID("label-claim"); ok {
			t.Fatalf("a second machine record named label-claim was created despite the collision check")
		}
	})
}

// TestIAMT336_NoOldFields_AtWire exercises the strict-decoder
// guarantee: an old client that still sends the `machine` / `osUser`
// body fields to `machines.enrol-code` is refused with
// E_JSON_FIELD_UNKNOWN. SPEC §3.4 explicitly requires this: "the old
// admin machines enrol-code <name> <osUser> form must not silently
// mint something different from what its arguments say — either it
// keeps working exactly as documented or it refuses in words that
// name the change."
func TestIAMT336_NoOldFields_AtWire(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// Sending the old body shape directly over the wire must fail. The
	// name field is back in 1.4, but under its own name and meaning:
	// `name` is the administrator's label for the registration, while
	// `machine` and `osUser` were the machine's own facts he had to go
	// and ask somebody for. An old client sending the old pair must be
	// told no, not quietly given a code that means something else.
	_, err := root.Exec("machines.enrol-code", map[string]any{
		"proto":   1,
		"machine": "enroltest",
		"osUser":  `MACHINE\svc`,
	})
	if err == nil {
		t.Fatal("machines.enrol-code with old `machine`/`osUser` body fields succeeded; should have been refused")
	}
	if !strings.Contains(err.Error(), "E_JSON_FIELD_UNKNOWN") {
		t.Fatalf("old body shape must be refused with E_JSON_FIELD_UNKNOWN, got %v", err)
	}
	if !strings.Contains(err.Error(), "machine") {
		t.Fatalf("refusal should name the offending field for the operator, got %v", err)
	}

	// And the store must NOT carry a pending entry — a refused call
	// cannot leak a code into the world.
	st := f.store.Get()
	if len(st.PendingEnrolments) != 0 {
		t.Fatalf("state.PendingEnrolments len = %d after a refused wire call, want 0", len(st.PendingEnrolments))
	}

	// Sanity: the legitimate form still works after the refusal above.
	code, _, err := root.MachinesInvite("office-pc")
	if err != nil {
		t.Fatalf("machines.enrol-code after the refusal: %v", err)
	}
	if code == "" {
		t.Fatal("machines.enrol-code returned an empty enrolCode")
	}
}
