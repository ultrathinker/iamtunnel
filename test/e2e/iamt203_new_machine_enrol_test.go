package e2e

// iamt203_new_machine_enrol_test.go is the end-to-end gate for IAMT-203:
// a brand-new machine — never seeded into st.Machines by the test,
// never having existed in state at all — must be enrollable end to end
// through the real roles: an admin mints an invitation, the machine
// dials as "enrol" with the resulting code and runs the real "enrol"
// exec, and the machine then shows up in `machines.list`.
//
// 1.3 (IAMT-336) turned this file's subject inside out and it is worth
// saying exactly how, because three of the tests below now assert the
// opposite of what they asserted before.
//
// The invitation used to be BOUND: `machines.enrol-code <name>
// <osUser>` named the machine in advance, and the enrolling machine
// either matched that binding or was refused. IAMT-203 was the bug
// that the bound name had to already exist. In 1.3 the invitation
// names nothing at all — it is one anonymous, single-use, 15-minute
// secret — and the machine reports its own hostname and OS account in
// the `enrol` body (SPEC §3.4). IAMT-203's defect therefore cannot
// recur by construction: there is no name at mint time to look up.
// What is still worth proving end-to-end, and is proved below, is that
// the whole chain works through the real roles and that the three
// refusals that replaced the old bindings actually fire on the wire.
//
// Canary for TestE2E_EnrolCodeForNewMachineName_RegistersMachine: make
// cmdMachinesEnrolCode require a `machine` field again (a `Machine
// string` in its request struct plus a `st.MachineByID` guard) and this
// test goes red at the mint call — the admin client no longer sends one.

import (
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestE2E_EnrolCodeForNewMachineName_RegistersMachine is the main IAMT-203
// gate: claim/admin -> machines.enrol-code -> enrol role with that code,
// naming a never-seen machine -> machines.list shows the machine, all
// through real roles and without ever writing into st.Machines directly.
func TestE2E_EnrolCodeForNewMachineName_RegistersMachine(t *testing.T) {
	f := newFixture(t, nil)
	const newMachineName = "enroltest-canary"

	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)}, "root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()

	// Sanity: nothing seeded this name, this test included.
	if got, err := readStateJSONState(t, f); err == nil {
		if _, ok := got.MachineByID(newMachineName); ok {
			t.Fatalf("test setup bug: %q already exists in state", newMachineName)
		}
	}

	code, _, err := root.MachinesInvite(newMachineName)
	if err != nil {
		t.Fatalf("machines.enrol-code for a brand-new name %q must succeed, got: %v", newMachineName, err)
	}
	parsed, err := config.ParseEnrolCode(code)
	if err != nil {
		t.Fatalf("parse enrol code: %v", err)
	}

	// The pending invitation is visible to the admin before any machine
	// dials in — machines.list must show it without inventing a third
	// machine.state value (PROTOCOL §1.6). Since 1.3 it carries nothing
	// but an expiry: there is no name to show, because no name has been
	// chosen yet.
	_, pending, err := root.MachinesList()
	if err != nil {
		t.Fatalf("machines.list: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("machines.list showed %d pending enrolments, want exactly the one just minted: %+v", len(pending), pending)
	}
	if pending[0].Expires == "" {
		t.Fatalf("the pending enrolment has no expiry — an invitation whose 15-minute window is invisible cannot be waited out: %+v", pending[0])
	}

	ephemeral, err := config.DeriveEphemeralSigner(parsed.Secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}
	machineKey := genSigner(t)
	pubLine := authorizedLine(machineKey.PublicKey())

	resp := doEnrol(t, f, ephemeral, parsed.Secret, "", `MACHINE\svc`, pubLine)
	if !strings.Contains(resp, `"state":"enrolled"`) {
		t.Fatalf("enrol response missing state=enrolled: %q", resp)
	}
	if !strings.Contains(resp, `"machine":"`+newMachineName+`"`) {
		t.Fatalf("enrol response missing machine id %q: %q", newMachineName, resp)
	}

	got, err := readStateJSONState(t, f)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	m, ok := got.MachineByID(newMachineName)
	if !ok {
		t.Fatalf("machine %q not in state.json after enrol", newMachineName)
	}
	if m.MachineKey != pubLine {
		t.Fatalf("enrolled machineKey = %q, want %q", m.MachineKey, pubLine)
	}
	if m.State != "enrolled" {
		t.Fatalf("enrolled machine state = %q, want %q", m.State, "enrolled")
	}
	if len(got.PendingEnrolments) != 0 {
		t.Fatalf("the redeemed invitation survived a successful enrol: %+v", got.PendingEnrolments)
	}

	list, _, err := root.MachinesList()
	if err != nil {
		t.Fatalf("machines.list after enrol: %v", err)
	}
	found := false
	for _, mv := range list {
		if mv.ID == newMachineName {
			found = true
		}
	}
	if !found {
		t.Fatalf("machines.list does not show %q after enrol: %+v", newMachineName, list)
	}
}

// TestE2E_TwoInvitationsAreIndependent is the inversion of the test
// that stood here before. That one — EnrolCodeReissueForNewMachineName_
// BurnsOldCode — required a second `enrol-code` FOR THE SAME NAME to
// invalidate the first, because both were bindings of one name and two
// live bindings of one name would have been ambiguous.
//
// Invitations carry no name in 1.3, so two of them are not two versions
// of one thing; they are two invitations, for two machines, quite
// possibly minted for two different people minutes apart. Burning the
// first when the second is minted would silently break whoever was
// handed it. Both must live until redeemed or expired, and redeeming
// one must leave the other alone.
//
// Canary: add `st.PendingEnrolments = nil` before the append in
// cmdMachinesEnrolCode's Store.Update and this test goes red at
// "the first invitation stopped working".
func TestE2E_TwoInvitationsAreIndependent(t *testing.T) {
	f := newFixture(t, nil)

	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)}, "root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()

	code1, _, err := root.MachinesInvite("enroltest-first")
	if err != nil {
		t.Fatalf("first machines.enrol-code: %v", err)
	}
	parsed1, err := config.ParseEnrolCode(code1)
	if err != nil {
		t.Fatalf("parse first code: %v", err)
	}
	eph1, err := config.DeriveEphemeralSigner(parsed1.Secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive first ephemeral: %v", err)
	}

	code2, _, err := root.MachinesInvite("enroltest-second")
	if err != nil {
		t.Fatalf("second machines.enrol-code: %v", err)
	}
	if code2 == code1 {
		t.Fatal("two invitations minted the same secret — an invitation is 256 bits of fresh randomness or it is nothing")
	}
	parsed2, err := config.ParseEnrolCode(code2)
	if err != nil {
		t.Fatalf("parse second code: %v", err)
	}
	eph2, err := config.DeriveEphemeralSigner(parsed2.Secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive second ephemeral: %v", err)
	}

	// Redeem the SECOND one first, precisely because that is the order
	// in which a burn-the-old-one bug would look harmless.
	resp2 := doEnrol(t, f, eph2, parsed2.Secret, "", `MACHINE\svc`, authorizedLine(genSigner(t).PublicKey()))
	if !strings.Contains(resp2, `"state":"enrolled"`) {
		t.Fatalf("the second invitation did not enrol: %q", resp2)
	}

	resp1 := doEnrol(t, f, eph1, parsed1.Secret, "", `MACHINE\svc`, authorizedLine(genSigner(t).PublicKey()))
	if !strings.Contains(resp1, `"state":"enrolled"`) {
		t.Fatalf("the first invitation stopped working once a second was minted: %q", resp1)
	}

	got, err := readStateJSONState(t, f)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	for _, want := range []string{"enroltest-first", "enroltest-second"} {
		if _, ok := got.MachineByID(want); !ok {
			t.Fatalf("machine %q not in state.json after enrol", want)
		}
	}
	if len(got.PendingEnrolments) != 0 {
		t.Fatalf("both invitations were redeemed but %d pending entries remain: %+v", len(got.PendingEnrolments), got.PendingEnrolments)
	}
}

// TestE2E_EnrolUnderAnExistingMachineName_RefusedWithTheRemedy is the
// other inversion. Its predecessor —
// EnrolCodeForAlreadyRegisteredMachine_StillWorks — required that a
// machine which already exists could be handed a fresh code and
// re-register with a new key, because SPEC §6.2 / RUNBOOK §4
// (rotate-hostkey) went through exactly that path.
//
// It cannot go through that path any more, and it must not: the
// invitation no longer proves WHICH machine is redeeming it, so an
// enrol that accepted an existing name would let anybody holding a
// fresh invitation overwrite any machine's long-term key by simply
// claiming its name. Key rotation for a machine that already exists
// is `machines.rekey`, which authenticates as that machine.
//
// What this test pins is the refusal AND its remedy sentence. Since
// 1.3 a machine names itself from its own hostname, so a REINSTALLED
// machine collides with its own old record on every single attempt —
// the ordinary path, not a corner case. A refusal that only said
// "already in use" would leave its owner with nothing to do next.
//
// Canary: drop the `iamtunnel admin machines remove` clause from the
// collision refusal in runEnrolFromPending and this test goes red at
// "the refusal does not say what to do about it".
func TestE2E_EnrolUnderAnExistingMachineName_RefusedWithTheRemedy(t *testing.T) {
	f := newFixture(t, nil)

	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)}, "root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()

	// f.machineID ("vm1") is seeded by the fixture as already
	// "verified" (harness_test.go). The invitation is minted under a
	// FREE name and its entry is then renamed onto the taken one:
	// minting "vm1" outright is what the mint-time check refuses, and
	// this test is about the refusal one layer down, at redeem.
	code, _, err := root.MachinesInvite("enroltest-collide")
	if err == nil {
		forgeInvitationName(t, f, code, f.machineID)
	}
	if err != nil {
		t.Fatalf("machines.enrol-code: %v", err)
	}
	parsed, err := config.ParseEnrolCode(code)
	if err != nil {
		t.Fatalf("parse enrol code: %v", err)
	}
	ephemeral, err := config.DeriveEphemeralSigner(parsed.Secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}

	before, err := readStateJSONState(t, f)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	original, ok := before.MachineByID(f.machineID)
	if !ok {
		t.Fatalf("test setup bug: the fixture did not seed %q", f.machineID)
	}
	originalKey := original.MachineKey

	resp := doEnrol(t, f, ephemeral, parsed.Secret, "", `MACHINE\svc2`, authorizedLine(genSigner(t).PublicKey()))
	if strings.Contains(resp, `"state":"enrolled"`) {
		t.Fatalf("enrolling under an existing machine's name succeeded — any invitation holder could take over any machine: %q", resp)
	}
	if !strings.Contains(resp, "E_ENROL_SECRET_INVALID") {
		t.Fatalf("a name collision must be refused with E_ENROL_SECRET_INVALID, got: %q", resp)
	}
	if !strings.Contains(resp, "machines remove") {
		t.Fatalf("the refusal does not say what to do about it — a reinstalled machine hits this every time and its owner is left with nothing to try: %q", resp)
	}

	after, err := readStateJSONState(t, f)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	m, ok := after.MachineByID(f.machineID)
	if !ok {
		t.Fatalf("machine %q disappeared after a refused collision", f.machineID)
	}
	if m.MachineKey != originalKey {
		t.Fatalf("the refused attempt still overwrote the machine's long-term key: was %q, now %q", originalKey, m.MachineKey)
	}
}

// TestE2E_EnrolCodeExpiredForNewMachineName_Refused: an expired
// invitation is refused with its own code, and the attempt does not
// fabricate a machine.
func TestE2E_EnrolCodeExpiredForNewMachineName_Refused(t *testing.T) {
	f := newFixture(t, nil)
	const name = "enroltest-expired"

	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)}, "root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()

	code, _, err := root.MachinesInvite(name)
	if err != nil {
		t.Fatalf("machines.enrol-code: %v", err)
	}
	parsed, err := config.ParseEnrolCode(code)
	if err != nil {
		t.Fatalf("parse enrol code: %v", err)
	}
	ephemeral, err := config.DeriveEphemeralSigner(parsed.Secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}

	// There is exactly one invitation in flight and no name to match it
	// by, so expiring "the pending entry" means expiring every one of
	// them — which the assertion below keeps honest by refusing to run
	// if the count is ever anything but one.
	if err := f.store.Update(func(st *state.State) error {
		if len(st.PendingEnrolments) != 1 {
			t.Fatalf("expected exactly one pending enrolment to expire, found %d", len(st.PendingEnrolments))
		}
		st.PendingEnrolments[0].Expires = state.NewZonedTime(f.clock.Now().Add(-time.Minute))
		return nil
	}); err != nil {
		t.Fatalf("expire pending enrolment: %v", err)
	}

	pubLine := authorizedLine(genSigner(t).PublicKey())
	resp := doEnrol(t, f, ephemeral, parsed.Secret, "", `MACHINE\svc`, pubLine)
	if !strings.Contains(resp, "E_ENROL_SECRET_EXPIRED") {
		t.Fatalf("expired pending enrolment must be refused with E_ENROL_SECRET_EXPIRED, got: %q", resp)
	}

	got, err := readStateJSONState(t, f)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if _, ok := got.MachineByID(name); ok {
		t.Fatalf("an expired enrol attempt created machine %q", name)
	}
}

// TestE2E_MintRefusesAReservedOrInvalidName. The grammar and the
// reserved-literal set that registration names must satisfy (PROTOCOL
// §2.1) have moved twice, and this test has followed them both times.
//
// They were checked when an administrator typed a name into
// `machines.enrol-code`. 1.3 took the name off that command entirely,
// so the check could only live at redeem time, where the MACHINE named
// itself. 1.4 gives the command a name again — the administrator's own
// label for the registration, not the machine's hostname — so the check
// belongs back here, in front of the person who typed it. That is also
// simply kinder: a name refused at mint costs one retry, a name refused
// at redeem has already been handed to somebody else.
//
// "enrol", "bootstrap" and "machine" are the ones that matter most:
// each is a real SSH username this gateway resolves to a ROLE
// (lookup.go), so a registration under one of them would sit in the
// same namespace as a login role.
//
// Canary: drop the ValidateName / reservedPersonNames checks at the top
// of cmdMachinesEnrolCode and this test goes red on the first row.
func TestE2E_MintRefusesAReservedOrInvalidName(t *testing.T) {
	f := newFixture(t, nil)

	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)}, "root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()

	for _, bad := range []string{"", "enrol", "bootstrap", "machine", "pairing", "Bad-Name", "-leadinghyphen"} {
		if _, _, err := root.MachinesInvite(bad); err == nil {
			t.Errorf("machines.enrol-code minted an invitation under the invalid or reserved name %q", bad)
		}
	}

	// Not one of them left anything behind: a refused mint must not
	// leak a code into the world.
	got, err := readStateJSONState(t, f)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if len(got.PendingEnrolments) != 0 {
		t.Fatalf("refused names left %d invitation(s) behind: %+v", len(got.PendingEnrolments), got.PendingEnrolments)
	}
}

// TestE2E_MachinesRemove_OfARealMachine is what is left of the test that
// stood here before. That one — MachinesRemove_RevokesPendingEnrolment —
// proved an admin could retract an invitation that no device had
// claimed yet, by naming it. There is no name to give any more, and
// `machines.remove` no longer matches pending entries at all
// (cmdMachinesRemove says so in as many words). The only way to retract
// an invitation in 1.3 is to wait out its 15-minute expiry, which is
// short for exactly this reason. That is a real, deliberate loss of a
// capability, and it is written down here rather than quietly dropped
// with the test.
//
// What survives, and is worth keeping e2e, is the other half: removing
// a machine that does exist works, is idempotent-by-refusal, and the
// removal reaches disk.
func TestE2E_MachinesRemove_OfARealMachine(t *testing.T) {
	f := newFixture(t, nil)

	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)}, "root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()

	if err := root.MachinesRemove(f.machineID); err != nil {
		t.Fatalf("machines.remove of a real machine: %v", err)
	}

	got, err := readStateJSONState(t, f)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if _, ok := got.MachineByID(f.machineID); ok {
		t.Fatalf("machine %q survived machines.remove", f.machineID)
	}

	if err := root.MachinesRemove(f.machineID); err == nil {
		t.Fatal("machines.remove of an already-removed machine: expected E_NOT_FOUND, got success")
	} else if !strings.Contains(err.Error(), "E_NOT_FOUND") {
		t.Fatalf("machines.remove of an already-removed machine = %v, want E_NOT_FOUND", err)
	}
}

// TestE2E_MachinesRemove_ClearsTheWayForAReinstall closes the loop the
// collision refusal opens: its remedy sentence tells the machine's
// owner to have an administrator run `machines remove`, and this proves
// that doing so actually lets the machine back in under its own name.
// A remedy that did not work would be worse than no remedy.
func TestE2E_MachinesRemove_ClearsTheWayForAReinstall(t *testing.T) {
	f := newFixture(t, nil)

	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)}, "root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()

	if err := root.MachinesRemove(f.machineID); err != nil {
		t.Fatalf("machines.remove: %v", err)
	}

	code, _, err := root.MachinesInvite(f.machineID)
	if err != nil {
		t.Fatalf("machines.enrol-code: %v", err)
	}
	parsed, err := config.ParseEnrolCode(code)
	if err != nil {
		t.Fatalf("parse enrol code: %v", err)
	}
	ephemeral, err := config.DeriveEphemeralSigner(parsed.Secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}

	newKey := genSigner(t)
	pubLine := authorizedLine(newKey.PublicKey())
	resp := doEnrol(t, f, ephemeral, parsed.Secret, "", `MACHINE\svc`, pubLine)
	if !strings.Contains(resp, `"state":"enrolled"`) {
		t.Fatalf("a reinstalled machine could not re-enrol under its own name after the old record was removed — the remedy the refusal prints does not work: %q", resp)
	}

	got, err := readStateJSONState(t, f)
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	m, ok := got.MachineByID(f.machineID)
	if !ok {
		t.Fatalf("machine %q not in state.json after re-enrol", f.machineID)
	}
	if m.MachineKey != pubLine {
		t.Fatalf("re-enrolled machineKey = %q, want the freshly presented %q", m.MachineKey, pubLine)
	}
}

// readStateJSONState is readStateJSON's typed-return twin, for tests
// that want the state.State value itself (e.g. to call its methods)
// rather than decoding into a caller-supplied pointer.
func readStateJSONState(t *testing.T, f *fixture) (state.State, error) {
	t.Helper()
	var st state.State
	err := readStateJSON(f.dir, &st)
	return st, err
}

// forgeInvitationName rewrites a live invitation's name to one
// `machines.enrol-code` would have refused. It stands for the two ways
// a collision still reaches runEnrolFromPending now that the mint
// checks first: a hand-edited state.json, and a name that became taken
// between the invitation going out and being redeemed.
func forgeInvitationName(t *testing.T, f *fixture, code, to string) {
	t.Helper()
	parsed, err := config.ParseEnrolCode(code)
	if err != nil {
		t.Fatalf("parse enrol code: %v", err)
	}
	hash := state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(parsed.Secret))
	if err := f.store.Update(func(st *state.State) error {
		pe, ok := st.FindPendingEnrolmentBySecretHash(hash)
		if !ok {
			t.Fatal("the invitation just minted is not in state")
		}
		pe.Name = to
		return nil
	}); err != nil {
		t.Fatalf("forge the invitation name: %v", err)
	}
}
