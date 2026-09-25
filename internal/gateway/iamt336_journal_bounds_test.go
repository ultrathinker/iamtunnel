package gateway

// iamt336_journal_bounds_test.go — what an enrol attempt may put into
// events.jsonl.
//
// The enrol body is the only place in this product where a caller who
// has authenticated with nothing but a one-shot invitation gets to hand
// the gateway free-form strings. Since 1.3 that is by design: the
// machine reports its own hostname and OS account, and the gateway
// records them (SPEC §3.4). But a refused attempt used to write the
// claimed name into the journal twice — once as the event's object, and
// again inside the refusal text the event carries as errMsg — without
// either copy passing the grammar that would have bounded it.
//
// So a holder of a live invitation could send a valid secret and a
// megabyte-long machine name: validation refuses it, and the refusal
// appends the attacker's megabyte to events.jsonl, twice, on every
// attempt. The journal is append-only and sits on the gateway's data
// disk; it is also the thing an administrator reads to find out what
// happened. Filling it is both a disk-space attack and a way to make
// the log unreadable, and anything the caller wrote — including,
// if they put it there, a secret — is in it verbatim and forever.
//
// A journal entry about a name that was refused for being unusable does
// not need the whole name. It needs enough to recognise, and a bound.
//
// Found by the review of the IAMT-336 branch.

import (
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// iamt336JournalCap is the longest any single caller-supplied value may
// be once it reaches the journal. It leaves room for the 64 characters
// clipForJournal keeps plus the byte count it appends, and is still far
// under anything worth calling a flood — the test proves a bound
// exists, not which exact one was chosen.
const iamt336JournalCap = 128

// iamt336FloodRun is a run of the caller's own filler longer than
// anything that may survive clipping.
const iamt336FloodRun = iamt336JournalCap

// TestIAMT336_ARefusedNameCannotFloodTheJournal is the review finding as
// a test: one enrol attempt with an oversized claimed name must not put
// an oversized anything into events.jsonl.
//
// Canary: drop the clipForJournal calls around the claimed name in
// runEnrol's enrol.failed event and in runEnrolFromPending's invalid-name
// refusal, and this test goes red naming the field that carried the
// megabyte through.
func TestIAMT336_ARefusedNameCannotFloodTheJournal(t *testing.T) {
	f, c := iamt336Fixture(t)

	secret, _ := c.mint(t, "vm-invited")
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}

	// A name that is invalid for two independent reasons — the capitals
	// and the length — so a fix that only bounded one of them still
	// leaves this red.
	flood := strings.Repeat("A", 200000)

	resp := doEnrolViaWire(t, f, eph, secret, flood, `MACHINE\svc`, authorizedLine(genSigner(t).PublicKey()))
	if !strings.Contains(resp, "E_ENROL_SECRET_INVALID") {
		t.Fatalf("an unusable machine name must be refused, got %q", clipForTest(resp))
	}

	evs, _, rerr := f.log.Read(events.Filter{Types: []events.EventType{events.EventEnrolFailed}})
	if rerr != nil {
		t.Fatalf("read journal: %v", rerr)
	}
	if len(evs) != 1 {
		t.Fatalf("enrol.failed events = %d, want exactly 1", len(evs))
	}
	e := evs[0]

	if len(e.Object) > iamt336JournalCap {
		t.Errorf("enrol.failed object is %d bytes — the caller's own refused string, written to the journal whole. One attempt per megabyte fills the gateway's disk and buries every other entry in it.", len(e.Object))
	}
	if msg, _ := e.Details["errMsg"].(string); len(msg) > 512 {
		t.Errorf("enrol.failed errMsg is %d bytes — the refusal text interpolates the caller's raw string, so bounding the object alone changed nothing.", len(msg))
	}
	// Whatever survives must not be the flood itself, in either field.
	for name, got := range map[string]string{"object": e.Object, "errMsg": toStr(e.Details["errMsg"])} {
		if strings.Contains(got, strings.Repeat("A", iamt336FloodRun)) {
			t.Errorf("enrol.failed %s still carries an unbounded run of the caller's input", name)
		}
	}
}

// TestIAMT336_AnOversizedOSUserIsBoundedToo. osUser comes from the same
// body, through the same grammar check, into the same refusal text. A
// fix that bounded only the machine name would leave the identical hole
// one field along.
func TestIAMT336_AnOversizedOSUserIsBoundedToo(t *testing.T) {
	f, c := iamt336Fixture(t)

	secret, _ := c.mint(t, "vm-invited")
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}

	flood := `MACHINE\` + strings.Repeat("b", 200000)
	resp := doEnrolViaWire(t, f, eph, secret, "vm-legit", flood, authorizedLine(genSigner(t).PublicKey()))
	if !strings.Contains(resp, "E_ENROL_SECRET_INVALID") {
		t.Fatalf("an unusable osUser must be refused, got %q", clipForTest(resp))
	}

	evs, _, rerr := f.log.Read(events.Filter{Types: []events.EventType{events.EventEnrolFailed}})
	if rerr != nil {
		t.Fatalf("read journal: %v", rerr)
	}
	if len(evs) != 1 {
		t.Fatalf("enrol.failed events = %d, want exactly 1", len(evs))
	}
	if msg := toStr(evs[0].Details["errMsg"]); len(msg) > 512 {
		t.Errorf("enrol.failed errMsg is %d bytes: the osUser refusal interpolates the caller's raw string", len(msg))
	}
}

// TestIAMT336_AValidNameReachesTheJournalWhole is the other half, and
// the reason the bound is not simply "truncate everything". The
// collision refusal — the one a reinstalled machine meets every single
// time — is about a name that PASSED the grammar, and an administrator
// reading the journal to find out why a machine will not register needs
// that name in full, not an abbreviation of it.
func TestIAMT336_AValidNameReachesTheJournalWhole(t *testing.T) {
	f, c := iamt336Fixture(t)

	// The longest name the grammar allows: 32 characters.
	const longestValid = "m0123456789012345678901234567890"
	if len(longestValid) != 32 {
		t.Fatalf("test fixture bug: %q is %d characters, want 32", longestValid, len(longestValid))
	}

	// Register it once, so the second attempt collides on the name.
	secret1, _ := c.mint(t, longestValid)
	eph1, err := config.DeriveEphemeralSigner(secret1, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}
	if resp := doEnrolViaWire(t, f, eph1, secret1, "", `MACHINE\svc`, authorizedLine(genSigner(t).PublicKey())); !strings.Contains(resp, `"state":"enrolled"`) {
		t.Fatalf("the longest valid name did not enrol: %q", resp)
	}

	// The second invitation is minted free and then forged onto the
	// taken name: minting it outright is what cmdMachinesEnrolCode now
	// refuses, and this test is about the REDEEM-time refusal's journal
	// entry.
	secret2, _ := c.mint(t, "m-second")
	hash2 := state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(secret2))
	if err := f.store.Update(func(st *state.State) error {
		pe, ok := st.FindPendingEnrolmentBySecretHash(hash2)
		if !ok {
			t.Fatal("the second invitation is not in state")
		}
		pe.Name = longestValid
		return nil
	}); err != nil {
		t.Fatalf("forge the second invitation's name: %v", err)
	}
	eph2, err := config.DeriveEphemeralSigner(secret2, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral 2: %v", err)
	}
	if resp := doEnrolViaWire(t, f, eph2, secret2, "", `MACHINE\svc`, authorizedLine(genSigner(t).PublicKey())); !strings.Contains(resp, "E_ENROL_SECRET_INVALID") {
		t.Fatalf("a name already in use must be refused: %q", resp)
	}

	evs, _, rerr := f.log.Read(events.Filter{Types: []events.EventType{events.EventEnrolFailed}})
	if rerr != nil {
		t.Fatalf("read journal: %v", rerr)
	}
	if len(evs) != 1 {
		t.Fatalf("enrol.failed events = %d, want exactly 1", len(evs))
	}
	if evs[0].Object != longestValid {
		t.Errorf("enrol.failed object = %q, want the full name %q — an administrator reading this entry is trying to find out which machine cannot register", evs[0].Object, longestValid)
	}
}

func toStr(v any) string {
	s, _ := v.(string)
	return s
}

func clipForTest(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
