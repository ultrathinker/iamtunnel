package gateway

// pairing_window_burn_test.go — M-13 (code review 23.09.2026, review F-06):
// the pairing PIN was defended by the per-address limiter alone.
//
// Three wrong PINs from one address ban that address for three minutes —
// and nothing else happened. A window open for two minutes could be
// ground at from as many addresses as the attacker had: three guesses
// each, never a ban, a 6-digit PIN (10^6) and no ceiling on the total.
// A single IPv6 subscriber normally holds a 2^64 /64, so "per address"
// was not even a speed bump there, and the address was compared as an
// exact string.
//
// Two rules are pinned here: a handful of misses ACROSS ALL ADDRESSES
// burns the window itself — with the reason in the journal, because the
// operator who opened it has to be able to tell a burnt window from an
// expired one — and an IPv6 peer counts as its /64, not as its address.

import (
	"fmt"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// pairingMissLimit is PairingWindowMissLimit as this file needs it: a
// literal, so the rows below compile against the tree the defect lived
// in (the constant is part of the fix).
const pairingMissLimit = 10

// missFrom grades one wrong PIN from one address, with its own
// fingerprint — the identity the per-address limiter counts.
func missFrom(t *testing.T, f *fixture, addr, fp, pin, line string) *cmdError {
	t.Helper()
	_, cerr := runPairingAt(f, addr, fp, pin, line)
	return cerr
}

// requireRefusalCode pins one attempt's wire code. t.Helper() is what
// makes a failure report the CALLER's line — this file's own row — and
// not this function's.
func requireRefusalCode(t *testing.T, stage string, cerr *cmdError, want string) {
	t.Helper()
	if cerr == nil {
		t.Fatalf("%s: got success, want refusal %s (M-13, review F-06)", stage, want)
	}
	if cerr.code != want {
		t.Fatalf("%s: refusal = %s, want %s (M-13, review F-06)", stage, cerr.code, want)
	}
}

// TestM13ManyWrongPINsFromManyAddressesBurnTheWindow is the ceiling the
// finding asked for: the window tolerates a handful of misses in total,
// from any addresses, and then it is gone.
func TestM13ManyWrongPINsFromManyAddressesBurnTheWindow(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "135790", 2*time.Minute)
	line := authorizedLine(genSigner(t).PublicKey())

	// One miss short of the limit, each from its OWN address, so the
	// per-address limiter never fires: nothing but the window's own
	// counter stands between an attacker with many addresses and a
	// 10^6 search.
	for i := 1; i <= pairingMissLimit-1; i++ {
		cerr := missFrom(t, f, fmt.Sprintf("203.0.113.%d:4000", i), fmt.Sprintf("fp-%d", i), "000000", line)
		requireRefusalCode(t, fmt.Sprintf("wrong PIN %d of %d", i, pairingMissLimit), cerr, "E_PAIRING_PIN_INVALID")
	}

	// The last one ends the window — and the client is told what it did,
	// not merely that some PIN was wrong.
	cerr := missFrom(t, f, "203.0.113.10:4000", "fp-10", "000000", line)
	requireRefusalCode(t, "the miss that reaches the limit", cerr, "E_PAIRING_INACTIVE")

	if f.store.Get().PairingPending != nil {
		t.Errorf("the pairing window is still open after %d wrong PINs from %d different addresses — a per-address limiter is worth nothing against an attacker who has more than one address, so the window itself must burn (M-13, review F-06)", pairingMissLimit, pairingMissLimit)
	}

	// An operator reading the journal has to find out why the PIN stopped
	// working, and only the journal can say it: the window has no memory
	// once it is gone.
	evs, _, rerr := events.ReadFile(f.logPath, events.Filter{})
	if rerr != nil {
		t.Fatalf("read the journal: %v", rerr)
	}
	burned := false
	for _, e := range evs {
		if e.Type == events.EventAdminOp && e.Result == "pairing.burn:ok" {
			burned = true
		}
	}
	if !burned {
		t.Errorf("no admin.op event records the burn — a burnt window and an expired one look the same to the operator who opened it (M-13, review F-06)")
	}
}

// TestM13PairingLimiterCountsAnIPv6SixtyFourAsOneAddress is the other
// half: on IPv6 the address an attacker cannot change for free is the
// /64, and three guesses per /64 is a ceiling that means something.
func TestM13PairingLimiterCountsAnIPv6SixtyFourAsOneAddress(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "135790", 2*time.Minute)
	line := authorizedLine(genSigner(t).PublicKey())

	for i := 1; i <= 3; i++ {
		cerr := missFrom(t, f, fmt.Sprintf("[2001:db8:7:7::%d]:4000", i), fmt.Sprintf("fp-%d", i), "000000", line)
		requireRefusalCode(t, fmt.Sprintf("wrong PIN %d from a /64", i), cerr, "E_PAIRING_PIN_INVALID")
	}
	// A fourth address of the SAME /64 is already banned: the counter
	// belongs to the /64, not to the address inside it.
	cerr := missFrom(t, f, "[2001:db8:7:7::9999]:4000", "fp-4", "000000", line)
	requireRefusalCode(t, "a fourth address inside the same /64", cerr, "E_PAIRING_LOCKED")
}

// TestM13PeerHostIsTheIdentityAnAttackerCannotChange covers the
// reduction both limiters share (the main login limiter joined it in
// IAMT-446, so the /64 rule reaches it too), including the addresses that
// must NOT change: an IPv4 peer and anything that is not an address at
// all.
func TestM13PeerHostIsTheIdentityAnAttackerCannotChange(t *testing.T) {
	cases := []struct{ addr, want string }{
		{"127.0.0.1:61000", "127.0.0.1"},
		{"203.0.113.7", "203.0.113.7"},
		{"[2001:db8:1:2:3:4:5:6]:5000", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2:9:8:7:6]:2222", "2001:db8:1:2::/64"},
		{"[2001:db8:1:3::1]:2222", "2001:db8:1:3::/64"},
		{"[::ffff:203.0.113.7]:2222", "203.0.113.7"},
		{"a-literal-test-address", "a-literal-test-address"},
	}
	for _, c := range cases {
		if got := peerHost(c.addr); got != c.want {
			t.Errorf("peerHost(%q) = %q, want %q — both limiters count the identity an attacker cannot change for free, and on IPv6 that is the /64, not the address (M-13, review F-06; IAMT-446 made the main limiter share this key)", c.addr, got, c.want)
		}
	}
}
