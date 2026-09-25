package gateway

// iamt330_pairing_lockout_concealment_test.go — IAMT-323 review follow-up
// (IAMT-330, LOW): a banned address must learn nothing about the window,
// either. The review found the exec layer read the window BEFORE the
// limiter, so a client that handshakes while the window is open and then
// execs after a stop (or expiry) got E_PAIRING_INACTIVE / E_PAIRING_EXPIRED
// even while banned — window state leaking past a lockout the handshake
// layer already conceals (pairingKeyCallback consults Allow first). With
// the limiter first, a banned address sees E_PAIRING_LOCKED and nothing
// else; the window read keeps its place ahead of every PIN grade, so
// INACTIVE and EXPIRED keep billing nobody.

import (
	"testing"
	"time"
)

func TestPairingLockoutConcealsTheWindowState(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "111111", time.Hour)

	const addr = "203.0.113.7:40003"
	key := genSigner(t)
	fp := fingerprintOf(t, key.PublicKey())
	line := authorizedLine(key.PublicKey())

	// Burn the address: three graded wrong PINs, then the counter bans it.
	for i := 0; i < 3; i++ {
		_, cerr := runPairingAt(f, addr, fp, "999999", line)
		wantPairingRefusal(t, "wrong PIN to earn the ban", cerr, "E_PAIRING_PIN_INVALID", 2)
	}

	// Stop the window. The banned address must still see LOCKED — not
	// INACTIVE, which would tell it the window's state from behind the
	// lockout.
	pairingStopDirect(t, f, "alice")
	_, cerr := runPairingAt(f, addr, fp, "999999", line)
	wantPairingRefusal(t, "banned address with a stopped window", cerr, "E_PAIRING_LOCKED", 2)

	// Same behind an expired window: LOCKED, not EXPIRED.
	seedPairingWindow(t, f, "111111", -time.Second)
	_, cerr = runPairingAt(f, addr, fp, "999999", line)
	wantPairingRefusal(t, "banned address with an expired window", cerr, "E_PAIRING_LOCKED", 2)

	// And the concealment has no cost for un-banned addresses: an
	// un-banned one still gets the precise INACTIVE/EXPIRED refusals (and
	// still bills nobody — TestIAMT325_InactiveAndExpiredRecordNoFailure
	// pins that arithmetic).
}
