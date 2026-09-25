package gateway

// R2-CX F-04: a pairing connection whose window is replaced or closed
// after its handshake is refused without any counter moving (F-12 of the
// round-1 review; PROTOCOL §6.1) - for a wrong PIN of the right shape,
// which is billed to the address only after the grading transaction has
// found the connection's own window. A PIN of the wrong shape was billed
// before: g.pairRate.RecordFailure ran first, and the transaction that
// then found the window gone or replaced answered stale with the address
// already charged. Holding a few connections admitted to window A and
// sending malformed PINs as window B opens bans the address - and with it
// the operator's own device pairing from the same place - for guesses at
// a window that no longer existed.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestR2CX_F04_AMalformedPinOnAWindowGoneBeforeItsGradingBillsNobody(t *testing.T) {
	for _, c := range []struct {
		name     string
		window   func(t *testing.T, f *fixture)
		wantCode string
	}{
		{"replaced", func(t *testing.T, f *fixture) { seedPairingWindow(t, f, "222222", time.Hour) }, "E_PAIRING_INACTIVE"},
		{"closed", func(t *testing.T, f *fixture) {
			if err := f.store.Update(func(st *state.State) error { st.PairingPending = nil; return nil }); err != nil {
				t.Fatal(err)
			}
		}, "E_PAIRING_INACTIVE"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, nil)
			const addr = "203.0.113.9:40001"
			key := genSigner(t)
			fp := fingerprintOf(t, key.PublicKey())
			line := authorizedLine(key.PublicKey())
			malformed, err := json.Marshal(pairingRequest{Proto: 1, Pin: "12ab45", Pubkey: line})
			if err != nil {
				t.Fatal(err)
			}

			// Three malformed PINs, each from a connection admitted to
			// window A, each landing as A is replaced (or closed) - after
			// the fast check, before the transaction. Three would reach
			// the limiter's threshold if any of them were billed.
			t.Cleanup(func() { afterPairingFastCheckFn = nil })
			for i := 0; i < 3; i++ {
				seedPairingWindow(t, f, "111111", time.Hour)
				bindingA := pairingWindowBindingHex(f.store.Get().PairingPending)
				afterPairingFastCheckFn = func() { c.window(t, f) }
				_, cerr := f.gw.runPairing(malformed, addr, fp, bindingA, f.clock.Now())
				afterPairingFastCheckFn = nil
				wantPairingRefusal(t, "malformed PIN on a window gone before its grading", cerr, c.wantCode, 2)
				if pp := f.store.Get().PairingPending; pp != nil && pp.Misses != 0 {
					t.Fatalf("the window open now was charged %d misses for a guess at the one before it", pp.Misses)
				}
			}

			// The address was billed nothing: its next wrong PIN, at a
			// window it was admitted to, is graded - not locked out.
			seedPairingWindow(t, f, "111111", time.Hour)
			_, cerr := runPairingAt(f, addr, fp, "000000", line)
			wantPairingRefusal(t, "a wrong PIN after three malformed ones at windows that were gone", cerr, "E_PAIRING_PIN_INVALID", 2)
		})
	}
}
