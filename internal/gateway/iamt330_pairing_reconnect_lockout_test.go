package gateway

// iamt330_pairing_reconnect_lockout_test.go — IAMT-323 review follow-up
// (IAMT-330): the pairing lockout must survive reconnection.
//
// The review found that the pairing limiter was keyed by the raw
// ip:port of each connection, and every pairing connection carries
// exactly one exec before it closes — so a client that reconnects per
// guess drew a fresh failure counter every time and the three-strikes
// ban never triggered over the network. The unit tests had hidden this
// by grading every attempt at one literal address.
//
// This test drives four REAL fresh TCP
// dials from the same source machine, each a full SSH handshake plus
// one wrong-PIN admin.pair, and the fourth connection must find the
// door closed.

import (
	"strings"
	"testing"
	"time"
)

func TestPairingLockoutSurvivesReconnection(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "135790", 2*time.Minute)
	attacker := genSigner(t)
	line := authorizedLine(attacker.PublicKey())

	// Three wrong PINs, each on its own fresh connection — exactly what a
	// reconnect-per-guess attacker does. Each must be graded (PIN_INVALID):
	// the ban begins at the fourth attempt, not the first.
	for i, pin := range []string{"111111", "222222", "333333"} {
		env, _ := iamt143Exec(t, f.addr, "pairing", attacker, "admin.pair",
			pairingRequest{Proto: 1, Pin: pin, Pubkey: line})
		if env.Error == nil || env.Error.Code != "E_PAIRING_PIN_INVALID" {
			t.Fatalf("wrong PIN #%d on a fresh connection: got code %q, want E_PAIRING_PIN_INVALID", i+1, errCode(env))
		}
	}
	requirePairingWindowOpen(t, f, "after three wrong PINs")

	// The fourth connection from the same machine must be refused: the
	// limiter counts the ADDRESS, so a fresh source port buys nothing.
	// Before the fix each reconnect drew a fresh ip:port counter and this
	// dial was accepted like the first three. (The dial error itself is
	// opaque by SSH design — the server's reason never reaches the client.)
	err := pairingDialErr(t, f.addr, attacker)
	if err == nil {
		t.Fatal("fourth connection from the same address was accepted: the pairing lockout did not survive reconnection")
	}

	// Why it was refused: probe the handshake seam from a port the attacker
	// never used — still the same machine, so still banned.
	_, cbErr := f.gw.pairingKeyCallback("127.0.0.1:61000", fingerprintOf(t, attacker.PublicKey()), f.clock.Now())
	if cbErr == nil || !strings.Contains(cbErr.Error(), "rate limited") {
		t.Fatalf("fresh-port handshake from the banned address = %v, want the limiter's rate-limit refusal", cbErr)
	}
}

// errCode pulls the wire code out of an exec envelope for failure messages.
func errCode(env iamt143WireEnvelope) string {
	if env.Error == nil {
		return "<no error>"
	}
	return env.Error.Code
}
