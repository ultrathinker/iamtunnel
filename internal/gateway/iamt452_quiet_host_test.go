package gateway

// IAMT-452 meets M-13 (merge of main affe89f). auth.success is folded per
// login, key and host, and the host came from peerHost - which the merge
// taught to collapse an IPv6 address to its /64 for the two limiters. For
// a limiter the /64 is the point: inside it an attacker changes address
// for free. For the journal it was a loss: one key logging in from two
// computers of one IPv6 network within the quiet period was one line, and
// the second computer's address was in none.

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
)

func TestIAMT452_TwoComputersInOneIPv6NetworkAreTwoSources(t *testing.T) {
	f := newFixture(t, nil)
	fp := auth.Fingerprint(genSigner(t).PublicKey())
	for _, addr := range []string{
		"[2001:db8:1:2::10]:50000",
		"[2001:db8:1:2::20]:50001", // another computer, same /64
		"[2001:db8:1:2::10]:50002", // the first one again: a repeat
	} {
		f.gw.AuthAccepted(addr, "root", fp, "root", auth.RolePerson)
	}
	evs := iamt452Successes(t, f, "root")
	if len(evs) != 2 {
		t.Fatalf("one key from two computers of one IPv6 /64 wrote %d auth.success, want two - one per computer: %+v", len(evs), evs)
	}
	if evs[0].Address != "[2001:db8:1:2::10]:50000" || evs[1].Address != "[2001:db8:1:2::20]:50001" {
		t.Errorf("the lines name %q and %q, want each computer's own address", evs[0].Address, evs[1].Address)
	}
}
