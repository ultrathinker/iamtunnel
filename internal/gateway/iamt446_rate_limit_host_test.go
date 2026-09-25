package gateway

// IAMT-446: the main login limiter counted failures per "ip:port" - the
// string RemoteAddr gives. Every TCP connection gets a fresh source port,
// so every reconnect started a fresh counter: key spray from one address
// was never banned at all, and an address that had earned a ban walked
// past it by reconnecting. The pairing limiter has counted per host since
// IAMT-330; the main one did not. Both now count by peerHost.

import "testing"

func TestIAMT446_ABanSurvivesAReconnect(t *testing.T) {
	f := newFixture(t, nil)

	// One more unknown key than the address threshold allows, each on a
	// connection of its own - so each from a new source port.
	for i := 0; i <= f.gw.cfg.RateConfig.MaxUnknownFailures; i++ {
		if c, err := dialHuman(t, f.addr, f.person, f.machineID, genSigner(t)); err == nil {
			c.Close()
			t.Fatalf("attempt %d: a key nobody registered was let in", i)
		}
	}

	// The person's own key, from the same address, on yet another
	// connection: the address is banned, and a new port must not matter.
	if c, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey); err == nil {
		c.Close()
		t.Fatalf("after %d unknown keys from one address, a new connection from it was let in: the ban was keyed by the source port, and reconnecting walked past it",
			f.gw.cfg.RateConfig.MaxUnknownFailures+1)
	}
}
