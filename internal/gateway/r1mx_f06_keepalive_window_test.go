package gateway

// F-06 of the round-1 review (24.09.2026): a machine that stops
// answering keepalives is torn down and the journal says so -
// machine.disconnected with result "keepalive-timeout" - but the line
// does not say how long the machine was silent or over what window the
// gateway watched. An operator looking at "the machine drops every
// minute" has the reason and nothing to measure it against.
//
// What the finding proposes verbatim is not what went in. It asks for the
// miss count passed into onDead; at the point onDead runs, the count IS
// the configured maximum - sshx/keepalive.go ends the loop on
// `miss >= maxMisses` and nowhere else - so the count on its own says
// nothing the config does not. And it asks for a second event for the
// same fact, which would put two lines in the journal for one death. What
// went in instead: the numbers the probe actually ran with (interval,
// misses, and the window they add up to) go into the one
// machine.disconnected line that already reports the death, taken from
// the same source of truth the probe uses.

import (
	"fmt"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestR1MXF06_AMachineThatStopsAnsweringKeepalivesSaysHowLongItWasSilent(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.Keepalive = sshx.Keepalive{Interval: 80 * time.Millisecond, MaxMisses: 2}
	})
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	fm.goSilent()
	waitUntil(t, "the silent machine was not torn down", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return !ok
	})

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventMachineDisconnected}})
	if err != nil {
		t.Fatalf("read the machine.disconnected journal: %v", err)
	}
	var dead *events.Event
	for i := range evs {
		if evs[i].Result == "keepalive-timeout" {
			dead = &evs[i]
		}
	}
	if dead == nil {
		t.Fatalf("no machine.disconnected with the keepalive reason: %+v", evs)
	}
	// The removal above is what the gateway did; this is what it knew:
	// the numbers the probe ran with, so the line is readable years later
	// without the config file it was written under.
	if got := fmt.Sprint(dead.Details["misses"]); got != "2" {
		t.Errorf("details.misses = %v, want the 2 misses the probe waited for (F-06): the death is the only place an operator sees why a machine dropped", dead.Details["misses"])
	}
	if got := fmt.Sprint(dead.Details["interval"]); got != "80ms" {
		t.Errorf("details.interval = %v, want the probe interval the gateway ran with (80ms)", dead.Details["interval"])
	}
	if got := fmt.Sprint(dead.Details["window"]); got != "160ms" {
		t.Errorf("details.window = %v, want how long the machine was silent before the gateway gave up (2 misses at 80ms = 160ms)", dead.Details["window"])
	}
}
