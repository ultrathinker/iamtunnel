package gateway

// F-24 (round-1 review, 24.09.2026): serveHumanSession reads the
// draining flag exactly once, at its top, and the session it is building
// becomes visible to a drain only at OpenSession - a whole setup (the door
// reservation, the iamtunnel-target open, the nested SSH handshake) later. A
// Drain that starts inside that window sees zero registered sessions, tells
// nobody, and returns: the stop that called it proceeds on the belief that
// nothing is running, while the session it never counted finishes its
// setup, opens the door, and works - to be cut by the very restart the
// drain was supposed to be gentle about.
//
// The test parks a human session inside exactly that window (on
// beforeSendCommandFn, the F-23 seam, just before the session's door.open
// goes on the wire - by then the session has already read draining==false)
// and runs a Drain to completion around it. Then the setup is allowed to
// finish. What must not happen is the session completing after the drain
// has already reported done.

import (
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
)

func TestR1CX_F24_DrainCannotFinishWhileASessionIsStillBeingEstablished(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// The victim: a session channel accepted before the stop, parked in the
	// blind spot between its draining check and its registration in the
	// engine's session list.
	parked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	prevSeam := beforeSendCommandFn.Load()
	seam := func(mc *machineConn, cmd core.Command) {
		if cmd.Op != "door.open" {
			return
		}
		once.Do(func() {
			close(parked)
			<-release
		})
	}
	beforeSendCommandFn.Store(&seam)
	t.Cleanup(func() { beforeSendCommandFn.Store(prevSeam) })

	victim, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer victim.Close()
	hs := openHumanSession(t, victim, f) // the session channel alone starts serveHumanSession

	select {
	case <-parked:
	case <-time.After(10 * time.Second):
		t.Fatal("the session never reached the setup between its draining check and its registration")
	}

	// The stop. With the session still invisible, a drain has nothing to
	// wait for.
	drainDone := make(chan struct{})
	go func() {
		f.gw.Drain(10 * time.Second)
		close(drainDone)
	}()
	waitUntil(t, "the drain did not begin", func() bool { return f.gw.draining.Load() })
	select {
	case <-drainDone:
	case <-time.After(500 * time.Millisecond):
		// The drain is still holding: it sees the parked setup (the fixed
		// world). Either way the assertion below decides.
	}

	// The setup finishes - after the stop, whatever the drain believed: the
	// door opens, the nested handshake runs, the session registers, starts,
	// and carries traffic.
	close(release)
	hs.shell(t)
	const marker = "r1-cx-f24-alive-after-drain"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write to the session that outlived the drain: %v", err)
	}
	readUntil(t, hs.ch, marker)

	select {
	case <-drainDone:
		t.Fatalf("the drain completed while a session was still being established: the session finished its setup after the gateway had already reported the stop done and works (%s round-tripped) - a stop that proceeds now cuts a session the drain never counted and never told (F-24)", marker)
	default:
	}

	// The fixed world: the drain was held until this session registered, so
	// the session was told the gateway is restarting, and the drain holds
	// until the session actually leaves.
	if got, ok := iamt466ReadWithin(hs.ch.Stderr(), "gateway is restarting", 5*time.Second); !ok {
		t.Fatalf("the session that slipped under the drain was never told the gateway is restarting (stderr: %q)", got)
	}
	_ = hs.ch.Close()
	select {
	case <-drainDone:
	case <-time.After(9 * time.Second):
		t.Fatal("the drain did not end when the session left")
	}
}
