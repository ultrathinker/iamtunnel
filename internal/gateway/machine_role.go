package gateway

import (
	"errors"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// handleMachine registers a machine connection - only while no other
// connection for the same id is registered: a second one is refused with
// E_MACHINE_ALREADY_ONLINE and the first is left alone (PROTOCOL §5; a
// reconnect is accepted once the old epoch has left the registry) - opens the one iamtunnel-control channel and runs the initial
// door.status handshake (PROTOCOL §7 "tunnel-connected"). All door policy
// after this point is driven exclusively through machineConn.driveOne.
func (g *Gateway) handleMachine(sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, id string) {
	epoch := g.nextEpoch()
	mc, err := newMachineConn(g, id, sconn, epoch)
	if err != nil {
		_ = sconn.Close()
		return
	}

	accepted, reconnect := g.reg.registerIfVacant(mc)
	if !accepted {
		g.appendEvent(events.Event{
			Type:   events.EventMachineRejected,
			Actor:  id,
			Object: id,
			Result: "E_MACHINE_ALREADY_ONLINE",
		})
		_ = sconn.Close()
		return
	}
	result := "connected"
	if reconnect {
		result = "reconnected"
	}
	g.appendEvent(events.Event{
		Type:    events.EventMachineConnected,
		Actor:   id,
		Object:  id,
		Result:  result,
		Details: map[string]interface{}{"tunnelEpoch": epoch},
	})

	// The probe's own numbers go into the record with the death (F-06,
	// round-1 review 24.09.2026): "keepalive-timeout" says a machine went
	// silent, and the window says for how long the gateway watched before
	// it believed it. Taken from Resolved, the same source the probe uses,
	// so the line cannot claim numbers the probe did not run with.
	keepaliveInterval, keepaliveMisses, _ := g.cfg.Keepalive.Resolved()
	mc.setStopProbe(g.cfg.Keepalive.Probe(sconn, func() {
		mc.teardownWith("keepalive-timeout", map[string]interface{}{
			"misses":   keepaliveMisses,
			"interval": keepaliveInterval.String(),
			"window":   (time.Duration(keepaliveMisses) * keepaliveInterval).String(),
		})
	}))

	// PROTOCOL §5: only the gateway opens channels toward the machine
	// (iamtunnel-control, iamtunnel-target); any channel-open the machine
	// itself attempts is a protocol violation.
	go func() {
		for n := range chans {
			_ = n.Reject(ssh.Prohibited, "machines do not open channels")
		}
	}()
	// The machine's only permitted global request is keepalive@iamtunnel;
	// the table's default-deny covers everything else (PROTOCOL §5).
	go func() {
		for r := range reqs {
			d := sshx.LookupGlobalRequest(r.Type)
			_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, nil)
		}
	}()

	// PROTOCOL §5.1: the machine accepts the control channel within
	// ControlAcceptTimeout, or the transport is closed and the machine
	// reconnects as usual. Unbounded, a machine that answered its
	// keepalives and nothing else held its registry slot - and turned its
	// own honest reconnects away as E_MACHINE_ALREADY_ONLINE - for good
	// (IAMT-450).
	ctrlCh, ctrlReqs, err := sshx.OpenChannelWithDeadline(sconn, "iamtunnel-control", time.Now().Add(g.cfg.ControlAcceptTimeout), mc.doneCh)
	if err != nil {
		if errors.Is(err, sshx.ErrOpenChannelTimeout) {
			mc.teardown("control-open-timeout")
		} else {
			mc.teardown("control-open-failed")
		}
		return
	}
	mc.attachControl(ctrlCh, ctrlReqs)

	// Initial door.status: the automaton starts Closed/offline (NewMachine)
	// and only closedStatus's Installed:false branch sets Online - no
	// reservation may be admitted before this completes (see stateView.
	// MachineOnline, which reads exactly this flag). Under driveMu (F-23):
	// the sweep's answer is applied to the automaton as one wire cycle,
	// serialized with any cycle another goroutine may already be running.
	mc.driveOneSync(core.Command{Op: "door.status"})
	if mc.IsOnline() && g.needsSSHDProbe(id) {
		// Counted in g.probesWG, not in g.wg (IAMT-161). handleMachine
		// returns immediately so it can start serving the machine's
		// channels while the probe runs to completion; the probe's
		// finishSSHDProbe writes events.jsonl + state.json. Without the
		// WaitGroup, a probe still running when Close has returned can
		// create a state.json.tmp.<pid>.<nanos> file *after* every
		// t.Cleanup callback has run, and t.TempDir RemoveAll fails with
		// "directory is not empty". Close blocks on g.probesWG below.
		g.probesWG.Add(1)
		g.probesInFlight.Add(1)
		go func() {
			defer g.probesWG.Done()
			defer g.probesInFlight.Add(-1)
			g.runSSHDProbe(mc)
		}()
	}
}
