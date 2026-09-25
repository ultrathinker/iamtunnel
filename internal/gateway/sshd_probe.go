package gateway

// sshd_probe.go implements PROTOCOL §7's sshd-probe. It is intentionally
// attached to a live machineConn: only that connection can open
// iamtunnel-target and only its door automaton can install and remove the
// temporary administrators_authorized_keys line.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// needsSSHDProbe reports whether the current record still needs a proof. It
// deliberately includes rejected records: the next tunnel is a documented
// retry opportunity, while verified records are not probed repeatedly.
func (g *Gateway) needsSSHDProbe(machineID string) bool {
	st := g.cfg.Store.Get()
	m, ok := st.MachineByID(machineID)
	return ok && m.RequestedOSUser != "" && m.OSUserStatus != state.OSUserStatusVerified
}

// runSSHDProbe performs an automatic ordered two-phase proof with one absolute
// budget. A reconnect and machines.set-user both reach this entry point without
// an administrator deciding that a prior substitution is resolved.
func (g *Gateway) runSSHDProbe(mc *machineConn) error {
	return g.runSSHDProbeWithMismatchClear(mc, false)
}

// runSSHDProbeForAdmin is the explicit administrator re-verification path.
// Only this path may clear mismatch when the target has returned to the
// already-pinned key. A different observed key remains a mismatch and must
// instead be accepted deliberately with machines.rekey.
func (g *Gateway) runSSHDProbeForAdmin(mc *machineConn) error {
	return g.runSSHDProbeWithMismatchClear(mc, true)
}

// probeDeadline returns the deadline one budget-bounded probe wait may use:
// the shared budget, unless a test installed probeDeadlineFn (IAMT-304). A
// deadline later than the shared one is ignored, so the seam can only shorten
// what PROTOCOL §7 gives the probe — a test must never be able to assert
// behaviour the product cannot have, and a probe that outlived its announced
// deadline is exactly what IAMT-304 is about.
//
// It is consulted once per bounded wait rather than once per probe because
// the interesting states a test needs are "already spent" (before the
// reservation) and "spends itself while door.open is in flight" — both are
// properties of one wait, and a single value captured at the top of the probe
// cannot express the second without also squeezing phase one.
func (g *Gateway) probeDeadline(shared time.Time) time.Time {
	if g.probeDeadlineFn == nil {
		return shared
	}
	if d := g.probeDeadlineFn(shared); d.Before(shared) {
		return d
	}
	return shared
}

// runSSHDProbeWithMismatchClear performs the ordered two-phase proof with one absolute budget.
// Its deferred completion is the security boundary for the temporary door:
// after reserve succeeds, every return including a recovered panic first feeds
// the appropriate terminal event into the door automaton, which emits and
// drives door.close before the state/event verdict is committed.
func (g *Gateway) runSSHDProbeWithMismatchClear(mc *machineConn, mayClearMismatch bool) (err error) {
	mc.probeMu.Lock()
	defer mc.probeMu.Unlock()

	var requested string
	st := g.cfg.Store.Get()
	if m, ok := st.MachineByID(mc.id); ok {
		requested = m.RequestedOSUser
	}
	if requested == "" {
		return g.finishSSHDProbe(mc.id, requested, errors.New("requested OS user is empty"))
	}

	// PROTOCOL §7 gives the whole probe one absolute budget. Phase one spends
	// it on the shared deadline below; the two waits the gateway itself bounds
	// (the reservation context and phase two's connection) go through
	// probeDeadline, whose production value is that same deadline — and whose
	// only other value a test may install is an earlier one.
	deadline := time.Now().Add(g.cfg.SSHDProbeTimeout)
	reserved := false
	outcomeWritten := false
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sshd probe panic: %v", r)
		}
		if reserved {
			// A probe only holds a reservation: it deliberately never creates a
			// shell, exec, or counted session. NestedFailure is consequently the
			// matching terminal transition even after successful user-auth.
			if closeErr := mc.releaseProbeReservation(); closeErr != nil {
				if err == nil {
					err = fmt.Errorf("release temporary probe door reservation: %w", closeErr)
				} else {
					err = fmt.Errorf("%w; additionally failed to release temporary probe door reservation: %v", err, closeErr)
				}
			}
		}
		if !outcomeWritten {
			err = g.finishSSHDProbe(mc.id, requested, err)
		}
	}()

	// Phase 1: observe the target's host key before any door is installed.
	observed, observeErr := g.observeSSHDHostKey(mc, deadline)
	if observeErr != nil {
		return observeErr
	}
	stickyMismatch, pinErr := g.pinSSHDHostKeyWithMismatchClear(mc.id, observed, mayClearMismatch)
	if pinErr != nil {
		err = pinErr
		return err
	}
	if stickyMismatch {
		return errors.New("recorded SSHD host-key mismatch requires explicit administrator verification")
	}

	ctx, cancel := context.WithDeadline(context.Background(), g.probeDeadline(deadline))
	defer cancel()
	opened, reason := mc.reserve(ctx)
	if !opened {
		// IAMT-304: a reservation that fails with the budget gone is a
		// deadline verdict, not an open failure — the probe must say so
		// itself, because reserve cannot know whose budget it was given.
		// "While reserving" covers both shapes the deadline takes: the send
		// was refused because there was no time left, or the wait for the
		// reply ended at the deadline rather than at DoorOpenTimeout. The
		// reason names which, and whether anything reached the wire.
		if ctx.Err() != nil {
			return fmt.Errorf("sshd probe deadline exceeded while reserving the temporary door: %s", reason)
		}
		return fmt.Errorf("temporary door did not open: %s", reason)
	}
	reserved = true

	// Phase 2: public-key user-auth as exactly the requested account. No
	// channel, shell or exec is opened after this authentication succeeds.
	var doorID string
	doorID, err = g.authenticateProbeUser(mc, requested, observed, g.probeDeadline(deadline))
	if isSSHAuthFailed(err) {
		// IAMT-461, as on a person's way in: a refused door key is as often
		// a door the machine closed on its own timer - a session had kept
		// the automaton at open - as a refused account. Ask the machine
		// before judging the account; through a new door, try once more.
		switch mc.recheckDoor(ctx, doorID) {
		case doorReopened:
			_, err = g.authenticateProbeUser(mc, requested, observed, g.probeDeadline(deadline))
		case doorUnavailable:
			// The automaton has released this reservation already.
			reserved = false
			err = fmt.Errorf("the temporary door was gone and no new one opened: %w", err)
		}
	}
	if err != nil {
		return err
	}
	// The protocol records the successful proof before it asks the target to
	// remove the temporary key. The deferred reservation release below is still
	// unconditional, including when this state write or the return path panics.
	outcomeWritten = true
	if err = g.finishSSHDProbe(mc.id, requested, nil); err != nil {
		return err
	}
	return nil
}

func (g *Gateway) observeSSHDHostKey(mc *machineConn, deadline time.Time) (string, error) {
	if g.phaseOneObserveFn != nil {
		return g.phaseOneObserveFn(mc, deadline)
	}
	target, reqs, err := g.openProbeTarget(mc, deadline)
	if err != nil {
		return "", err
	}
	defer target.Close()
	go discardRequests(reqs)

	var observed string
	conn := sshx.NewChannelConn(target)
	_ = conn.SetDeadline(deadline)
	probeCfg1 := &ssh.ClientConfig{
		User: "iamtunnel-hostkey-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			observed = authorizedKeyLine(key)
			return nil
		},
	}
	// PROTOCOL §5.2: ordered KEX/cipher/MAC and host-key algorithm lists
	// applied to the probe handshake (IAMT-173).
	sshx.ApplyClientConfig(probeCfg1)
	client, _, _, handshakeErr := ssh.NewClientConn(conn, "localhost:22", probeCfg1)
	if client != nil {
		_ = client.Close()
	}
	// x/crypto's public client API performs the mandatory `none` auth request
	// after KEX. A target that requires public keys therefore returns an auth
	// error here, but only after HostKeyCallback has observed the KEX host key.
	if observed == "" {
		if handshakeErr == nil {
			handshakeErr = errors.New("target supplied no SSH host key")
		}
		return "", fmt.Errorf("target host-key handshake: %w", handshakeErr)
	}
	return observed, nil
}

// authenticateProbeUser answers the id of the door whose key it tried, so a
// refusal can be checked against that door (IAMT-461).
func (g *Gateway) authenticateProbeUser(mc *machineConn, user, pinned string, deadline time.Time) (string, error) {
	target, reqs, err := g.openProbeTarget(mc, deadline)
	if err != nil {
		return "", err
	}
	defer target.Close()
	go discardRequests(reqs)
	signer, doorID := mc.currentDoorSigner()
	if signer == nil {
		return doorID, errors.New("temporary door has no signer")
	}
	want, err := state.DecodeKeyBlob(pinned)
	if err != nil {
		return doorID, fmt.Errorf("pinned SSHD host key: %w", err)
	}
	conn := sshx.NewChannelConn(target)
	_ = conn.SetDeadline(deadline)
	probeCfg2 := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !bytes.Equal(key.Marshal(), want) {
				return errors.New("target SSHD host key changed during probe")
			}
			return nil
		},
	}
	// PROTOCOL §5.2: ordered KEX/cipher/MAC and host-key algorithm lists
	// applied to the user-auth probe handshake (IAMT-173).
	sshx.ApplyClientConfig(probeCfg2)
	client, _, _, err := ssh.NewClientConn(conn, "localhost:22", probeCfg2)
	if client != nil {
		defer client.Close()
	}
	if err != nil {
		return doorID, fmt.Errorf("SSH public-key user-auth for %q: %w", user, err)
	}
	return doorID, nil
}

func (g *Gateway) openProbeTarget(mc *machineConn, deadline time.Time) (ssh.Channel, <-chan *ssh.Request, error) {
	ch, reqs, err := sshx.OpenChannelWithDeadline(mc.sconn, "iamtunnel-target", deadline, mc.doneCh)
	switch {
	case errors.Is(err, sshx.ErrOpenChannelTimeout):
		// Nothing can call back an open that is still unanswered. Cutting
		// this dead tunnel is safer than leaving a probe (and potentially
		// its later door) without an owner.
		mc.teardown("sshd-probe-target-timeout")
		return nil, nil, errors.New("iamtunnel-target open timed out")
	case errors.Is(err, sshx.ErrOpenChannelStopped):
		return nil, nil, errors.New("machine tunnel disconnected")
	}
	return ch, reqs, err
}

func (g *Gateway) pinSSHDHostKey(machineID, observed string) error {
	_, err := g.pinSSHDHostKeyWithMismatchClear(machineID, observed, false)
	return err
}

// pinSSHDHostKeyWithMismatchClear records the phase-one observation. A
// mismatch is sticky on every automatic path. The sole exception is the
// explicit administrator verification path, which may clear it only after a
// new observation has matched the existing pinned key.
func (g *Gateway) pinSSHDHostKeyWithMismatchClear(machineID, observed string, mayClearMismatch bool) (stickyMismatch bool, err error) {
	// The state write and the line that records it are ONE publication
	// (R3 F-03, round-3 review 24.09.2026): "gateway backup" reads
	// state.json and events.jsonl and accepts the pair only if nothing
	// moved under it, and this is the write that marks a machine suspect.
	// Until this round the mark had NO line at all - the state said
	// "mismatch" and the journal said nothing about why, while the sticky
	// rule (only an administrator's explicit verify may clear it) leans on
	// that state and the audit of the decision leans on the journal.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	mismatch := false
	var pinnedFP, observedFP string
	err = g.cfg.Store.Update(func(st *state.State) error {
		for i := range st.Machines {
			m := &st.Machines[i]
			if m.ID != machineID {
				continue
			}
			if m.SSHDHostKey != nil {
				pinned, err := state.DecodeKeyBlob(*m.SSHDHostKey)
				if err != nil {
					return fmt.Errorf("stored SSHD host key: %w", err)
				}
				seen, err := state.DecodeKeyBlob(observed)
				if err != nil {
					return fmt.Errorf("observed SSHD host key: %w", err)
				}
				if !bytes.Equal(pinned, seen) {
					m.HostKeyStatus = state.HostKeyStatusMismatch
					m.ObservedSSHDHostKey = &observed
					mismatch = true
					if fp, ferr := state.ComputeFingerprint(*m.SSHDHostKey); ferr == nil {
						pinnedFP = fp
					}
					if fp, ferr := state.ComputeFingerprint(observed); ferr == nil {
						observedFP = fp
					}
					return nil
				}
				if m.HostKeyStatus == state.HostKeyStatusMismatch && !mayClearMismatch {
					// Do not overwrite the foreign key that made the machine
					// suspect merely because a later automatic probe agrees with
					// the pinned key. An administrator must explicitly verify it.
					stickyMismatch = true
					return nil
				}
			}
			m.SSHDHostKey = &observed
			m.ObservedSSHDHostKey = &observed
			m.HostKeyStatus = state.HostKeyStatusMatch
			return nil
		}
		return errors.New("machine disappeared during sshd probe")
	})
	if err != nil {
		return false, err
	}
	if mismatch {
		// The line the human path writes for the same fact (hostkey.mismatch,
		// §3.5): the actor is the gateway itself, the probe path has no person
		// to name, and the details say which path saw it.
		g.appendEvent(events.Event{
			Type:        events.EventHostKeyMismatch,
			Actor:       "gateway",
			Object:      machineID,
			Result:      "mismatch",
			Fingerprint: observedFP,
			Details: map[string]interface{}{
				"observed": observedFP,
				"pinned":   pinnedFP,
				"path":     "sshd-probe",
			},
		})
		return false, errors.New("target SSHD host key does not match the pinned key")
	}
	return stickyMismatch, nil
}

func (g *Gateway) finishSSHDProbe(machineID, requested string, probeErr error) error {
	// Same publication, same lock as above (R3 F-03): the state says the
	// machine is verified (or rejected) and the line says so too, and a
	// backup must not be able to keep one without the other. This function
	// is called from the probe path only - never from under a command that
	// already holds the lock (machines.verify does NOT take it: it would
	// meet its own probe here), which is why the lock is taken once, in
	// the writers, rather than around the whole probe with its network I/O.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if probeErr == nil {
		probeErr = g.cfg.Store.Update(func(st *state.State) error {
			for i := range st.Machines {
				m := &st.Machines[i]
				if m.ID != machineID || m.RequestedOSUser != requested {
					continue
				}
				verified := requested
				m.VerifiedOSUser = &verified
				m.OSUserStatus = state.OSUserStatusVerified
				m.State = "verified"
				return nil
			}
			return errors.New("machine or requested OS user changed during sshd probe")
		})
	}
	if probeErr != nil {
		_ = g.cfg.Store.Update(func(st *state.State) error {
			for i := range st.Machines {
				m := &st.Machines[i]
				if m.ID == machineID && m.RequestedOSUser == requested {
					m.VerifiedOSUser = nil
					m.OSUserStatus = state.OSUserStatusRejected
					m.State = "enrolled"
				}
			}
			return nil
		})
		g.appendEvent(events.Event{Type: events.EventEnrolFailed, Actor: machineID, Object: machineID, Result: "sshd-probe", Details: map[string]interface{}{"reason": probeErr.Error(), "requestedOsUser": requested}})
		return probeErr
	}
	g.appendEvent(events.Event{Type: events.EventEnrolVerified, Actor: machineID, Object: machineID, Result: "verified", Details: map[string]interface{}{"requestedOsUser": requested}})
	return nil
}

func authorizedKeyLine(key ssh.PublicKey) string {
	return string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(key)))
}
