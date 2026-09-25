package gateway

import (
	"sync"

	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// stateView answers auth.Lookup and acl.View from the two places PROTOCOL and
// the acl package's own doc comment say the answers must come from: persisted
// facts read from the state store, and live connection facts read from the
// in-memory machine registry of the running gateway - never the other way
// round.
type stateView struct {
	store *state.Store
	reg   *registry
}

// Resolve implements auth.Lookup: fingerprint -> (Subject, ok, error). It is
// called from the SSH PublicKeyCallback path, including on unsigned probes, so
// it only ever reads the store snapshot - no side effects.
//
// The one-shot enrol/bootstrap paths resolve to a "pending" principal:
// the SSH handshake itself does not consult PendingEnrolment.Expires or
// BootstrapPending.Expires — that expiry is enforced atomically when the
// "enrol" / "admin.claim" exec body runs. Resolving the key here just
// decides "yes, this key is one of the one-shot secrets we issued, the
// caller is allowed to send the exec body". A repeat attempt, even with
// the same key, that finds the pending entry gone (consumed or expired)
// is simply unknown-key at the SSH layer (PROTOCOL §3.2/§3.3: the
// PublicKeyCallback accepts this key only with the enrol role and only
// until the code is spent).
func (v *stateView) Resolve(fingerprint string) (auth.Subject, bool, error) {
	st := v.store.Get()
	if person, ok := personWithKey(st, fingerprint); ok {
		return auth.Subject{Name: person, Role: auth.RolePerson}, true, nil
	}
	for _, m := range st.Machines {
		fp, err := state.ComputeFingerprint(m.MachineKey)
		if err == nil && fp == fingerprint {
			return auth.Subject{Name: m.ID, Role: auth.RoleMachine}, true, nil
		}
		// Machine.EnrolPending is NOT consulted (IAMT-336 / 1.3). It
		// was where an invitation lived when invitations were bound to
		// a machine; every invitation now lives unbound in
		// st.PendingEnrolments below, and runEnrol reads only that
		// list. A key admitted from here could therefore never enrol
		// anything — but nothing in 1.3 clears the field either, so a
		// state.json carried over from 1.2 would keep letting that key
		// open an enrol session for good, long past the expiry written
		// beside it. An invitation that cannot be redeemed must not
		// open a session, and one that cannot be revoked by waiting is
		// the opposite of what the 15-minute TTL is for. The field
		// stays valid on disk (validate.go still checks its shape, so
		// a 1.2 file still loads) and is simply never honoured again.
	}
	for _, pe := range st.PendingEnrolments {
		efp, eerr := state.ComputeFingerprint(pe.PublicKey)
		if eerr == nil && efp == fingerprint {
			// IAMT-336 / 1.3: pending enrolments are unbound, so
			// Subject.Name is empty here. The enrol handler that
			// receives this identity must not use it as a machine id;
			// the machine id arrives in the enrol exec body, not in
			// the SSH handshake. See handleEnrol.
			return auth.Subject{Name: "", Role: auth.RoleEnrol}, true, nil
		}
	}
	if st.BootstrapPending != nil {
		bfp, err := state.ComputeFingerprint(st.BootstrapPending.PublicKey)
		if err == nil && bfp == fingerprint {
			return auth.Subject{Name: "", Role: auth.RoleBootstrap}, true, nil
		}
	}
	return auth.Subject{}, false, nil
}

// personWithKey names the person a key belongs to - the lookup the
// handshake makes (Resolve), and the one a connection is held to for as
// long as it lasts (key_conns.go).
func personWithKey(st state.State, fingerprint string) (string, bool) {
	for _, p := range st.People {
		for _, k := range p.Keys {
			if k.Fingerprint == fingerprint {
				return p.Name, true
			}
		}
	}
	return "", false
}

// knownFingerprint reports whether fingerprint belongs to any registered
// person or machine key, independent of algorithm policy - this is the SPEC
// §1.4 classification ("known-key" vs "unknown-key") used for rate limiting,
// which must not be gated by AcceptKey the way auth.Handler.Resolve is.
func (v *stateView) knownFingerprint(fingerprint string) bool {
	_, ok, _ := v.Resolve(fingerprint)
	return ok
}

func (v *stateView) PersonExists(person string) bool {
	st := v.store.Get()
	return st.HasPerson(person)
}

func (v *stateView) MachineExists(machine string) bool {
	st := v.store.Get()
	_, ok := st.MachineByID(machine)
	return ok
}

func (v *stateView) MachineVerified(machine string) bool {
	st := v.store.Get()
	m, ok := st.MachineByID(machine)
	return ok && m.State == "verified"
}

func (v *stateView) MachineOnline(machine string) bool {
	mc, ok := v.reg.get(machine)
	if !ok {
		return false
	}
	return mc.doorMachine.Snapshot().Online
}

// registry is the live machine-connection table (SPEC §4: the machine table,
// id -> ServerConn. It is the ONLY place "is this machine online right now" can be
// answered from - never state.json, which cannot know about a live socket.
type registry struct {
	mu        sync.Mutex
	byID      map[string]*machineConn
	lastEpoch map[string]uint64
}

func newRegistry() *registry {
	return &registry{
		byID:      make(map[string]*machineConn),
		lastEpoch: make(map[string]uint64),
	}
}

func (r *registry) get(id string) (*machineConn, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	mc, ok := r.byID[id]
	return mc, ok
}

// Get is the exported counterpart of get; tests outside the gateway
// package use it to read the registry without poking unexported
// methods.
func (r *registry) Get(id string) (*machineConn, bool) { return r.get(id) }

// register installs mc as the current connection for its id and returns the
// previous connection, if any. The gateway itself no longer takes this path:
// a live connection is never evicted, a second one is refused
// (registerIfVacant, E_MACHINE_ALREADY_ONLINE - PROTOCOL §5); register is
// kept for the tests that need to stage a replaced connection. The swap
// happens under the registry lock so MachineOnline never observes two
// connections for one id.
func (r *registry) register(mc *machineConn) (old *machineConn, hadOld bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old, hadOld = r.byID[mc.id]
	r.byID[mc.id] = mc
	return old, hadOld
}

// all snapshots the live machine connections, for shutdown sweeps. The
// slice is a copy, so a caller may tear entries down while iterating it.
func (r *registry) all() []*machineConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*machineConn, 0, len(r.byID))
	for _, mc := range r.byID {
		out = append(out, mc)
	}
	return out
}

// registerIfVacant is the admission rule for product machine connections.
// A second transport never replaces a registered one: possessing a machine
// key must not be enough to knock a live machine off line. reconnect reports
// that this id had an earlier epoch for a precise audit event.
func (r *registry) registerIfVacant(mc *machineConn) (accepted, reconnect bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, occupied := r.byID[mc.id]; occupied {
		return false, false
	}
	_, reconnect = r.lastEpoch[mc.id]
	r.byID[mc.id] = mc
	r.lastEpoch[mc.id] = mc.epoch
	return true, reconnect
}

// remove drops mc from the registry, but only if it is still the current
// connection for its id - a stale teardown of an already-replaced connection
// must not evict the newer one.
func (r *registry) remove(mc *machineConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.byID[mc.id]; ok && cur == mc {
		delete(r.byID, mc.id)
	}
}
