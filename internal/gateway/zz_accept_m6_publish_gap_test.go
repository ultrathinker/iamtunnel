package gateway

import (
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// M-6: granting and revoking access are atomic with respect to each
// other.
//
// Before the fix grants.grant wrote the grant to state.json and then, as
// a SEPARATE step, published it into the ACL engine. Between the steps
// grants.revoke could run entirely: it does not find the grant in the
// engine (ErrNoGrant is silently ignored) and returns "revoked", while
// the late AddGrant resurrects the grant in the engine -- live access
// that state.json does not have, until the gateway is restarted. The
// same applies to set-caps, people.remove and machines.remove (their
// publication into the engine is applyRevocations).
//
// The test controls the pause itself, via accessPublishPause -- it does
// not rely on the scheduler and does not require -race: the grant parks
// strictly between the state write and the publication, while the
// revoke runs in full. One assertion: when BOTH commands returned, the
// engine is not allowed to let through a pair that state.json does not
// have.
//
// The accessPublishPause hook is part of this check, not a "setting":
// on code without a pause point the interleaving cannot be exposed
// deterministically at all, so a fix without the hook is untestable by
// this test in principle.
func TestM6_RevokeInPublishGapDoesNotResurrect(t *testing.T) {
	f := newFixture(t, nil)

	// Clean start: the fixture pair's grant is in neither state nor engine.
	if err := f.store.Update(func(st *state.State) error {
		st.RevokeAccess(f.person, f.machineID)
		return nil
	}); err != nil {
		t.Fatalf("remove fixture grant from state: %v", err)
	}
	if _, err := f.gw.aclE.Revoke(f.person, f.machineID, f.clock.Now()); err != nil && err != acl.ErrNoGrant {
		t.Fatalf("remove fixture grant from engine: %v", err)
	}
	// Check is no good here: the machine is not connected, and it answers
	// "offline" regardless of the grant. We look at the engine's live
	// grants directly -- GrantsFor is the very view by which the engine
	// answers the question "who gets in".
	for _, g := range f.gw.aclE.GrantsFor(f.person, f.clock.Now()) {
		if g.Machine == f.machineID {
			t.Fatalf("fixture left a live engine grant for %s: %+v", f.machineID, g)
		}
	}

	entered := make(chan struct{})
	proceed := make(chan struct{})
	var parked int32 // only the first command (the grant) parks; the others pass by
	accessPublishPause = func() {
		if !atomic.CompareAndSwapInt32(&parked, 0, 1) {
			return
		}
		close(entered)
		<-proceed
	}
	defer func() { accessPublishPause = nil }()

	grantBody, err := json.Marshal(map[string]any{
		"proto": 1, "person": f.person, "machine": f.machineID, "until": "", "caps": []string{"shell"},
	})
	if err != nil {
		t.Fatalf("marshal grants.grant body: %v", err)
	}
	type cmdResult struct {
		val any
		err *cmdError
	}
	grantDone := make(chan cmdResult, 1)
	go func() {
		val, cerr := cmdGrantsGrant(f.gw, "admin", f.clock.Now(), grantBody)
		grantDone <- cmdResult{val, cerr}
	}()

	// The grant has parked at the pause: it is already in state.json, not
	// yet in the engine.
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("grants.grant never reached the state-to-engine seam")
	}

	revBody, err := json.Marshal(map[string]any{
		"proto": 1, "person": f.person, "machine": f.machineID,
	})
	if err != nil {
		t.Fatalf("marshal grants.revoke body: %v", err)
	}
	revDone := make(chan cmdResult, 1)
	go func() {
		val, cerr := cmdGrantsRevoke(f.gw, "admin", f.clock.Now(), revBody)
		revDone <- cmdResult{val, cerr}
	}()

	// Either the revoke managed to run entirely inside the pause (the
	// defect is not serialized), or it honestly waits for the mutex
	// (fixed). We wait a bounded time only so as not to slow a green
	// run; the final assertion is unaffected by the wait. The value is
	// received exactly once: select consumes it from the channel, the
	// same channel cannot be waited on again.
	var revRes cmdResult
	var revGot bool
	select {
	case revRes = <-revDone:
		revGot = true // revoked inside the pause -- resurrection is inevitable
	case <-time.After(2 * time.Second):
		// revoked into the queue behind the grant -- publication is serialized
	}

	close(proceed)
	gres := <-grantDone
	if gres.err != nil {
		t.Fatalf("grants.grant: %v", gres.err)
	}
	if !revGot {
		// the serialized revoke finishes as soon as the grant releases
		// the publication; the channel is buffered, the goroutine does not leak
		revRes = <-revDone
	}
	if revRes.err != nil {
		t.Fatalf("grants.revoke: %v", revRes.err)
	}

	// state.json does not have the pair -- both commands agree on that.
	st := f.store.Get()
	for _, gr := range st.Grants {
		if gr.Person == f.person && gr.Machine == f.machineID {
			t.Fatalf("state.json still holds the grant after revoke: %+v", gr)
		}
	}

	// The main line: when both commands returned, the engine must not
	// still hold a live grant for a pair that state.json does not have.
	// On non-serialized code the late AddGrant resurrects the grant
	// exactly here.
	for _, g := range f.gw.aclE.GrantsFor(f.person, f.clock.Now()) {
		if g.Machine == f.machineID {
			t.Fatalf("engine still holds a live grant for %s -> %s after both commands returned, "+
				"while state.json has none: the revoke slipped into the publish gap and the late "+
				"AddGrant resurrected it (until=%v, caps=%v)",
				f.person, f.machineID, g.Until, g.Caps)
		}
	}
}
