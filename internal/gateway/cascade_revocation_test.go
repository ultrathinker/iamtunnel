package gateway

// cascade_revocation_test.go: IAMT-72. The store withdraws a grant on its own
// in exactly three situations (state/model.go's reconcileGrants, the only
// producer DrainRevocations ever drains from - see RevocationReason there):
// a person disappears, a machine disappears, or a machine's key changes
// under an id that still exists. Gateway.applyRevocations (admin_role.go) is
// the harness that is supposed to turn each of those into the same two
// consequences an explicit "grants.revoke" already gets tested for
// (admin_scenarios_test.go's TestAdmin_RevokeKillsLiveSessionImmediately):
// the acl.Engine forgets the grant and any live session on it dies, and the
// journal gets an event explaining why.
//
// Before this file, nothing exercised applyRevocations itself against a real
// acl.Engine and a real live session - the existing coverage either checked
// the store's own bookkeeping (state package's identity_test.go,
// adversarial_gateway_test.go's TestAdvMachineKeyFingerprintPinSurvivesStateChange)
// or hand-rolled the journal write without going through the gateway
// (events/journal_test.go's TestFix1_RevocationReachesTheJournal).

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// journalHasGrantRevoke reports whether the log holds a grant.revoke event
// for person -> machine with the given reason.
func journalHasGrantRevoke(t *testing.T, evs []events.Event, person, machine string, reason state.RevocationReason) bool {
	t.Helper()
	object := person + " -> " + machine
	for _, e := range evs {
		if e.Type != events.EventGrantRevoke {
			continue
		}
		if e.Object == object && e.Details["reason"] == string(reason) {
			return true
		}
	}
	return false
}

// ---- §3.1: the person was removed -------------------------------------------

// TestCascade_PersonRemovedKillsLiveSessionAndForgetsGrant covers the
// person-removed cascade: removing a person ends their live sessions and the acl.Engine
// forgets the grant, not just the state file. The second half is proven by
// re-adding a person of the same name with a fresh key and no new grant:
// if applyRevocations had not called acl.Revoke, the engine's old, never-
// revoked grant would still answer "allowed" for that name.
func TestCascade_PersonRemovedKillsLiveSessionAndForgetsGrant(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)

	waitUntil(t, "session did not become active before people.remove", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	if _, err := root.PeopleRemove(f.person); err != nil {
		t.Fatalf("people.remove: %v", err)
	}

	text := readAll(t, hs.ch, 2*time.Second)
	if !strings.Contains(text, "grant was revoked") && !strings.Contains(text, "grant expired") {
		t.Fatalf("live session survived (or died silently) after its person was removed, got %q", text)
	}
	waitUntil(t, "door did not close after the cascade ended the only session", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	// Engine-level proof the grant itself is gone, not just that this one
	// network session happened to die: bring a person of the same name back
	// with a fresh key, grant nothing new, and confirm access is still
	// refused. Person removal has no machine teardown to confound this the
	// way machine removal does (see the next test's comment).
	newKey := genSigner(t)
	addPerson(t, f, f.person, "user", newKey)
	client2, err := dialHuman(t, f.addr, f.person, f.machineID, newKey)
	if err != nil {
		t.Fatalf("dial after re-add: %v", err)
	}
	defer client2.Close()
	ch, reqs, err := client2.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session after re-add: %v", err)
	}
	go discardSSHRequests(reqs)
	line := readAll(t, ch, 2*time.Second)
	if !strings.Contains(line, "Access to this machine is currently unavailable") {
		t.Fatalf("re-added person with no fresh grant was let in; the engine still held the old grant, got %q", line)
	}

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventGrantRevoke}})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if !journalHasGrantRevoke(t, evs, f.person, f.machineID, state.RevokedPersonRemoved) {
		t.Fatalf("journal has no grant.revoke event with reason %q for %s -> %s; got %+v", state.RevokedPersonRemoved, f.person, f.machineID, evs)
	}
}

// ---- §3.2: the machine was removed ------------------------------------------

// TestCascade_MachineRemovedKillsAllLiveSessionsForThatMachine covers the
// machine-removed cascade:
// removing a machine ends every live session on it, for every
// person, not just one.
//
// This test registers its two live sessions directly against acl.Engine
// (the same OpenSession/onRevoke boundary TestCascade_EveryDrainedRevocationLeavesNoLiveSession
// uses) instead of bridging real SSH traffic through them. That is a
// deliberate choice, not a shortcut: cmdMachinesRemove both tears down the
// machine's own tunnel (mc.teardown, which cancels mc.ctx and makes
// core.Bridge close the human channel on its own - see human_role.go's
// comment on mc.ctx) and, moments later, calls applyRevocations, whose
// acl.Revoke fires the onRevoke callback that ALSO closes the human channel
// (human_role.go's writeAndClose). With a real bridge in place those two
// closers race on the same golang.org/x/crypto/ssh channel with no
// synchronization between them - `go test -race` catches it reliably. That
// race is a genuine, pre-existing defect, but it is a channel-close ordering bug
// orthogonal to the invariant under test here (whether acl.Revoke runs at all), so
// fixing it is out of scope here; testing through the engine boundary
// exercises the exact invariant without depending
// on that unrelated race's outcome.
func TestCascade_MachineRemovedKillsAllLiveSessionsForThatMachine(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	bobKey := genSigner(t)
	addPerson(t, f, "bob", "user", bobKey)
	if _, err := root.GrantsGrant("bob", f.machineID, futureRFC3339(f)); err != nil {
		t.Fatalf("grants.grant bob: %v", err)
	}

	aliceGot := make(chan acl.DenyReason, 1)
	if _, err := f.gw.aclE.OpenSession(f.person, f.machineID, f.clock.Now(), func(r acl.DenyReason) { aliceGot <- r }); err != nil {
		t.Fatalf("OpenSession alice: %v", err)
	}
	bobGot := make(chan acl.DenyReason, 1)
	if _, err := f.gw.aclE.OpenSession("bob", f.machineID, f.clock.Now(), func(r acl.DenyReason) { bobGot <- r }); err != nil {
		t.Fatalf("OpenSession bob: %v", err)
	}

	if err := root.MachinesRemove(f.machineID); err != nil {
		t.Fatalf("machines.remove: %v", err)
	}

	for who, got := range map[string]chan acl.DenyReason{f.person: aliceGot, "bob": bobGot} {
		select {
		case reason := <-got:
			if reason != acl.DenyGrantRevoked {
				t.Errorf("%s: onRevoke reason = %v, want DenyGrantRevoked", who, reason)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s's live session was not killed after the machine was removed", who)
		}
	}
	for _, s := range f.gw.aclE.Sessions() {
		if s.Machine == f.machineID {
			t.Errorf("session %s on %s still listed live after the machine was removed", s.ID, f.machineID)
		}
	}

	// Engine-level proof: bring the same machine id back online under a
	// fresh key, grant nothing new, and confirm alice is still refused. If
	// applyRevocations had not called acl.Revoke, her old grant would still
	// be sitting in the engine, un-revoked and not yet expired, and this
	// would wrongly let her in.
	newMachineKey := genSigner(t)
	if err := f.store.Update(func(st *state.State) error {
		sshdHostKeyLine := authorizedLine(f.sshd.signer.PublicKey())
		st.Machines = append(st.Machines, state.Machine{
			ID: f.machineID, Name: f.machineID, State: "verified",
			MachineKey:  authorizedLine(newMachineKey.PublicKey()),
			SSHDHostKey: &sshdHostKeyLine,
			OSUser:      `MACHINE\svc`,
		})
		return nil
	}); err != nil {
		t.Fatalf("re-add machine: %v", err)
	}
	newFM := newFakeMachine(t, f.addr, f.machineID, newMachineKey, f.sshd.addr(), fakeMachineBehavior{})
	f.machMu.Lock()
	f.current = newFM
	f.machMu.Unlock()
	f.waitMachineOnline(t)

	aliceClient2, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial after re-add: %v", err)
	}
	defer aliceClient2.Close()
	ch, reqs, err := aliceClient2.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session after re-add: %v", err)
	}
	go discardSSHRequests(reqs)
	line := readAll(t, ch, 2*time.Second)
	if !strings.Contains(line, "Access to this machine is currently unavailable") {
		t.Fatalf("alice was let into the re-added machine with no fresh grant; the engine still held the old one, got %q", line)
	}

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventGrantRevoke}})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if !journalHasGrantRevoke(t, evs, f.person, f.machineID, state.RevokedMachineRemoved) {
		t.Fatalf("journal has no grant.revoke event with reason %q for %s -> %s; got %+v", state.RevokedMachineRemoved, f.person, f.machineID, evs)
	}
	if !journalHasGrantRevoke(t, evs, "bob", f.machineID, state.RevokedMachineRemoved) {
		t.Fatalf("journal has no grant.revoke event with reason %q for bob -> %s; got %+v", state.RevokedMachineRemoved, f.machineID, evs)
	}
}

// ---- §3.3: the machine's key was replaced ------------------------------------

// TestCascade_MachineRekeyedKillsLiveSessionAndForgetsGrant covers the
// rekeyed-machine cascade. No admin command in this build ever changes a
// registered machine's door key in place (machines.rekey replaces a
// recorded mismatching sshd host key after an administrator confirms it,
// not the door key; grep confirms internal/gateway/*.go, excluding
// tests, never assigns state.Machine.MachineKey after construction) - so
// there is no exec command to drive this through end to end. What the
// cascade is about is the harness (applyRevocations) reacting correctly to
// whichever
// mutation reaches it, so this test mutates the store directly, exactly the
// way TestAdvMachineKeyFingerprintPinSurvivesStateChange (adversarial_gateway_test.go)
// already does to prove the store's own half, and then calls
// g.applyRevocations itself - the same two calls cmdPeopleRemove and
// cmdMachinesRemove already make after their own Store.Update. That is why
// the harness function is called
// directly rather than inventing a product-code trigger for it.
//
// Unlike machine removal, nothing tears the machine's tunnel down here, so a
// live session dying is unambiguous proof that acl.Revoke ran - there is no
// competing explanation.
func TestCascade_MachineRekeyedKillsLiveSessionAndForgetsGrant(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)

	waitUntil(t, "session did not become active before the re-key", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	newKey := genSigner(t)
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID == f.machineID {
				st.Machines[i].MachineKey = authorizedLine(newKey.PublicKey())
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("re-key update: %v", err)
	}

	now := f.clock.Now()
	f.gw.applyRevocations(now)

	text := readAll(t, hs.ch, 2*time.Second)
	if !strings.Contains(text, "grant was revoked") && !strings.Contains(text, "grant expired") {
		t.Fatalf("live session survived (or died silently) after its machine was re-keyed, got %q", text)
	}

	// The machine's own tunnel is untouched by a re-key (nothing calls
	// mc.teardown for it): the registry entry, and the door, are still
	// there. Only the grant died.
	if mc, ok := f.gw.reg.get(f.machineID); !ok {
		t.Fatal("re-key tore down the machine's tunnel; it should not have")
	} else {
		waitUntil(t, "door did not close once the re-key ended the only session", func() bool {
			return mc.doorMachine.Snapshot().Sessions == 0
		})
	}

	// Engine-level proof: Check() must now report the grant revoked, not
	// merely absent-and-then-reappearing, for the same person/machine pair.
	if d := f.gw.aclE.Check(f.person, f.machineID, now); d.Allowed || d.Reason != acl.DenyGrantRevoked {
		t.Fatalf("acl.Check(%s, %s) after re-key = %+v, want DenyGrantRevoked", f.person, f.machineID, d)
	}

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventGrantRevoke}})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if !journalHasGrantRevoke(t, evs, f.person, f.machineID, state.RevokedMachineRekeyed) {
		t.Fatalf("journal has no grant.revoke event with reason %q for %s -> %s; got %+v", state.RevokedMachineRekeyed, f.person, f.machineID, evs)
	}
}

// ---- §2.3: the end-to-end sweep ----------------------------------------------

// cascadePair is one (person, machine) whose grant the sweep below expects
// applyRevocations to have killed, and the RevocationReason it expects the
// journal to carry for it.
type cascadePair struct {
	person, machine string
	reason          state.RevocationReason
}

// TestCascade_EveryDrainedRevocationLeavesNoLiveSession is the
// "end-to-end assertion": not one example of the cascade but every currently
// known way the store produces one (state/model.go's three RevocationReason
// values), mixed into a single transaction together with a second instance
// of "machine removed" and a control pair that the transaction never
// touches. It asserts the invariant generically, off state.Revocation itself
// rather than off which admin command triggered it: for every revocation
// DrainRevocations hands back, applyRevocations must (a) kill that pair's
// live session and (b) leave no trace of it in Sessions(), while a pair
// nothing touched stays untouched. A future fourth way to populate
// DrainRevocations (state/model.go grows a new RevocationReason, or a new
// call site starts feeding the same mechanism) is covered by construction as
// long as it flows through reconcileGrants -> DrainRevocations ->
// applyRevocations, the same seam this test drives; only a cascade that
// bypasses that seam entirely would slip past it, and the header comment
// above already established DrainRevocations is where every such record is
// produced.
//
// This test and TestCascade_PersonRemovedKillsLiveSessionAndForgetsGrant are
// the two asks this file pins that must be proven by a red run: deleting the
// g.aclE.Revoke call in applyRevocations must fail this test, because it
// drives the cascade through the acl.Engine directly (OpenSession/onRevoke)
// rather than through a real SSH bridge that a machine-teardown side effect
// could kill for the wrong reason.
func TestCascade_EveryDrainedRevocationLeavesNoLiveSession(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	until := state.NewZonedTime(f.clock.Now().Add(time.Hour))
	extraMachines := []struct {
		id  string
		key ssh.Signer
	}{
		{"vm2", genSigner(t)},
		{"vm3", genSigner(t)},
		{"vm4", genSigner(t)},
		{"vm5", genSigner(t)},
	}
	if err := f.store.Update(func(st *state.State) error {
		for _, name := range []string{"bob", "carol", "dave", "erin"} {
			st.People = append(st.People, state.Person{Name: name, Role: "user"})
		}
		for _, m := range extraMachines {
			st.Machines = append(st.Machines, state.Machine{
				ID: m.id, Name: m.id, State: "verified",
				MachineKey: authorizedLine(m.key.PublicKey()), OSUser: `MACHINE\svc`,
			})
		}
		for _, g := range []struct{ person, machine string }{
			{"bob", "vm2"},   // will lose bob (person removed)
			{"carol", "vm3"}, // will lose vm3 (machine removed)
			{"erin", "vm5"},  // will lose vm5 (machine removed, 2nd instance)
			{"dave", "vm4"},  // vm4 will be re-keyed
		} {
			if err := st.GrantAccess(g.person, g.machine, &until, "shell"); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed extra pairs: %v", err)
	}
	f.store.DrainRevocations() // nothing should be pending yet; keep the ledger clean for the count check below

	// acl.Check requires the machine to be online (View.MachineOnline, read
	// from the live registry, never from state.json - see acl.View's own
	// doc comment), so each extra machine needs a real tunnel up, even
	// though nothing ever bridges a session through it here.
	for _, m := range extraMachines {
		newFakeMachine(t, f.addr, m.id, m.key, f.sshd.addr(), fakeMachineBehavior{})
		waitUntil(t, "machine "+m.id+" did not come online", func() bool {
			mc, ok := f.gw.reg.get(m.id)
			return ok && mc.doorMachine.Snapshot().Online
		})
	}

	// Gateway.New only loads grants that already existed in state.json at
	// construction time (see its own comment); load these newly-seeded ones
	// into the running engine exactly the way cmdGrantsGrant does.
	u := until.Time.UTC()
	for _, g := range []struct{ person, machine string }{
		{"bob", "vm2"}, {"carol", "vm3"}, {"erin", "vm5"}, {"dave", "vm4"},
	} {
		if err := f.gw.aclE.AddGrant(acl.Grant{Person: g.person, Machine: g.machine, Until: &u, Caps: []string{"shell"}}, f.clock.Now()); err != nil {
			t.Fatalf("AddGrant %s->%s: %v", g.person, g.machine, err)
		}
	}

	affected := []cascadePair{
		{"bob", "vm2", state.RevokedPersonRemoved},
		{"carol", "vm3", state.RevokedMachineRemoved},
		{"erin", "vm5", state.RevokedMachineRemoved},
		{"dave", "vm4", state.RevokedMachineRekeyed},
	}
	control := cascadePair{f.person, f.machineID, ""} // never touched by the mutation below

	type watch struct {
		pair cascadePair
		got  chan acl.DenyReason
	}
	openWatch := func(p cascadePair) watch {
		got := make(chan acl.DenyReason, 1)
		if _, err := f.gw.aclE.OpenSession(p.person, p.machine, f.clock.Now(), func(r acl.DenyReason) { got <- r }); err != nil {
			t.Fatalf("OpenSession %s->%s: %v", p.person, p.machine, err)
		}
		return watch{pair: p, got: got}
	}
	watches := make([]watch, 0, len(affected))
	for _, p := range affected {
		watches = append(watches, openWatch(p))
	}
	controlWatch := openWatch(control)

	// One transaction, all three reasons at once plus a second "machine
	// removed" instance - a real cascade rarely comes one at a time.
	if err := f.store.Update(func(st *state.State) error {
		for i, p := range st.People {
			if p.Name == "bob" {
				st.People = append(st.People[:i], st.People[i+1:]...)
				break
			}
		}
		kept := st.Machines[:0]
		for _, m := range st.Machines {
			if m.ID == "vm3" || m.ID == "vm5" {
				continue
			}
			kept = append(kept, m)
		}
		st.Machines = kept
		for i := range st.Machines {
			if st.Machines[i].ID == "vm4" {
				st.Machines[i].MachineKey = authorizedLine(genSigner(t).PublicKey())
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("cascade update: %v", err)
	}

	// applyRevocations itself drains the store's ledger (DrainRevocations is
	// destructive - a second call sees nothing), so this is the one and only
	// place anything reads it; the count is verified below through the
	// journal instead, one grant.revoke event per affected pair and no more.
	now := f.clock.Now()
	f.gw.applyRevocations(now)

	for _, w := range watches {
		select {
		case reason := <-w.got:
			if reason != acl.DenyGrantRevoked {
				t.Errorf("%s->%s: onRevoke reason = %v, want DenyGrantRevoked", w.pair.person, w.pair.machine, reason)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s->%s: cascade revocation (reason %s) did not kill the live session", w.pair.person, w.pair.machine, w.pair.reason)
		}
	}
	select {
	case reason := <-controlWatch.got:
		t.Errorf("%s->%s: untouched control pair was killed anyway, reason %v", control.person, control.machine, reason)
	default:
	}

	live := f.gw.aclE.Sessions()
	for _, w := range watches {
		for _, s := range live {
			if s.Person == w.pair.person && s.Machine == w.pair.machine {
				t.Errorf("%s->%s: session %s still listed live after its cascade revocation", w.pair.person, w.pair.machine, s.ID)
			}
		}
	}
	controlStillLive := false
	for _, s := range live {
		if s.Person == control.person && s.Machine == control.machine {
			controlStillLive = true
		}
	}
	if !controlStillLive {
		t.Errorf("%s->%s: untouched control session was removed from Sessions() too", control.person, control.machine)
	}

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventGrantRevoke}})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if len(evs) != len(affected) {
		t.Errorf("journal holds %d grant.revoke events, want exactly %d (one per affected pair, none for the control): %+v", len(evs), len(affected), evs)
	}
	for _, p := range affected {
		if !journalHasGrantRevoke(t, evs, p.person, p.machine, p.reason) {
			t.Errorf("%s->%s: journal has no grant.revoke event with reason %q", p.person, p.machine, p.reason)
		}
	}
}
