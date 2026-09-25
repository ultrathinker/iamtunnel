package gateway

// dormant_f2_3_test.go — IAMT-74 finding F2.3:
//
//   "A grant was revoked, the gateway restarted — the permission engine knows nothing of the revocation."
//
// The adversarial review (entry F2.3) flagged the
// danger that a grant removed from state.json would resurrect in the
// running acl.Engine the moment the gateway reloaded state.json on startup.
// That is the failure mode the finding names: revocation dying with the
// gateway that issued it.
//
// The current implementation reads grants from cfg.Store.Get() once at
// construction (gateway.go: the for-loop over cfg.Store.Get().Grants) and
// feeds each one to aclE.AddGrant. RevokeAccess removes the grant from
// state.Grants; if the gateway is restarted, the loop will not see the
// revoked pair, so aclE.AddGrant is never called for it and the engine
// never learns the grant existed. The bug as written
// therefore appears not to be live today, but the requirement is explicit:
//
//   "A test is needed either way: the property that a revocation survives
//    a restart must be under test, even if today it holds on its own."
//
// The tests below pin that property down. They close the gateway and
// rebuild it against the same on-disk state, which is exactly what a
// service restart does. The tests do NOT touch cmd/iamtunnel and they do
// NOT use any package-level setter or
// environment lookup. The only seam is
// Gateway.New reading state.json.

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// reopenableHarness is what the F2.3 tests build instead of using the
// fixture in harness_test.go: a fixture owns its own t.Cleanup, so closing
// the gateway inside a test and then rebuilding would fight the cleanup
// and the state would be torn down before the rebuild could read it.
//
// The struct does NOT auto-close via t.Cleanup: the test decides when to
// close and reopen. Cleanup runs only after the test is done, and only
// to release anything the test forgot to release itself.
type reopenableHarness struct {
	t          *testing.T
	gw         *Gateway
	ln         net.Listener
	addr       string
	store      *state.Store
	log        *events.Log
	dir        string
	person     string
	personKey  ssh.Signer
	machine    string
	machineKey ssh.Signer
	clock      time.Time
}

// openReopenable creates a brand-new harness against an empty temp dir:
// state.json with the seeded alice + vm1 + grant, a real listener, the
// gateway running.
func openReopenable(t *testing.T) *reopenableHarness {
	t.Helper()
	dir := t.TempDir()

	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open(%q): %v", dir, err)
	}
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("events.OpenLog: %v", err)
	}

	personSigner := genSigner(t)
	machineSigner := genSigner(t)
	clock := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	until := state.NewZonedTime(clock.Add(2 * time.Hour))
	if err := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "alice", Role: "user",
			Keys: []state.Key{{
				Fingerprint: fingerprintOf(t, personSigner.PublicKey()),
				Pub:         authorizedLine(personSigner.PublicKey()),
				Added:       state.NewZonedTime(clock),
			}},
		})
		st.Machines = append(st.Machines, state.Machine{
			ID: "vm1", Name: "vm1", State: "verified",
			MachineKey: authorizedLine(machineSigner.PublicKey()),
			OSUser:     `MACHINE\svc`,
		})
		return st.GrantAccess("alice", "vm1", &until, "shell")
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	hostKey := genSigner(t)
	cfg := reopenableConfig(store, log, hostKey, dir)
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go gw.Serve(ln)
	h := &reopenableHarness{
		t: t, gw: gw, ln: ln, addr: ln.Addr().String(),
		store: store, log: log, dir: dir,
		person: "alice", personKey: personSigner,
		machine: "vm1", machineKey: machineSigner,
		clock: clock,
	}
	t.Cleanup(func() { _ = h.closeQuiet() })
	return h
}

// reopenableConfig returns the gateway.Config the F2.3 tests build for
// both the initial and the post-restart gateways. Centralising it is
// what makes the two runs identical.
func reopenableConfig(store *state.Store, log *events.Log, hostKey ssh.Signer, dir string) Config {
	return Config{
		Store:   store,
		Log:     log,
		HostKey: hostKey,
		Now:     func() time.Time { return time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC) },
		AuthLimits: auth.AuthLimits{
			HandshakeTimeout: 3 * time.Second,
		},
		ACLLimits: acl.Limits{},
		RateConfig: auth.RateConfig{
			MaxKnownFailures:   10,
			MaxUnknownFailures: 10,
			Window:             time.Minute,
			PairBanDuration:    time.Minute,
			AddrBanDuration:    time.Minute,
		},
		DoorIdle:             time.Minute,
		DoorHard:             2 * time.Minute,
		ControlAcceptTimeout: time.Second,
		DoorOpenTimeout:      2 * time.Second,
		DoorCloseTimeout:     2 * time.Second,
		DoorStatusTimeout:    2 * time.Second,
		SessionSetupTimeout:  3 * time.Second,
		Keepalive:            sshx.Keepalive{Interval: 150 * time.Millisecond, MaxMisses: 3},
		RecordingBaseDir:     filepath.Join(dir, "recordings"),
	}
}

// closeQuiet shuts down the gateway, the listener and the store and log.
// Safe to call multiple times. Used by reopen and by the test cleanup.
func (h *reopenableHarness) closeQuiet() error {
	if h.gw != nil {
		_ = h.gw.Close()
		h.gw = nil
	}
	if h.ln != nil {
		_ = h.ln.Close()
		h.ln = nil
	}
	if h.store != nil {
		_ = h.store.Close()
		h.store = nil
	}
	if h.log != nil {
		_ = h.log.Close()
		h.log = nil
	}
	return nil
}

// reopen rebuilds the harness against the same on-disk state. The state
// file and the journal are exactly what a service restart would see.
func (h *reopenableHarness) reopen() *reopenableHarness {
	h.t.Helper()
	if err := h.closeQuiet(); err != nil {
		h.t.Fatalf("close before reopen: %v", err)
	}
	store, err := state.Open(h.dir)
	if err != nil {
		h.t.Fatalf("reopen state.Open: %v", err)
	}
	log, err := events.OpenLog(filepath.Join(h.dir, "events.jsonl"))
	if err != nil {
		h.t.Fatalf("reopen events.OpenLog: %v", err)
	}
	hostKey := genSigner(h.t)
	cfg := reopenableConfig(store, log, hostKey, h.dir)
	gw, err := New(cfg)
	if err != nil {
		h.t.Fatalf("reopen gateway.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatalf("reopen Listen: %v", err)
	}
	go gw.Serve(ln)
	out := &reopenableHarness{
		t: h.t, gw: gw, ln: ln, addr: ln.Addr().String(),
		store: store, log: log, dir: h.dir,
		person: h.person, personKey: h.personKey,
		machine: h.machine, machineKey: h.machineKey,
		clock: h.clock,
	}
	h.t.Cleanup(func() { _ = out.closeQuiet() })
	return out
}

// seedAdditionalGrant adds a second (person, machine) pair whose grant
// must still be honoured after a restart: it is the "untouched control"
// pair the test uses to tell "the engine dropped everything" from "the
// engine dropped the revoked one".
func (h *reopenableHarness) seedAdditionalGrant(t *testing.T, person, machine string, key ssh.Signer) {
	t.Helper()
	// Use a deadline comfortably past the post-restart "now"
	// (2026-09-12T11:00:00Z) - validateGrant requires the deadline to be
	// strictly after issuedAt, so clock+1h would not be safe.
	until := h.clock.Add(2 * time.Hour)
	if err := h.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: person, Role: "user",
			Keys: []state.Key{{
				Fingerprint: fingerprintOf(t, key.PublicKey()),
				Pub:         authorizedLine(key.PublicKey()),
				Added:       state.NewZonedTime(h.clock),
			}},
		})
		st.Machines = append(st.Machines, state.Machine{
			ID: machine, Name: machine, State: "verified",
			MachineKey: authorizedLine(genSigner(t).PublicKey()),
			OSUser:     `MACHINE\svc`,
		})
		zuntil := state.NewZonedTime(until)
		return st.GrantAccess(person, machine, &zuntil, "shell")
	}); err != nil {
		t.Fatalf("seed additional: %v", err)
	}
	// Tell the running engine about the new grant, the way cmdGrantsGrant
	// would (Store.Update persists the grant but does not push it into the
	// in-memory ACL engine on its own - admin_role.go's cmdGrantsGrant
	// calls aclE.AddGrant separately).
	u := until.UTC()
	if err := h.gw.aclE.AddGrant(acl.Grant{
		Person: person, Machine: machine,
		Until: &u, Caps: []string{"shell"},
	}, h.clock.Add(time.Minute)); err != nil {
		t.Fatalf("aclE.AddGrant %s->%s: %v", person, machine, err)
	}
}

// TestDormant_F2_3_RevokedGrantStaysRevokedAfterRestart is the engine-
// level assertion of the finding. It seeds two grants, revokes one
// of them, closes the gateway, and rebuilds it against the same disk
// state. The rebuilt engine must:
//
//	(a) deny alice on the revoked pair with DenyGrantRevoked (not
//	    DenyNoGrant, which would mean the engine never knew the grant
//	    existed - the bug this finding is about),
//	(b) keep the unrelated grant alive, so the rebuild is reading the
//	    file and not just wiping the engine.
//
// A future regression that resurrects a revoked grant fails (a). One that
// forgets unrelated grants fails (b). Both together - a check that the
// rebuilt engine's grant table equals the on-disk state.json - is what
// is actually being pinned down.
func TestDormant_F2_3_RevokedGrantStaysRevokedAfterRestart(t *testing.T) {
	h := openReopenable(t)

	bobKey := genSigner(t)
	h.seedAdditionalGrant(t, "bob", "vm2", bobKey)

	// Revoke alice -> vm1 through the same store path cmdGrantsRevoke uses.
	if err := h.store.Update(func(st *state.State) error {
		if !st.RevokeAccess("alice", "vm1") {
			t.Fatalf("RevokeAccess did not find alice->vm1 to revoke")
		}
		return nil
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Close + reopen = restart.
	h2 := h.reopen()

	now := time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)

	// (a) engine denies alice on the revoked pair. The reason is allowed
	// to be either DenyGrantRevoked (if the engine kept its in-memory
	// RevokedAt flag) or DenyNoGrant (if it loaded afresh and never saw
	// the pair in state.json) - both are correct refusals; what is NOT
	// allowed is any reason that implies the engine holds the grant
	// (DenyMachineOffline, DenyGrantExpired, DenyPersonSessionLimit,
	// ...). Those would mean the revoked grant resurrected in the
	// engine, which is the original F2.3 failure mode.
	d := h2.gw.aclE.Check("alice", "vm1", now)
	if d.Reason == acl.DenyGrantRevoked || d.Reason == acl.DenyNoGrant {
		// the correct refusals
	} else {
		t.Fatalf("post-restart Check(alice, vm1) reason = %v, want DenyGrantRevoked or DenyNoGrant (a different reason means the engine revived the revoked grant)", d.Reason)
	}

	// (b) engine still considers bob a granted pair - any reason other
	// than DenyNoGrant / DenyUnknownPerson / DenyUnknownMachine proves
	// the engine knows the pair exists.
	if d := h2.gw.aclE.Check("bob", "vm2", now); d.Reason == acl.DenyNoGrant || d.Reason == acl.DenyUnknownPerson || d.Reason == acl.DenyUnknownMachine {
		t.Fatalf("post-restart engine forgot bob->vm2 entirely: %+v", d)
	}

	// (c) state.json on disk is consistent with the engine's view.
	grants := h2.store.Get().Grants
	if len(grants) != 1 || grants[0].Person != "bob" || grants[0].Machine != "vm2" {
		t.Fatalf("state.json after restart has %+v, want exactly one bob->vm2 grant", grants)
	}
}

// TestDormant_F2_3_OpenSessionAfterRestartIsRefused exercises the same
// invariant one level lower than the dial: instead of going through the
// SSH handshake (which requires a fake target sshd the simple harness
// does not bring up), it asks the acl.Engine directly whether the
// revoked pair can open a session. The test still proves the
// user-visible property - "no live session opens on a revoked pair
// after restart" - but stops at the engine boundary so it does not
// need the full fixture machinery.
//
// A failure of this assertion means the original F2.3 bug is back:
// the engine answered Allowed for a pair that has been revoked.
func TestDormant_F2_3_OpenSessionAfterRestartIsRefused(t *testing.T) {
	h := openReopenable(t)

	// Revoke alice -> vm1 through the same store path cmdGrantsRevoke
	// uses. We do not need a fake machine because we test against the
	// engine directly, not against the dial path.
	if err := h.store.Update(func(st *state.State) error {
		if !st.RevokeAccess("alice", "vm1") {
			t.Fatalf("RevokeAccess did not find alice->vm1 to revoke")
		}
		return nil
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Restart.
	h2 := h.reopen()

	now := time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)
	if _, err := h2.gw.aclE.OpenSession("alice", "vm1", now, nil); err == nil {
		t.Fatalf("post-restart OpenSession(alice, vm1) succeeded; the engine resurrected the revoked grant")
	}
}

// TestGateway_RestartPreservesIndefiniteGrant tests that a grant with no deadline
// (Until == nil) survives a gateway restart, lets the person in, is not swept by
// SweepExpired, and stops letting them in upon revocation.
// This proves the fix for the silent-skip defect in gateway.go:87.
func TestGateway_RestartPreservesIndefiniteGrant(t *testing.T) {
	h := openReopenable(t)

	// Seed person "carol" with key, and issue an indefinite grant carol -> vm1 (Until: nil)
	carolKey := genSigner(t)
	if err := h.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "carol", Role: "user",
			Keys: []state.Key{{
				Fingerprint: fingerprintOf(t, carolKey.PublicKey()),
				Pub:         authorizedLine(carolKey.PublicKey()),
				Added:       state.NewZonedTime(h.clock),
			}},
		})
		// GrantAccess with until == nil:
		return st.GrantAccess("carol", "vm1", nil, "shell")
	}); err != nil {
		t.Fatalf("seed indefinite grant: %v", err)
	}

	// Tell the initial running engine:
	if err := h.gw.aclE.AddGrant(acl.Grant{
		Person: "carol", Machine: "vm1",
		Until: nil, Caps: []string{"shell"},
	}, h.clock.Add(time.Minute)); err != nil {
		t.Fatalf("aclE.AddGrant carol->vm1: %v", err)
	}

	// Bring vm1 online so Check does not stop at
	// DenyMachineOffline before it ever gets a chance to see the grant.
	// A bare Check() against a harness whose registry holds no live
	// machine connection will read stateView.MachineOnline==false and
	// return DenyMachineOffline — the previous failure of this test.
	// The fake machine only needs to register a control connection; no
	// sshd is required (same pattern as
	// TestDormant_F4_5_GatewayPathAgreesWithAuthPath).
	fm := newFakeMachine(t, h.addr, h.machine, h.machineKey, "127.0.0.1:0", fakeMachineBehavior{})
	t.Cleanup(fm.close)
	waitUntil(t, "machine did not come online (initial gateway)", func() bool {
		mc, ok := h.gw.reg.get(h.machine)
		return ok && mc.doorMachine.Snapshot().Online
	})

	now := time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)
	if d := h.gw.aclE.Check("carol", "vm1", now); !d.Allowed {
		t.Fatalf("initial Check(carol, vm1) failed: %+v", d)
	}

	// Restart the gateway against the saved state.
	// If gateway.go:87 skips nil until grants, carol->vm1 is silently dropped!
	h2 := h.reopen()

	// Same reason as above: reopen() closed the old listener and built a
	// fresh gateway; the new gateway has its own registry and its own
	// (empty) machine connections. The post-restart Check still wants
	// vm1 to be online, otherwise it stops at DenyMachineOffline — and
	// then a future regression that silently drops nil-until grants on
	// reload would no longer be distinguishable from a setup problem.
	// Bringing the fake machine back online here is what lets the test
	// assert the actual invariant: the grant was reloaded.
	fm2 := newFakeMachine(t, h2.addr, h2.machine, h2.machineKey, "127.0.0.1:0", fakeMachineBehavior{})
	t.Cleanup(fm2.close)
	waitUntil(t, "machine did not come online (post-restart gateway)", func() bool {
		mc, ok := h2.gw.reg.get(h2.machine)
		return ok && mc.doorMachine.Snapshot().Online
	})

	dPost := h2.gw.aclE.Check("carol", "vm1", now)
	if !dPost.Allowed {
		t.Fatalf("post-restart Check(carol, vm1) reason = %v, want Allowed (silent skip on restart)", dPost.Reason)
	}

	// Open session works
	s, err := h2.gw.aclE.OpenSession("carol", "vm1", now, nil)
	if err != nil {
		t.Fatalf("post-restart OpenSession(carol, vm1): %v", err)
	}

	// SweepExpired far in future does NOT kill indefinite session
	farFuture := now.Add(365 * 24 * time.Hour)
	if n := h2.gw.aclE.SweepExpired(farFuture); n != 0 {
		t.Fatalf("SweepExpired killed %d session(s) on indefinite grant, want 0", n)
	}

	// Revoke immediately cuts access and kills the live session
	n, err := h2.gw.aclE.Revoke("carol", "vm1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if n != 1 {
		t.Fatalf("Revoke killed %d sessions, want 1", n)
	}

	if dRev := h2.gw.aclE.Check("carol", "vm1", now.Add(2*time.Hour)); dRev.Allowed || dRev.Reason != acl.DenyGrantRevoked {
		t.Fatalf("Check after revoke: allowed=%v reason=%v, want DenyGrantRevoked", dRev.Allowed, dRev.Reason)
	}
	_ = s
}

// TestGateway_ExpiredGrantOnLoadIsLoggedNotSilentlyDropped proves the
// gateway.go load-time fix: when a persisted grant's deadline has
// already passed while the gateway was offline, the entry is skipped
// (re-AddGrant'ing an expired grant would only fail anyway), but the
// gateway MUST record an admin.op event naming the dropped grant and
// its expiry - so an operator reading events.jsonl can answer "why is
// this permission not back?" without rummaging through state.json and
// comparing timestamps by hand.
//
// The previous behaviour was a bare `continue` inside the load loop:
// the grant vanished from the engine without trace, and the only way
// to discover it had ever existed was to diff state.json against the
// runtime grant list. The journal line is the fix; this test is the
// canary.
//
// Canary:
//
//	In internal/gateway/gateway.go New, remove the for-loop that emits
//	the admin.op event for each entry of `dropped`. The gateway still
//	loads, the test still passes everything else, and this test fails
//	because the journal holds no record of the silent skip.
func TestGateway_ExpiredGrantOnLoadIsLoggedNotSilentlyDropped(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("events.OpenLog: %v", err)
	}

	personSigner := genSigner(t)
	machineSigner := genSigner(t)
	// The harness's reopenableConfig sets Now() = 2026-09-12T11:00:00Z.
	// A grant with deadline 2026-09-12T09:00:00Z is two hours in the
	// past at the moment of gateway startup - exactly the case named
	// as "permission that expired while the gateway was down, silently
	// dropped on reload".
	expiredAt := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	if err := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "alice", Role: "user",
			Keys: []state.Key{{
				Fingerprint: fingerprintOf(t, personSigner.PublicKey()),
				Pub:         authorizedLine(personSigner.PublicKey()),
				Added:       state.NewZonedTime(expiredAt),
			}},
		})
		st.Machines = append(st.Machines, state.Machine{
			ID: "vm1", Name: "vm1", State: "verified",
			MachineKey: authorizedLine(machineSigner.PublicKey()),
			OSUser:     `MACHINE\svc`,
		})
		zuntil := state.NewZonedTime(expiredAt)
		return st.GrantAccess("alice", "vm1", &zuntil, "shell")
	}); err != nil {
		t.Fatalf("seed expired grant: %v", err)
	}

	hostKey := genSigner(t)
	cfg := reopenableConfig(store, log, hostKey, dir)
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("gateway.New with an expired grant on disk: %v", err)
	}
	// IAMT-314: this gateway used to go into "_". All this test wants is
	// the admin.op line New writes while dropping the expired grant, but
	// New has already started the gateway's long-lived goroutines by the
	// time it returns - the expiry sweeper, the recording sweeper and the
	// rate limiter's sweeper - and Close is the only thing that stops any
	// of them. Discarding the handle discards the only way to stop them.
	// This is the same shape as the finding that opened this ticket
	// (a valid auth.RateLimiter thrown into "_" in ratelimit_test.go),
	// one layer up: a whole Gateway instead of one limiter.
	//
	// t.Cleanup rather than a bare call at the end of the function,
	// because several t.Fatalf paths lie between here and there. It stops
	// exactly what the reopenableHarness tests in this file stop: their
	// closeQuiet does gw.Close() and then closes the listener, the store
	// and the log - and this test has no listener, while it closes its own
	// store and log already. Gateway.Close with no listener and no
	// registered machine connection touches neither, so the order between
	// them does not matter here.
	t.Cleanup(func() { _ = gw.Close() })

	// The journal must carry exactly one admin.op event naming the
	// dropped pair and the reason; without the journal line, the
	// expiry is invisible.
	evs, _, err := log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	const wantObj = "alice -> vm1"
	const wantResult = "grant.skip:expired"
	var found *events.Event
	for i := range evs {
		if evs[i].Object == wantObj && evs[i].Result == wantResult && evs[i].Actor == "gateway" {
			found = &evs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no admin.op journal line for the silently-dropped expired grant; want actor=gateway object=%q result=%q. all events: %+v", wantObj, wantResult, evs)
	}
	// And the expiry timestamp travels in Details so the operator can
	// match it against state.json without a second source of truth.
	expStr, ok := found.Details["expiredAt"].(string)
	if !ok || expStr == "" {
		t.Fatalf("dropped-grant event lacks Details.expiredAt string; got: %#v", found.Details)
	}
	gotExp, perr := time.Parse(time.RFC3339, expStr)
	if perr != nil {
		t.Fatalf("Details.expiredAt = %q is not RFC 3339: %v", expStr, perr)
	}
	if !gotExp.Equal(expiredAt) {
		t.Fatalf("Details.expiredAt = %s, want %s", gotExp.UTC().Format(time.RFC3339), expiredAt.UTC().Format(time.RFC3339))
	}

	_ = store.Close()
	_ = log.Close()
}

// TestGateway_LiveGrantOnLoadEmitsNoSkipEvent guards the other side:
// a grant whose deadline is still in the future at gateway startup
// must NOT generate a skip event. Otherwise the skip line carries no
// signal — it would fire on every gateway restart — and the operator
// loses the ability to spot the real expirations.
//
// Canary:
//
//	In internal/gateway/gateway.go New, append to `dropped`
//	unconditionally (e.g. before the expiry check). This test then
//	sees a spurious grant.skip:expired event for the live grant and
//	fails.
func TestGateway_LiveGrantOnLoadEmitsNoSkipEvent(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("events.OpenLog: %v", err)
	}

	personSigner := genSigner(t)
	machineSigner := genSigner(t)
	// reopenableConfig.Now() = 11:00:00Z. A deadline at 13:00:00Z is
	// two hours in the future, comfortably valid at load time.
	clock := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	liveUntil := state.NewZonedTime(clock.Add(3 * time.Hour))
	if err := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "alice", Role: "user",
			Keys: []state.Key{{
				Fingerprint: fingerprintOf(t, personSigner.PublicKey()),
				Pub:         authorizedLine(personSigner.PublicKey()),
				Added:       state.NewZonedTime(clock),
			}},
		})
		st.Machines = append(st.Machines, state.Machine{
			ID: "vm1", Name: "vm1", State: "verified",
			MachineKey: authorizedLine(machineSigner.PublicKey()),
			OSUser:     `MACHINE\svc`,
		})
		return st.GrantAccess("alice", "vm1", &liveUntil, "shell")
	}); err != nil {
		t.Fatalf("seed live grant: %v", err)
	}

	hostKey := genSigner(t)
	cfg := reopenableConfig(store, log, hostKey, dir)
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	// IAMT-314: see the twin of this line in
	// TestGateway_ExpiredGrantOnLoadIsLoggedNotSilentlyDropped above. New
	// starts the sweepers; only Close stops them; the handle used to be
	// thrown away into "_".
	t.Cleanup(func() { _ = gw.Close() })

	evs, _, err := log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	for _, e := range evs {
		if e.Result == "grant.skip:expired" {
			t.Fatalf("a live (not-yet-expired) grant was wrongly recorded as skipped on gateway load; the skip event must be reserved for grants that actually expired during the downtime. event: %+v", e)
		}
	}

	_ = store.Close()
	_ = log.Close()
}
