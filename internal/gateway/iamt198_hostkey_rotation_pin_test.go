package gateway

// iamt198_hostkey_rotation_pin_test.go — IAMT-198: the end-to-end THREATS
// candidate #9 (from an internal threat audit) that no
// single existing test covers: after "gateway rotate-hostkey" AND a
// restart, both a person client (internal/client) and a machine
// (internal/server) pinned to the OLD fingerprint must be refused, and a
// client with the NEW connection string must get through. Every piece of
// this has its own unit test already (IAMT-174's admin rotate-hostkey
// exec, internal/client's and internal/server's own fingerprint-pin
// tests) — what none of them exercises together is the full sequence: a
// LIVE gateway still presenting the old key right after rotation, a real
// process restart picking the new key off disk, and both roles' real
// dial code refusing the stale pin against that restarted gateway.
//
// This file starts two independent generations of *Gateway over the SAME
// on-disk directory (state.json, events.jsonl, hostkey — exactly what
// "iamtunnel gateway run" persists), with the second generation
// constructed the same way gatewayRuntimeConfig (cmd/iamtunnel/gateway.go)
// does: Store/Log reopened, HostKey reloaded from hostKeyPath(dir) via
// this package's own loadOrGenerateHostKey (lifecycle.go) — not a new
// test hook, the same unexported helper RotateHostKey itself and
// TestIAMT174_AdminRotateHostkeySwapsKeyAndKeepsOld already call.
//
// Canaries (read the assertions below for the exact lines):
//   - if internal/client's HostKeyCallback stopped checking the pin (accepted
//     any key), the "client with stale pin A must be refused" assertion
//     would go red first — see the t.Fatal("CANARY: client connect with the
//     OLD pin A succeeded...") line.
//   - if gateway run after rotation somehow still presented the OLD key
//     (e.g. a restart that failed to reload hostkey from disk), the
//     "restarted gateway must present a DIFFERENT fingerprint" check goes
//     red first, before any client/machine dial is even attempted — see
//     the t.Fatal("restarted gateway still presents the OLD fingerprint A...")
//     line right after starting the second generation.
//
// Rules: no product code, docs/SPEC.md, docs/PROTOCOL.md or harness_test.go
// touched; every key and file lives under t.TempDir(); every listener is
// 127.0.0.1:0; the test closes both gateway generations itself before
// returning, on every path (see iamt198Gateway.close's sync.Once and the
// deferred/Cleanup calls below).

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/server"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// iamt198Gateway is one generation of the gateway process: its own
// Store/Log/listener, all rooted at the same on-disk dir across
// generations of the same test.
type iamt198Gateway struct {
	gw    *Gateway
	addr  string
	store *state.Store
	log   *events.Log

	closeOnce sync.Once
}

// close tears this generation down exactly once, gateway first (stops
// accepting/serving and tears down live connections under g.wg — see
// IAMT-172/195), then the on-disk store and log — the same order
// production shutdown uses (cmd/iamtunnel/gateway.go's runGateway defers).
// Safe to call more than once (t.Cleanup plus an explicit mid-test call
// both reach it in this file).
func (g *iamt198Gateway) close() {
	g.closeOnce.Do(func() {
		_ = g.gw.Close()
		_ = g.store.Close()
		_ = g.log.Close()
	})
}

// startIAMT198Gateway opens (or re-opens) the gateway's on-disk state at
// dir and serves it on a fresh 127.0.0.1:0 listener. Calling it a second
// time on the same dir after the first generation's close() is exactly
// the restart IAMT-198 step 3 asks for: state.json, events.jsonl and the
// host key file are all read fresh off disk, precisely as a real
// "iamtunnel gateway run" would after a process restart, and precisely
// how RotateHostKey's own doc comment says a live gateway is expected to
// pick up a rotated key — only via restart, never in place.
func startIAMT198Gateway(t *testing.T, dir string, clock *fakeClock) *iamt198Gateway {
	t.Helper()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open(%s): %v", dir, err)
	}
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		_ = store.Close()
		t.Fatalf("events.OpenLog: %v", err)
	}
	hostKey, err := loadOrGenerateHostKey(hostKeyPath(dir))
	if err != nil {
		_ = store.Close()
		_ = log.Close()
		t.Fatalf("load host key from %s: %v", dir, err)
	}
	cfg := Config{
		Store:               store,
		Log:                 log,
		HostKey:             hostKey,
		Now:                 clock.Now,
		DataDir:             dir,
		RecordingBaseDir:    filepath.Join(dir, "recordings"),
		SSHDProbeTimeout:    2 * time.Second,
		SessionSetupTimeout: 3 * time.Second,
	}
	gw, err := New(cfg)
	if err != nil {
		_ = store.Close()
		_ = log.Close()
		t.Fatalf("gateway.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = gw.Close()
		_ = store.Close()
		_ = log.Close()
		t.Fatalf("listen: %v", err)
	}
	go gw.Serve(ln)
	g := &iamt198Gateway{gw: gw, addr: ln.Addr().String(), store: store, log: log}
	t.Cleanup(g.close)
	return g
}

func iamt198AddPerson(t *testing.T, store *state.Store, clock *fakeClock, name, role string, key ssh.Signer) {
	t.Helper()
	if err := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: name, Role: role,
			Keys: []state.Key{{Fingerprint: fingerprintOf(t, key.PublicKey()), Pub: authorizedLine(key.PublicKey()), Added: state.NewZonedTime(clock.Now())}},
		})
		return nil
	}); err != nil {
		t.Fatalf("add person %s: %v", name, err)
	}
}

// iamt198AddMachine seeds a machine that is enrolled (has a machine key on
// record and can therefore authenticate as "machine:<id>", per
// stateView.Resolve in lookup.go — auth only ever looks at MachineKey, not
// State) but not yet verified: this test never opens the door or requests
// a session, only the pinned host-key check on Dial, so "verified" (which
// also demands a VerifiedOSUser/OSUserStatus/SSHDHostKey trio for §4.3)
// would be more than this scenario needs. state.State's own validation
// (validate.go) requires State to be "enrolled" or "verified" and OSUser
// to be a non-empty "DOMAIN\name" — both satisfied here with the minimum
// that passes Store.Update's validation.
func iamt198AddMachine(t *testing.T, store *state.Store, id string, key ssh.Signer) {
	t.Helper()
	if err := store.Update(func(st *state.State) error {
		st.Machines = append(st.Machines, state.Machine{
			ID: id, Name: id, State: "enrolled",
			MachineKey: authorizedLine(key.PublicKey()),
			OSUser:     `MACHINE\svc`,
		})
		return nil
	}); err != nil {
		t.Fatalf("add machine %s: %v", id, err)
	}
}

// iamt198NoopSpawnWatchdog stands in for winkeys.SpawnWatchdog: this test
// never calls door.open (it only dials, to exercise the pinned host-key
// check), so the watchdog is never actually spawned — server.Config just
// requires a non-nil constructor to pass setDefaults without requiring a
// real DoorwatchExe.
func iamt198NoopSpawnWatchdog(_, _, _ string, _ int, _ time.Duration, _, _ string, _, _ int) (*winkeys.Watchdog, error) {
	return nil, nil
}

func iamt198ServerConfig(t *testing.T, addr, fingerprint string, machineKey ssh.Signer) server.Config {
	t.Helper()
	tree := testsupport.NewSSHTree(t)
	return server.Config{
		GatewayAddr:        addr,
		GatewayFingerprint: fingerprint,
		MachineID:          "vm1",
		MachineKey:         machineKey,
		KeyFile:            tree.KeyPath("administrators_authorized_keys"),
		DoorLockPath:       filepath.Join(tree.Home, "door.lock"),
		OwnerUID:           testUIDForDoor(),
		OwnerGID:           testGIDForDoor(),
		TargetAddr:         "127.0.0.1:1",
		SpawnWatchdog:      iamt198NoopSpawnWatchdog,
		DialTimeout:        5 * time.Second,
		HandshakeTimeout:   5 * time.Second,
	}
}

// iamt198Connect drives the real internal/client.Connect against addr
// pinned to fingerprint, as person:machine. It reports only the dial-level
// outcome (err == nil means the host-key check and SSH auth both
// succeeded) — this test is about the fingerprint pin, not about a
// verified machine granting a shell, so "machine" need not be a real
// registered machine for this call.
func iamt198Connect(t *testing.T, addr, fingerprint, person, machine string, key ssh.Signer) error {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr %s: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %s: %v", portStr, err)
	}
	_, err = client.Connect(context.Background(), client.ConnectOptions{
		Conn:           config.ConnString{Host: host, Port: port, Person: person, Fingerprint: fingerprint},
		Machine:        machine,
		Signer:         key,
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		In:             strings.NewReader(""),
		Out:            io.Discard,
		DialTimeout:    5 * time.Second,
	})
	return err
}

// TestIAMT198_HostKeyRotation_OldPinRejectedAfterRestart is the THREATS
// candidate #9 sequence, end to end (T:86-90).
func TestIAMT198_HostKeyRotation_OldPinRejectedAfterRestart(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock(time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC))

	// ---- generation 1: hostkey A --------------------------------------
	gen1 := startIAMT198Gateway(t, dir, clock)

	rootKey := genSigner(t)
	iamt198AddPerson(t, gen1.store, clock, "root", "admin", rootKey)
	aliceKey := genSigner(t)
	iamt198AddPerson(t, gen1.store, clock, "alice", "user", aliceKey)
	machineKey := genSigner(t)
	iamt198AddMachine(t, gen1.store, "vm1", machineKey)

	fpA := auth.Fingerprint(gen1.gw.cfg.HostKey.PublicKey())

	// Step 1: client and machine, both pinned to A, connect successfully.
	if err := iamt198Connect(t, gen1.addr, fpA, "alice", "vm1", aliceKey); err != nil {
		t.Fatalf("step 1: client connect pinned to A (before rotation) failed: %v", err)
	}
	m1, err := server.Dial(context.Background(), iamt198ServerConfig(t, gen1.addr, fpA, machineKey))
	if err != nil {
		t.Fatalf("step 1: machine Dial pinned to A (before rotation) failed: %v", err)
	}
	_ = m1 // never Served: Dial succeeding is the fact under test; gen1.close tears the transport down.

	// Step 2: admin runs gateway.rotate-hostkey over the remote exec
	// surface (PROTOCOL §6, IAMT-174) against the LIVE gateway.
	rootConn := dialAdmin198(t, gen1.addr, fpA, "root", rootKey)
	oldFP, newFP, err := rootConn.GatewayRotateHostkey()
	if err != nil {
		t.Fatalf("step 2: gateway.rotate-hostkey as admin: %v", err)
	}
	if oldFP != fpA {
		t.Fatalf("step 2: gateway.rotate-hostkey oldFingerprint = %q, want the live gateway's %q", oldFP, fpA)
	}
	if newFP == "" || newFP == fpA {
		t.Fatalf("step 2: gateway.rotate-hostkey newFingerprint = %q, want a fresh fingerprint distinct from %q", newFP, fpA)
	}
	_ = rootConn.Close()

	// Step 2 continued: the LIVE gateway (no restart yet) still presents A
	// — RotateHostKey's own doc comment: "A LIVE gateway keeps presenting
	// the in-memory old key until it is restarted." Assert it by actually
	// connecting again, pinned to A, both as the admin and as the person
	// client — a fresh dial, not just reusing an already-open connection.
	if got := auth.Fingerprint(gen1.gw.cfg.HostKey.PublicKey()); got != fpA {
		t.Fatalf("step 2: live gateway's in-memory HostKey fingerprint changed to %q without a restart — want it to stay %q until restart", got, fpA)
	}
	if err := iamt198Connect(t, gen1.addr, fpA, "alice", "vm1", aliceKey); err != nil {
		t.Fatalf("step 2: client connect pinned to A against the LIVE (not yet restarted) gateway should still succeed: %v", err)
	}
	rootConn2 := dialAdmin198(t, gen1.addr, fpA, "root", rootKey)
	_ = rootConn2.Close()

	// Step 3: stop the gateway and start a fresh one on the SAME dir.
	gen1.close()
	gen2 := startIAMT198Gateway(t, dir, clock)

	fpB := auth.Fingerprint(gen2.gw.cfg.HostKey.PublicKey())
	if fpB != newFP {
		t.Fatalf("restarted gateway presents fingerprint %q, want the rotated fingerprint gateway.rotate-hostkey reported (%q)", fpB, newFP)
	}
	// CANARY: if "gateway run" after rotation somehow still loaded the old
	// key (e.g. a restart path that failed to reread hostKeyPath(dir) and
	// fell back to a freshly generated or cached signer), this is the
	// first place it would show, before any client/machine dial below
	// even runs.
	if fpB == fpA {
		t.Fatal("CANARY: restarted gateway still presents the OLD fingerprint A — gateway run after rotate-hostkey did not pick up the rotated key from disk")
	}

	// Step 4: client with the stale pin A is refused, verbatim text from
	// internal/client/knownhosts.go's ErrFingerprintMismatch, before any
	// further handshake byte is exchanged.
	err = iamt198Connect(t, gen2.addr, fpA, "alice", "vm1", aliceKey)
	if err == nil {
		// CANARY: this is the line that goes red if internal/client's
		// HostKeyCallback stopped checking the pin (e.g. accepted any key
		// unconditionally) — the connection would succeed against a
		// gateway now presenting a DIFFERENT key.
		t.Fatal("CANARY: client connect with the OLD pin A succeeded against the restarted gateway (which now presents B) — internal/client is not enforcing the pinned fingerprint")
	}
	const wantSubstr = "the gateway host-key fingerprint changed"
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("step 4: client connect with the stale pin A: error = %q, want it to contain %q (internal/client/knownhosts.go's ErrFingerprintMismatch)", err.Error(), wantSubstr)
	}
	if !strings.Contains(err.Error(), fpA) || !strings.Contains(err.Error(), fpB) {
		t.Fatalf("step 4: client stale-pin error %q does not name both the pinned (%q) and the presented (%q) fingerprints", err.Error(), fpA, fpB)
	}

	// Step 4 continued: the machine with the stale pin A is refused the
	// same way, via internal/server's own ErrFingerprintMismatch, and
	// Run (not just Dial) must not retry it.
	scfgStale := iamt198ServerConfig(t, gen2.addr, fpA, machineKey)
	_, err = server.Dial(context.Background(), scfgStale)
	if err == nil {
		t.Fatal("CANARY: machine Dial with the OLD pin A succeeded against the restarted gateway (which now presents B) — internal/server is not enforcing the pinned fingerprint")
	}
	if !errors.Is(err, server.ErrFingerprintMismatch) {
		t.Fatalf("step 4: machine Dial with the stale pin A: error = %v, want errors.Is(err, server.ErrFingerprintMismatch)", err)
	}

	runCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	start := time.Now()
	go func() { runDone <- server.Run(runCtx, scfgStale) }()
	select {
	case runErr := <-runDone:
		elapsed := time.Since(start)
		if !errors.Is(runErr, server.ErrFingerprintMismatch) {
			t.Fatalf("step 4: server.Run with the stale pin A returned %v, want errors.Is(err, server.ErrFingerprintMismatch)", runErr)
		}
		if elapsed > 3*time.Second {
			t.Fatalf("step 4: server.Run took %s to refuse a fingerprint mismatch — run.go's own contract is to return immediately ("+
				"\"refusing to retry\"), not retry with backoff", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("step 4: server.Run with a stale pin did not return within 5s — it looks like it is retrying a fingerprint mismatch instead of refusing immediately (run.go)")
	}

	// Step 5: client with the NEW connection string (pin B) connects.
	if err := iamt198Connect(t, gen2.addr, fpB, "alice", "vm1", aliceKey); err != nil {
		t.Fatalf("step 5: client connect with the rotated pin B against the restarted gateway: %v", err)
	}
}

// dialAdmin198 is this file's own admin dial helper: harness_test.go's
// dialAdmin takes a *fixture, which this test deliberately does not build
// (it needs two independent gateway generations over one dir, not one
// fixture's single gateway) — same admin.Dial call, just parameterised on
// addr/fingerprint directly instead of through a fixture.
func dialAdmin198(t *testing.T, addr, fingerprint, person string, key ssh.Signer) *admin.Conn {
	t.Helper()
	conn, err := admin.Dial(admin.Peer{Addr: addr, Fingerprint: fingerprint}, person, key, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial as %s: %v", person, err)
	}
	return conn
}
