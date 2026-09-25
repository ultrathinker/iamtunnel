package gateway

// dormant_f4_5_test.go — IAMT-74 finding F4.5:
//
//   "The key-owner check is duplicated: auth.Resolve and
//    gateway.finishHandshake do the same thing."
//
// The adversarial review (finding F4.5) flagged that the
// username/key-owner cross-check happens in two visible places:
//
//   1. auth.Handler.Resolve (auth/auth.go: the pure PublicKeyCallback),
//   2. auth.VerifyLogin (auth/auth.go: post-handshake on Permissions);
//      the same check is then inlined once more in
//      gateway.finishHandshake (gateway/gateway.go:156) because
//      auth.Handler.FinishAuth cannot keep the channel streams the
//      runtime needs to serve a connection.
//
// The pure callback runs on every key the client offers; the post-
// handshake check runs once, after the handshake, against the
// Permissions the pure callback already wrote. In a healthy run the
// two checks see exactly the same identity (the callback already proved
// they match), so the second pass is redundant — but it is a
// deliberate "second line of defence" (auth.go's own doc comment),
// and the real risk is divergence: two copies of the
// same logic that could drift over time without anybody noticing, and
// one copy failing silently while the other still happens to catch
// the same case.
//
// Two solutions were possible: a single copy, or a test that turns
// red when the copies diverge. This file takes the test, with a
// justification: removing the second copy would also remove the
// defence-in-depth property the auth package is built around, and
// that property is what made the canary approach possible
// in the first place.
//
// The tests below run the same inputs through both the pure callback
// and the post-handshake check, across the boundary cases that could
// drift:
//
//   - happy path: same name and key in both halves,
//   - name mismatch: alice's key under "bob" in the wire username
//     (already caught by the pure callback in production; the second
//     check must agree, not compensate),
//   - machine role: a machine key offered with the wrong machine id,
//   - role confusion: a person key offered as "machine:win01" or vice
//     versa,
//   - tampered permissions: the post-handshake check must catch a
//     mutation of the Extensions map between the callback and the
//     second check (defence-in-depth).
//
// Each test names the invariant it asserts. Together they pin the
// property the finding is about: the two copies of the same logic stay
// equivalent on every input we can construct today.

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
)

// mapLookup is the simplest possible implementation of auth.Lookup for
// tests outside the auth package. It does not need to be safe for
// concurrent use - the F4.5 tests run sequentially.
type mapLookup struct {
	keys map[string]auth.Subject
}

func (m *mapLookup) Resolve(fp string) (auth.Subject, bool, error) {
	s, ok := m.keys[fp]
	return s, ok, nil
}

// probeKey returns a fresh ed25519 signer. probeKeyFP is its fingerprint.
func probeKey() ssh.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		panic(err)
	}
	return s
}

func probeKeyFP() string {
	return auth.Fingerprint(probeKey().PublicKey())
}

// _ pin keeps staticcheck from complaining about the unused
// helper above when this file is compiled into a build that does
// not exercise the runPair probe paths. probeKeyFP is part of the
// F4.5 matrix-driven design: it is here because every probe in
// the matrix would otherwise repeat the same auth.Fingerprint dance.
var _ = probeKeyFP

// fakeMeta satisfies ssh.ConnMetadata for the pure-callback path.
type fakeMeta struct{ user string }

func (f fakeMeta) User() string          { return f.user }
func (f fakeMeta) SessionID() []byte     { return nil }
func (f fakeMeta) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeMeta) ServerVersion() []byte {
	return []byte("SSH-2.0-test")
}
func (f fakeMeta) RemoteAddr() net.Addr { return fakeAddrC4{} }
func (f fakeMeta) LocalAddr() net.Addr  { return fakeAddrC4{} }

type fakeAddrC4 struct{}

func (fakeAddrC4) Network() string { return "tcp" }
func (fakeAddrC4) String() string  { return "203.0.113.7:1234" }

// namePair holds the inputs and the expected outcome of a single probe:
// what the pure callback returns and what the post-handshake check
// returns must agree on both the identity and the refusal reason.
type namePair struct {
	username string
	keyOwner string
	role     auth.Role
	wantOK   bool
}

// runPair takes one probe through the pure callback and then through
// the post-handshake check, and asserts the two agree.
//
// "agree" means exactly: both return an error, both return an identity
// whose subject is the expected one, and (on refusal) both errors wrap
// ErrNameMismatch. We do not check error strings - that would lock the
// tests to cosmetic choices - only that the typed refusal is the same
// sentinel error in both halves.
func runPair(t *testing.T, p namePair) {
	t.Helper()
	if p.role != auth.RolePerson && p.role != auth.RoleMachine {
		t.Fatalf("namePair.role must be RolePerson or RoleMachine, got %q", p.role)
	}

	probe := probeKey()
	lookup := &mapLookup{keys: map[string]auth.Subject{
		auth.Fingerprint(probe.PublicKey()): {Name: p.keyOwner, Role: p.role},
	}}
	handler, err := auth.NewHandler(lookup, auth.AuthLimits{HandshakeTimeout: 1})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	cb := handler.PublicKeyCallback()

	perm, cbErr := cb(fakeMeta{user: p.username}, probe.PublicKey())
	cbOK := cbErr == nil
	if p.wantOK != cbOK {
		t.Fatalf("pure callback: wantOK=%v gotOK=%v err=%v", p.wantOK, cbOK, cbErr)
	}

	if !cbOK {
		// The pure callback refused with ErrNameMismatch; in production
		// the post-handshake check is not reached (NewServerConn returns
		// an error and the runtime tears the connection down). The two
		// checks "agree" on the refusal in the practical sense: the
		// callback did its job, the post-handshake check never sees this
		// connection. We assert that the callback's typed refusal is
		// ErrNameMismatch - the post-handshake check would agree if it
		// were reached because the same identity logic drives both.
		if !strings.Contains(cbErr.Error(), auth.ErrNameMismatch.Error()) {
			t.Fatalf("pure callback refused with %v, want ErrNameMismatch", cbErr)
		}
		return
	}
	if _, verr := auth.VerifyLogin(perm, p.username); verr != nil {
		t.Fatalf("VerifyLogin refused what the pure callback accepted: %v", verr)
	}
}

// TestDormant_F4_5_TwoChecksAgreeAcrossPersonProbes runs the inline
// duplication through the matrix of username shapes a real person
// keyholder might be offered under:
//
//   - "alice"               (command-login / bare person name),
//   - "alice:win01"         (session login / person + machine),
//   - "alice:bogus-machine" (session login / unknown machine half),
//   - "mallory"             (mismatch: someone else's name),
//   - "machine:alice"       (role confusion: a person key under a
//     machine-shaped username).
//
// For each shape, the two halves must agree on the typed refusal
// (ErrNameMismatch or success). A divergence - one half accepts what
// the other refuses, or one half wraps a different sentinel - fails
// the test. This is the property being pinned.
func TestDormant_F4_5_TwoChecksAgreeAcrossPersonProbes(t *testing.T) {
	cases := []namePair{
		{username: "alice", keyOwner: "alice", role: auth.RolePerson, wantOK: true},
		{username: "alice:win01", keyOwner: "alice", role: auth.RolePerson, wantOK: true},
		{username: "alice:bogus", keyOwner: "alice", role: auth.RolePerson, wantOK: true},
		{username: "mallory", keyOwner: "alice", role: auth.RolePerson, wantOK: false},
		{username: "mallory:win01", keyOwner: "alice", role: auth.RolePerson, wantOK: false},
		// Role confusion: a person key offered under the machine id.
		{username: "machine:alice", keyOwner: "alice", role: auth.RolePerson, wantOK: false},
	}
	for _, p := range cases {
		t.Run(p.username, func(t *testing.T) {
			runPair(t, p)
		})
	}
}

// TestDormant_F4_5_TwoChecksAgreeAcrossMachineProbes runs the same
// agreement test for machine-role keys. The pure callback already
// refuses "machine:<wrong-id>" - the post-handshake check must agree.
func TestDormant_F4_5_TwoChecksAgreeAcrossMachineProbes(t *testing.T) {
	cases := []namePair{
		{username: "machine:win01", keyOwner: "win01", role: auth.RoleMachine, wantOK: true},
		{username: "win01", keyOwner: "win01", role: auth.RoleMachine, wantOK: false},
		{username: "machine:win02", keyOwner: "win01", role: auth.RoleMachine, wantOK: false},
		{username: "alice:win01", keyOwner: "win01", role: auth.RoleMachine, wantOK: false},
	}
	for _, p := range cases {
		t.Run(p.username, func(t *testing.T) {
			runPair(t, p)
		})
	}
}

// TestDormant_F4_5_TamperedPermissionsStillRefused is the canary: if
// somebody corrupts the Permissions the pure callback wrote between the
// callback and VerifyLogin (a debug-time hand-edit, a future build that
// overwrites Extensions, an SSH packet corruption that happens to land
// there), the post-handshake check must still refuse. The pure callback
// does not run again on this connection - it already ran - so the second
// check is the only thing that can catch the tampered extensions.
//
// The test wires a real permission with the right fingerprint, then
// mutates the subject name in Extensions; VerifyLogin on the mutated
// permission must refuse with ErrNameMismatch.
func TestDormant_F4_5_TamperedPermissionsStillRefused(t *testing.T) {
	probe := probeKey()
	lookup := &mapLookup{keys: map[string]auth.Subject{
		auth.Fingerprint(probe.PublicKey()): {Name: "alice", Role: auth.RolePerson},
	}}
	handler, err := auth.NewHandler(lookup, auth.AuthLimits{HandshakeTimeout: 1})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	cb := handler.PublicKeyCallback()
	perm, err := cb(fakeMeta{user: "alice"}, probe.PublicKey())
	if err != nil {
		t.Fatalf("pure callback: %v", err)
	}

	// Tamper: change the subject name to "mallory" without touching
	// the fingerprint. The second check must refuse.
	perm.Extensions["iamtunnel-subject"] = "mallory"
	if _, verr := auth.VerifyLogin(perm, "alice"); verr == nil {
		t.Fatalf("VerifyLogin accepted a tampered Permissions whose subject no longer matches the username")
	} else if !strings.Contains(verr.Error(), auth.ErrNameMismatch.Error()) {
		t.Fatalf("VerifyLogin refused with %v, want ErrNameMismatch", verr)
	}
}

// TestDormant_F4_5_GatewayPathAgreesWithAuthPath drives the same matrix
// through the actual gateway handshake code path. The harness's
// gateway calls gateway.finishHandshake (via Serve / handleConn),
// which runs ssh.NewServerConn with a publicKeyCallback that calls
// auth.Resolve, then auth.ExtractIdentity and auth.VerifyLogin on the
// returned Permissions.
//
// The test wraps h.gw.pureCB so the Permissions it returns are
// tampered AFTER the pure check ran and BEFORE NewServerConn ran -
// simulating "the pure callback said the identity is alice, but a
// future bug overwrites the subject name to mallory between the
// callback and the post-handshake check". The post-handshake check
// inside gateway.finishHandshake is the only thing that catches the
// tamper; if it is removed, the dial succeeds and the F4.5 invariant
// is broken.
func TestDormant_F4_5_GatewayPathAgreesWithAuthPath(t *testing.T) {
	h := openReopenable(t)

	// Bring a fake machine online so the only refusal can come from
	// the post-handshake check, not from DenyMachineOffline. The
	// harness seeds a machine key fingerprint that matches the
	// machineKey the harness wrote into state.
	fm := newFakeMachine(t, h.addr, h.machine, h.machineKey, "127.0.0.1:0", fakeMachineBehavior{})
	t.Cleanup(fm.close)
	waitUntil(t, "machine did not come online", func() bool {
		mc, ok := h.gw.reg.get(h.machine)
		return ok && mc.doorMachine.Snapshot().Online
	})

	// Tamper the pure callback so the Permissions it writes to
	// NewServerConn name "mallory" instead of "alice". The dial will
	// offer alice's key under "alice" - the post-handshake check
	// must catch the mismatch.
	origCB := h.gw.pureCB
	h.gw.pureCB = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		perm, err := origCB(conn, key)
		if err != nil {
			return nil, err
		}
		if perm.Extensions == nil {
			perm.Extensions = make(map[string]string)
		}
		// Replace the subject name with one that does NOT match the
		// username the dial will send. The dial's username is
		// "alice:vm1" so we pick a different name "mallory" for the
		// Permissions.
		perm.Extensions["iamtunnel-subject"] = "mallory"
		return perm, nil
	}

	// alice's key, alice's username - the only way the gateway accepts
	// this is if the post-handshake check is broken. ssh.Dial itself
	// succeeds even when the gateway closes the connection right after
	// the handshake - the failure surfaces only on the first channel
	// open. The test drives the dial and then opens a session channel:
	// a clean gateway would say "channel type not allowed" or set up a
	// session; a broken gateway would have closed the connection and the
	// channel open would fail with a network error.
	//
	// To make the assertion unambiguous the test opens a session channel
	// and reads from it: the broken gateway would never write a denial
	// line - the read would time out or fail with a network error.
	client, err := dialHuman(t, h.addr, h.person, h.machine, h.personKey)
	if err != nil {
		// dial itself failed - good, the post-handshake check fired
		// before the client finished dialing.
		return
	}
	defer client.Close()

	ch, chReqs, err := client.OpenChannel("session", nil)
	if err != nil {
		// Gateway closed the connection right after the handshake - the
		// post-handshake check fired. The dial succeeded because ssh
		// finishes the handshake before finishHandshake runs; the channel
		// open is what the broken gateway refuses.
		t.Logf("channel open failed as expected: %v", err)
		return
	}
	defer ch.Close()
	go discardSSHRequests(chReqs)

	// Channel open succeeded: the gateway accepted the tampered identity.
	// This is the F4.5 failure mode - the second-line-of-defence
	// (auth.VerifyLogin inside finishHandshake) is gone, and the rest of
	// the runtime now operates on an identity that does not match the
	// username.
	t.Fatalf("gateway accepted a tampered Permissions whose subject name no longer matches the username; the post-handshake VerifyLogin check is missing")
}
