package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---- test server -----------------------------------------------------

type authResult struct {
	id  Identity
	err error
}

// startServer listens on loopback and authenticates every accepted
// connection with the handler's FinishAuth. The host key and every
// client key are generated in-process; nothing touches the disk.
func startServer(t *testing.T, h *Handler, sink EventSink) (addr string, results <-chan authResult, stop func()) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	cfg := h.ServerConfig(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ch := make(chan authResult, 16)
	results = ch
	done := make(chan struct{})
	// IAMT-314: stop() waited only for the accept loop, never for the
	// per-connection handshakes it spawned, so a handshake goroutine could
	// still be running when the package ended. Adds happen only from the
	// accept loop, and stop() joins that loop before Wait, so Add can never
	// race Wait here.
	var handshakes sync.WaitGroup
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			handshakes.Add(1)
			go func(c net.Conn) {
				defer handshakes.Done()
				sconn, id, err := h.FinishAuth(c, cfg, sink, time.Now())
				if sconn != nil {
					defer sconn.Close()
				}
				ch <- authResult{id: id, err: err}
			}(c)
		}
	}()
	return ln.Addr().String(), results, func() { _ = ln.Close(); <-done; handshakes.Wait() }
}

// dialIn connects as user with the given signers.
func dialIn(t *testing.T, addr, user string, signers ...ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test loopback; the host key is generated above
		Timeout:         5 * time.Second,
	}
	return ssh.Dial("tcp", addr, cfg)
}

// waitResult waits for the server side to finish one authentication.
func waitResult(t *testing.T, results <-chan authResult) authResult {
	t.Helper()
	select {
	case r := <-results:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("server side did not finish authentication in 10s")
		return authResult{}
	}
}

// forgedSigner presents someone else's public key but signs with its
// own private key - a blob forged under a foreign signature.
type forgedSigner struct {
	shown ssh.PublicKey
	real  ssh.Signer
}

func (f forgedSigner) PublicKey() ssh.PublicKey { return f.shown }
func (f forgedSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return f.real.Sign(rand, data)
}

// ---- gate 2: eight keys, the correct one last -------------------------

func TestEightKeysCorrectLast(t *testing.T) {
	w := newWorld(t)
	addr, results, stop := startServer(t, w.handler, w.sink)
	defer stop()

	var signers []ssh.Signer
	for i := 0; i < 7; i++ {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("signer %d: %v", i, err)
		}
		signers = append(signers, s)
	}
	signers = append(signers, w.aliceSign) // the correct key comes last

	conn, err := dialIn(t, addr, "alice", signers...)
	if err != nil {
		t.Fatalf("dial with 8 keys (correct last): %v", err)
	}
	defer conn.Close()

	r := waitResult(t, results)
	if r.err != nil {
		t.Fatalf("server side: %v", r.err)
	}
	if r.id.Subject.Name != "alice" || r.id.Fingerprint != w.aliceFP {
		t.Fatalf("identity = %+v, want alice with %s", r.id, w.aliceFP)
	}
	acc, den, _ := w.sink.counts()
	if acc != 1 || den != 0 {
		t.Fatalf("journal: accepted=%d denied=%d, want 1/0", acc, den)
	}
}

// ---- gate 3: two identities, session opens as the KEY's owner ---------

func TestTwoIdentities(t *testing.T) {
	w := newWorld(t)
	addr, results, stop := startServer(t, w.handler, w.sink)
	defer stop()

	// bob's client walks alice's key first: the pure callback refuses
	// the mismatch, the client proceeds to its own key, and the session
	// opens as bob - from the key, not from the order of offers.
	conn, err := dialIn(t, addr, "bob", w.aliceSign, w.bobSign)
	if err != nil {
		t.Fatalf("dial bob [alice, bob]: %v", err)
	}
	r := waitResult(t, results)
	if r.err != nil {
		t.Fatalf("server side: %v", r.err)
	}
	if r.id.Subject.Name != "bob" || r.id.Fingerprint != w.bobFP {
		t.Fatalf("identity = %+v, want bob with %s", r.id, w.bobFP)
	}
	_ = conn.Close()

	// And the mirror: alice's client with both keys opens as alice.
	conn2, err := dialIn(t, addr, "alice", w.aliceSign, w.bobSign)
	if err != nil {
		t.Fatalf("dial alice [alice, bob]: %v", err)
	}
	defer conn2.Close()
	r2 := waitResult(t, results)
	if r2.err != nil {
		t.Fatalf("server side (alice): %v", r2.err)
	}
	if r2.id.Subject.Name != "alice" {
		t.Fatalf("identity = %+v, want alice", r2.id)
	}
}

// ---- gate 4: a blob forged under a foreign signature -------------------

func TestForgedBlobRejected(t *testing.T) {
	w := newWorld(t)
	addr, results, stop := startServer(t, w.handler, w.sink)
	defer stop()

	// The blob says alice (a registered key), the signature is bob's.
	forged := forgedSigner{shown: w.aliceSign.PublicKey(), real: w.bobSign}
	if _, err := dialIn(t, addr, "alice", forged); err == nil {
		t.Fatal("forged blob accepted, want refusal")
	}
	r := waitResult(t, results)
	if r.err == nil {
		t.Fatal("server side accepted the forged handshake")
	}
	_, den, _ := w.sink.counts()
	if den == 0 {
		t.Fatal("no AuthDenied event for the forged handshake")
	}
}

// ---- gate 6: name mismatch over the wire -------------------------------

func TestNameMismatchIntegration(t *testing.T) {
	w := newWorld(t)
	addr, results, stop := startServer(t, w.handler, w.sink)
	defer stop()

	// Only alice's key, but the username says bob: every offer is
	// refused and the connection dies without authentication.
	if _, err := dialIn(t, addr, "bob", w.aliceSign); err == nil {
		t.Fatal("mismatched login accepted over the wire")
	}
	r := waitResult(t, results)
	if r.err == nil {
		t.Fatal("server side accepted the mismatch")
	}
	var denied *ErrDenied
	if !errors.As(r.err, &denied) {
		t.Fatalf("error = %v, want *ErrDenied", r.err)
	}
	// x/crypto does not surface the username on an auth failure, only
	// the fact - so the user field may be empty here; the typed reason
	// and the denial event are the contract.
	_ = denied
}

// ---- gate 7: the algorithm policy over the wire -------------------------

func TestAlgorithmPolicyIntegration(t *testing.T) {
	w := newWorld(t)

	// rsa 2048: registered under alice so the only refusal reason left
	// is the algorithm.
	weak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa2048: %v", err)
	}
	weakSign, err := ssh.NewSignerFromKey(weak)
	if err != nil {
		t.Fatalf("rsa2048 signer: %v", err)
	}
	weakPK, err := ssh.NewPublicKey(&weak.PublicKey)
	if err != nil {
		t.Fatalf("rsa2048 pubkey: %v", err)
	}
	w.lookup.keys[Fingerprint(weakPK)] = Subject{Name: "alice", Role: RolePerson}

	// rsa 4096: registered too.
	strong, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("rsa4096: %v", err)
	}
	strongSign, err := ssh.NewSignerFromKey(strong)
	if err != nil {
		t.Fatalf("rsa4096 signer: %v", err)
	}
	strongPK, err := ssh.NewPublicKey(&strong.PublicKey)
	if err != nil {
		t.Fatalf("rsa4096 pubkey: %v", err)
	}
	w.lookup.keys[Fingerprint(strongPK)] = Subject{Name: "alice", Role: RolePerson}

	// ecdsa nistp256: the closest real key to the SPEC's "ecdsa-sha1"
	// refusal (no such wire type exists in SSH; every ecdsa is refused).
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	ecSign, err := ssh.NewSignerFromKey(ec)
	if err != nil {
		t.Fatalf("ecdsa signer: %v", err)
	}
	ecPK, err := ssh.NewPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatalf("ecdsa pubkey: %v", err)
	}
	w.lookup.keys[Fingerprint(ecPK)] = Subject{Name: "alice", Role: RolePerson}

	addr, results, stop := startServer(t, w.handler, w.sink)
	defer stop()

	// rsa 2048 - refused.
	if _, err := dialIn(t, addr, "alice", weakSign); err == nil {
		t.Fatal("rsa 2048 accepted over the wire")
	}
	waitResult(t, results)

	// ecdsa - refused.
	if _, err := dialIn(t, addr, "alice", ecSign); err == nil {
		t.Fatal("ecdsa accepted over the wire")
	}
	waitResult(t, results)

	// rsa 4096 - accepted.
	conn, err := dialIn(t, addr, "alice", strongSign)
	if err != nil {
		t.Fatalf("rsa 4096 refused: %v", err)
	}
	r := waitResult(t, results)
	if r.err != nil {
		t.Fatalf("server side: %v", r.err)
	}
	if r.id.Fingerprint != Fingerprint(strongPK) {
		t.Fatalf("identity fingerprint = %s, want the rsa 4096 one", r.id.Fingerprint)
	}
	_ = conn.Close()

	// ed25519 - accepted (control).
	conn2, err := dialIn(t, addr, "alice", w.aliceSign)
	if err != nil {
		t.Fatalf("ed25519 refused: %v", err)
	}
	defer conn2.Close()
	r2 := waitResult(t, results)
	if r2.err != nil || r2.id.Fingerprint != w.aliceFP {
		t.Fatalf("ed25519: %+v err=%v", r2.id, r2.err)
	}
}

// ---- MaxAuthTries bites -----------------------------------------------

func TestTooManyKeysDropped(t *testing.T) {
	w := newWorld(t)
	addr, results, stop := startServer(t, w.handler, w.sink)
	defer stop()

	// 33 unknown keys: more than MaxAuthTries=32, the server must cut
	// the walk short instead of serving an endless agent.
	var signers []ssh.Signer
	for i := 0; i < 33; i++ {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("signer %d: %v", i, err)
		}
		signers = append(signers, s)
	}
	if _, err := dialIn(t, addr, "alice", signers...); err == nil {
		t.Fatal("33-key walk accepted, want the connection dropped")
	}
	r := waitResult(t, results)
	if r.err == nil {
		t.Fatal("server side reported no error on the 33-key walk")
	}
}

// ---- machine role over the wire ----------------------------------------

func TestMachineRoleIntegration(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	handler, err := NewHandler(NewMapLookup(map[string]Subject{
		Fingerprint(signer.PublicKey()): {Name: "win01", Role: RoleMachine},
	}), AuthLimits{HandshakeTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	sink := &countingSink{}
	addr, results, stop := startServer(t, handler, sink)
	defer stop()

	conn, err := dialIn(t, addr, "machine:win01", signer)
	if err != nil {
		t.Fatalf("machine dial: %v", err)
	}
	defer conn.Close()
	r := waitResult(t, results)
	if r.err != nil {
		t.Fatalf("server side: %v", r.err)
	}
	if r.id.Subject.Role != RoleMachine || r.id.Subject.Name != "win01" {
		t.Fatalf("identity = %+v", r.id)
	}
	// A machine key under a person-style username is refused.
	if _, err := dialIn(t, addr, "win01", signer); err == nil {
		t.Fatal("machine key accepted with a person-style username")
	}
	waitResult(t, results)
}
