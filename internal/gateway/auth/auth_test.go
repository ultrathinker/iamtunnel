package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---- fakes ----------------------------------------------------------

// MapLookup is the in-memory Lookup fake; dump() snapshots it for the
// purity test.
type MapLookup struct {
	mu   sync.Mutex
	keys map[string]Subject
}

func NewMapLookup(keys map[string]Subject) *MapLookup {
	cp := make(map[string]Subject, len(keys))
	for k, v := range keys {
		cp[k] = v
	}
	return &MapLookup{keys: cp}
}

func (m *MapLookup) Resolve(fp string) (Subject, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.keys[fp]
	return s, ok, nil
}

func (m *MapLookup) dump() map[string]Subject {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[string]Subject, len(m.keys))
	for k, v := range m.keys {
		cp[k] = v
	}
	return cp
}

// countingSink records every event the package emits.
type countingSink struct {
	mu           sync.Mutex
	accepted     int
	denied       int
	rateExceeded int
}

func (s *countingSink) AuthAccepted(addr, user, fp, subject string, role Role) {
	s.mu.Lock()
	s.accepted++
	s.mu.Unlock()
}

func (s *countingSink) AuthDenied(addr, user, fp, reason string) {
	s.mu.Lock()
	s.denied++
	s.mu.Unlock()
}

func (s *countingSink) RateExceeded(addr, fp string, until time.Time) {
	s.mu.Lock()
	s.rateExceeded++
	s.mu.Unlock()
}

func (s *countingSink) counts() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted, s.denied, s.rateExceeded
}

// fakeMeta implements ssh.ConnMetadata for callback-level unit tests.
type fakeMeta struct{ user string }

func (f fakeMeta) User() string          { return f.user }
func (f fakeMeta) SessionID() []byte     { return nil }
func (f fakeMeta) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeMeta) ServerVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeMeta) RemoteAddr() net.Addr  { return fakeAddr{} }
func (f fakeMeta) LocalAddr() net.Addr   { return fakeAddr{} }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "203.0.113.7:1234" }

// ---- fixtures --------------------------------------------------------

type world struct {
	handler    *Handler
	lookup     *MapLookup
	sink       *countingSink
	limiter    *RateLimiter
	aliceSign  ssh.Signer
	bobSign    ssh.Signer
	aliceFP    string
	bobFP      string
	callbackFn func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error)
}

func newWorld(t *testing.T) *world {
	t.Helper()
	alicePub, alicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("alice key: %v", err)
	}
	bobPub, bobPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("bob key: %v", err)
	}
	aliceSign, err := ssh.NewSignerFromKey(alicePriv)
	if err != nil {
		t.Fatalf("alice signer: %v", err)
	}
	bobSign, err := ssh.NewSignerFromKey(bobPriv)
	if err != nil {
		t.Fatalf("bob signer: %v", err)
	}
	alicePK, err := ssh.NewPublicKey(alicePub)
	if err != nil {
		t.Fatalf("alice pubkey: %v", err)
	}
	bobPK, err := ssh.NewPublicKey(bobPub)
	if err != nil {
		t.Fatalf("bob pubkey: %v", err)
	}
	lookup := NewMapLookup(map[string]Subject{
		Fingerprint(alicePK): {Name: "alice", Role: RolePerson},
		Fingerprint(bobPK):   {Name: "bob", Role: RolePerson},
	})
	sink := &countingSink{}
	limiter, err := NewRateLimiter(RateConfig{
		MaxKnownFailures:   10,
		MaxUnknownFailures: 50,
		Window:             time.Minute,
		PairBanDuration:    time.Minute,
		AddrBanDuration:    time.Minute,
	}, sink)
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	// IAMT-314: the A-3 sweeper goroutine started by NewRateLimiter lives
	// until Close; this fixture outlives no test, so tie it to the test.
	t.Cleanup(limiter.Close)
	handler, err := NewHandler(lookup, AuthLimits{
		MaxSessionsPerPerson:  4,
		MaxSessionsPerMachine: 8,
		HandshakeTimeout:      10 * time.Second,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	return &world{
		handler:    handler,
		lookup:     lookup,
		sink:       sink,
		limiter:    limiter,
		aliceSign:  aliceSign,
		bobSign:    bobSign,
		aliceFP:    Fingerprint(alicePK),
		bobFP:      Fingerprint(bobPK),
		callbackFn: handler.PublicKeyCallback(),
	}
}

// ---- gate 5: the callback is pure ------------------------------------

func TestCallbackPurity(t *testing.T) {
	w := newWorld(t)
	w.callbackFn(fakeMeta{user: "alice"}, w.aliceSign.PublicKey()) // warm-up

	keysBefore := w.lookup.dump()
	accBefore, denBefore, rateBefore := w.sink.counts()
	limBefore := map[string]RateDecision{}
	for _, pair := range [][2]string{{"203.0.113.7", "fp-a"}, {"203.0.113.7", "fp-b"}} {
		limBefore[pair[0]+"/"+pair[1]] = w.limiter.Allow(pair[0], pair[1], t0)
	}

	for i := 0; i < 100; i++ {
		// Known key under its own name...
		if _, err := w.callbackFn(fakeMeta{user: "alice"}, w.aliceSign.PublicKey()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		// ...and refusals, which are the tempting place to smuggle in a
		// counter or a journal line.
		if _, err := w.callbackFn(fakeMeta{user: "mallory"}, w.aliceSign.PublicKey()); err == nil {
			t.Fatalf("call %d: mismatch not refused", i)
		}
		if _, err := w.callbackFn(fakeMeta{user: "alice"}, w.bobSign.PublicKey()); err == nil {
			t.Fatalf("call %d: mismatch not refused", i)
		}
	}

	keysAfter := w.lookup.dump()
	if !reflect.DeepEqual(keysBefore, keysAfter) {
		t.Fatal("lookup state changed during 100 callback calls")
	}
	accAfter, denAfter, rateAfter := w.sink.counts()
	if accAfter != accBefore || denAfter != denBefore || rateAfter != rateBefore {
		t.Fatalf("journal changed: accepted %d->%d denied %d->%d rate %d->%d",
			accBefore, accAfter, denBefore, denAfter, rateBefore, rateAfter)
	}
	for _, pair := range [][2]string{{"203.0.113.7", "fp-a"}, {"203.0.113.7", "fp-b"}} {
		d := w.limiter.Allow(pair[0], pair[1], t0)
		if d != limBefore[pair[0]+"/"+pair[1]] {
			t.Fatalf("rate limiter changed for %v: %+v -> %+v", pair, limBefore[pair[0]+"/"+pair[1]], d)
		}
	}
}

func TestCallbackUnknownKeyError(t *testing.T) {
	w := newWorld(t)
	// A truly unregistered key.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	if _, cbErr := w.callbackFn(fakeMeta{user: "alice"}, pk); cbErr == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestCallbackKnownKeyGivesPermissions(t *testing.T) {
	w := newWorld(t)
	perm, err := w.callbackFn(fakeMeta{user: "alice"}, w.aliceSign.PublicKey())
	if err != nil {
		t.Fatalf("alice/alice: %v", err)
	}
	id, err := ExtractIdentity(perm)
	if err != nil {
		t.Fatalf("ExtractIdentity: %v", err)
	}
	if id.Subject.Name != "alice" || id.Subject.Role != RolePerson || id.Fingerprint != w.aliceFP {
		t.Fatalf("identity = %+v", id)
	}
}

func TestCallbackNameMismatch(t *testing.T) {
	w := newWorld(t)
	// alice's key offered under bob's name: refused, so the client walks on.
	if _, err := w.callbackFn(fakeMeta{user: "bob"}, w.aliceSign.PublicKey()); err == nil {
		t.Fatal("name mismatch accepted by the callback")
	}
	// And the other way.
	if _, err := w.callbackFn(fakeMeta{user: "alice"}, w.bobSign.PublicKey()); err == nil {
		t.Fatal("name mismatch accepted by the callback")
	}
}

func TestCallbackAlgorithmRejectedBeforeLookup(t *testing.T) {
	w := newWorld(t)
	// rsa 2048 is generated and REGISTERED under alice's subject: the
	// only possible refusal reason is the algorithm policy.
	weak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	weakPK, err := ssh.NewPublicKey(&weak.PublicKey)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	w.lookup.keys[Fingerprint(weakPK)] = Subject{Name: "alice", Role: RolePerson}
	if _, err := w.callbackFn(fakeMeta{user: "alice"}, weakPK); err == nil {
		t.Fatal("rsa 2048 accepted")
	}
}

// ---- login verification ----------------------------------------------

func TestVerifyLoginPersonMatches(t *testing.T) {
	w := newWorld(t)
	perm, _ := w.callbackFn(fakeMeta{user: "alice"}, w.aliceSign.PublicKey())
	for _, name := range []string{"alice", "alice:win01"} {
		id, err := VerifyLogin(perm, name)
		if err != nil {
			t.Fatalf("VerifyLogin(%q): %v", name, err)
		}
		if id.Subject.Name != "alice" || id.Fingerprint != w.aliceFP {
			t.Fatalf("VerifyLogin(%q) = %+v", name, id)
		}
	}
}

func TestVerifyLoginNameMismatch(t *testing.T) {
	w := newWorld(t)
	// The gateway itself is the attacker here: permissions say alice,
	// the username said bob. (In the real flow the pure callback
	// already refuses this; VerifyLogin is the second line.)
	perm, _ := w.callbackFn(fakeMeta{user: "alice"}, w.aliceSign.PublicKey())
	if _, err := VerifyLogin(perm, "bob"); err == nil {
		t.Fatal("VerifyLogin accepted a mismatching username")
	}
	if _, err := VerifyLogin(perm, "alice:win01:extra"); err == nil {
		t.Fatal("VerifyLogin accepted a malformed username")
	}
}

func TestVerifyLoginMachineRole(t *testing.T) {
	_, bobPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	bobSign, _ := ssh.NewSignerFromKey(bobPriv)
	bobPK, _ := ssh.NewPublicKey(bobPriv.Public())
	fp := Fingerprint(bobPK)

	handler, err := NewHandler(NewMapLookup(map[string]Subject{
		fp: {Name: "win01", Role: RoleMachine},
	}), AuthLimits{HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	perm, err := handler.PublicKeyCallback()(fakeMeta{user: "machine:win01"}, bobSign.PublicKey())
	if err != nil {
		t.Fatalf("machine callback: %v", err)
	}
	if _, err := VerifyLogin(perm, "machine:win01"); err != nil {
		t.Fatalf("machine login: %v", err)
	}
	if _, err := VerifyLogin(perm, "win01"); err == nil {
		t.Fatal("machine identity accepted a person-style username")
	}
}

func TestExtractIdentityRejectsEmpty(t *testing.T) {
	if _, err := ExtractIdentity(nil); err == nil {
		t.Fatal("nil permissions accepted")
	}
	if _, err := ExtractIdentity(&ssh.Permissions{}); err == nil {
		t.Fatal("permissionless permissions accepted")
	}
}

// ---- configuration ----------------------------------------------------

func TestServerConfigMaxAuthTries(t *testing.T) {
	w := newWorld(t)
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	cfg := w.handler.ServerConfig(signer)
	if cfg.MaxAuthTries != 32 {
		t.Fatalf("MaxAuthTries = %d, want 32 (SPEC 6.1: default 6 cuts off a person with a seventh agent key)", cfg.MaxAuthTries)
	}
	if cfg.PublicKeyCallback == nil {
		t.Fatal("no public key callback installed")
	}
}

func TestAuthLimitsAreParameters(t *testing.T) {
	w := newWorld(t)
	l := w.handler.Limits()
	if l.MaxSessionsPerPerson != 4 || l.MaxSessionsPerMachine != 8 || l.HandshakeTimeout != 10*time.Second {
		t.Fatalf("limits not carried through: %+v", l)
	}
	if _, err := NewHandler(NewMapLookup(nil), AuthLimits{MaxSessionsPerPerson: -1, HandshakeTimeout: time.Second}); err == nil {
		t.Fatal("negative person limit accepted")
	}
	if _, err := NewHandler(NewMapLookup(nil), AuthLimits{HandshakeTimeout: 0}); err == nil {
		t.Fatal("zero handshake timeout accepted")
	}
	if _, err := NewHandler(nil, AuthLimits{HandshakeTimeout: time.Second}); err == nil {
		t.Fatal("nil lookup accepted")
	}
}

func TestHandshakeDeadlineIsComputedFromInjectedNow(t *testing.T) {
	w := newWorld(t) // 10s timeout
	got := w.handler.HandshakeDeadline(t0)
	if !got.Equal(t0.Add(10 * time.Second)) {
		t.Fatalf("deadline = %v, want %v", got, t0.Add(10*time.Second))
	}
}
