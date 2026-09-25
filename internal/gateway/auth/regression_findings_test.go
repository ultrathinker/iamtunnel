package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// spyConn wraps a net.Conn and tracks calls to SetDeadline.
type spyConn struct {
	net.Conn
	mu           sync.Mutex
	deadlines    []time.Time
	lastDeadline time.Time
}

func (s *spyConn) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.deadlines = append(s.deadlines, t)
	s.lastDeadline = t
	s.mu.Unlock()
	return s.Conn.SetDeadline(t)
}

func (s *spyConn) RemoteAddr() net.Addr {
	return fakeAddr{}
}

// recordingSink records details of AuthDenied and RateExceeded events.
type recordingSink struct {
	mu           sync.Mutex
	accepted     int
	deniedAddr   string
	deniedUser   string
	deniedFP     string
	deniedReason string
	rateAddr     string
	rateFP       string
	rateUntil    time.Time
}

func (s *recordingSink) AuthAccepted(addr, user, fp, subject string, role Role) {
	s.mu.Lock()
	s.accepted++
	s.mu.Unlock()
}

func (s *recordingSink) AuthDenied(addr, user, fp, reason string) {
	s.mu.Lock()
	s.deniedAddr = addr
	s.deniedUser = user
	s.deniedFP = fp
	s.deniedReason = reason
	s.mu.Unlock()
}

func (s *recordingSink) RateExceeded(addr, fp string, until time.Time) {
	s.mu.Lock()
	s.rateAddr = addr
	s.rateFP = fp
	s.rateUntil = until
	s.mu.Unlock()
}

// FINDING A-1: RecordSuccess wipes an address's unknown-key spray counter,
// letting an attacker with one valid key (or from a shared network/NAT)
// evade the brute-force rate limit indefinitely.
func TestFinding_A1_RecordSuccessResetsAddressSprayCounter(t *testing.T) {
	cfg := RateConfig{
		MaxKnownFailures:   10,
		MaxUnknownFailures: 10,
		Window:             5 * time.Minute,
		PairBanDuration:    15 * time.Minute,
		AddrBanDuration:    30 * time.Minute,
	}
	l, _ := NewRateLimiter(cfg, nil)
	defer l.Close() // IAMT-314: stop the A-3 sweeper goroutine
	addr := "203.0.113.10"

	// 9 failed attempts with unknown keys
	for i := 0; i < 9; i++ {
		l.RecordFailure(addr, fmt.Sprintf("fp-unknown-%d", i), false, t0)
	}

	// 1 successful login (say, the attacker holds one account, or a legitimate colleague signs in from the same NAT)
	l.RecordSuccess(addr, "fp-known", t0.Add(time.Second))

	// 2 more attempts with unknown keys: 11 failures in the 5-minute window in total
	l.RecordFailure(addr, "fp-unknown-9", false, t0.Add(2*time.Second))
	l.RecordFailure(addr, "fp-unknown-10", false, t0.Add(3*time.Second))

	// The address must now be banned (the threshold of 10 is exceeded). But delete(l.addrs, addr) wiped the history!
	d := l.Allow(addr, "fp-probe", t0.Add(4*time.Second))
	if d.Allow {
		t.Fatalf("FINDING A-1: address not banned after 11 spray attempts with an intervening success: Allow=%+v", d)
	}
}

// FINDING A-2: RecordSuccess deletes the entry from l.addrs and l.pairs even while a ban is active,
// lifting the ban early and directly violating PROTOCOL §1.4 ("successful authentication does not
// shorten an active ban").
//
// NOTE: two more A-2 tests follow below; they close a real gap in the
// defence — the PAIR ban. This test checks the ADDRESS ban, and after the
// A-1 fix it effectively asserts the same thing as the A-1 test (after
// the A-1 fix RecordSuccess no longer touches l.addrs at all). It is kept
// alive as an explicitly pinned intention: a successful login does not
// shorten a ban. Not a canary.
func TestFinding_A2_RecordSuccessCancelsActiveBan(t *testing.T) {
	cfg := RateConfig{
		MaxKnownFailures:   5,
		MaxUnknownFailures: 5,
		Window:             5 * time.Minute,
		PairBanDuration:    15 * time.Minute,
		AddrBanDuration:    30 * time.Minute,
	}
	l, _ := NewRateLimiter(cfg, nil)
	defer l.Close()
	addr := "198.51.100.5"

	// Exhaust the limit (5 failures) -> the address is banned for 30 minutes
	for i := 0; i < 5; i++ {
		l.RecordFailure(addr, fmt.Sprintf("fp-unknown-%d", i), false, t0)
	}
	if d := l.Allow(addr, "any", t0); !d.Banned {
		t.Fatalf("precondition failed: the address must be banned")
	}

	// Call RecordSuccess while the ban is active (say, from a parallel handshake)
	l.RecordSuccess(addr, "valid-fp", t0.Add(time.Minute))

	// PROTOCOL §1.4: "Successful authentication does not shorten an active ban."
	d := l.Allow(addr, "any", t0.Add(time.Minute))
	if !d.Banned {
		t.Fatalf("FINDING A-2: active address ban reset by a RecordSuccess call (PROTOCOL §1.4): Allow=%+v", d)
	}
}

// FINDING A-2 (pair ban): RecordSuccess while a PAIR ban is active
// (known=true, same addr and same fingerprint) must NOT lift that ban.
// The old A-2 test ended up exercising the address ban, and after the
// A-1 fix RecordSuccess no longer touches l.addrs at all — so the PAIR-ban
// defence had no guard. This test closes the real gap.
func TestFinding_A2_PairBanRecordSuccessKeepsBan(t *testing.T) {
	cfg := RateConfig{
		MaxKnownFailures:   5,
		MaxUnknownFailures: 5,
		Window:             5 * time.Minute,
		PairBanDuration:    15 * time.Minute,
		AddrBanDuration:    30 * time.Minute,
	}
	l, _ := NewRateLimiter(cfg, nil)
	defer l.Close()
	addr := "203.0.113.20"
	fp := "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// 5 failures with a known key (known=true) -> PAIR ban for PairBanDuration
	for i := 0; i < 5; i++ {
		d := l.RecordFailure(addr, fp, true, t0.Add(time.Duration(i)*time.Second))
		if i < 4 && !d.Allow {
			t.Fatalf("A-2 test setup error: intermediate failure %d was rejected: %+v", i+1, d)
		}
	}
	if d := l.Allow(addr, fp, t0); !d.Banned {
		t.Fatalf("A-2 test setup error: pair not banned after 5 failures: %+v", d)
	}

	// RecordSuccess while the PAIR ban is active.
	l.RecordSuccess(addr, fp, t0.Add(time.Minute))

	// PROTOCOL §1.4: successful authentication does not shorten an active ban.
	d := l.Allow(addr, fp, t0.Add(time.Minute))
	if !d.Banned {
		t.Fatalf("FINDING A-2: RecordSuccess lifted the active PAIR ban (PROTOCOL §1.4): Allow=%+v", d)
	}
}

// FINDING A-2 (pair ban, cleanup): RecordSuccess AFTER the ban has expired
// must delete the pair's entry. This is the second half of the same defence:
// the ban is held while it is active and cleaned up once it has expired. If
// the defence were written the other way around (always clean up), the first
// half would never fire; if the defence were "never touch it"
// (a forgotten cleanup), the l.pairs map would grow from every single
// failed attempt with a known key.
func TestFinding_A2_PairBanRecordSuccessCleansUpAfterExpiry(t *testing.T) {
	cfg := RateConfig{
		MaxKnownFailures:   5,
		MaxUnknownFailures: 5,
		Window:             5 * time.Minute,
		PairBanDuration:    15 * time.Minute,
		AddrBanDuration:    30 * time.Minute,
	}
	l, _ := NewRateLimiter(cfg, nil)
	defer l.Close()
	addr := "203.0.113.30"
	fp := "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// 5 failures -> PAIR ban until t0 + PairBanDuration.
	for i := 0; i < 5; i++ {
		l.RecordFailure(addr, fp, true, t0.Add(time.Duration(i)*time.Second))
	}

	// Time has moved past bannedTill.
	after := t0.Add(cfg.PairBanDuration + time.Minute)

	// RecordSuccess after the ban has expired must delete the entry.
	l.RecordSuccess(addr, fp, after)

	l.mu.Lock()
	_, exists := l.pairs[pairKey{addr, fp}]
	l.mu.Unlock()
	if exists {
		t.Fatalf("FINDING A-2: RecordSuccess after ban expiry did not clean up the pair entry: l.pairs[%q/%q] still exists", addr, fp)
	}
}

// FINDING A-3: unbounded memory growth in the RateLimiter: entries in l.addrs
// are never removed once their window has passed, causing a denial of service.
//
// The test does NOT call Allow on the accumulated addresses — it waits out the
// window and requires the background sweeper to clean the map on its own. The
// old version called Allow on each of the 200 addresses, and those Allow calls
// ran stateOf internally, which itself removed the entry for the very key the
// request came in on. In other words, the test was actively helping the
// implementation do what it is not obliged to do itself. There are no Allow
// calls now — cleaning up is the sweeper's job alone.
func TestFinding_A3_RateLimiterUnboundedMemoryLeak(t *testing.T) {
	// The smallest sane window, to keep the run fast.
	cfg := RateConfig{
		MaxKnownFailures:   10,
		MaxUnknownFailures: 10,
		Window:             100 * time.Millisecond,
		PairBanDuration:    200 * time.Millisecond,
		AddrBanDuration:    200 * time.Millisecond,
	}
	l, err := NewRateLimiter(cfg, nil)
	if err != nil {
		t.Fatalf("A-3 test setup error: NewRateLimiter: %v", err)
	}
	defer l.Close()

	// An attacker probes the gateway from 200 random IPs. Each failure is
	// stamped with the wall clock (the ticker runs on wall clock; the only
	// way to know the sweeper actually runs is to let it have wall clock).
	for i := 0; i < 200; i++ {
		l.RecordFailure(fmt.Sprintf("192.0.2.%d", i), "fp-fake", false, time.Now())
	}

	// Wait until the ticker has fired at least twice AFTER the last failure
	// fell out of the window. On the first tick (T≈Window) the entries are
	// still inside the window and are not cleaned; on the second (T≈2*Window)
	// they no longer are.
	//
	// IAMT-322: this used to be a single time.Sleep(5*Window) and a single
	// check — i.e. a bet that the sweeper goroutine would get scheduled at
	// least once in those 500ms. On a loaded machine that is a bet on the
	// scheduler: for the test to go red it took just one ~400ms stretch of
	// sweeper starvation while the test itself slept peacefully by the clock.
	// Now the map is polled (same data, no Allow calls — cleaning up is the
	// sweeper's job) up to an absolute deadline of 50 windows: entries are
	// removed all together, so "empty" is an irreversible state and the first
	// empty reading is honest. A healthy run empties on the second or third
	// tick; a broken sweeper (say, sweepLoop deleted) goes red
	// deterministically on every run — just at second 5 instead of 0.5. The
	// substantive claim of finding A-3 — "expired entries are removed by the
	// sweeper itself, no leak" — is not weakened; only the nominal bet "makes
	// it within 5 windows", which the finding never made, was dropped.
	//
	// Review fix (IAMT-322, second round): even 50 windows is still a nominal
	// bet on the scheduler, just ten times wider than before.
	// Below, that bet is taken out of play with a starvation witness: the
	// deadline rules nothing until the witness confirms the process had a
	// chance to earn the failure.
	// Review fix (IAMT-322, third round): the witness's baseline is taken
	// HERE, in the parent, before the go statement, and the deadline is
	// counted from the same point — one clock for both verdicts. Previously
	// last was initialised inside the goroutine, but go only guarantees the
	// closure will start running at some point: a process that slept right
	// after the go statement would set the baseline AFTER the starvation, the
	// witness would show a near-zero maxGap, and an honestly starved run
	// would fail the deadline even though the sweeper was innocent — the very
	// lie the witness exists to prevent, only moved into its own setup. By
	// Go's memory model, the parent's write before `go f()` happens-before
	// any code in f's body: the goroutine cannot observe last from any moment
	// later than when the parent decided to start observing, so a starvation
	// that happened before the goroutine was first scheduled still shows up
	// in its first time.Since(last). The deadline starting from the same
	// point is not an accident: the verdict window [deadline, verdict] must
	// lie inside the witness's window, otherwise a starvation wedged between
	// two time.Now() calls would eat the deadline budget while staying
	// invisible to the witness. After the go statement the parent no longer
	// touches last — this goroutine is its only writer, no locking needed.
	last := time.Now()
	deadline := last.Add(50 * cfg.Window)

	// The starvation witness uses the same race-free pattern that the IAMT-320
	// fix pinned down (TestIAMT304_OpenWaitIsBoundedByTheProbeBudget): every
	// goroutine wakeup contributes its own interval to maxGap — both the
	// timer firing and the stop signal with a final time.Since(last) reading —
	// so the largest starvation cannot be lost in the select race between a
	// closed witnessStop and a long-expired timer (Go picks randomly among
	// ready cases; without the final reading it is exactly the largest
	// starvation — the one the witness exists for — that would drop). The
	// threshold: a 25ms tick overstated 20x (500ms) — the drainStarvedGap
	// argument from the IAMT-316 fix, rescaled to this test's numbers. A
	// healthy run never sees gaps like that; the 100+ second process stalls
	// observed on the test VM give gaps orders of magnitude above it.
	const starvationGap = 500 * time.Millisecond
	witnessStop := make(chan struct{})
	witnessGaps := make(chan time.Duration, 1)
	go func() {
		const step = 25 * time.Millisecond
		var maxGap time.Duration
		for {
			select {
			case <-witnessStop:
				if gap := time.Since(last); gap > maxGap {
					maxGap = gap
				}
				witnessGaps <- maxGap
				return
			case <-time.After(step):
				now := time.Now()
				if gap := now.Sub(last); gap > maxGap {
					maxGap = gap
				}
				last = now
			}
		}
	}()
	var witnessOnce sync.Once
	var witnessMax time.Duration
	stopWitness := func() time.Duration {
		witnessOnce.Do(func() {
			close(witnessStop)
			witnessMax = <-witnessGaps
		})
		return witnessMax
	}
	t.Cleanup(func() { stopWitness() })

	for {
		l.mu.Lock()
		count := len(l.addrs)
		l.mu.Unlock()
		if count == 0 {
			break
		}
		if !time.Now().Before(deadline) {
			// The deadline has passed and the map is not empty. The verdict
			// is honest only if the sweeper had a real chance to earn it:
			// cross-check with the starvation witness.
			maxGap := stopWitness()
			if maxGap >= starvationGap {
				t.Logf("IAMT-322: within %v (50 windows) the sweeper did not clean the map (%d entries left), but this run is INVALID rather than failed: the starvation witness saw a scheduling gap of %v against a 25ms tick (20x the requested budget) — under a stall like that the sweeper may honestly never have received a single tick. Neither the leak nor the sweeper's health is proven by such a run; a healthy run empties on the second or third tick, and a broken sweeper on a machine that can keep time goes red right here — on every run, deterministically.", 50*cfg.Window, count, maxGap)
				return
			}
			t.Fatalf("FINDING A-3: RateLimiter memory leak: %d expired address entries not removed from the map within %v (50 windows) after the window passed — the sweeper did not clean the map (starvation witness: max scheduling gap %v against threshold %v, i.e. the process did get enough time)", count, 50*cfg.Window, maxGap, starvationGap)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// FINDING A-4: ParseUsername accepts the reserved names "machine", "enrol:win01",
// "bootstrap:win01", directly violating the PROTOCOL §2.1 grammar and the §2.2 refusal table.
func TestFinding_A4_ParseUsernameAcceptsReservedNames(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"reserved literal machine", "machine"},
		{"enrol with machine suffix", "enrol:win01"},
		{"bootstrap with machine suffix", "bootstrap:win01"},
		{"machine as human prefix", "machine:win01"},
	}

	for _, tc := range cases {
		got, err := ParseUsername(tc.in)
		if err == nil {
			t.Fatalf("FINDING A-4: ParseUsername(%q) wrongly accepted: %+v, expected a refusal per PROTOCOL §2.1/2.2", tc.in, got)
		}
	}
}

// FINDING A-5: one username "machine:win01" resolves to two different identities
// (a RolePerson named "machine" and a RoleMachine with ID "win01") because the reserved-name check is missing.
func TestFinding_A5_OneUsernameResolvesToTwoIdentities(t *testing.T) {
	alicePub, alicePriv, _ := ed25519.GenerateKey(rand.Reader)
	aliceSign, _ := ssh.NewSignerFromKey(alicePriv)
	alicePK, _ := ssh.NewPublicKey(alicePub)
	aliceFP := Fingerprint(alicePK)

	machPub, machPriv, _ := ed25519.GenerateKey(rand.Reader)
	machSign, _ := ssh.NewSignerFromKey(machPriv)
	machPK, _ := ssh.NewPublicKey(machPub)
	machFP := Fingerprint(machPK)

	lookup := NewMapLookup(map[string]Subject{
		aliceFP: {Name: "machine", Role: RolePerson},
		machFP:  {Name: "win01", Role: RoleMachine},
	})
	h, _ := NewHandler(lookup, AuthLimits{HandshakeTimeout: 5 * time.Second})

	// 1. The machine key authenticates as RoleMachine
	idMach, errMach := h.Resolve("machine:win01", machSign.PublicKey())
	if errMach != nil || idMach.Subject.Role != RoleMachine {
		t.Fatalf("machine authentication error: %v", errMach)
	}

	// 2. A person key named "machine" also authenticates successfully under the same username!
	idPerson, errPerson := h.Resolve("machine:win01", aliceSign.PublicKey())
	if errPerson == nil && idPerson.Subject.Role == RolePerson {
		t.Fatalf("FINDING A-5: username 'machine:win01' resolved to RolePerson (subject 'machine') even though 'machine' is a reserved machine-login prefix")
	}
}

// FINDING A-6: FinishAuth sets HandshakeDeadline via conn.SetDeadline but
// never clears it on a successful completion, so an established session is
// cut off by timeout after HandshakeTimeout seconds.
//
// The test brings up a live TCP connection (like the integration tests), not
// net.Pipe: only then does the handshake actually reach success, and the
// server side can see the last deadline set on the socket — exactly the one
// that outlives a live session. At t0 the handshake would fail BEFORE the
// first key is offered (auth.go:317 sets the deadline into the past), and
// the deadline assertion under test would never be reached.
func TestFinding_A6_FinishAuthLeavesSocketDeadline(t *testing.T) {
	w := newWorld(t)
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("A-6 test setup error: generating the host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("A-6 test setup error: creating the host signer: %v", err)
	}
	cfg := w.handler.ServerConfig(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("A-6 test setup error: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	var (
		spyMu       sync.Mutex
		spyDeadline time.Time
		spyReady    = make(chan struct{})
	)
	authDone := make(chan error, 1)
	go func() {
		raw, aerr := ln.Accept()
		if aerr != nil {
			authDone <- aerr
			return
		}
		spy := &spyConn{Conn: raw}
		sconn, _, ferr := w.handler.FinishAuth(spy, cfg, w.sink, time.Now())
		if sconn != nil {
			_ = sconn.Close()
		}
		spyMu.Lock()
		spyDeadline = spy.lastDeadline
		spyMu.Unlock()
		close(spyReady)
		authDone <- ferr
	}()

	clientCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(w.aliceSign)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, err := ssh.Dial("tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("A-6 test setup error: the client could not connect: %v", err)
	}
	defer conn.Close()

	select {
	case err := <-authDone:
		if err != nil {
			t.Fatalf("A-6 test setup error: FinishAuth returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("A-6 test setup error: handshake timeout")
	}
	<-spyReady

	// The deadline must be reset to time.Time{} (the zero time), otherwise the socket will die with an i/o timeout
	spyMu.Lock()
	last := spyDeadline
	spyMu.Unlock()

	if !last.IsZero() {
		t.Fatalf("FINDING A-6: FinishAuth did not reset the socket deadline after the successful handshake; last deadline = %v", last)
	}
}

// FINDING A-7: on a failed handshake FinishAuth calls sink.AuthDenied with empty
// user and fingerprint fields, violating the mandatory event fields of PROTOCOL §1.7 and making
// the gateway ignore the event entirely (invisible brute-forcing).
//
// The test brings up a live TCP connection and offers a deliberately unknown key:
// only then does the handshake reach PublicKeyCallback, and FinishAuth lands in
// the branch auth.go:369-376 (NOT auth.go:362-368), where every offered key
// must be recorded with its fingerprint and name. At t0 the handshake would fail
// BEFORE the first offered key and the assertion under test would never fire.
func TestFinding_A7_FinishAuthDeniedDropsFingerprintAndUser(t *testing.T) {
	w := newWorld(t)
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("A-7 test setup error: generating the host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("A-7 test setup error: creating the host signer: %v", err)
	}
	cfg := w.handler.ServerConfig(signer)

	sink := &recordingSink{}

	// Unknown key — a real ed25519 key not registered in the lookup.
	unknownPub, unknownPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("A-7 test setup error: generating the unknown key: %v", err)
	}
	unknownSign, err := ssh.NewSignerFromKey(unknownPriv)
	if err != nil {
		t.Fatalf("A-7 test setup error: creating the unknown signer: %v", err)
	}
	unknownPK, err := ssh.NewPublicKey(unknownPub)
	if err != nil {
		t.Fatalf("A-7 test setup error: creating the unknown pubkey: %v", err)
	}
	unknownFP := Fingerprint(unknownPK)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("A-7 test setup error: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	authDone := make(chan error, 1)
	go func() {
		raw, aerr := ln.Accept()
		if aerr != nil {
			authDone <- aerr
			return
		}
		_, _, ferr := w.handler.FinishAuth(raw, cfg, sink, time.Now())
		authDone <- ferr
	}()

	clientCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(unknownSign)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	if _, err := ssh.Dial("tcp", addr, clientCfg); err == nil {
		t.Fatal("A-7 test setup error: the unknown key was accepted")
	}

	select {
	case err := <-authDone:
		if err == nil {
			t.Fatal("A-7 test setup error: expected an authentication failure for the unknown key, but FinishAuth completed successfully")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("A-7 test setup error: handshake timeout")
	}

	sink.mu.Lock()
	fp := sink.deniedFP
	user := sink.deniedUser
	reason := sink.deniedReason
	sink.mu.Unlock()

	// PROTOCOL §1 (lines 22-23) and §1.7: fingerprint and address are mandatory for auth.failure
	if fp == "" || user == "" {
		t.Fatalf("FINDING A-7: FinishAuth called AuthDenied with an empty fingerprint %q and user %q on authentication failure (reason=%q)", fp, user, reason)
	}
	if fp != unknownFP {
		t.Fatalf("FINDING A-7: FinishAuth passed a wrong fingerprint to AuthDenied: fp=%q (expected %q)", fp, unknownFP)
	}
	if user != "alice" {
		t.Fatalf("FINDING A-7: FinishAuth passed a wrong username to AuthDenied: user=%q (expected alice)", user)
	}
}

// FINDING A-8 REFUTED by a direct check (13.09): the t.Skip was
// removed and the test PASSED — certificates are already rejected.
// *ssh.Certificate does not implement ssh.CryptoPublicKey, so AcceptKey
// refuses it on the very first check ("key offers no crypto payload to
// inspect"), exactly as the comment above the function intends. The patch
// suggested by the review would have added a second check of the same thing
// and only obscured the fact that the defence already exists.
//
// The test is not thrown away but kept alive as a guard: should anyone ever
// swap certificate parsing into AcceptKey or weaken the first check, this is
// where it goes red. The name was aligned with what it actually checks.
func TestAcceptKey_RefusesOpenSSHCertificates(t *testing.T) {

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	pubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("pubKey: %v", err)
	}

	cert := &ssh.Certificate{
		Key:             pubKey,
		CertType:        ssh.UserCert,
		KeyId:           "test-cert",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatalf("SignCert: %v", err)
	}

	// SPEC §6.1: "Public keys only; ed25519 by default, rsa >= 3072; no ecdsa-sha1/dsa."
	// Certificates are allowed by neither the protocol nor the spec.
	if err := AcceptKey(cert); err == nil {
		t.Fatalf("FINDING A-8: AcceptKey accepted an OpenSSH certificate of type %q instead of refusing it per SPEC §6.1", cert.Type())
	}
}

// FINDING A-9: RateLimiter.Allow wipes the address's failure counter while
// checking a non-banned address, returning Failures = 0 instead of the actual failure count.
func TestFinding_A9_AllowDiscardsAddressFailuresCount(t *testing.T) {
	cfg := RateConfig{
		MaxKnownFailures:   10,
		MaxUnknownFailures: 10,
		Window:             5 * time.Minute,
		PairBanDuration:    15 * time.Minute,
		AddrBanDuration:    30 * time.Minute,
	}
	l, _ := NewRateLimiter(cfg, nil)
	defer l.Close() // IAMT-314: stop the A-3 sweeper goroutine
	addr := "192.0.2.99"

	// 8 failed attempts with unknown keys
	for i := 0; i < 8; i++ {
		l.RecordFailure(addr, fmt.Sprintf("fp-%d", i), false, t0)
	}

	// Allow for a new unknown key from the same address
	d := l.Allow(addr, "fresh-unknown-fp", t0)
	if d.Failures != 8 {
		t.Fatalf("FINDING A-9: Allow reported Failures = %d, expected 8", d.Failures)
	}
}
