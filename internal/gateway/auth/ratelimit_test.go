package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var t0 = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

// auditRate builds the limiter with the numbers the audit fix settled
// on: known keys 10 per pair, unknown keys 50 per address, 5 min
// window, 15/30 min bans.
func auditRate(t *testing.T) (*RateLimiter, *countingSink) {
	t.Helper()
	sink := &countingSink{}
	l, err := NewRateLimiter(RateConfig{
		MaxKnownFailures:   10,
		MaxUnknownFailures: 50,
		Window:             5 * time.Minute,
		PairBanDuration:    15 * time.Minute,
		AddrBanDuration:    30 * time.Minute,
	}, sink)
	if err != nil {
		t.Fatalf("NewRateLimiter: %v", err)
	}
	// IAMT-314: NewRateLimiter starts the A-3 sweeper goroutine; Close is
	// the only thing that stops it. Without this the sweeper of every
	// limiter this helper ever built is still running when the package
	// ends, which is precisely what goleak_test.go now refuses.
	t.Cleanup(l.Close)
	return l, sink
}

// freshFingerprints mints n real ed25519 keys and returns their
// fingerprints - a fresh key per attempt, exactly like the attack.
func freshFingerprints(t *testing.T, n int) []string {
	t.Helper()
	fps := make([]string, n)
	for i := 0; i < n; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
		pk, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("pubkey %d: %v", i, err)
		}
		fps[i] = Fingerprint(pk)
	}
	return fps
}

// gate 1 fix, attack test: 100 attempts with 100 fresh keys from one
// address must be stopped. (Before the fix this test was green with the
// protection fully disabled - the spray slid under the per-pair
// counter.)
func TestRateLimitStopsKeySpray(t *testing.T) {
	l, sink := auditRate(t)
	fps := freshFingerprints(t, 100)

	stoppedAt := -1
	for i, fp := range fps {
		d := l.RecordFailure("203.0.113.7", fp, false, t0)
		if !d.Allow {
			stoppedAt = i + 1
			break
		}
	}
	if stoppedAt != 50 {
		t.Fatalf("spray stopped at attempt %d, want 50 (MaxUnknownFailures)", stoppedAt)
	}
	// Every further attempt from that address is refused, on any key.
	for i := 50; i < 100; i++ {
		if d := l.RecordFailure("203.0.113.7", fps[i], false, t0); d.Allow {
			t.Fatalf("attempt %d allowed while the address is banned", i+1)
		}
	}
	d := l.Allow("203.0.113.7", "whatever-key", t0)
	if d.Allow || !d.PerAddress {
		t.Fatalf("Allow after spray = %+v, want a per-address refusal", d)
	}
	if !d.Until.Equal(t0.Add(30 * time.Minute)) {
		t.Fatalf("address ban until = %v, want %v", d.Until, t0.Add(30*time.Minute))
	}
	if sink.rateExceeded != 1 {
		t.Fatalf("RateExceeded emitted %d times, want 1", sink.rateExceeded)
	}
}

// gate 1 fix, office test: two people behind one address; one mangles
// their key ten times (ten UNKNOWN fingerprints - keys the gateway does
// not know), the other logs in fine. Neither is locked out.
func TestRateLimitOfficeNotLocked(t *testing.T) {
	l, _ := auditRate(t)
	fps := freshFingerprints(t, 10)
	for i, fp := range fps {
		if d := l.RecordFailure("198.51.100.9", fp, false, t0); !d.Allow {
			t.Fatalf("failure %d: unexpected ban: %+v", i+1, d)
		}
	}
	// Ten unknown keys is far below the address threshold of 50, so the
	// second person walks right in.
	d := l.Allow("198.51.100.9", "second-person-key", t0)
	if !d.Allow {
		t.Fatalf("office locked out by one person's key confusion: %+v", d)
	}
	// A successful login from the same address does NOT clear the address
	// spray counter (A-1 fix: prevents laundering).
	l.RecordSuccess("198.51.100.9", "second-person-key", t0)
	d = l.RecordFailure("198.51.100.9", freshFingerprints(t, 1)[0], false, t0)
	if d.Failures != 11 {
		t.Fatalf("address counter after success = %d, want 11", d.Failures)
	}
}

// The two scales are independent: known-key failures do not move the
// address counter, unknown-key failures do not touch any pair.
func TestRateLimitKnownAndUnknownScalesIndependent(t *testing.T) {
	l, _ := auditRate(t)
	// Ten known-key failures hit the pair, not the address...
	for i := 0; i < 10; i++ {
		l.RecordFailure("203.0.113.7", "fp-known", true, t0)
	}
	if d := l.Allow("203.0.113.7", "fp-known", t0); !d.Banned {
		t.Fatalf("known pair after 10 failures: %+v, want banned", d)
	}
	// ...and the address scale is untouched by them.
	if d := l.Allow("203.0.113.7", "fp-other", t0); !d.Allow {
		t.Fatalf("address banned by known-key failures: %+v", d)
	}
	// And forty-nine unknown offers do not ban any pair.
	fps := freshFingerprints(t, 49)
	for i, fp := range fps {
		l.RecordFailure("198.51.100.9", fp, false, t0)
		_ = i
	}
	if d := l.Allow("198.51.100.9", "fp-someone", t0); !d.Allow {
		t.Fatalf("pair banned by unknown-key spray: %+v", d)
	}
}

func TestRateLimitPairBanDuration(t *testing.T) {
	l, sink := auditRate(t)
	for i := 0; i < 10; i++ {
		l.RecordFailure("203.0.113.7", "fp-known", true, t0)
	}
	d := l.Allow("203.0.113.7", "fp-known", t0)
	if !d.Banned || d.PerAddress {
		t.Fatalf("pair after threshold: %+v", d)
	}
	if !d.Until.Equal(t0.Add(15 * time.Minute)) {
		t.Fatalf("pair ban until = %v, want %v", d.Until, t0.Add(15*time.Minute))
	}
	if sink.rateExceeded != 1 {
		t.Fatalf("RateExceeded emitted %d times, want 1", sink.rateExceeded)
	}
}

func TestRateLimitBanExpires(t *testing.T) {
	l, _ := auditRate(t)
	for i := 0; i < 10; i++ {
		l.RecordFailure("a", "f", true, t0)
	}
	d := l.Allow("a", "f", t0)
	if !d.Banned {
		t.Fatal("threshold not reached")
	}
	// Still inside the ban.
	if d := l.Allow("a", "f", d.Until.Add(-time.Second)); d.Allow {
		t.Fatal("allowed one second before the ban ends")
	}
	// The ban has expired.
	if d := l.Allow("a", "f", d.Until); !d.Allow {
		t.Fatalf("still banned after expiry: %+v", d)
	}
	// And the pair's counter starts over.
	d = l.RecordFailure("a", "f", true, d.Until)
	if !d.Allow || d.Failures != 1 {
		t.Fatalf("after expiry: %+v, want a clean single failure", d)
	}
}

func TestRateLimitWindowSlides(t *testing.T) {
	l, _ := auditRate(t)
	// Two failures at the very start of the 5-minute window...
	l.RecordFailure("a", "f", true, t0)
	l.RecordFailure("a", "f", true, t0.Add(time.Second))
	// ...aging out by the time the third one arrives past the window.
	later := t0.Add(6 * time.Minute)
	d := l.RecordFailure("a", "f", true, later)
	if !d.Allow {
		t.Fatalf("old failures still counted after the window: %+v", d)
	}
	if d.Failures != 1 {
		t.Fatalf("live failures = %d, want 1 (the fresh one)", d.Failures)
	}
}

func TestRateLimitSuccessResets(t *testing.T) {
	l, _ := auditRate(t)
	l.RecordFailure("a", "f", true, t0)
	l.RecordFailure("a", "f", true, t0)
	l.RecordSuccess("a", "f", t0)
	d := l.RecordFailure("a", "f", true, t0)
	if !d.Allow || d.Failures != 1 {
		t.Fatalf("after success: %+v, want one fresh failure", d)
	}
}

func TestNewRateLimiterRejectsBadConfig(t *testing.T) {
	// The six invalid configs below start nothing: NewRateLimiter validates
	// before "go l.sweepLoop()" (ratelimit.go:102), so a rejected config
	// leaves no goroutine to close. The accepted one at the end of this
	// function does - see the comment there.
	for i, cfg := range []RateConfig{
		{MaxKnownFailures: 0, MaxUnknownFailures: 50, Window: time.Minute, PairBanDuration: time.Minute, AddrBanDuration: time.Minute},
		{MaxKnownFailures: -1, MaxUnknownFailures: 50, Window: time.Minute, PairBanDuration: time.Minute, AddrBanDuration: time.Minute},
		{MaxKnownFailures: 10, MaxUnknownFailures: 0, Window: time.Minute, PairBanDuration: time.Minute, AddrBanDuration: time.Minute},
		{MaxKnownFailures: 10, MaxUnknownFailures: 50, Window: 0, PairBanDuration: time.Minute, AddrBanDuration: time.Minute},
		{MaxKnownFailures: 10, MaxUnknownFailures: 50, Window: time.Minute, PairBanDuration: 0, AddrBanDuration: time.Minute},
		{MaxKnownFailures: 10, MaxUnknownFailures: 50, Window: time.Minute, PairBanDuration: time.Minute, AddrBanDuration: 0},
	} {
		if _, err := NewRateLimiter(cfg, nil); err == nil {
			t.Errorf("case %d: NewRateLimiter(%+v): no error", i, cfg)
		}
	}
	l, err := NewRateLimiter(RateConfig{
		MaxKnownFailures: 10, MaxUnknownFailures: 50, Window: time.Minute,
		PairBanDuration: time.Minute, AddrBanDuration: time.Minute,
	}, nil)
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	// IAMT-314: this limiter is real. A valid config means NewRateLimiter
	// has already started the A-3 sweeper, and the result used to go into
	// "_", so nothing ever called Close: the sweeper was still parked in
	// its select when goleak photographed the end of this package. Binding
	// it and closing it is the whole fix - Close itself is correct (it
	// closes sweepStop under the mutex and then waits on sweepDone, which
	// sweepLoop closes on its way out), and every other limiter in this
	// package was already being closed.
	t.Cleanup(l.Close)
}
