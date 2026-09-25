package auth

import (
	"fmt"
	"sync"
	"time"
)

// RateConfig parameterises the failure limiter (SPEC 6.1) on TWO scales,
// because two different things can go wrong with an offered key:
//
//   - A KNOWN key (the gateway has the fingerprint registered) fails:
//     this is usually a person who mixed up their keys. Counted per
//     (addr, fingerprint) pair with a low threshold - the fingerprint
//     half keeps an office behind one NAT address from being locked out
//     because one member misconfigured their agent.
//   - An UNKNOWN key is offered: no person is behind it, this is key
//     spray. Counting per pair is useless here - the attacker mints a
//     fresh key per attempt, so the pair never repeats. Counted per
//     ADDRESS with a much higher threshold instead.
//
// All values are parameters; time is always injected.
type RateConfig struct {
	// MaxKnownFailures caps failed authentications of one (addr,
	// fingerprint) pair inside Window before that pair is banned.
	MaxKnownFailures int
	// MaxUnknownFailures caps offers of unknown fingerprints from one
	// address inside Window before the whole address is banned.
	MaxUnknownFailures int
	// Window is the sliding window both counters live in.
	Window time.Duration
	// PairBanDuration is how long a (addr, fingerprint) pair stays
	// banned once its known-key threshold trips.
	PairBanDuration time.Duration
	// AddrBanDuration is how long an address stays banned once its
	// unknown-key threshold trips.
	AddrBanDuration time.Duration
}

// RateDecision is the verdict for one authentication attempt right now.
type RateDecision struct {
	Allow      bool
	Banned     bool      // true when the attempt is refused by a ban
	Until      time.Time // end of the current ban, valid when Banned
	Failures   int       // failures counted on the deciding scale
	PerAddress bool      // true when the deciding scale is the address (unknown keys)
}

type pairKey struct{ addr, fingerprint string }

type failState struct {
	failures   []time.Time // timestamps inside the window
	bannedTill time.Time
}

// RateLimiter counts failed authentications - known keys per
// (addr, fingerprint) pair, unknown keys per address - and bans the
// offending scale when a threshold trips. It is a stateful collaborator
// called by the gateway's connection manager: Allow before the
// handshake, RecordFailure after a failed one, RecordSuccess after a
// successful one. It is deliberately NOT part of the pure
// PublicKeyCallback, which must stay free of side effects (SPEC 6.1).
//
// A background sweeper runs once per Window and evicts entries whose
// last failure fell out of the window. Without it, an address that
// sprays and goes silent would stay in l.addrs until the process exits
// - that was the A-3 leak, and A-3's chosen fix is the sweeper. Close
// stops it; without Close the goroutine lives for the lifetime of the
// process, which is acceptable for the single RateLimiter owned by the
// gateway.
type RateLimiter struct {
	cfg  RateConfig
	sink EventSink

	mu    sync.Mutex
	pairs map[pairKey]*failState // known keys: per (addr, fingerprint)
	addrs map[string]*failState  // unknown keys: per address

	sweepStop chan struct{}
	sweepDone chan struct{}
}

// NewRateLimiter validates the config; sink may be nil (no events).
func NewRateLimiter(cfg RateConfig, sink EventSink) (*RateLimiter, error) {
	if cfg.MaxKnownFailures <= 0 {
		return nil, fmt.Errorf("auth: rate limit MaxKnownFailures must be positive")
	}
	if cfg.MaxUnknownFailures <= 0 {
		return nil, fmt.Errorf("auth: rate limit MaxUnknownFailures must be positive")
	}
	if cfg.Window <= 0 || cfg.PairBanDuration <= 0 || cfg.AddrBanDuration <= 0 {
		return nil, fmt.Errorf("auth: rate limit Window and ban durations must be positive")
	}
	l := &RateLimiter{
		cfg:       cfg,
		sink:      sink,
		pairs:     make(map[pairKey]*failState),
		addrs:     make(map[string]*failState),
		sweepStop: make(chan struct{}),
		sweepDone: make(chan struct{}),
	}
	go l.sweepLoop()
	return l, nil
}

// Close stops the background sweeper. Idempotent and safe to call
// multiple times. gateway.Gateway.Close calls this on shutdown
// (IAMT-304 round 6): a real production process has exactly one
// RateLimiter for its whole life and would never notice a missing
// Close, but a test that builds and discards many Gateways in one
// process leaks one sweepLoop goroutine per fixture without it - a
// goroutine dump from a live flake found several hundred of them
// still parked in select, accumulated scheduler and GC bookkeeping
// that starved whatever ran after them.
func (l *RateLimiter) Close() {
	l.mu.Lock()
	select {
	case <-l.sweepStop:
		l.mu.Unlock()
		return
	default:
		close(l.sweepStop)
	}
	l.mu.Unlock()
	<-l.sweepDone
}

// sweepLoop is the background timer for the A-3 fix. It fires once per
// Window and drops every entry whose last failure fell out of the
// window and that is not currently banned. Without this goroutine an
// address that fails once and goes silent stays in l.addrs until the
// process exits, which is the OOM the A-3 finding called out.
func (l *RateLimiter) sweepLoop() {
	defer close(l.sweepDone)
	ticker := time.NewTicker(l.cfg.Window)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			l.sweepExpiredLocked(time.Now())
			l.mu.Unlock()
		case <-l.sweepStop:
			return
		}
	}
}

// Allow reports whether this address (and, for a known key, this pair)
// may attempt authentication now. An address ban silences everything
// from that address; a pair ban silences only that pair.
func (l *RateLimiter) Allow(addr, fingerprint string, now time.Time) RateDecision {
	l.mu.Lock()
	defer l.mu.Unlock()
	dAddr := stateOf(l.addrs, addr, l.cfg.Window, now)
	if dAddr.Banned {
		return RateDecision{Allow: false, Banned: true, Until: dAddr.Until, Failures: dAddr.Failures, PerAddress: true}
	}
	dPair := stateOf(l.pairs, pairKey{addr, fingerprint}, l.cfg.Window, now)
	if dPair.Banned {
		return RateDecision{Allow: false, Banned: true, Until: dPair.Until, Failures: dPair.Failures}
	}
	if dPair.Failures > 0 {
		return RateDecision{Allow: true, Failures: dPair.Failures}
	}
	if dAddr.Failures > 0 {
		return RateDecision{Allow: true, Failures: dAddr.Failures, PerAddress: true}
	}
	return RateDecision{Allow: true}
}

// RecordFailure counts one failed authentication. known tells which
// scale the failure belongs to: a known fingerprint counts against its
// (addr, fingerprint) pair; an unknown one against the whole address.
// When the threshold trips, the scale is banned until now+duration and
// exactly one RateExceeded event is emitted. Failures recorded while
// already banned neither extend the ban nor re-emit the event.
func (l *RateLimiter) RecordFailure(addr, fingerprint string, known bool, now time.Time) RateDecision {
	l.mu.Lock()
	var (
		st      *failState
		maxF    int
		banDur  time.Duration
		perAddr bool
	)
	if known {
		k := pairKey{addr, fingerprint}
		st = l.pairs[k]
		if st == nil {
			st = &failState{}
			l.pairs[k] = st
		}
		maxF, banDur = l.cfg.MaxKnownFailures, l.cfg.PairBanDuration
	} else {
		st = l.addrs[addr]
		if st == nil {
			st = &failState{}
			l.addrs[addr] = st
		}
		maxF, banDur = l.cfg.MaxUnknownFailures, l.cfg.AddrBanDuration
		perAddr = true
	}
	if now.Before(st.bannedTill) {
		d := RateDecision{Allow: false, Banned: true, Until: st.bannedTill, Failures: l.liveLocked(st, now), PerAddress: perAddr}
		l.mu.Unlock()
		return d
	}
	st.failures = append(st.failures, now)
	n := l.liveLocked(st, now)
	if n >= maxF {
		st.bannedTill = now.Add(banDur)
		st.failures = nil
		d := RateDecision{Allow: false, Banned: true, Until: st.bannedTill, PerAddress: perAddr}
		sink, until := l.sink, st.bannedTill
		l.mu.Unlock()
		if sink != nil {
			sink.RateExceeded(addr, fingerprint, until)
		}
		return d
	}
	d := RateDecision{Allow: true, Failures: n, PerAddress: perAddr}
	l.mu.Unlock()
	return d
}

// RecordSuccess clears the pair's history if not banned: an authentication
// that succeeded with a known key clears that pair's failure counter.
// Per PROTOCOL §1.4, successful authentication never reduces an active ban,
// and it never clears the address's unknown-key spray counter (A-1, A-2).
func (l *RateLimiter) RecordSuccess(addr, fingerprint string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := pairKey{addr, fingerprint}
	if st, ok := l.pairs[k]; ok {
		if !now.Before(st.bannedTill) {
			delete(l.pairs, k)
		}
	}
}

// stateOf returns the current view of one counter, dropping failures
// that fell out of the window, and evicts expired unbanned entries.
func stateOf[K comparable](m map[K]*failState, k K, window time.Duration, now time.Time) RateDecision {
	st, ok := m[k]
	if !ok {
		return RateDecision{Allow: true}
	}
	n := liveIn(st, window, now)
	if now.Before(st.bannedTill) {
		return RateDecision{Allow: false, Banned: true, Until: st.bannedTill, Failures: n}
	}
	if n == 0 {
		delete(m, k)
		return RateDecision{Allow: true}
	}
	return RateDecision{Allow: true, Failures: n}
}

func (l *RateLimiter) sweepExpiredLocked(now time.Time) {
	for k, st := range l.addrs {
		if !now.Before(st.bannedTill) && liveIn(st, l.cfg.Window, now) == 0 {
			delete(l.addrs, k)
		}
	}
	for k, st := range l.pairs {
		if !now.Before(st.bannedTill) && liveIn(st, l.cfg.Window, now) == 0 {
			delete(l.pairs, k)
		}
	}
}

// liveLocked drops failures that fell out of the window and returns how
// many are still counted.
func (l *RateLimiter) liveLocked(st *failState, now time.Time) int {
	return liveIn(st, l.cfg.Window, now)
}

func liveIn(st *failState, window time.Duration, now time.Time) int {
	cutoff := now.Add(-window)
	live := st.failures[:0]
	for _, t := range st.failures {
		if t.After(cutoff) {
			live = append(live, t)
		}
	}
	st.failures = live
	return len(live)
}
