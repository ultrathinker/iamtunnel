package server

import (
	"errors"
	"testing"
	"time"
)

var errR153AuthRefused = errors.New("dial gateway: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")

func r153Config() Config {
	return Config{
		BackoffBase: time.Second, BackoffMax: 30 * time.Second,
		AuthBackoffBase: 30 * time.Second, AuthBackoffMax: 5 * time.Minute,
	}
}

// A machine the gateway no longer knows must not knock every 30 seconds:
// the gateway blocks the whole address after more than ten refusals in
// five minutes, and that block also stops the machine's new registration
// (16.10.2026). Held to the gateway's own threshold: in the first
// five minutes the agent may try only a few times.
func TestR153_ARefusedKeyIsRetriedSlowly(t *testing.T) {
	cfg := r153Config()
	delay := cfg.BackoffBase
	var at time.Duration
	attempts := 1 // the first dial
	for attempts < 50 {
		var wait time.Duration
		wait, delay = nextRetry(cfg, errR153AuthRefused, delay)
		at += wait
		if at > 5*time.Minute {
			break
		}
		attempts++
	}
	if attempts > 5 {
		t.Fatalf("%d attempts with a refused key in the first five minutes; the gateway blocks the address after more than ten, so this is the storm that blocked it", attempts)
	}
	if delay > cfg.AuthBackoffMax*13/10 {
		t.Fatalf("the delay grew to %s, past the cap of %s", delay, cfg.AuthBackoffMax)
	}
}

// An ordinary failure - an outage, a timeout - keeps the short backoff:
// the slow pause is for a refusal of the key only.
func TestR153_AnOutageKeepsTheShortBackoff(t *testing.T) {
	cfg := r153Config()
	wait, next := nextRetry(cfg, errors.New("dial tcp 192.0.2.10:2027: i/o timeout"), cfg.BackoffBase)
	if wait != cfg.BackoffBase {
		t.Fatalf("an outage waited %s, want the base %s", wait, cfg.BackoffBase)
	}
	if next > cfg.BackoffMax*13/10 {
		t.Fatalf("the next delay %s is past the outage cap %s", next, cfg.BackoffMax)
	}
	if isAuthRefusal(errors.New("connection refused")) || isAuthRefusal(nil) {
		t.Fatal("a refused connection or nil counted as a refused key")
	}
}
