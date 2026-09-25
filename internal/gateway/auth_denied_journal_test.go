package gateway

// auth_denied_journal_test.go covers IAMT-118:
// Every attempt to authenticate with an unknown key must be recorded in events.jsonl
// with its address, fingerprint, actor and reason. Slow brute-force attacks must
// not be invisible in the journal.
//
// Since R4 F-11 the refusals fold the way IAMT-452 folds successes: the same
// host and refusal kind inside one quiet period is one line, the rest counted
// until the period ends. A slow brute force - the attack IAMT-118 is about -
// spaces its attempts past the quiet period and so still earns one line per
// attempt; a spray inside the period earns one line plus the count, which is
// the record a person reads afterwards.

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestAuthDenied_UnknownKeyRecordedInJournal(t *testing.T) {
	f := newFixture(t, nil)

	unknownKey := genSigner(t)
	unknownFP := fingerprintOf(t, unknownKey.PublicKey())

	cfg := &ssh.ClientConfig{
		User:            "attacker",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(unknownKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// Dial with the unknown key: handshake MUST fail.
	client, err := ssh.Dial("tcp", f.addr, cfg)
	if err == nil {
		client.Close()
		t.Fatal("dial with unknown key unexpectedly succeeded")
	}

	waitUntil(t, "journal did not record auth.failure event", func() bool {
		evs, _, rerr := f.log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
		if rerr != nil {
			return false
		}
		return len(evs) >= 1
	})

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
	if err != nil {
		t.Fatalf("failed reading journal: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected exactly 1 auth.failure event in journal, got %d", len(evs))
	}

	e := evs[0]
	if e.Fingerprint != unknownFP {
		t.Fatalf("journal auth.failure fingerprint = %q, want %q", e.Fingerprint, unknownFP)
	}
	if !strings.Contains(e.Address, "127.0.0.1") {
		t.Fatalf("journal auth.failure address = %q, want loopback address", e.Address)
	}
	if !strings.Contains(e.Result, "auth: unknown key") {
		t.Fatalf("journal auth.failure result = %q, want containing 'auth: unknown key'", e.Result)
	}
	if e.Actor != "attacker" {
		t.Fatalf("journal auth.failure actor = %q, want %q", e.Actor, "attacker")
	}
	if e.Object != "attacker" {
		t.Fatalf("journal auth.failure object = %q, want %q", e.Object, "attacker")
	}
}

// Two keys from one host inside one quiet period: the fold writes one line
// while the period lasts - the first attempt's - and the count of the rest
// arrives when it ends. Neither attempt is lost: the first is the line, the
// second is the summary's repeat, naming the last attempt's key. (Before
// R4 F-11 this test demanded one line per key, which was the flood's write
// path into the journal; the slow-brute-force guarantee above is unchanged,
// and TestF11_PostBanKeySprayIsOneLinePerKind pins the fold's buckets.)
func TestAuthDenied_MultipleUnknownKeysAllRecordedInJournal(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.AuthSuccessQuiet = time.Minute })

	k1 := genSigner(t)
	fp1 := fingerprintOf(t, k1.PublicKey())
	k2 := genSigner(t)
	fp2 := fingerprintOf(t, k2.PublicKey())

	cfg := &ssh.ClientConfig{
		User:            "attacker2",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(k1, k2)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", f.addr, cfg)
	if err == nil {
		client.Close()
		t.Fatal("dial with unknown keys unexpectedly succeeded")
	}

	// Inside the period: one line, the first offered key's.
	waitUntil(t, "journal did not record the folded auth.failure line", func() bool {
		evs, _, rerr := f.log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
		return rerr == nil && len(evs) == 1
	})

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
	if err != nil {
		t.Fatalf("failed reading journal: %v", err)
	}
	first := evs[0]
	if first.Fingerprint != fp1 {
		t.Fatalf("folded line fingerprint = %q, want the first offered key's %q", first.Fingerprint, fp1)
	}
	if !strings.Contains(first.Address, "127.0.0.1") {
		t.Fatalf("folded line address = %q, want loopback address", first.Address)
	}
	if !strings.Contains(first.Result, "auth: unknown key") {
		t.Fatalf("folded line result = %q, want containing 'auth: unknown key'", first.Result)
	}
	if first.Actor != "attacker2" || first.Object != "attacker2" {
		t.Fatalf("folded line actor/object = %q/%q, want 'attacker2' twice", first.Actor, first.Object)
	}

	// When the period ends, the sweep writes the count: the second key is
	// the repeat the summary names.
	f.clock.Advance(2 * time.Minute)
	waitUntil(t, "the quiet period's count never arrived in the journal", func() bool {
		evs, _, rerr := f.log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
		return rerr == nil && len(evs) == 2
	})
	evs, _, err = f.log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
	if err != nil {
		t.Fatalf("failed reading journal: %v", err)
	}
	summary := evs[1]
	if summary.Fingerprint != fp2 {
		t.Fatalf("summary fingerprint = %q, want the last offered key's %q", summary.Fingerprint, fp2)
	}
	if n, _ := summary.Details["repeats"].(float64); n != 1 {
		t.Fatalf("summary repeats = %v, want 1 (one attempt after the folded line)", summary.Details["repeats"])
	}
	if !strings.Contains(summary.Result, "auth: unknown key") {
		t.Fatalf("summary result = %q, want containing 'auth: unknown key'", summary.Result)
	}
	if summary.Actor != "attacker2" {
		t.Fatalf("summary actor = %q, want 'attacker2'", summary.Actor)
	}
}
