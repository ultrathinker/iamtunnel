package gateway

// R4 F-11 (review, 24.09.2026): every TCP connect and every offered
// key from an unauthenticated peer cost the journal one line - file lock,
// tail read, write, fsync - and nothing aggregated them. The port is on
// the internet by design; `while true; do nc gw 2222 </dev/null; done`
// filled the disk with auth.handshake_failure, one per connect, and
// `ssh -i k1 … -i k32` after a ban wrote one auth.failure per offered key,
// rate limiter or no. When the journal then refused to grow, IAMT-451
// refused every session and every mutating command for EVERYONE. The
// rotated archives were never cleaned at all, so the disk filled stayed
// filled.
//
// The fix folds refused attempts the way IAMT-452 folds successes: the
// same host and refusal kind within the quiet period is one line now,
// the rest counted, and the count is written when the period ends. A
// slow brute force still gets a line per attempt - each lands outside
// the quiet period - and a flood gets one line per period plus the
// count, which is the fact a person reads afterwards.

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// f11RefusedDial opens one connection offering every key in turn - the
// shape `ssh -i k1 … -i k32` produces - and requires the handshake to fail.
func f11RefusedDial(t *testing.T, addr, user string, signers ...ssh.Signer) {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		_ = client.Close()
		t.Fatalf("dial as %q with %d unknown key(s) unexpectedly succeeded", user, len(signers))
	}
}

// f11AuthFailures reads every auth.failure line in the journal and
// archives, including the current one.
func f11AuthFailures(t *testing.T, f *fixture) []events.Event {
	t.Helper()
	evs, _, err := events.ReadHistory(filepath.Dir(f.logPath), events.Filter{Types: []events.EventType{events.EventAuthFailure}})
	if err != nil {
		t.Fatalf("read the auth.failure journal: %v", err)
	}
	return evs
}

func f11CountContaining(evs []events.Event, substr string) int {
	n := 0
	for _, e := range evs {
		if strings.Contains(e.Result, substr) {
			n++
		}
	}
	return n
}

func TestF11_RefusedKeysFromOneHostAreOneLinePerQuietWindow(t *testing.T) {
	f := newFixture(t, nil)

	// Five keys, one connection, one host, seconds apart: before the fold
	// this wrote five auth.failure lines, five locks, five fsyncs - and a
	// loop over the pattern never stopped. After it, the quiet period holds
	// one line and the count of the rest; a slower sweep (one key per quiet
	// period) would still get a line per attempt, which is the property
	// IAMT-118 promised for slow brute force.
	keys := make([]ssh.Signer, 5)
	for i := range keys {
		keys[i] = genSigner(t)
	}
	f11RefusedDial(t, f.addr, "anybody", keys...)

	var evs []events.Event
	waitUntil(t, "F-11: the five refused keys did not fold into one line", func() bool {
		got := f11AuthFailures(t, f)
		if len(got) == 1 {
			evs = got
			return true
		}
		return false
	})
	first := evs[0]
	if first.Fingerprint != fingerprintOf(t, keys[0].PublicKey()) {
		t.Fatalf("the folded line's fingerprint = %q, want the first offered key's", first.Fingerprint)
	}
	if first.Actor != "anybody" || first.Object != "anybody" {
		t.Fatalf("the folded line's actor/object = %q/%q, want the offered login twice", first.Actor, first.Object)
	}
	if !strings.Contains(first.Result, "auth: unknown key") {
		t.Fatalf("the folded line's result = %q, want the unknown-key refusal", first.Result)
	}
}

func TestF11_PostBanKeySprayIsOneLinePerKind(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		// A two-failure ban so the test crosses it in two keys; the ban
		// itself outlasts the test, as a production ban outlasts a flood.
		cfg.RateConfig = auth.RateConfig{
			MaxKnownFailures:   2,
			MaxUnknownFailures: 2,
			Window:             time.Minute,
			PairBanDuration:    time.Minute,
			AddrBanDuration:    15 * time.Minute,
		}
	})

	// Connection one: two unknown keys. The second trips the address ban -
	// exactly one RateExceeded line says so - and both refusals are the
	// plain unknown-key kind.
	k1, k2 := genSigner(t), genSigner(t)
	f11RefusedDial(t, f.addr, "spray", k1, k2)

	// Connection two, banned address: six more keys, every one of them
	// refused by the limiter before any lookup. Before the fold each of
	// the six wrote its own "rate limited" auth.failure - the rate limiter
	// decides whether a key is tried, not whether a line is written, and
	// this is the loop that never stopped. After the fold: one line.
	keys := make([]ssh.Signer, 6)
	for i := range keys {
		keys[i] = genSigner(t)
	}
	f11RefusedDial(t, f.addr, "spray", keys...)

	waitUntil(t, "F-11: the post-ban spray did not fold into one line per kind", func() bool {
		evs := f11AuthFailures(t, f)
		return f11CountContaining(evs, "auth: unknown key") == 1 &&
			f11CountContaining(evs, "rate limited") == 2 // the spray line, plus the ban's own RateExceeded line
	})
}

func TestF11_HandshakeFloodIsOneLine(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.AuthSuccessQuiet = time.Minute })

	// Eight connects that die after the version exchange - the nc loop's
	// shape. Before the fold: eight auth.handshake_failure lines, one per
	// connect, each with a lock, a tail read and an fsync.
	for i := 0; i < 8; i++ {
		raw, err := net.Dial("tcp", f.addr)
		if err != nil {
			t.Fatalf("connect %d: %v", i+1, err)
		}
		if _, err := raw.Write([]byte("SSH-2.0-r4-f11-flood\r\n")); err != nil {
			t.Fatalf("connect %d: write version: %v", i+1, err)
		}
		buf := make([]byte, 256)
		_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = raw.Read(buf)
		_ = raw.Close()
	}

	handshakeFailures := func() []events.Event {
		evs, _, err := events.ReadHistory(filepath.Dir(f.logPath), events.Filter{Types: []events.EventType{events.EventAuthHandshakeFailure}})
		if err != nil {
			t.Fatalf("read the auth.handshake_failure journal: %v", err)
		}
		return evs
	}
	waitUntil(t, "F-11: the eight connect flood did not fold into one handshake_failure line", func() bool {
		return len(handshakeFailures()) == 1
	})

	// And the attempts were not lost: when the quiet period ends, the
	// count arrives - eight connects, one line, seven repeats.
	f.clock.Advance(2 * time.Minute)
	waitUntil(t, "F-11: the folds of the handshake flood were never counted", func() bool {
		evs := handshakeFailures()
		if len(evs) != 2 {
			return false
		}
		n, _ := evs[1].Details["repeats"].(float64)
		return n == 7
	})
}

// f11Archives lists the rotated journal archives beside the current one,
// oldest name first (the names carry their UTC timestamps).
func f11Archives(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the journal dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && e.Name() != "events.jsonl" && events.IsLogFileName(e.Name()) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

// f11Pad forces the journal past its rotate size the IAMT-452 way.
func f11Pad(t *testing.T, f *fixture) {
	t.Helper()
	for i := 0; i < 40; i++ {
		f.gw.appendEvent(events.Event{Type: events.EventAdminOp, Actor: "r4-f11", Object: "pad", Result: "ok",
			Details: map[string]interface{}{"n": i, "pad": strings.Repeat("x", 100)}})
	}
}

func f11PruneEvents(t *testing.T, f *fixture) []events.Event {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}, Result: "journal.archive.prune"})
	if err != nil {
		t.Fatalf("read the prune journal: %v", err)
	}
	return evs
}

func TestF11_JournalArchivesArePrunedByAge(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.JournalRotateBytes = 4 << 10
		cfg.JournalArchiveRetentionDays = 1
	})
	f11Pad(t, f)
	var archive string
	waitUntil(t, "F-11: the journal never rotated", func() bool {
		if a := f11Archives(t, filepath.Dir(f.logPath)); len(a) == 1 {
			archive = a[0]
			return true
		}
		return false
	})

	// The archive's age is the timestamp in its name, and that timestamp
	// comes from the same clock the sweep reads: two days forward make it
	// a day too old for a one-day retention.
	f.clock.Advance(48 * time.Hour)
	waitUntil(t, "F-11: an archive older than the retention was never pruned - the disk the flood filled stays filled", func() bool {
		return len(f11Archives(t, filepath.Dir(f.logPath))) == 0
	})
	waitUntil(t, "F-11: the pruning was not journaled (PROTOCOL §8: every deletion is an event)", func() bool {
		evs := f11PruneEvents(t, f)
		return len(evs) == 1 && evs[0].Object == archive
	})
}

func TestF11_JournalArchivesArePrunedByCount(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.JournalRotateBytes = 4 << 10
		// Age is switched off by being made irrelevant; the count is what
		// bounds a flood: one archive is all the retention keeps.
		cfg.JournalArchiveRetentionDays = 36500
		cfg.JournalArchiveMaxCount = 1
	})
	f11Pad(t, f)
	var first string
	waitUntil(t, "F-11: the journal never rotated (first archive)", func() bool {
		a := f11Archives(t, filepath.Dir(f.logPath))
		if len(a) == 1 {
			first = a[0]
			return true
		}
		return false
	})
	// One fake second forward: two rotations in the same second would want
	// one archive name, and the second would step aside instead.
	f.clock.Advance(time.Second)
	f11Pad(t, f)
	// The second rotation and the prune of the archive it pushes out land on
	// the same sweep tick, so the moment with both archives on disk can slip
	// between polls; the settled state is what the test waits for: exactly
	// one prune event, naming the older archive, and exactly one archive
	// left - not the older one.
	waitUntil(t, "F-11: the oldest archive beyond the count bound was never pruned", func() bool {
		evs := f11PruneEvents(t, f)
		if len(evs) != 1 || evs[0].Object != first {
			return false
		}
		a := f11Archives(t, filepath.Dir(f.logPath))
		return len(a) == 1 && a[0] != first
	})
}
