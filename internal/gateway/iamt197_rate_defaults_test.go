package gateway

// iamt197_rate_defaults_test.go — candidate #6 of the THREATS audit (IAMT-196):
// the production rate-limit defaults must match THREATS T:198 and
// PROTOCOL §1.4 numerically -- 10 failed attempts in a 5-minute window,
// a 15-minute ban of the pair (known-key) and of the address
// (unknown-key). The ban mechanism itself is held by
// auth/ratelimit_test.go (with its own numbers); this test holds the
// PRODUCTION defaults that Config.setDefaults assembles.
//
// Note: setDefaults requires Store/Log/HostKey BEFORE the RateConfig
// branch (config.go: Store is required), so a literally empty Config
// would be refused; the test builds a minimal valid Config with
// directories strictly inside t.TempDir() and leaves RateConfig zero,
// so that it is exactly the defaults branch that fires.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestIAMT197_RateLimitDefaultsMatchProtocol(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	defer func() { _ = store.Close() }()
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("events.OpenLog: %v", err)
	}
	defer func() { _ = log.Close() }()

	cfg := Config{
		Store:            store,
		Log:              log,
		HostKey:          genSigner(t),
		RecordingBaseDir: filepath.Join(dir, "recordings"),
	}
	if err := cfg.setDefaults(); err != nil {
		t.Fatalf("setDefaults: %v", err)
	}

	// The numbers of THREATS T:198 / PROTOCOL §1.4: 10 attempts, a 5-minute
	// window, a 15-minute ban -- separately per pair (address, fingerprint)
	// for known keys and separately per address for unknown ones.
	want := auth.RateConfig{
		MaxKnownFailures:   10,
		MaxUnknownFailures: 10,
		Window:             5 * time.Minute,
		PairBanDuration:    15 * time.Minute,
		AddrBanDuration:    15 * time.Minute,
	}
	if cfg.RateConfig != want {
		t.Fatalf("IAMT-197: production RateConfig defaults = %+v, want exactly %+v (THREATS T:198 / PROTOCOL §1.4: 10 attempts / 5-minute window / 15-minute ban)", cfg.RateConfig, want)
	}
}
