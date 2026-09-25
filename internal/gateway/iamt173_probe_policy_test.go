package gateway

// IAMT-173 (1.0 blocker), round 3: canaries on internal/gateway/sshd_probe.go's
// two sshx.ApplyClientConfig calls (probeCfg1 in observeSSHDHostKey,
// probeCfg2 in authenticateProbeUser) must exercise the real §7 probe
// path through a live machineConn (runSSHDProbe), not a throwaway config
// built by the test itself.
//
// The probe's own two phases are strictly sequential and each opens a
// fresh connection to f.sshd (openProbeTarget), so a per-connection
// counter on f.sshd's cfgMod lets one test pin phase 1's target to a
// PROTOCOL §1 algorithm (so it always succeeds) while pinning phase 2's
// target to a non-policy one - isolating authenticateProbeUser's own
// policy call from observeSSHDHostKey's.

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestIAMT173_SSHDProbe_Phase1_RejectsNonPolicyKEX: remove
// sshx.ApplyClientConfig(probeCfg1) from observeSSHDHostKey and this goes
// red - the client falls back to x/crypto's library defaults (which
// include ecdh-sha2-nistp256), phase 1 succeeds instead of failing, and
// the probe goes on to attempt phase 2 (visible as a public-key auth
// attempt against f.sshd, i.e. userAuthenticatedByPublicKey no longer
// empty, and/or a differently-worded error).
func TestIAMT173_SSHDProbe_Phase1_RejectsNonPolicyKEX(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.SSHDProbeTimeout = 3 * time.Second })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	prepareSSHDProbe(t, f)

	// Outside PROTOCOL §1's KEX list for every connection - both probe
	// phases would hit this if either failed to apply its own policy.
	f.sshd.setCfgMod(func(cfg *ssh.ServerConfig) {
		cfg.KeyExchanges = []string{"ecdh-sha2-nistp256"}
	})

	err := f.gw.runSSHDProbe(probeMachineConn(t, f))
	if err == nil {
		t.Fatal("sshd probe accepted a target offering only a non-PROTOCOL-§1 KEX (ecdh-sha2-nistp256) and succeeded — sshd_probe.go's observeSSHDHostKey is not applying sshx.ApplyClientConfig's KEX policy")
	}
	if !strings.Contains(err.Error(), "target host-key handshake") {
		t.Fatalf("expected phase 1 (host-key observation) to be the one that failed, got a differently-shaped error: %v", err)
	}
	// PublicKeyCallback (phase 2's own signature) only fires once a
	// transport is established; phase 1 sends no auth attempt at all
	// (see observeSSHDHostKey's own comment on the mandatory "none"
	// request). A non-empty user here would mean phase 2 ran despite
	// phase 1 having failed to negotiate KEX - impossible unless phase 1
	// silently fell back to defaults and "succeeded" against the same
	// non-policy target.
	if got := f.sshd.userAuthenticatedByPublicKey(); got != "" {
		t.Fatalf("phase 2 attempted public-key auth (user=%q) even though phase 1's KEX should have failed first", got)
	}
}

// TestIAMT173_SSHDProbe_Phase2_RejectsNonPolicyKEX isolates
// authenticateProbeUser's own sshx.ApplyClientConfig(probeCfg2) call:
// phase 1's target is pinned to a PROTOCOL §1 algorithm (so it always
// succeeds, regardless of this test), phase 2's target is pinned outside
// it. Remove probeCfg2's ApplyClientConfig call and this goes red - the
// client falls back to defaults, negotiates ecdh-sha2-nistp256 with
// phase 2's target, completes public-key auth, and the whole probe
// succeeds instead of failing.
func TestIAMT173_SSHDProbe_Phase2_RejectsNonPolicyKEX(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.SSHDProbeTimeout = 3 * time.Second })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	prepareSSHDProbe(t, f)

	var conns atomic.Int32
	f.sshd.setCfgMod(func(cfg *ssh.ServerConfig) {
		if conns.Add(1) == 1 {
			// Phase 1 (observeSSHDHostKey): PROTOCOL §1, always succeeds.
			cfg.KeyExchanges = []string{"curve25519-sha256"}
			return
		}
		// Phase 2 (authenticateProbeUser): outside PROTOCOL §1, but still
		// one x/crypto itself proposes by default (defaultKexAlgos
		// includes ecdh-sha2-nistp256).
		cfg.KeyExchanges = []string{"ecdh-sha2-nistp256"}
	})

	err := f.gw.runSSHDProbe(probeMachineConn(t, f))
	if err == nil {
		t.Fatal("sshd probe's phase 2 (user-auth) accepted a non-PROTOCOL-§1 KEX target and the probe succeeded — sshd_probe.go's authenticateProbeUser is not applying sshx.ApplyClientConfig's KEX policy")
	}
	if !strings.Contains(err.Error(), "user-auth") {
		t.Fatalf("expected phase 2 (user-auth) to be the one that failed, got a differently-shaped error: %v", err)
	}
	if got := f.sshd.userAuthenticatedByPublicKey(); got != "" {
		t.Fatalf("phase 2's public-key auth callback ran (user=%q) despite a KEX mismatch — the nested handshake should never have reached user-auth", got)
	}
}

// TestIAMT173_SSHDProbe_AcceptsPolicyKEXBothPhases is the control: f.sshd
// pinned to curve25519-sha256 (PROTOCOL §1's first KEX choice) for every
// connection lets both probe phases through, exactly like the existing
// TestSSHDProbe_SuccessVerifiesRequestedUserAndClosesDoor - proving a
// rejection above is really about the non-policy KEX, not some unrelated
// probe breakage.
func TestIAMT173_SSHDProbe_AcceptsPolicyKEXBothPhases(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.SSHDProbeTimeout = 3 * time.Second })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	prepareSSHDProbe(t, f)

	f.sshd.setCfgMod(func(cfg *ssh.ServerConfig) {
		cfg.KeyExchanges = []string{"curve25519-sha256"}
	})

	if err := f.gw.runSSHDProbe(probeMachineConn(t, f)); err != nil {
		t.Fatalf("probe should succeed against a target offering curve25519-sha256 (PROTOCOL §1) in both phases: %v", err)
	}
	if got := f.sshd.userAuthenticatedByPublicKey(); got != probeUser {
		t.Fatalf("probe public-key auth user = %q, want requestedOsUser %q", got, probeUser)
	}
}
