package gateway

// IAMT-173 (1.0 blocker), round 3: canary on internal/gateway/human_role.go's
// sshx.ApplyClientConfig(nestedCfg) call must exercise the real product
// nested-handshake path (PROTOCOL §5.2: the gateway's handshake to the
// machine's target sshd MUST use the same ordered algorithm lists as the
// outer handshake, not x/crypto defaults) - not re-run the policy helper
// on a throwaway config (round 2's canary only checked the shape of a
// config built by the TEST itself).
//
// f.sshd (fakeTargetSSHD) is the real product's nested-handshake peer: a
// live human session opened through the gateway drives human_role.go's
// serveHumanSession end to end, over the real machine splice
// (internal/server's spliceTarget, via fakeMachine). Pinning f.sshd's own
// ssh.ServerConfig to a single KEX algorithm proves the gateway's policy
// on the wire, not just on a struct field.

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// TestIAMT173_NestedHandshake_RejectsNonPolicyKEX: remove
// sshx.ApplyClientConfig(nestedCfg) from human_role.go's nested handshake
// and this goes red - the gateway falls back to x/crypto's library
// defaults, which include ecdh-sha2-nistp256, and the nested handshake
// below - which this test expects to fail - succeeds instead, so the
// human session proceeds instead of being denied.
func TestIAMT173_NestedHandshake_RejectsNonPolicyKEX(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// Outside PROTOCOL §1's KEX list, but still one x/crypto itself will
	// propose by default (defaultKexAlgos includes ecdh-sha2-nistp256) -
	// a gateway that fell back to defaults would still negotiate this
	// nested handshake successfully.
	f.sshd.setCfgMod(func(cfg *ssh.ServerConfig) {
		cfg.KeyExchanges = []string{"ecdh-sha2-nistp256"}
	})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dialHuman: %v", err)
	}
	defer client.Close()

	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session channel: %v", err)
	}
	go discardSSHRequests(reqs)

	msg := readAll(t, ch, 3*time.Second)
	if !strings.Contains(msg, "the target machine's sshd service is not responding") {
		t.Fatalf("nested handshake with a non-PROTOCOL-§1 KEX (ecdh-sha2-nistp256) should be denied as sshd-unreachable (the nested handshake never negotiates), got: %q — human_role.go is not applying sshx.ApplyClientConfig's KEX policy to the nested handshake", msg)
	}

	evs, _, err := f.gw.cfg.Log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	found := false
	for _, ev := range evs {
		if ev.Actor == f.person && ev.Object == f.machineID {
			found = true
			if ev.Result != acl.DenyMachineSSHDUnreachable.String() {
				t.Fatalf("audit event Result = %q, want %q (nested handshake should never complete KEX against a non-policy peer)", ev.Result, acl.DenyMachineSSHDUnreachable.String())
			}
			break
		}
	}
	if !found {
		t.Fatalf("no EventSessionDrop recorded for %s on %s; events: %+v", f.person, f.machineID, evs)
	}
}

// TestIAMT173_NestedHandshake_AcceptsPolicyKEX is the control: f.sshd
// pinned to curve25519-sha256 (PROTOCOL §1's first KEX choice) instead
// must let the nested handshake through and the session must actually
// carry bytes end to end.
func TestIAMT173_NestedHandshake_AcceptsPolicyKEX(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	f.sshd.setCfgMod(func(cfg *ssh.ServerConfig) {
		cfg.KeyExchanges = []string{"curve25519-sha256"}
	})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dialHuman: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	acc := drain(hs.ch)
	if _, err := hs.ch.Write([]byte("PING")); err != nil {
		t.Fatalf("write PING: %v", err)
	}
	if !waitContains(t, acc, "PING", 3*time.Second) {
		t.Fatalf("gateway should accept a target sshd offering curve25519-sha256 (PROTOCOL §1); echo never arrived: %q", acc.get())
	}
}
