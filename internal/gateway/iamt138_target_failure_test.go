package gateway

// iamt138_target_failure_test.go — IAMT-138:
//
//   "Nobody checks whether the machine's sshd is alive before connecting".
//
// First, answered from the code: what happens today when the
// target machine's sshd does not answer -- what refusal the person sees and
// whether it is distinguishable from no machine at all -- that
// indistinguishability is the defect itself, because the person cannot
// tell what to fix: the network, the service, or access. The liveness
// check is not a goal in itself: the point is that the refusal names the
// reason.

import (
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// TestTargetFailure_DoorClosedImmediately tests that when target sshd fails
// to respond during nested handshake, the door reservation failure triggers
// immediate door close without waiting for DoorIdle (15 minutes).
//
// Canary 3:
//
//	In internal/gateway/human_role.go, remove mc.nestedHandshakeFailed().
//	The test will fail on line:
//	  t.Fatalf("door remained open after target failure; want closed door immediately")
func TestTargetFailure_DoorClosedImmediately(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// Close target sshd listener so dial from machine's spliceTarget fails
	_ = f.sshd.listener.Close()

	// Alice dials human session
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

	line := readAll(t, ch, 3*time.Second)
	if !strings.Contains(line, "the target machine's sshd service is not responding") {
		t.Fatalf("human expected sshd-specific denial, got: %q", line)
	}

	// Verify that the door automaton has closed the door immediately
	// rather than remaining open for DoorIdle
	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatalf("machine went offline")
	}

	snap := mc.doorMachine.Snapshot()
	if snap.State != core.Closed && snap.State != core.Closing {
		t.Fatalf("door remained open after target failure; want closed door immediately")
	}
}

// TestHumanDenial_SSHDUnreachableDistinguishableFromOffline tests that a human
// receiving a denial when sshd is dead gets a clear, specific message naming
// the sshd service, distinguishable from the generic "machine offline" message.
func TestHumanDenial_SSHDUnreachableDistinguishableFromOffline(t *testing.T) {
	f := newFixture(t, nil)

	// 1. When machine is offline:
	clientOffline, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dialHuman offline: %v", err)
	}
	chOffline, reqsOffline, err := clientOffline.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session channel: %v", err)
	}
	go discardSSHRequests(reqsOffline)
	offlineMsg := readAll(t, chOffline, 3*time.Second)
	_ = clientOffline.Close()

	if !strings.Contains(offlineMsg, "Access to this machine is currently unavailable") {
		t.Fatalf("offline message must contain the unavailable refusal, got %q", offlineMsg)
	}
	if strings.Contains(offlineMsg, "sshd") {
		t.Fatalf("offline message should not mention sshd, got %q", offlineMsg)
	}

	// 2. When machine is online but target sshd is dead:
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	_ = f.sshd.listener.Close()

	clientSSHDDead, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dialHuman sshd dead: %v", err)
	}
	defer clientSSHDDead.Close()
	chSSHDDead, reqsSSHDDead, err := clientSSHDDead.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session channel: %v", err)
	}
	go discardSSHRequests(reqsSSHDDead)
	sshdDeadMsg := readAll(t, chSSHDDead, 3*time.Second)

	if !strings.Contains(sshdDeadMsg, "the target machine's sshd service is not responding") {
		t.Fatalf("sshd dead message must mention the sshd service, got %q", sshdDeadMsg)
	}
	if offlineMsg == sshdDeadMsg {
		t.Fatalf("offlineMsg and sshdDeadMsg must be distinguishable, but both are %q", offlineMsg)
	}
}

// TestTargetFailure_AuditDenyReasonIsTyped guards Fix 3:
// The denial reason in the session drop audit event MUST match the typed
// constant acl.DenyMachineSSHDUnreachable.String() ("machine sshd is unreachable"),
// and must NOT be a loose raw string like "sshd unreachable" or "machine is not verified".
//
// Canary 5 (Fix 3):
//
//	In internal/gateway/human_role.go denyHumanSSHDUnreachable, change Result to "sshd unreachable".
//	The test will fail on line:
//	  t.Fatalf("audit event Result = %q, want %q", ev.Result, acl.DenyMachineSSHDUnreachable.String())
func TestTargetFailure_AuditDenyReasonIsTyped(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	_ = f.sshd.listener.Close()

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
	_ = readAll(t, ch, 3*time.Second)

	evs, _, err := f.gw.cfg.Log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	found := false
	for _, ev := range evs {
		if ev.Actor == f.person && ev.Object == f.machineID {
			found = true
			if ev.Result != acl.DenyMachineSSHDUnreachable.String() {
				t.Fatalf("audit event Result = %q, want %q", ev.Result, acl.DenyMachineSSHDUnreachable.String())
			}
			if ev.Result != "machine sshd is unreachable" {
				t.Fatalf("audit event Result literal mismatch: %q", ev.Result)
			}
			break
		}
	}
	if !found {
		t.Fatalf("no EventSessionDrop recorded for %s on %s; events: %+v", f.person, f.machineID, evs)
	}
}

// TestTargetFailure_DoorKeyRejectedDistinguishableFromUnreachable guards 138-2:
// When target sshd accepts TCP and completes key exchange, but rejects the door key
// (e.g. wrong user, key permissions, authorized_keys not reloaded yet), the failure
// must report DenyMachineSSHAuthFailed ("machine sshd rejected door key"), NOT
// DenyMachineSSHDUnreachable ("machine sshd is unreachable").
//
// Canary 6 (138-2):
//
//	In internal/gateway/human_role.go, collapse the auth-failure branch into unreachable
//	(remove `if isSSHAuthFailed(err) { g.denyHumanSSHAuthFailed(...) }`).
//	The test will fail on line:
//	  t.Fatalf("audit event Result = %q, want %q", ev.Result, acl.DenyMachineSSHAuthFailed.String())
func TestTargetFailure_DoorKeyRejectedDistinguishableFromUnreachable(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// Keep target sshd listener open, but configure it to reject public key auth:
	f.sshd.setKeyAllowed(func([]byte) bool { return false })

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
	if !strings.Contains(msg, "the target machine's sshd service rejected the door key") {
		t.Fatalf("human message expected rejection of door key, got: %q", msg)
	}
	if strings.Contains(msg, "is not responding") {
		t.Fatalf("human message should not claim sshd is not answering when it rejected key, got: %q", msg)
	}

	evs, _, err := f.gw.cfg.Log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	found := false
	for _, ev := range evs {
		if ev.Actor == f.person && ev.Object == f.machineID {
			found = true
			if ev.Result != acl.DenyMachineSSHAuthFailed.String() {
				t.Fatalf("audit event Result = %q, want %q", ev.Result, acl.DenyMachineSSHAuthFailed.String())
			}
			if ev.Result != "machine sshd rejected door key" {
				t.Fatalf("audit event Result literal mismatch: %q", ev.Result)
			}
			break
		}
	}
	if !found {
		t.Fatalf("no EventSessionDrop recorded for %s on %s; events: %+v", f.person, f.machineID, evs)
	}

	// Verify that the door is closed immediately
	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatalf("machine went offline")
	}
	snap := mc.doorMachine.Snapshot()
	if snap.State != core.Closed && snap.State != core.Closing {
		t.Fatalf("door remained open after door key rejection; want closed door immediately")
	}
}
