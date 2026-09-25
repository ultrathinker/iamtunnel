package gateway

import (
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// TestIAMT189_ForbiddenSSHRequestsAreJournaled drives the real human SSH
// connection through the three independently routed forbidden paths: a
// channel-open, a global request, and a request on a session channel. It is
// the canary for human_role.go's reject branches: removing any corresponding
// recordSSHRequestReject call leaves the wire refusal intact but makes this
// assertion fail with the exact request/code pair that vanished from
// events.jsonl.
func TestIAMT189_ForbiddenSSHRequestsAreJournaled(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer client.Close()

	directPayload := ssh.Marshal(struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{"127.0.0.1", 8080, "127.0.0.1", 12345})
	if _, _, err := client.OpenChannel("direct-tcpip", directPayload); err == nil {
		t.Fatal("IAMT-189 canary setup: direct-tcpip unexpectedly opened")
	}

	forwardPayload := ssh.Marshal(struct {
		BindAddr string
		BindPort uint32
	}{"0.0.0.0", 8080})
	ok, _, err := client.SendRequest("tcpip-forward", true, forwardPayload)
	if err != nil || ok {
		t.Fatalf("IAMT-189 canary setup: tcpip-forward refusal = ok:%v err:%v", ok, err)
	}

	hs := openHumanSession(t, client, f)
	ok, err = hs.ch.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
	if err != nil || ok {
		t.Fatalf("IAMT-189 canary setup: subsystem refusal = ok:%v err:%v", ok, err)
	}
	// IAMT-197 (candidate #2 of the THREATS audit): ssh-agent and X11
	// forwarding on a person's session are forbidden just like forward and
	// subsystem -- a refusal on the wire plus a session.drop with its own
	// code from sshRequestRejectCode (human_role.go). x11-req carries the
	// RFC 4254 §6.4 payload (single, protocol, cookie, screen) and is
	// rejected before parsing.
	ok, err = hs.ch.SendRequest("auth-agent-req@openssh.com", true, nil)
	if err != nil || ok {
		t.Fatalf("IAMT-197: auth-agent-req@openssh.com refusal = ok:%v err:%v; want a wire-level failure", ok, err)
	}
	ok, err = hs.ch.SendRequest("x11-req", true, ssh.Marshal(struct {
		Single           bool
		Protocol, Cookie string
		Screen           uint32
	}{true, "MIT-MAGIC-COOKIE-1", "iamt197-cookie", 0}))
	if err != nil || ok {
		t.Fatalf("IAMT-197: x11-req refusal = ok:%v err:%v; want a wire-level failure", ok, err)
	}
	_ = hs.ch.Close()

	for _, want := range []struct {
		request string
		code    string
	}{
		{"direct-tcpip", "E_SSH_FORWARD_FORBIDDEN"},
		{"tcpip-forward", "E_SSH_FORWARD_FORBIDDEN"},
		{"subsystem", "E_SSH_SUBSYSTEM_FORBIDDEN"},
		{"auth-agent-req@openssh.com", "E_SSH_AGENT_FORBIDDEN"},
		{"x11-req", "E_SSH_X11_FORBIDDEN"},
	} {
		want := want
		waitUntil(t, "IAMT-189 canary: events.jsonl has no session.drop for "+want.request+" with "+want.code, func() bool {
			evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
			if err != nil {
				t.Fatalf("read events.jsonl: %v", err)
			}
			for _, ev := range evs {
				if ev.Actor == f.person && ev.Object == f.machineID && ev.Result == want.code && ev.Details["sshRequest"] == want.request {
					return true
				}
			}
			return false
		})
	}
}
