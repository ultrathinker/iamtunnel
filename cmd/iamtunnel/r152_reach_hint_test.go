package main

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type r152TimeoutErr struct{}

func (r152TimeoutErr) Error() string   { return "dial tcp 10.0.0.1:2027: i/o timeout" }
func (r152TimeoutErr) Timeout() bool   { return true }
func (r152TimeoutErr) Temporary() bool { return true }

// A dropped connection and a refused one want opposite moves, and a
// bare "i/o timeout" said neither (29.09.2026, a machine whose gateway's
// security group did not admit it).
func TestR152_ReachHintTellsATimeoutFromARefusal(t *testing.T) {
	var ne net.Error = r152TimeoutErr{}
	if h := reachHint("gw:2027", ne); !strings.Contains(h, "security group") || !strings.Contains(h, "private address") {
		t.Fatalf("timeout hint = %q, want the firewall / security group move", h)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	_, derr := net.DialTimeout("tcp", addr, 2*time.Second)
	if derr == nil {
		t.Skip("the closed port answered; nothing to learn from this machine")
	}
	if h := reachHint(addr, derr); !strings.Contains(h, "nothing listens") {
		t.Fatalf("refusal hint for %v = %q, want the nothing-listens move", derr, h)
	}

	if h := reachHint("gw:2027", errors.New("ssh: handshake failed: unable to authenticate")); h != "" {
		t.Fatalf("an authentication failure got a network hint: %q", h)
	}
}
