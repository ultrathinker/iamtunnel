//go:build windows && !nogui

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
)

// TestIAMT231_AgentPromptHostForms pins the ssh destination and the
// OpenSSH known_hosts pattern "Copy AI prompt" builds (IAMT-231, review
// IAMT-227 #4): an IPv6 gateway saved as "[addr]" must reach OpenSSH as the
// bare address with exactly one pair of brackets in known_hosts, and port 22
// uses the plain host.
//
// Canary: in gui_actions.go guiAgentPrompt, replace
// `host := strings.TrimSuffix(strings.TrimPrefix(cs.Host, "["), "]")` with
// `host := cs.Host` — the IPv6 case fails on the known_hosts assertion
// ("[[2001:db8::1]]:2222").
func TestIAMT231_AgentPromptHostForms(t *testing.T) {
	cases := []struct {
		host        string
		port        int
		wantPattern string
		wantDest    string
	}{
		{"[2001:db8::1]", 2222, "[2001:db8::1]:2222 ", " 2001:db8::1 \"hostname\""},
		{"gw.example", 22, "gw.example ", " gw.example \"hostname\""},
		{"203.0.113.10", 2022, "[203.0.113.10]:2022 ", " 203.0.113.10 \"hostname\""},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			dir := t.TempDir()
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("setup: key: %v", err)
			}
			pk, err := ssh.NewPublicKey(pub)
			if err != nil {
				t.Fatalf("setup: public key: %v", err)
			}
			cs := config.ConnString{Host: tc.host, Port: tc.port, Person: "alice", Fingerprint: ssh.FingerprintSHA256(pk)}
			if err := client.SaveConnection(dir, cs, false); err != nil {
				t.Fatalf("setup: save connection: %v", err)
			}
			recorded := fmt.Sprintf("%s:%d %s", tc.host, tc.port, ssh.MarshalAuthorizedKey(pk))
			if err := os.WriteFile(client.KnownHostsPath(dir), []byte(recorded), 0o600); err != nil {
				t.Fatalf("setup: known_hosts: %v", err)
			}

			prompt, err := guiAgentPrompt(dir, "vm1")
			if err != nil {
				t.Fatalf("guiAgentPrompt: %v", err)
			}
			agentHosts, err := os.ReadFile(filepath.Join(dir, "agent_known_hosts"))
			if err != nil {
				t.Fatalf("agent_known_hosts not written: %v", err)
			}
			if !strings.HasPrefix(string(agentHosts), tc.wantPattern+"ssh-ed25519 ") {
				t.Fatalf("agent_known_hosts = %q, want prefix %q", agentHosts, tc.wantPattern+"ssh-ed25519 ")
			}
			if !strings.Contains(prompt, "-l alice:vm1"+tc.wantDest) {
				t.Fatalf("prompt has no destination %q:\n%s", "-l alice:vm1"+tc.wantDest, prompt)
			}
		})
	}
}
