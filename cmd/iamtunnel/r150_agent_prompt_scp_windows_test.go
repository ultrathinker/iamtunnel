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

// r150PromptLine returns the prompt line that starts with prefix, trimmed.
func r150PromptLine(t *testing.T, prompt, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(prompt, "\n") {
		if l := strings.TrimSpace(line); strings.HasPrefix(l, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(l, prefix))
		}
	}
	t.Fatalf("prompt has no line starting with %q:\n%s", prefix, prompt)
	return ""
}

// r150Args splits a command line the way a shell would for these lines:
// on spaces, keeping double-quoted parts whole.
func r150Args(line string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ' ' && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// r150ScpHost is scp's own split of a remote operand ([host]:path or
// host:path, the first ':' outside brackets): "" when the operand is local.
func r150ScpHost(arg string) (host, path string) {
	if strings.HasPrefix(arg, "[") {
		end := strings.Index(arg, "]:")
		if end < 0 {
			return "", ""
		}
		return arg[1:end], arg[end+2:]
	}
	i := strings.Index(arg, ":")
	if i <= 0 {
		return "", ""
	}
	return arg[:i], arg[i+1:]
}

// TestR150_AgentPromptHasWorkingScpLines: the prompt tells the agent to use
// scp (not base64 on stdin), and the lines it gives are copyable as they
// are — the person:machine user rides in -o User=, never as user@host
// (whose ':' scp would read as the path separator), the remote operand is
// host:/C:/..., and the key, known_hosts and port are the ssh line's.
func TestR150_AgentPromptHasWorkingScpLines(t *testing.T) {
	for _, tc := range []struct{ saved, host string }{
		{"203.0.113.10", "203.0.113.10"},
		{"[2001:db8::1]", "2001:db8::1"},
	} {
		t.Run(tc.saved, func(t *testing.T) {
			dir := t.TempDir()
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("setup: key: %v", err)
			}
			pk, err := ssh.NewPublicKey(pub)
			if err != nil {
				t.Fatalf("setup: public key: %v", err)
			}
			cs := config.ConnString{Host: tc.saved, Port: 2022, Person: "alice", Fingerprint: ssh.FingerprintSHA256(pk)}
			if err := client.SaveConnection(dir, cs, false); err != nil {
				t.Fatalf("setup: save connection: %v", err)
			}
			recorded := fmt.Sprintf("%s:%d %s", tc.saved, 2022, ssh.MarshalAuthorizedKey(pk))
			if err := os.WriteFile(client.KnownHostsPath(dir), []byte(recorded), 0o600); err != nil {
				t.Fatalf("setup: known_hosts: %v", err)
			}
			prompt, err := guiAgentPrompt(dir, "vm1")
			if err != nil {
				t.Fatalf("guiAgentPrompt: %v", err)
			}
			if strings.Contains(prompt, "base64 on standard input") || strings.Contains(prompt, "not available") {
				t.Fatalf("prompt still sends the agent to base64 on stdin:\n%s", prompt)
			}
			if !strings.Contains(prompt, "if one is held for approval, tell the person the approval-id and wait") {
				t.Fatalf("prompt lacks the approval rule:\n%s", prompt)
			}

			for _, which := range []string{"upload:", "download:"} {
				args := r150Args(r150PromptLine(t, prompt, which))
				if len(args) < 2 || args[0] != "scp" {
					t.Fatalf("%s line is not an scp call: %q", which, args)
				}
				want := map[string]bool{"User=alice:vm1": false, "IdentitiesOnly=yes": false, "StrictHostKeyChecking=yes": false}
				var port, identity, knownHosts string
				for i := 1; i < len(args)-1; i++ {
					switch args[i] {
					case "-o":
						if _, ok := want[args[i+1]]; ok {
							want[args[i+1]] = true
						}
						if strings.HasPrefix(args[i+1], "UserKnownHostsFile=") {
							knownHosts = args[i+1]
						}
					case "-P":
						port = args[i+1]
					case "-i":
						identity = args[i+1]
					}
				}
				for opt, seen := range want {
					if !seen {
						t.Fatalf("%s line lacks -o %s: %q", which, opt, args)
					}
				}
				if port != "2022" || identity != client.KeyPath(dir) || knownHosts != "UserKnownHostsFile="+filepath.Join(dir, "agent_known_hosts") {
					t.Fatalf("%s line: port=%q identity=%q knownHosts=%q, want the ssh line's", which, port, identity, knownHosts)
				}
				remote := args[len(args)-1]
				if which == "download:" {
					remote = args[len(args)-2]
				}
				host, path := r150ScpHost(remote)
				if host != tc.host || path != "/C:/TEST111/file" {
					t.Fatalf("%s remote operand %q splits as host %q path %q, want %q and /C:/TEST111/file", which, remote, host, path, tc.host)
				}
				if strings.Contains(strings.Join(args, " "), "@") {
					t.Fatalf("%s line uses user@host: %q", which, args)
				}
			}
		})
	}
}
