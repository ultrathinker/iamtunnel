//go:build !nogui

package main

// iamt332_round9_planted_names_test.go — the planted-entry tests for the
// two round-9 sites in this package (IAMT-332, SPEC §3.1): selftest's
// directory probe and the "Copy AI prompt" agent_known_hosts write. The
// rows plant at the names the OLD code used and trusted — the fixed
// ".iamtunnel-selftest-probe" probe name and the final agent_known_hosts
// name — and require the sentinel byte-identical and the plant intact.
// On the pre-round-9 tree every row fails on its own assertion line:
// the old flat write went through the plant (or refused the plant's
// directory as "not writable", a false negative a plant could force on
// a healthy directory).
//
// The refusal-wording trick this relies on lives in the client package's
// tests; these rows assert behaviour (success, byte identity), which is
// the same on every tree this file compiles on.

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// r9Plant is one entry kind a plant can occupy a predictable name with.
// The symlink row skips on an unprivileged Windows without Developer
// Mode; the hard-link row is the Windows-native member of the class and
// needs no privilege at all; the FIFO row skips here and goes red on
// the POSIX legs.
type r9Plant struct {
	name string
	kind string // what Lstat must still report at the planted path
	// plant installs the entry at at and returns the sentinel bytes the
	// operation must leave unchanged (nil when there is no target file).
	plant func(t *testing.T, at string) []byte
}

func r9Plants() []r9Plant {
	return []r9Plant{
		{"symlink", "symlink", func(t *testing.T, at string) []byte {
			_, s := testsupport.PlantSymlinkAt(t, at)
			return s
		}},
		{"hard link", "file", func(t *testing.T, at string) []byte {
			s := testsupport.WriteSentinelFile(t, at+".sentinel")
			testsupport.PlantHardLinkAt(t, at, at+".sentinel")
			return s
		}},
		{"directory", "directory", func(t *testing.T, at string) []byte {
			testsupport.PlantDirectoryAt(t, at)
			return nil
		}},
		{"fifo", "fifo", func(t *testing.T, at string) []byte {
			testsupport.PlantFIFOAt(t, at)
			return nil
		}},
	}
}

// TestIAMT332R9SelftestProbeIgnoresPlantedProbeName pins the selftest
// directory probe: a plant at the old fixed probe name must not steer
// the probe's write into somebody else's file, must not be reported as
// "the directory is not writable" (a plant must not be able to blind
// selftest), and the probe must leave no temporary behind.
func TestIAMT332R9SelftestProbeIgnoresPlantedProbeName(t *testing.T) {
	for _, p := range r9Plants() {
		t.Run(p.name, func(t *testing.T) {
			dir := t.TempDir()
			at := filepath.Join(dir, ".iamtunnel-selftest-probe")
			sentinel := p.plant(t, at)
			var got selfCheck
			err := testsupport.RunBounded(t, 5*time.Second, "selftest's directory probe with a planted "+p.name, func() error {
				got = checkRoleDir("client", dir, nil)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !got.ok {
				t.Fatalf("selftest reported %q as unusable (%q) — a plant at the old fixed probe name must not blind the check", dir, got.detail)
			}
			if sentinel != nil {
				testsupport.AssertBytesUnchanged(t, at+".sentinel", sentinel)
			}
			testsupport.AssertKindStillThere(t, at, p.kind)
			entries, rerr := os.ReadDir(dir)
			if rerr != nil {
				t.Fatalf("read the directory back: %v", rerr)
			}
			for _, e := range entries {
				// Skip the plant itself and the sentinel it aims at; both
				// are ours, not the probe's.
				if e.Name() == filepath.Base(at) || strings.HasSuffix(e.Name(), ".sentinel") {
					continue
				}
				if strings.HasPrefix(e.Name(), ".iamtunnel-selftest-probe") {
					t.Errorf("the probe left %s behind in %s — the probe's own temporaries must be removed", e.Name(), dir)
				}
			}
		})
	}
}

// r9AgentClientDir builds a client directory with a saved connection and
// a recorded gateway key — everything guiAgentPrompt needs to reach the
// agent_known_hosts write.
func r9AgentClientDir(t *testing.T) (clientDir string, wantKnownHosts []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer from key: %v", err)
	}
	pub := signer.PublicKey()
	cs := config.ConnString{Host: "gw.example", Port: 2200, Person: "ann", Fingerprint: ssh.FingerprintSHA256(pub)}
	clientDir = t.TempDir()
	if err := client.SaveConnection(clientDir, cs, true); err != nil {
		t.Fatalf("save the connection: %v", err)
	}
	recorded := fmt.Sprintf("%s:%d %s", cs.Host, cs.Port, ssh.MarshalAuthorizedKey(pub))
	if err := os.WriteFile(client.KnownHostsPath(clientDir), []byte(recorded), 0o600); err != nil {
		t.Fatalf("record the gateway key: %v", err)
	}
	wantKnownHosts = []byte(fmt.Sprintf("[%s]:%d %s", cs.Host, cs.Port, ssh.MarshalAuthorizedKey(pub)))
	return clientDir, wantKnownHosts
}

// TestIAMT332R9AgentKnownHostsIgnoresPlantedFinal pins the "Copy AI
// prompt" write at agent_known_hosts: a plant at that name (the write
// runs elevated when the GUI is elevated; on Windows a hard link needs
// no privilege at all) must never steer the write into somebody else's
// file. The write replaces the ENTRY — so, unlike the tmp-name rows in
// the client package, the plant itself is not required to survive the
// call; what must survive is the sentinel its link aims at. The
// directory row pins the no-hang half on every tree: a directory
// occupying the final name legitimately fails the replace, promptly,
// and corrupts nothing.
func TestIAMT332R9AgentKnownHostsIgnoresPlantedFinal(t *testing.T) {
	for _, p := range r9Plants() {
		t.Run(p.name, func(t *testing.T) {
			clientDir, wantKnownHosts := r9AgentClientDir(t)
			at := filepath.Join(clientDir, "agent_known_hosts")
			sentinel := p.plant(t, at)
			var prompt string
			err := testsupport.RunBounded(t, 5*time.Second, "guiAgentPrompt with a planted "+p.name+" at "+at, func() error {
				var e error
				prompt, e = guiAgentPrompt(clientDir, "m1")
				return e
			})
			if p.kind == "directory" {
				// The replace may fail (a directory holds the name), but
				// only promptly and without touching anything else.
				if err == nil {
					checkAgentKnownHostsContent(t, at, wantKnownHosts, prompt)
				}
				return
			}
			if err != nil {
				t.Fatalf("guiAgentPrompt failed: %v — the writer must work around the plant, not fail because of it", err)
			}
			if sentinel != nil {
				testsupport.AssertBytesUnchanged(t, at+".sentinel", sentinel)
			}
			checkAgentKnownHostsContent(t, at, wantKnownHosts, prompt)
		})
	}
}

// checkAgentKnownHostsContent requires the write to have landed: the
// file exists with exactly the OpenSSH line, and the prompt carries the
// ssh command that points at it.
func checkAgentKnownHostsContent(t *testing.T, at string, wantKnownHosts []byte, prompt string) {
	t.Helper()
	if !strings.Contains(prompt, "ssh -i") {
		short := prompt
		if len(short) > 120 {
			short = short[:120]
		}
		t.Fatalf("the prompt lost its ssh line: %q", short)
	}
	got, err := os.ReadFile(at)
	if err != nil {
		t.Fatalf("agent_known_hosts was not written: %v", err)
	}
	if string(got) != string(wantKnownHosts) {
		t.Fatalf("agent_known_hosts content: got %q, want %q", got, wantKnownHosts)
	}
}
