package client_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func connToFake(fg *fakeGateway, person string) config.ConnString {
	host, port := splitAddr(fg.addr)
	return config.ConnString{Host: host, Port: port, Person: person, Fingerprint: fg.fingerprint()}
}

func splitAddr(addr string) (string, int) {
	h, p, ok := strings.Cut(addr, ":")
	if !ok {
		return addr, 0
	}
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return h, n
}

// TestMachinesRefusesWrongFingerprintBeforeAnyProtocol proves
// "a mismatched fingerprint means refusal, with zero attempts to
// continue": the pinned fingerprint is deliberately wrong, and the
// assertion is that the gateway double's exec handler is never even
// invoked, not merely that an error came back.
func TestMachinesRefusesWrongFingerprintBeforeAnyProtocol(t *testing.T) {
	invoked := false
	fg := newFakeGateway(t, func(command string, request []byte) []byte {
		invoked = true
		return canonicalMachinesMineOK()
	})
	cs := connToFake(fg, "alice")
	cs.Fingerprint = "SHA256:" + repeat43('B') // definitely not fg's real fingerprint

	dir := t.TempDir()
	_, err := client.Machines(context.Background(), dir, cs, testSigner(t), time.Second)
	if err == nil {
		t.Fatal("wrong fingerprint: want an error, got nil")
	}
	var cfe *config.Error
	if !errors.As(err, &cfe) || cfe.Class != config.ClassUser {
		t.Fatalf("wrong fingerprint: err = %v, want a ClassUser *config.Error", err)
	}
	if !strings.Contains(err.Error(), "gateway host-key fingerprint changed") {
		t.Fatalf("wrong fingerprint: message %q does not name the reason", err.Error())
	}
	if invoked {
		t.Fatal("the fake gateway's exec handler ran despite the fingerprint mismatch — the client attempted to continue past a failed pin check")
	}
}

func TestMachinesAcceptsCorrectFingerprint(t *testing.T) {
	fg := newFakeGateway(t, func(command string, request []byte) []byte {
		return canonicalMachinesMineOK()
	})
	cs := connToFake(fg, "alice")
	dir := t.TempDir()
	machines, err := client.Machines(context.Background(), dir, cs, testSigner(t), time.Second)
	if err != nil {
		t.Fatalf("correct fingerprint: %v", err)
	}
	if len(machines) != 1 || machines[0].ID != "win01" {
		t.Fatalf("machines = %+v, want one entry \"win01\"", machines)
	}
}

// TestKnownHostsIsolation proves, by behavior, that a sentinel
// "real" known_hosts under a fake home directory must survive byte-for-
// byte, while this package's own, separate known_hosts file records the
// verified key.
func TestKnownHostsIsolation(t *testing.T) {
	tree := testsupport.NewSSHTree(t)
	fakeHome := tree.Home
	sshDir := tree.SSHDir
	realKnownHosts := filepath.Join(sshDir, "known_hosts")
	sentinel := []byte("gw.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI-sentinel-do-not-touch\n")
	if err := os.WriteFile(realKnownHosts, sentinel, 0o600); err != nil {
		t.Fatalf("write sentinel known_hosts: %v", err)
	}
	before, err := os.ReadFile(realKnownHosts)
	if err != nil {
		t.Fatalf("read sentinel before: %v", err)
	}

	testsupport.ApplyPlatformDataEnv(t, fakeHome)
	t.Setenv("USERPROFILE", fakeHome)

	fg := newFakeGateway(t, func(command string, request []byte) []byte {
		return canonicalMachinesMineOK()
	})
	cs := connToFake(fg, "alice")
	clientDir := t.TempDir() // deliberately NOT under fakeHome
	if _, err := client.Machines(context.Background(), clientDir, cs, testSigner(t), time.Second); err != nil {
		t.Fatalf("Machines: %v", err)
	}

	after, err := os.ReadFile(realKnownHosts)
	if err != nil {
		t.Fatalf("read sentinel after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("the real known_hosts changed:\nbefore: %q\nafter:  %q", before, after)
	}
	if entries, _ := os.ReadDir(sshDir); len(entries) != 1 {
		t.Fatalf("fake ~/.ssh gained files: %v", entries)
	}

	ownKnownHosts, err := os.ReadFile(client.KnownHostsPath(clientDir))
	if err != nil {
		t.Fatalf("own known_hosts was not written: %v", err)
	}
	if len(ownKnownHosts) == 0 {
		t.Fatal("own known_hosts is empty after a successful, verified connection")
	}
}
