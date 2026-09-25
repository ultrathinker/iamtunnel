package client_test

import (
	"bytes"
	"os"
	"runtime"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/client"
)

func TestEnsureKeyGeneratesThenPersists(t *testing.T) {
	dir := t.TempDir()
	s1, err := client.EnsureKey(dir)
	if err != nil {
		t.Fatalf("first EnsureKey: %v", err)
	}
	info, err := os.Stat(client.KeyPath(dir))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	// Windows has no POSIX permission bits (os.WriteFile's mode only
	// controls the read-only attribute there); the owner-only check is
	// meaningful on the platforms that actually have group/other bits.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Errorf("key file mode = %v, want no access for group/other", info.Mode())
	}

	s2, err := client.EnsureKey(dir)
	if err != nil {
		t.Fatalf("second EnsureKey: %v", err)
	}
	if !bytes.Equal(s1.PublicKey().Marshal(), s2.PublicKey().Marshal()) {
		t.Fatal("EnsureKey generated a different key on the second call — the file was not reused")
	}
}

func TestEnsureKeyTwoDirsGetDifferentKeys(t *testing.T) {
	s1, err := client.EnsureKey(t.TempDir())
	if err != nil {
		t.Fatalf("dir1: %v", err)
	}
	s2, err := client.EnsureKey(t.TempDir())
	if err != nil {
		t.Fatalf("dir2: %v", err)
	}
	if bytes.Equal(s1.PublicKey().Marshal(), s2.PublicKey().Marshal()) {
		t.Fatal("two fresh directories produced the same key")
	}
}

func TestEnsureKeyCorruptFileIsNamedError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(client.KeyPath(dir), []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write corrupt key: %v", err)
	}
	if _, err := client.EnsureKey(dir); err == nil {
		t.Fatal("corrupt key file: want an error, got nil")
	}
}

// M-9c (code review 23.09.2026, review F-09). The window and the
// CLI can both be a first run at the same moment. Each used to see "no
// key", generate its own pair and publish it with an atomic REPLACE, so
// the second overwrote the first — and each caller was handed ITS OWN
// key, not the one on disk. The person then gives the admin the public
// half one of them printed, and after a restart the machine knows only
// the other: the grant can never authenticate, and the private half that
// was granted is gone.
//
// Every concurrent first run must come back with the SAME key — the one
// the file holds.
func TestM9cConcurrentFirstRunsAgreeOnOneKey(t *testing.T) {
	dir := t.TempDir()
	const runs = 8

	signers := make([]ssh.Signer, runs)
	errs := make([]error, runs)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-gate // all eight leave together: every one of them sees an empty directory
			signers[i], errs[i] = client.EnsureKey(dir)
		}(i)
	}
	close(gate)
	wg.Wait()

	// Which public key was each caller handed? Every concurrent first run
	// must be handed the ONE key the file holds, so there must be exactly
	// one answer here.
	handed := map[string]int{}
	var order []string
	for i, err := range errs {
		if err != nil {
			t.Errorf("first run %d failed: %v — two first runs at once must both come back with the same key, not with an error (M-9c, review F-09)", i, err)
			continue
		}
		pub := string(signers[i].PublicKey().Marshal())
		if _, seen := handed[pub]; !seen {
			order = append(order, pub)
		}
		handed[pub]++
	}
	if len(order) == 0 {
		t.Fatalf("not one of the %d concurrent first runs produced a key", runs)
	}
	if len(order) > 1 {
		t.Errorf("%d concurrent first runs were handed %d DIFFERENT public keys — each run generated its own pair and replaced the other's file, so the half a caller is told to register is not the half the disk keeps (M-9c, review F-09)", runs, len(order))
	}

	// The file must hold the key that was handed out: that is the whole
	// point of the grant the person is about to ask for.
	first := []byte(order[0])
	stored, err := client.EnsureKey(dir)
	if err != nil {
		t.Fatalf("reading back the key: %v", err)
	}
	if !bytes.Equal(stored.PublicKey().Marshal(), first) {
		t.Errorf("the key on disk is not the key EnsureKey returned to its first callers — a grant issued for the printed public half would never authenticate (M-9c, review F-09)")
	}

	// No leftovers from the losers: one key file, nothing else.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the client directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "key" {
		t.Errorf("the client directory holds %d entries (%v), want exactly the key file — a loser must read the winner's key, not leave a second one behind", len(entries), entries)
	}
}
