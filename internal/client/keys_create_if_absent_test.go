package client

// keys_create_if_absent_test.go — the in-package guards for M-9c's
// create-if-absent first run (code review 23.09.2026, review F-09).
//
// These two rows are guards, not the red evidence: they name helpers
// that only exist after the fix (readWinnersKey), so they could not
// compile against the tree the defect lived in. The red test for M-9c is
// TestM9cConcurrentFirstRunsAgreeOnOneKey in keys_test.go — it uses the
// public API only and went red on the old code with "N concurrent first
// runs were handed 3 DIFFERENT public keys".

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// TestM9cLoserWaitsForAKeyStillBeingWritten drives the gap the winner
// cannot avoid: datafile.Create claims the name and the bytes arrive one
// write later, so a loser reading in between sees an EMPTY file. An
// empty file is a key being born, not a corrupt key — the loser must
// wait for the writer that owns the name and then hand back that key.
func TestM9cLoserWaitsForAKeyStillBeingWritten(t *testing.T) {
	dir := t.TempDir()
	path := KeyPath(dir)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	want, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "iamtunnel client key")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	// The winner's shape: the name exists, empty, and the bytes land a
	// moment later. 0600 like datafile.Create gives it — on Unix the
	// loser's permission check runs on this very file, and an
	// owner-only key is what the product writes.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("claim the key's name: %v", err)
	}
	// ...and protected the way createKeyIfAbsent protects it — the 0600
	// above on Unix, its own access list on Windows (protectClaimedKey
	// is the test-only, platform-split half of that; see
	// keys_claim_windows_test.go). The loser's check runs on this very
	// file, so a simulation that left it as plain os.OpenFile made it
	// would be testing a state the product never creates.
	protectClaimedKey(t, path)
	written := make(chan struct{})
	go func() {
		defer close(written)
		time.Sleep(60 * time.Millisecond)
		_, _ = f.Write(pemBytes)
		_ = f.Close()
	}()
	defer func() { <-written }()

	got, err := readWinnersKey(path)
	if err != nil {
		t.Fatalf("the loser gave up on a key that was still being written: %v — an empty key file is a key being born, not a corrupt one", err)
	}
	if !bytes.Equal(got.PublicKey().Marshal(), want.PublicKey().Marshal()) {
		t.Errorf("the loser read a key that is not the one the winner published — every concurrent first run must return the key the disk holds")
	}
}

// TestM9cEnsureKeyRefusesAPlantAtTheKeyNameInsteadOfRegenerating pins
// the other half of the create-if-absent contract: an entry at the key's
// name that is not a regular file of ours is refused in words, left
// exactly where it was, and never written over — the fix must not turn
// "this name is taken by a plant" into "generate a new key here".
func TestM9cEnsureKeyRefusesAPlantAtTheKeyNameInsteadOfRegenerating(t *testing.T) {
	rows := []struct {
		name string
		// kind is what Lstat must still report at the name afterwards.
		kind string
		// wording is the refusal text the error must carry.
		wording string
		plant   func(t *testing.T, at string) []byte
	}{
		{"directory", "directory", "not a regular file", func(t *testing.T, at string) []byte {
			testsupport.PlantDirectoryAt(t, at)
			return nil
		}},
		{"fifo", "fifo", "not a regular file", func(t *testing.T, at string) []byte {
			testsupport.PlantFIFOAt(t, at)
			return nil
		}},
		{"symlink", "symlink", "is a symlink", func(t *testing.T, at string) []byte {
			_, s := testsupport.PlantSymlinkAt(t, at)
			return s
		}},
		{"hard link", "file", "links", func(t *testing.T, at string) []byte {
			s := testsupport.WriteSentinelFile(t, at+".sentinel")
			testsupport.PlantHardLinkAt(t, at, at+".sentinel")
			return s
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			dir := t.TempDir()
			at := KeyPath(dir)
			sentinel := r.plant(t, at)

			err := testsupport.RunBounded(t, 5*time.Second, "EnsureKey over a planted "+r.name+" at the key's name", func() error {
				_, e := EnsureKey(dir)
				return e
			})
			testsupport.RequireRefusal(t, err, r.wording)
			if sentinel != nil {
				testsupport.AssertBytesUnchanged(t, at+".sentinel", sentinel)
			}
			testsupport.AssertKindStillThere(t, at, r.kind)
		})
	}
}
