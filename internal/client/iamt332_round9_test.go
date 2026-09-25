package client

// iamt332_round9_test.go — the planted-entry tests for this package's
// three data-file writers and its saved-connection reader (IAMT-332
// round 9, SPEC §3.1: the client directory is NOT exempt — a privileged
// run aimed at it by --data-dir / IAMTUNNEL_DATA_DIR / client_dir makes
// every name in it attacker-plantable).
//
// The rows plant at the names the OLD writers used and trusted: the
// predictable final+".tmp" temporaries (keys.go, knownhosts.go,
// store.go) and the final name itself (LoadConnection's read). The
// assertions are byte-identity of the sentinel and kind-identity of the
// plant — on the pre-round-9 tree every write row fails on its own
// assertion line, because the old flat write went through the plant.
// The refusal rows assert the contract wording instead of a type, so
// the files compile against the tree that had the bug (that is why
// they use testsupport.RefusalIn, not datafile.IsRefusal).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// round9Plant is one entry kind a plant can occupy a predictable name
// with. The symlink row skips on an unprivileged Windows without
// Developer Mode; the hard-link row is the Windows-native member of the
// class and needs no privilege at all.
type round9Plant struct {
	name string
	kind string // what Lstat must still report at the planted path
	// plant installs the entry at at and returns the sentinel bytes the
	// operation must leave unchanged (nil when there is no target file).
	plant func(t *testing.T, at string) []byte
}

func round9Plants() []round9Plant {
	return []round9Plant{
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

// runPlanted runs every plant against one write site. mk builds a FRESH
// directory per row (the plants must never share a directory: the entry
// from one row would collide with the next row's plant) and returns the
// predictable name the old writer used, the operation under test, and
// the post-write assertions. Each row requires: no error, the sentinel
// byte-identical, the plant still the entry it was, and the write's
// real result still delivered (want).
func runPlanted(t *testing.T, what string, mk func(t *testing.T) (at string, op func() error, want func(t *testing.T))) {
	t.Helper()
	for _, p := range round9Plants() {
		t.Run(p.name, func(t *testing.T) {
			at, op, want := mk(t)
			sentinel := p.plant(t, at)
			err := testsupport.RunBounded(t, 5*time.Second, what+" with a planted "+p.name+" at "+at, op)
			if err != nil {
				t.Fatalf("%s failed: %v — the writer must work around the plant, not fail or hang because of it", what, err)
			}
			if sentinel != nil {
				testsupport.AssertBytesUnchanged(t, at+".sentinel", sentinel)
			}
			testsupport.AssertKindStillThere(t, at, p.kind)
			want(t)
		})
	}
}

func round9Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer from key: %v", err)
	}
	return signer
}

// TestIAMT332R9EnsureKeyIgnoresPlantedTmpName pins generateKey's old
// predictable temporary (KeyPath(dir)+".tmp"): a plant there must be
// ignored, the key must still be generated at its real name, and
// nobody else's file may be written through.
func TestIAMT332R9EnsureKeyIgnoresPlantedTmpName(t *testing.T) {
	runPlanted(t, "EnsureKey", func(t *testing.T) (string, func() error, func(t *testing.T)) {
		dir := t.TempDir()
		final := KeyPath(dir)
		return final + ".tmp", func() error {
				_, err := EnsureKey(dir)
				return err
			}, func(t *testing.T) {
				st, err := os.Stat(final)
				if err != nil {
					t.Fatalf("the key was not generated: %v", err)
				}
				if !st.Mode().IsRegular() {
					t.Fatalf("the key at %s is not a regular file: %v", final, st.Mode())
				}
			}
	})
}

// TestIAMT332R9RecordKnownHostIgnoresPlantedTmpName pins recordKnownHost's
// old predictable temporary: the rewrite that runs on EVERY successful
// connection must neither write through a plant at the old tmp name nor
// fail because of it.
func TestIAMT332R9RecordKnownHostIgnoresPlantedTmpName(t *testing.T) {
	key := round9Signer(t).PublicKey()
	wantLine := []byte("gw.example " + string(ssh.MarshalAuthorizedKey(key)))
	runPlanted(t, "recordKnownHost", func(t *testing.T) (string, func() error, func(t *testing.T)) {
		dir := t.TempDir()
		final := KnownHostsPath(dir)
		return final + ".tmp", func() error {
				return recordKnownHost(final, "gw.example", key)
			}, func(t *testing.T) {
				got, err := os.ReadFile(final)
				if err != nil {
					t.Fatalf("the known_hosts record was not written: %v", err)
				}
				if string(got) != string(wantLine) {
					t.Fatalf("known_hosts content: got %q, want %q", got, wantLine)
				}
			}
	})
}

// TestIAMT332R9SaveConnectionIgnoresPlantedTmpName pins store.go's old
// predictable temporary the same way.
func TestIAMT332R9SaveConnectionIgnoresPlantedTmpName(t *testing.T) {
	cs := config.ConnString{Host: "gw.example", Port: 2222, Person: "ann", Fingerprint: "SHA256:test"}
	runPlanted(t, "SaveConnection", func(t *testing.T) (string, func() error, func(t *testing.T)) {
		dir := t.TempDir()
		return ConnectionPath(dir) + ".tmp", func() error {
				return SaveConnection(dir, cs, true)
			}, func(t *testing.T) {
				got, err := LoadConnection(dir)
				if err != nil {
					t.Fatalf("the saved connection did not survive: %v", err)
				}
				if got != cs {
					t.Fatalf("saved connection: got %+v, want %+v", got, cs)
				}
			}
	})
}

// TestIAMT332R9LoadConnectionRefusesPlantedFinal pins the read side: a
// plant at the saved connection's FINAL name is refused in words —
// never read through (the old os.ReadFile happily loaded the planted
// file's bytes) and never wedged on (a FIFO there blocked the reader
// forever).
func TestIAMT332R9LoadConnectionRefusesPlantedFinal(t *testing.T) {
	rows := []struct {
		name  string
		kind  string // the refusal wording the error must carry
		plant func(t *testing.T, at string)
	}{
		{"symlink", "is a symlink", func(t *testing.T, at string) {
			// The target is a PARSEABLE connection string, so the old
			// reader did not merely misparse the plant — it succeeded
			// and returned attacker-chosen JSON.
			target := at + ".mallory"
			mallory, err := json.Marshal(config.ConnString{Host: "evil.example", Port: 1, Person: "mallory", Fingerprint: "SHA256:evil"})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if werr := os.WriteFile(target, mallory, 0o600); werr != nil {
				t.Fatalf("write the planted target: %v", werr)
			}
			if serr := os.Symlink(target, at); serr != nil {
				t.Skipf("this host does not grant symlink creation (%v)", serr)
			}
		}},
		{"directory", "not a regular file", func(t *testing.T, at string) {
			testsupport.PlantDirectoryAt(t, at)
		}},
		{"fifo", "not a regular file", func(t *testing.T, at string) {
			testsupport.PlantFIFOAt(t, at)
		}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			dir := t.TempDir()
			r.plant(t, ConnectionPath(dir))
			err := testsupport.RunBounded(t, 5*time.Second, "LoadConnection on a planted "+r.name, func() error {
				_, e := LoadConnection(dir)
				return e
			})
			testsupport.RequireRefusal(t, err, r.kind)
		})
	}
}
