package gateway

// IAMT-178 (THREATS §3.2, layer 1): the door's private key exists only
// in the gateway's memory and never lands on its disk -- not by itself,
// not inside a dump, not even as the public half (state.json does not
// serialize the door, events.jsonl carries at most doorId). This test
// is the canary that no future "convenient" debug dump or door
// persistence will pass quietly.

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// doorKeyMaterial returns every byte shape in which the door key could be
// recognized on disk: the raw ed25519 public half (it is also the tail of any
// dump of the raw private key, ed25519 priv = seed||pub), the marshaled SSH
// public blob and its authorized_keys line, plus the PEM block markers of a
// serialized private key. The raw private seed itself is not reachable
// through the ssh.Signer API — the pub-half check below still catches a raw
// private dump, because the public half is embedded in it byte-for-byte.
func doorKeyMaterial(signer ssh.Signer) [][]byte {
	blob := signer.PublicKey().Marshal()
	pub := blob[len(blob)-ed25519PubBytes:]
	return [][]byte{
		pub,
		blob,
		[]byte(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
		[]byte("OPENSSH PRIVATE KEY"),
		[]byte("PRIVATE KEY-----"),
	}
}

// ed25519PubBytes is the size of an ed25519 public key (RFC 8032).
const ed25519PubBytes = 32

// TestIAMT178_DoorPrivateKeyNeverReachesGatewayDisk opens a real door
// through the full session path (machine tunnel -> human shell), snapshots
// the signer out of the live machine connection while the door is open, and
// walks the gateway's whole data directory asserting that no file carries any
// recognizable shape of the door key. The scan repeats after the door closes,
// so a finalizer flushing key material at teardown is caught too.
func TestIAMT178_DoorPrivateKeyNeverReachesGatewayDisk(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	// Readiness -- as in door_lifecycle_events_test.go/iamt126:
	// connectMachine in the current fixture does NOT wait for online
	// (registration and the initial door.status run in parallel), a dial
	// before online gets an immediate denyMachineOffline and EOF on the
	// pty-req -- a PREPARATION failure, not the assertion under test.
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()

	hs := openHumanSession(t, client, f)
	hs.shell(t)

	const marker = "iamt178-door-open-marker"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readUntil(t, hs.ch, marker); !strings.Contains(got, marker) {
		t.Fatalf("echo did not contain marker: %q", got)
	}

	// The door must be open: a row on the machine, the signer alive in the
	// gateway's memory.
	installed, doorID := fm.doorInstalled()
	if !installed {
		t.Fatal("the door is not open -- the test never reached the live door key")
	}
	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("the machine is not in the gateway registry")
	}
	signer, signerDoorID := mc.currentDoorSigner()
	if signer == nil {
		t.Fatal("a live door without a key: currentDoorSigner returned nil while the door is open")
	}
	if signerDoorID != doorID {
		t.Fatalf("the signer belongs to door %q, the open door is %q", signerDoorID, doorID)
	}
	material := doorKeyMaterial(signer)

	// The gateway data directory in full: state.json, events.jsonl,
	// enrol-hmac.key, recordings/, lock files. RecordingBaseDir =
	// <root>/recordings.
	root := filepath.Dir(f.gw.cfg.RecordingBaseDir)

	scan := func(when string) {
		t.Helper()
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil // unreadable (lock) entries are skipped: we hunt the key, not permissions
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for _, m := range material {
				if bytes.Contains(data, m) {
					t.Errorf("%s: %s contains recognizable bytes of the door key (layer 1 of THREATS §3.2 broken), match size %d bytes", when, path, len(m))
					return nil
				}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("%s: walking the data directory: %v", when, walkErr)
		}
	}

	scan("while the door is open")

	// Close the session, wait for the door to close and repeat: recording
	// finalization and the door closing must not write anything extra to
	// the disk.
	//
	// There is NO "signer == nil after closing" assertion here and there
	// cannot be one: mc.doorKey is zeroed only when the machineConn
	// itself dies (machine_conn.go does not clear it when the door
	// closes), and zeroing keys in memory is a separate open improvement
	// of THREATS §8.7. IAMT-178 is about the DISK: even while the key
	// is alive in memory, not a single byte of its recognizable forms is
	// allowed to appear in the gateway's files.
	_ = hs.ch.Close()
	waitUntil(t, "the door did not close after the session ended", func() bool {
		inst, _ := fm.doorInstalled()
		return !inst
	})
	scan("after the door closed")
}
