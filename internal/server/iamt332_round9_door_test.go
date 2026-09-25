package server

// iamt332_round9_door_test.go — the planted-entry tests for the door
// status reader (IAMT-332 round nine). parseDiskDoorStatus reads the
// authorized_keys file by path to report "is a door installed" in the
// GUI, and the GUI is reachable with an attacker-chosen authorized_keys
// location (SPEC §3.1's environment control), so the name can be a
// plant. The old os.ReadFile read straight THROUGH a planted symlink —
// and the plant's content was parsed as door status, so the attacker
// chose what the GUI reported as installed. The reader now refuses the
// plant in the contract's words and the caller's existing "any error is
// no disk status" degradation turns that into the safe answer.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// forgedDoorLine produces one byte-for-byte valid door line the way
// winkeys.FormatLine does, keyed by a fresh key — the content a plant's
// target would hold if the attacker wanted the GUI to report a door
// installed. The old reader parsed exactly this through the plant.
func forgedDoorLine(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate the forged door key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("convert the forged door key: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(sshPub.Marshal())
	line := winkeys.Options + " ssh-ed25519 " + b64 + " " + winkeys.Marker + strings.Repeat("a1b2", 8)
	return []byte(line + "\n")
}

// TestIAMT332R9DoorStatusRefusesPlantedKeyFile pins the planted-name
// refusals of parseDiskDoorStatus: a symlink must be refused in words
// (the old code read through it and reported the attacker's door as
// installed), a directory or a FIFO must be refused as "not a regular
// file" (the old code answered with raw OS errors — or, on the FIFO,
// never answered at all). Every row runs under RunBounded: the no-hang
// rule is part of the contract being pinned.
func TestIAMT332R9DoorStatusRefusesPlantedKeyFile(t *testing.T) {
	for _, row := range []struct {
		name    string
		refusal string
		// plant sets up the plant at at and returns the bytes its target
		// holds (nil when there is no readable target).
		plant func(t *testing.T, at string) []byte
	}{
		{"symlink", "is a symlink", func(t *testing.T, at string) []byte {
			// The link aims at a forged door line, so the old reader did
			// not merely fail — it reported the attacker's door status.
			want := forgedDoorLine(t)
			if werr := os.WriteFile(at+".sentinel", want, 0o600); werr != nil {
				t.Fatalf("write the plant's target: %v", werr)
			}
			if serr := os.Symlink(at+".sentinel", at); serr != nil {
				t.Skipf("this host does not grant symlink creation (%v)", serr)
			}
			return want
		}},
		{"directory", "not a regular file", func(t *testing.T, at string) []byte {
			testsupport.PlantDirectoryAt(t, at)
			return nil
		}},
		{"fifo", "not a regular file", func(t *testing.T, at string) []byte {
			testsupport.PlantFIFOAt(t, at)
			return nil
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			at := filepath.Join(dir, "authorized_keys")
			want := row.plant(t, at)
			var (
				installed bool
				err       error
			)
			testsupport.RunBounded(t, 5*time.Second, "parseDiskDoorStatus on a planted "+row.name, func() error {
				installed, _, _, err = parseDiskDoorStatus(at, "")
				return nil
			})
			testsupport.RequireRefusal(t, err, row.refusal)
			if installed {
				t.Errorf("the door status reader reported a door installed from the content behind a planted %s — the plant's content must never be parsed", row.name)
			}
			if want != nil {
				testsupport.AssertBytesUnchanged(t, at+".sentinel", want)
			}
		})
	}
}
