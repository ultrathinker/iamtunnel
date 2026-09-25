package e2e

// pairing_admin_test.go is the PIN-pairing counterpart of
// TestE2E_AdminClaimSuccessPath (IAMT-323/IAMT-325/IAMT-326): against the
// real gateway.New+Serve, an existing admin opens a pairing window over the
// network (pairing.start), the new admin's machine parses the printed
// <host>:<port>#<fingerprint> reference, dials as username "pairing" with its
// OWN long-term key, and spends the PIN on the single "admin.pair" exec. The
// gateway must then: have the new admin in state.json, have burned the
// window in the same breath, refuse the replayed pairing login outright, and
// let the new admin run real admin commands with the key it just registered.
// Every step here runs through the same internal/admin wrappers the CLI and
// the GUI use — no raw channel I/O — so this is also the wire contract the
// IAMT-327 forms will drive.

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestE2E_AdminPairingSuccessPath(t *testing.T) {
	f := newFixture(t, nil)

	// The issuing admin: created directly in state here, exactly as the
	// rest of the e2e suite does (production has him from install/claim).
	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)}, "root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()

	// Step 1: the real admin command opens the window and prints the PIN
	// and the reference.
	start, err := root.PairingStart()
	if err != nil {
		t.Fatalf("pairing.start: %v", err)
	}
	if len(start.Pin) != 6 {
		t.Fatalf("pairing.start printed a %d-character PIN %q, want 6 digits", len(start.Pin), start.Pin)
	}

	// Step 2: the new admin's machine parses the reference exactly as
	// "iamtunnel admin pair" will. The fixture advertises 127.0.0.1:<real
	// port>, so the parsed peer must be the gateway itself, and the parsed
	// fingerprint must be the host key's - the checkable-before-the-PIN
	// property that keeps this role TOFU-free.
	ref, err := config.ParsePairingRef(start.Ref)
	if err != nil {
		t.Fatalf("parse pairing ref %q: %v", start.Ref, err)
	}
	// The fixture advertises 127.0.0.1 and the listener's own port, so the
	// parsed peer must come out exactly equal to the address the gateway is
	// serving - host and port in one comparison.
	if pairingAddr := ref.Host + ":" + strconv.Itoa(ref.Port); pairingAddr != f.addr {
		t.Fatalf("parsed ref points at %s, want the gateway's own address %s", pairingAddr, f.addr)
	}
	if ref.Fingerprint != gatewayFingerprintE2E(f) {
		t.Fatalf("parsed ref fingerprint = %q, want the gateway host key's %q", ref.Fingerprint, gatewayFingerprintE2E(f))
	}
	pairingPeer := admin.Peer{Addr: f.addr, Fingerprint: ref.Fingerprint}

	// Step 3: the new machine dials as username "pairing" with its own
	// long-term key - the key every later admin operation will
	// authenticate - and spends the PIN on admin.pair.
	newKey := genSigner(t)
	newPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newKey.PublicKey())))
	pairingConn, err := admin.Dial(pairingPeer, "pairing", newKey, 5*time.Second)
	if err != nil {
		t.Fatalf("pairing dial: %v", err)
	}
	res, err := pairingConn.PairClaim(start.Pin, newPubLine)
	if err != nil {
		t.Fatalf("admin.pair: %v", err)
	}
	_ = pairingConn.Close()
	if res.Role != "admin" {
		t.Fatalf("admin.pair role = %q, want admin", res.Role)
	}
	if res.Person == "" {
		t.Fatalf("admin.pair returned an empty person name")
	}

	// Step 4: state.json has the new admin and no window.
	var got state.State
	if err := readStateJSON(f.dir, &got); err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if !got.HasAnyAdmin() {
		t.Fatal("state.HasAnyAdmin() is false after admin.pair")
	}
	if got.PairingPending != nil {
		t.Fatal("PairingPending must be cleared in the same write that creates the admin")
	}
	found := false
	for _, p := range got.People {
		if p.Name == res.Person {
			found = true
			if p.Role != "admin" {
				t.Fatalf("paired person role = %q, want admin", p.Role)
			}
			if len(p.Keys) != 1 || p.Keys[0].Pub != newPubLine {
				t.Fatalf("paired person carries %+v, want exactly the presented key", p.Keys)
			}
		}
	}
	if !found {
		t.Fatalf("paired person %q not found in state.json", res.Person)
	}

	// Step 5: the new admin immediately runs a real admin command with the
	// key the pairing just registered - the whole point of the feature.
	asNew, err := admin.Dial(pairingPeer, res.Person, newKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial as the newly paired admin: %v", err)
	}
	defer asNew.Close()
	if _, err := asNew.PeopleList(); err != nil {
		t.Fatalf("people.list as the newly paired admin: %v", err)
	}

	// Step 6: the replayed pairing login is refused outright - the window
	// burned with the success, so the same PIN can never pair anyone else.
	if replayConn, derr := admin.Dial(pairingPeer, "pairing", newKey, 5*time.Second); derr == nil {
		_ = replayConn.Close()
		t.Fatal("replayed pairing dial succeeded after the window burned, want a handshake refusal")
	}
}
