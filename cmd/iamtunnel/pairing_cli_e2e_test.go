package main

// pairing_cli_e2e_test.go is the PIN-pairing counterpart of the IAMT-131
// install→claim chain (IAMT-323/IAMT-326): two real CLI invocations in two
// real role directories, against one real gatewayServeForChain gateway.
// The admin machine runs "admin pairing start --json", the new admin's
// machine — which has no key and no saved connection of its own, only the
// printed reference and the PIN — runs "admin pair", and from that moment
// every ordinary "admin ..." command works from the new machine. Nothing
// here touches internal/admin directly: the wrappers are proven in
// test/e2e, this test proves the commands a human types.

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestIAMT326_PairingAdminChain(t *testing.T) {
	gwDir := t.TempDir()

	// The issuing admin exists before the gateway starts — production
	// gave him to "gateway install" + "admin claim" long ago; the chain
	// tests seed him the same way startTestGateway does.
	_, rootPriv, rootSig := genTestKey(t)
	rootPub := authorizedKeyLine(rootSig.PublicKey())
	rootFP, err := state.ComputeFingerprint(rootPub)
	if err != nil {
		t.Fatalf("compute root fingerprint: %v", err)
	}
	store, err := state.Open(gwDir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	err = store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "root", Role: "admin",
			Keys: []state.Key{{Fingerprint: rootFP, Pub: rootPub, Added: state.NewZonedTime(time.Now())}},
		})
		return nil
	})
	if err != nil {
		t.Fatalf("seed root admin: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// gatewayServeForChain, not gatewayServe: the pairing reference the
	// window prints must carry a real port, exactly like the other
	// commands that embed a dialable URL (the reason the helper exists).
	addr, _, stop := gatewayServeForChain(t, gwDir, "127.0.0.1")
	t.Cleanup(stop)
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("split gateway addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("gateway port: %v", err)
	}
	hostFP := hostkeyFingerprintOnDisk(t, gwDir)

	// The admin machine: the seeded key at the path EnsureKey reads from
	// plus the saved connection — a normal, already-working workstation.
	dir1 := t.TempDir()
	c1 := clientDirFor(t, dir1)
	writeClientKeyPEM(t, c1, rootPriv)
	if err := client.SaveConnection(c1, config.ConnString{Host: host, Port: port, Person: "root", Fingerprint: hostFP}, false); err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}

	// Step 1: the admin opens the window over the network. --json makes
	// the PIN and the reference machine-readable — the same output the
	// GUI's future "open pairing window" button will consume.
	out, errs, code := driveInDir(t, dir1, "admin", "pairing", "start", "--json")
	if code != exitOK {
		t.Fatalf("admin pairing start: code=%d out=%q errs=%q", code, out, errs)
	}
	var start struct {
		Pin     string `json:"pin"`
		Expires string `json:"expires"`
		Ref     string `json:"ref"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &start); err != nil {
		t.Fatalf("pairing start printed %q, not the promised JSON result: %v", out, err)
	}
	// The PIN is six decimal digits (SPEC §3.5) — checked literally, not
	// against the code's own constant.
	if len(start.Pin) != 6 {
		t.Fatalf("pairing start printed a %d-character PIN %q, want 6 digits", len(start.Pin), start.Pin)
	}
	for i := 0; i < len(start.Pin); i++ {
		if start.Pin[i] < '0' || start.Pin[i] > '9' {
			t.Fatalf("pairing start printed PIN %q with a non-digit at %d", start.Pin, i)
		}
	}
	if _, err := time.Parse(time.RFC3339, start.Expires); err != nil {
		t.Fatalf("pairing start expiry %q is not RFC 3339: %v", start.Expires, err)
	}
	ref, err := config.ParsePairingRef(start.Ref)
	if err != nil {
		t.Fatalf("parse the printed pairing ref %q: %v", start.Ref, err)
	}
	if ref.Host != host || ref.Port != port {
		t.Fatalf("printed ref points at %s:%d, want the gateway's own %s:%d", ref.Host, ref.Port, host, port)
	}
	if ref.Fingerprint != hostFP {
		t.Fatalf("printed ref fingerprint = %q, want the host key's %q", ref.Fingerprint, hostFP)
	}

	// Step 2: the new admin's machine. Fresh directory — no key, no
	// connection string, nothing but the two strings a side channel
	// carried over. "admin pair" generates the machine's own key
	// (EnsureKey), pairs it, and saves the connection in one breath.
	dir2 := t.TempDir()
	out, errs, code = driveInDir(t, dir2, "admin", "pair", start.Ref, start.Pin, "--json")
	if code != exitOK {
		t.Fatalf("admin pair: code=%d out=%q errs=%q", code, out, errs)
	}
	var paired struct {
		Person          string `json:"person"`
		Role            string `json:"role"`
		ConnectionSaved bool   `json:"connectionSaved"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &paired); err != nil {
		t.Fatalf("admin pair printed %q, not the promised JSON result: %v", out, err)
	}
	if paired.Person == "" || paired.Role != "admin" {
		t.Fatalf("admin pair result = %+v, want a person name and role admin", paired)
	}
	if !paired.ConnectionSaved {
		t.Fatalf("admin pair reports connectionSaved=false — the new machine would need the manual connect-string step the command promises to spare it")
	}

	// Step 3: what the command saved is a working identity for the
	// gateway the ref pointed at.
	cs, err := client.LoadConnection(clientDirFor(t, dir2))
	if err != nil {
		t.Fatalf("LoadConnection after admin pair: %v", err)
	}
	if cs.Person != paired.Person || cs.Host != host || cs.Port != port || cs.Fingerprint != hostFP {
		t.Fatalf("saved connection = %+v, want person %q at %s:%d with fingerprint %q", cs, paired.Person, host, port, hostFP)
	}

	// Step 4: the gateway's state has exactly the two admins and no
	// window — the burn happened in the same write as the creation.
	data, err := os.ReadFile(filepath.Join(gwDir, "state.json"))
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	var doc struct {
		People []struct {
			Name string `json:"name"`
			Role string `json:"role"`
			Keys []struct {
				Pub string `json:"pub"`
			} `json:"keys"`
		} `json:"people"`
		PairingPending *json.RawMessage `json:"pairingPending"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("state.json does not parse: %v", err)
	}
	if len(doc.People) != 2 {
		t.Fatalf("state.json has %d people (%v), want the two admins", len(doc.People), doc.People)
	}
	// The key that got registered is the machine's own EnsureKey key —
	// the one the next step authenticates with.
	keyBytes, err := os.ReadFile(client.KeyPath(clientDirFor(t, dir2)))
	if err != nil {
		t.Fatalf("read the paired machine's key: %v", err)
	}
	pairedSigner, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("parse the paired machine's key: %v", err)
	}
	pairedPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pairedSigner.PublicKey())))
	for _, p := range doc.People {
		if p.Role != "admin" {
			t.Fatalf("person %q has role %q after pairing, want admin", p.Name, p.Role)
		}
		switch p.Name {
		case "root":
		case paired.Person:
			if len(p.Keys) != 1 || p.Keys[0].Pub != pairedPub {
				t.Fatalf("paired person carries %+v, want exactly the machine's own key", p.Keys)
			}
		default:
			t.Fatalf("unexpected person %q in state.json", p.Name)
		}
	}
	if doc.PairingPending != nil {
		t.Fatal("pairingPending must be cleared in the same write that created the admin")
	}

	// Step 5: the closure of the whole feature — the new machine runs a
	// real admin command with nothing but what "admin pair" left behind.
	out, errs, code = driveInDir(t, dir2, "admin", "people", "list")
	if code != exitOK || !strings.Contains(out, "root") || !strings.Contains(out, paired.Person) {
		t.Fatalf("admin people list from the paired machine: code=%d out=%q errs=%q, want both admins listed", code, out, errs)
	}

	// Step 6: the window is burned — replaying the same reference and PIN
	// is refused at the handshake ("pairing" is an unknown login again),
	// which the CLI reports as an unreachable gateway, exit code of the
	// env class, and never as a success.
	out, errs, code = driveInDir(t, dir2, "admin", "pair", start.Ref, start.Pin, "--json")
	if code != exitEnv {
		t.Fatalf("replayed admin pair: code=%d out=%q errs=%q, want the env-class dial refusal", code, out, errs)
	}
	if !strings.Contains(errs, "could not reach the gateway") {
		t.Fatalf("replayed admin pair stderr = %q, want the dial refusal", errs)
	}
}
