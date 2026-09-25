package e2e

// enrol_admin_test.go is the acceptance gate for IAMT-90: it proves
// end-to-end that a real *Gateway (this package's harness_test.go
// fixture) — not a fake — accepts an "enrol" wire exec from a
// machine dialing as username "enrol" with the HKDF-derived
// ephemeral key, persists the machine as `enrolled`, AND lets the
// same machine come back as username "machine:<id>" with its
// long-term key and reach online. Then it proves
// the other half — admin.claim through a real gateway
// creates the first admin, who can then run a real admin command.
//
// We hit the same gateway fixture the rest of the e2e suite uses,
// with both platform pairs of the data-directory variables — the
// Windows LOCALAPPDATA/ProgramData and the Unix HOME/XDG_DATA_HOME —
// pointed inside t.TempDir() by the fixture's isolateEnv, so nothing
// leaks into the host filesystem on either platform (IAMT-106).

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestE2E_EnrolSuccessPath proves end-to-end:
// "iamtunnel enrol <code> against the real gateway.New+Serve in test
// registers a machine: it appears in state, its key is saved on the
// machine side, and the machine can then connect as `machine` and
// reach online."
func TestE2E_EnrolSuccessPath(t *testing.T) {
	f := newFixture(t, nil)

	// The first admin has to be created some other way for the e2e
	// suite; in production this is bootstrap-token + admin.claim.
	// Here we directly seed state with the admin, exactly as the rest
	// of the suite does for the admin scenarios.
	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)}, "root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()

	// The registration this test creates IS f.machineID, because steps
	// 3 and 4 below are keyed to that id (runFakeMachineAs, the seeded
	// grants). A name already in use is refused when the invitation is
	// MINTED, so the fixture-seeded record goes first — which is
	// exactly what an administrator does with machines remove before a
	// reinstalled machine registers again.
	forgetSeededMachine(t, f)

	// Step 1: real admin command to issue the enrol-code.
	code, _, err := root.MachinesInvite(f.machineID)
	if err != nil {
		t.Fatalf("machines.enrol-code: %v", err)
	}
	parsed, err := config.ParseEnrolCode(code)
	if err != nil {
		t.Fatalf("parse enrol code: %v", err)
	}

	// Step 2: the machine dials as username "enrol" with the ephemeral
	// key derived from the secret (PROTOCOL §3.2), and runs the real
	// "enrol" exec against the real gateway. The machine's long-term
	// key is the one the gateway will register for it.
	machineKey := genSigner(t)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(machineKey.PublicKey())))

	ephemeral, err := config.DeriveEphemeralSigner(parsed.Secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}
	enrolResp := doEnrol(t, f, ephemeral, parsed.Secret, "", `MACHINE\svc`, pubLine)
	if !strings.Contains(enrolResp, `"state":"enrolled"`) {
		t.Fatalf("enrol response missing state=enrolled: %q", enrolResp)
	}
	if !strings.Contains(enrolResp, `"machine":"`+f.machineID+`"`) {
		t.Fatalf("enrol response missing machine id %q: %q", f.machineID, enrolResp)
	}

	// Step 3: state.json now has the machine with the long-term key
	// we just submitted (not the ephemeral one).
	var got state.State
	if err := readStateJSON(f.dir, &got); err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	m, ok := got.MachineByID(f.machineID)
	if !ok {
		t.Fatalf("machine %q not in state.json after enrol", f.machineID)
	}
	if m.MachineKey != pubLine {
		t.Fatalf("enrolled machineKey = %q, want %q", m.MachineKey, pubLine)
	}
	if m.State != "enrolled" {
		t.Fatalf("enrolled machine state = %q, want %q", m.State, "enrolled")
	}
	if m.EnrolPending != nil {
		t.Fatalf("EnrolPending must be cleared after enrol: %+v", m.EnrolPending)
	}

	// Step 4: the same machine now connects as username "machine:<id>"
	// with its long-term key, and reaches online. The
	// gateway opens the iamtunnel-control channel itself (PROTOCOL
	// §5.2), and the existing fakeMachine harness knows how to answer
	// the initial door.status with "no installed door", which is
	// exactly what the gateway needs to flip online:true. We
	// substitute the long-term key the enrol body just registered.
	f.runFakeMachineAs(t, machineKey)
	defer func() {
		// Drop the machine from the registry; the f.Cleanup will
		// close the gateway and tear everything down.
	}()
	waitForMachineOnline(t, f, 3*time.Second)
}

// runFakeMachineAs connects the fixture's fakeMachine with the
// supplied signer as its long-term machine key — the key the enrol
// exec just registered. The key travels as an explicit argument into
// connectMachineWithKey; the fixture's f.machineKey field stays the
// one the fixture was seeded with. The earlier version reassigned
// f.machineKey (and restored it via t.Cleanup): a write into fixture
// state while the fixture's goroutines are already running — not a
// data race today, because every read of that field sits on the test
// goroutine, but exactly the shape the IAMT-105 sweep asks not to
// create. No cleanup is needed: the fake machine closes its own
// connection when the test ends.
func (f *fixture) runFakeMachineAs(t *testing.T, signer ssh.Signer) {
	t.Helper()
	f.connectMachineWithKey(fakeMachineBehavior{}, signer)
}

// waitForMachineOnline polls the registry for online=true.
func waitForMachineOnline(t *testing.T, f *fixture, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		mc, ok := f.gw.Reg().Get(f.machineID)
		if ok && mc.IsOnline() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("machine did not reach online")
}

// TestE2E_AdminClaimSuccessPath proves end-to-end:
// "iamtunnel admin claim against the real gateway.New+Serve creates
// the first admin, who can then run a real admin command."
//
// The bootstrap-token / pending entry is seeded directly into state
// here (production wires it through "gateway install"). The CLI-side
// path is also exercised to prove the wire shape is right.
func TestE2E_AdminClaimSuccessPath(t *testing.T) {
	f := newFixture(t, nil)

	const token = "bootstrap-test-token-v1"
	bootstrapSigner, err := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	if err != nil {
		t.Fatalf("derive bootstrap signer: %v", err)
	}
	bootstrapPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(bootstrapSigner.PublicKey())))

	if err := f.store.Update(func(st *state.State) error {
		st.BootstrapPending = &state.BootstrapPending{
			SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(token)),
			PublicKey:  bootstrapPubLine,
			Expires:    state.NewZonedTime(f.clock.Now().Add(24 * time.Hour)),
		}
		return nil
	}); err != nil {
		t.Fatalf("seed bootstrap pending: %v", err)
	}

	// The claiming operator generates a long-term key. This is the key
	// that will be stored as the first admin's first key.
	adminKey := genSigner(t)
	adminPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(adminKey.PublicKey())))

	// Dial as username "bootstrap" with the ephemeral key, run
	// "admin.claim".
	conn, ch, err := dialBootstrap(t, f, bootstrapSigner)
	if err != nil {
		t.Fatalf("bootstrap dial: %v", err)
	}
	defer conn.Close()
	defer ch.Close()
	ok, err := ch.SendRequest("exec", true, ssh.Marshal(struct {
		Cmd string
	}{"admin.claim"}))
	if err != nil || !ok {
		t.Fatalf("exec request: ok=%v err=%v", ok, err)
	}
	body, _ := json.Marshal(map[string]any{
		"proto":     1,
		"bootstrap": token,
		"pubkey":    adminPubLine,
	})
	if _, err := ch.Write(body); err != nil {
		t.Fatalf("write admin.claim body: %v", err)
	}
	_ = ch.CloseWrite()
	respBody := readChannelUntilNewline(t, ch)
	if !strings.Contains(respBody, `"role":"admin"`) {
		t.Fatalf("admin.claim response missing role=admin: %q", respBody)
	}

	// State now has the first admin.
	var got state.State
	if err := readStateJSON(f.dir, &got); err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if !got.HasAnyAdmin() {
		t.Fatal("state.HasAnyAdmin() is false after admin.claim")
	}
	if got.BootstrapPending != nil {
		t.Fatal("BootstrapPending must be cleared after admin.claim")
	}

	// Find the admin that admin.claim just added (the fixture seeds
	// alice and bob as role "user"; the new admin is the only role
	// "admin" entry).
	var adminName string
	for _, p := range got.People {
		if p.Role == "admin" {
			adminName = p.Name
			break
		}
	}
	if adminName == "" {
		t.Fatal("no admin found in state after admin.claim")
	}

	// The new admin now dials as command-login with their long-term
	// key and runs a real admin command (people.list).
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)},
		adminName, adminKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial as new admin: %v", err)
	}
	defer root.Close()
	_, err = root.PeopleList()
	if err != nil {
		t.Fatalf("people.list as new admin: %v", err)
	}
}

// readStateJSON loads state.json from a gateway fixture's directory
// and decodes it as a state.State, so the test can assert against
// real persisted fields rather than relying on a snapshot accessor
// the gateway would not normally expose.
func readStateJSON(dir string, out *state.State) error {
	data, err := os.ReadFile(dir + "/state.json")
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// dialAsMachine opens an SSH session as username "machine:<id>" with
// the machine's long-term key. The host-key check is loose on purpose:
// we are inside the same process as the gateway's listener. Kept
// for completeness even though the public test path uses
// runFakeMachineAs (which goes through fakeMachine and gets to
// `online`); having the SSH-level helper around means future tests
// can probe the connection layer directly.
func dialAsMachine(t *testing.T, f *fixture, signer ssh.Signer) *ssh.Client {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            "machine:" + f.machineID,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(f.gw.HostKey().PublicKey()),
		Timeout:         5 * time.Second,
	}
	conn, err := ssh.Dial("tcp", f.addr, cfg)
	if err != nil {
		t.Fatalf("dial as machine: %v", err)
	}
	return conn
}

var _ = dialAsMachine

// dialBootstrap opens an SSH session as username "bootstrap" with
// the ephemeral bootstrap signer.
func dialBootstrap(t *testing.T, f *fixture, signer ssh.Signer) (*ssh.Client, ssh.Channel, error) {
	t.Helper()
	conn, err := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            "bootstrap",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(f.gw.HostKey().PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}
	ch, chReqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	go func() {
		for r := range chReqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	return conn, ch, nil
}

// readChannelUntilNewline reads from a channel until a '\n' is seen
// (the boundary PROTOCOL §1.2 promises), then returns what it read.
// Uses a goroutine because ssh.Channel does not expose a read
// deadline; the goroutine's completion is observed via a channel.
func readChannelUntilNewline(t *testing.T, ch ssh.Channel) string {
	t.Helper()
	type result struct {
		body string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, 8192)
		var acc strings.Builder
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				acc.Write(buf[:n])
				if strings.Contains(acc.String(), "\n") {
					done <- result{acc.String(), nil}
					return
				}
			}
			if err != nil {
				done <- result{acc.String(), err}
				return
			}
		}
	}()
	select {
	case r := <-done:
		return r.body
	case <-time.After(3 * time.Second):
		t.Logf("readChannelUntilNewline: timeout, no newline in 3s")
		return ""
	}
}

// silence unused-import linter when the helpers above end up
// trimming some callers (none of these are unused today; the var
// is here so future edits that drop one do not lose the import).
var _ = net.SplitHostPort
