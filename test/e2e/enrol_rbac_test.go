package e2e

// enrol_rbac_test.go proves that the roles
// `enrol` and `bootstrap` are strictly limited to their one operation,
// nothing else. The enumeration is taken FROM THE GATEWAY ITSELF via
// gateway.CommandNames() — not from a hand-written list beside the
// test — so a command added to the gateway's command table later is
// automatically included in the sweep. Each entry is driven over a
// real SSH connection and the test asserts the refusal itself (the
// exec request comes back false or the JSON envelope carries
// ok:false / E_EXEC_UNKNOWN); a matrix that only fires the requests
// and ignores the answers would stay green even if a command were
// allowed through.
//
// The non-exec surface is enumerated too: non-session channels
// (iamtunnel-control, iamtunnel-target, direct-tcpip) must be rejected
// on both one-shot logins, and state.json must keep the pending entry
// afterwards (nothing in the sweep consumed it).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// execEnvelopeProbe mirrors the response envelope the gateway writes
// for exec results (PROTOCOL §1.2), far enough to read ok and error.code.
type execEnvelopeProbe struct {
	OK    bool `json:"ok"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// runCommandOnRoleLogin dials the gateway as username "enrol" or
// "bootstrap" (whichever signer/pending entry the fixture seeded),
// opens one session channel and runs one exec with the given command
// name. It returns the exec-request acknowledgement and the raw JSON
// envelope the gateway answered with (possibly empty when the exec
// request itself was rejected and nothing was written).
func runCommandOnRoleLogin(t *testing.T, f *fixture, dial func(t *testing.T, f *fixture, signer ssh.Signer) (*ssh.Client, error), signer ssh.Signer, cmd string) (ok bool, envelope string) {
	t.Helper()
	conn, err := dial(t, f, signer)
	if err != nil {
		t.Fatalf("role dial for %q: %v", cmd, err)
	}
	defer conn.Close()
	ch, _, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session for %q: %v", cmd, err)
	}
	reqOK, sErr := ch.SendRequest("exec", true, ssh.Marshal(struct {
		Cmd string
	}{cmd}))
	if sErr != nil {
		_ = ch.Close()
		t.Fatalf("send exec %q: %v", cmd, sErr)
	}
	resp := readChannelUntilNewline(t, ch)
	_ = ch.Close()
	return reqOK, resp
}

// requireRefused asserts the one refusal shape the one-shot logins may
// produce for a foreign command: the exec request is not acknowledged,
// and whatever JSON came back says ok:false with E_EXEC_UNKNOWN. An
// acknowledged exec, or an envelope with ok:true, or any other error
// code, is a matrix failure — a command leaked through.
func requireRefused(t *testing.T, cmd string, reqOK bool, envelope string) {
	t.Helper()
	if reqOK && !strings.Contains(envelope, `"ok":false`) {
		t.Fatalf("role ran command %q: exec acknowledged and no refusal envelope (resp: %q)", cmd, envelope)
	}
	if envelope == "" {
		// Exec rejected at the request layer with no envelope: that is
		// a refusal by construction.
		return
	}
	var probe execEnvelopeProbe
	if err := json.Unmarshal([]byte(envelope), &probe); err != nil {
		t.Fatalf("command %q produced an unparseable envelope %q: %v", cmd, envelope, err)
	}
	if probe.OK {
		t.Fatalf("role ran command %q: envelope says ok:true (resp: %q)", cmd, envelope)
	}
	if probe.Error == nil {
		t.Fatalf("command %q refused without an error body (resp: %q)", cmd, envelope)
	}
	if probe.Error.Code != "E_EXEC_UNKNOWN" {
		t.Fatalf("command %q was refused with %q, want E_EXEC_UNKNOWN (the one-shot login must not even recognise it), resp: %q",
			cmd, probe.Error.Code, envelope)
	}
}

// e2eFreshMachine is the name the enrol tests have their machine claim
// for itself. It must not be f.machineID: the fixture seeds that one as
// an already-verified machine, and since 1.3 an enrol that claims the
// name of a machine that already exists is refused outright — a second
// machine cannot take over an existing identity (runEnrolFromPending).
// Tests that want the re-registration case ask for it explicitly, with
// forgetSeededMachine.
const e2eFreshMachine = "vm-fresh"

// seedEnrolPending puts one unbound invitation (carrying the given
// secret) into state so the ephemeral key derived from that secret
// passes the SSH handshake as username "enrol".
//
// Before 1.3 this seeded Machine.EnrolPending — the invitation lived on
// the machine it had been minted for. Invitations are unbound now and
// live in state.PendingEnrolments; nothing reads Machine.EnrolPending
// any more, and lookup.go deliberately no longer admits its key
// (iamt336_legacy_enrolpending_test.go), so seeding the old shape would
// leave every caller's handshake refused for a reason that has nothing
// to do with what they are testing.
func seedEnrolPending(t *testing.T, f *fixture, secret string) ssh.Signer {
	t.Helper()
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}
	ephPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(eph.PublicKey())))
	if err := f.store.Update(func(st *state.State) error {
		st.PendingEnrolments = append(st.PendingEnrolments, state.PendingEnrolment{
			// The invitation carries the name (1.4). Tests that plant
			// one directly must say which registration it is for, or
			// redeeming it is refused for a reason that has nothing to
			// do with what they are testing.
			Name:       e2eFreshMachine,
			SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(secret)),
			PublicKey:  ephPub,
			Expires:    state.NewZonedTime(f.clock.Now().Add(time.Hour)),
		})
		return nil
	}); err != nil {
		t.Fatalf("seed enrol pending: %v", err)
	}
	return eph
}

// forgetSeededMachine drops the fixture's pre-seeded machine from state,
// which is what an administrator does with `machines remove` before a
// reinstalled machine can register again under its own name. Tests that
// need the enrolled machine to BE f.machineID — because everything
// downstream of them (runFakeMachineAs, waitForMachineOnline, the
// seeded grants) is keyed to that id — call this first.
func forgetSeededMachine(t *testing.T, f *fixture) {
	t.Helper()
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID == f.machineID {
				st.Machines = append(st.Machines[:i], st.Machines[i+1:]...)
				return nil
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("forget the seeded machine: %v", err)
	}
}

// TestE2E_EnrolRoleCannotRunAnyOtherCommand is the matrix proof for the
// role "enrol": every exec command the gateway itself knows (plus the
// bootstrap-only "admin.claim") must be refused with E_EXEC_UNKNOWN on
// an enrol login. Only "enrol" itself (covered end-to-end by scenario
// 04) is permitted.
func TestE2E_EnrolRoleCannotRunAnyOtherCommand(t *testing.T) {
	f := newFixture(t, nil)

	const secret = "rbac-test-secret"
	eph := seedEnrolPending(t, f, secret)

	// The command list comes from the gateway, not from this file.
	// Sanity-check the enumeration is the real table: it must include
	// the admin commands and must NOT contain "enrol" (the enrol exec
	// is served by the enrol login path, outside the command table).
	commands := gateway.CommandNames()
	if len(commands) == 0 {
		t.Fatal("gateway.CommandNames() returned an empty command list; the enumeration is vacuous")
	}
	for _, want := range []string{"whoami", "people.list", "machines.enrol-code", "gateway.status"} {
		found := false
		for _, c := range commands {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("gateway.CommandNames() does not contain %q; the enumeration does not reflect the real command table", want)
		}
	}
	for _, c := range commands {
		if c == "enrol" {
			t.Fatalf("gateway.CommandNames() contains %q; the enrol exec must not be a command-table entry", c)
		}
	}
	// The bootstrap-only command is not in the command table either,
	// but an enrol login must not run it, so it joins the sweep.
	matrix := append(append([]string{}, commands...), "admin.claim")

	for _, cmd := range matrix {
		// A fresh connection per command: handleEnrol serves exactly
		// one session channel per connection (PROTOCOL §3.2: one
		// connection, one operation), so a shared connection would
		// not test what the matrix says it tests.
		reqOK, envelope := runCommandOnRoleLogin(t, f, dialEnrolConn, eph, cmd)
		requireRefused(t, cmd, reqOK, envelope)
	}

	// Non-exec surface: the machine-tunnel channels must not open on
	// an enrol login. If one of them opened, the one-shot role would
	// be a second way into the control/target paths.
	for _, chType := range []string{"iamtunnel-control", "iamtunnel-target", "direct-tcpip"} {
		conn, err := dialEnrolConn(t, f, eph)
		if err != nil {
			t.Fatalf("enrol dial for channel %q: %v", chType, err)
		}
		ch, _, chErr := conn.OpenChannel(chType, nil)
		if chErr == nil {
			_ = ch.Close()
			conn.Close()
			t.Fatalf("enrol login opened a %q channel; the one-shot role reached a machine-tunnel surface", chType)
		}
		conn.Close()
	}

	// Sanity: the pending entry is still there — none of the refused
	// execs consumed it, so the RIGHT machine can still enrol.
	rawState, err := readFile(filepath.Join(f.dir, "state.json"))
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if !strings.Contains(string(rawState), `"pendingEnrolments"`) {
		t.Fatalf("the pending invitation disappeared after running refused execs:\n%s", string(rawState))
	}
}

// TestE2E_BootstrapRoleCannotRunAnyOtherCommand is the matrix proof for
// the role "bootstrap": every exec command the gateway knows (plus the
// enrol-only "enrol") must be refused on a bootstrap login; only
// "admin.claim" (covered by TestE2E_AdminClaimSuccessPath) is permitted.
func TestE2E_BootstrapRoleCannotRunAnyOtherCommand(t *testing.T) {
	f := newFixture(t, nil)

	const token = "rbac-bootstrap-token"
	bs, err := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	if err != nil {
		t.Fatalf("derive bootstrap: %v", err)
	}
	bsPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(bs.PublicKey())))
	if err := f.store.Update(func(st *state.State) error {
		st.BootstrapPending = &state.BootstrapPending{
			SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(token)),
			PublicKey:  bsPub,
			Expires:    state.NewZonedTime(f.clock.Now().Add(time.Hour)),
		}
		return nil
	}); err != nil {
		t.Fatalf("seed bootstrap pending: %v", err)
	}

	commands := gateway.CommandNames()
	if len(commands) == 0 {
		t.Fatal("gateway.CommandNames() returned an empty command list; the enumeration is vacuous")
	}
	matrix := append(append([]string{}, commands...), "enrol")

	for _, cmd := range matrix {
		reqOK, envelope := runCommandOnRoleLogin(t, f, dialBootstrapConn, bs, cmd)
		requireRefused(t, cmd, reqOK, envelope)
	}

	for _, chType := range []string{"iamtunnel-control", "iamtunnel-target", "direct-tcpip"} {
		conn, err := dialBootstrapConn(t, f, bs)
		if err != nil {
			t.Fatalf("bootstrap dial for channel %q: %v", chType, err)
		}
		ch, _, chErr := conn.OpenChannel(chType, nil)
		if chErr == nil {
			_ = ch.Close()
			conn.Close()
			t.Fatalf("bootstrap login opened a %q channel; the one-shot role reached a machine-tunnel surface", chType)
		}
		conn.Close()
	}

	rawState, err := readFile(filepath.Join(f.dir, "state.json"))
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if !strings.Contains(string(rawState), `"bootstrapPending"`) {
		t.Fatalf("BootstrapPending disappeared after running refused execs:\n%s", string(rawState))
	}
}

// dialEnrolConn opens an SSH connection as username "enrol" with the
// ephemeral signer; unlike dialEnrol, it returns only the *ssh.Client
// (no session channel) because the RBAC matrix opens one channel per
// tested command.
func dialEnrolConn(t *testing.T, f *fixture, signer ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	conn, err := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            "enrol",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(f.gw.HostKey().PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// dialBootstrapConn is the bootstrap counterpart of dialEnrolConn.
func dialBootstrapConn(t *testing.T, f *fixture, signer ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	conn, err := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            "bootstrap",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(f.gw.HostKey().PublicKey()),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// readFile is a thin os.ReadFile alias kept separate so tests that
// do not need anything else from os get a one-import surface.
func readFile(p string) ([]byte, error) {
	return os.ReadFile(p)
}
