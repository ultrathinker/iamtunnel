package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway"
	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// ============================================================================
// LIFE CYCLE
// ============================================================================

// 1. Full machine enrolment from scratch.
//
// Assertion: a machine absent from state.json cannot pass SSH
// authentication on the gateway and is refused at the handshake
// phase. Full enrolment from scratch via the `enrol` protocol (SPEC
// §3.4) is deferred to phase 3 (CLI roles and exec commands).
func TestScenario01_FullMachineEnrolment(t *testing.T) {
	f := newFixture(t, nil)

	// An attempt to connect a machine with a new, unregistered key
	unregisteredKey := genSigner(t)
	raw, err := dialHumanRaw(f.addr, "machine:unregistered-box", unregisteredKey)
	if err == nil {
		_ = raw.Close()
		t.Fatal("the gateway allowed an unregistered machine to connect")
	}
	if !strings.Contains(err.Error(), "handshake failed") && !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("expected an authentication error, got: %v", err)
	}

	t.Log("Scenario 1: an unregistered machine was correctly refused by the gateway.")
	t.Log("The full enrol wire protocol (SPEC §3.4: iamtunnel-enrol://... with a secret and requestedOsUser) is implemented in phase 3 (SPEC §10).")
}

// 2. The sshd probe fails — the machine stays enrolled but unverified;
// then the probe succeeds — it becomes verified.
//
// Assertion: a machine in the "enrolled" (unverified) state does not
// admit a human (ACL refusal DenyMachineUnverified), and its door does
// not open. After the transition to "verified", the gateway opens the
// door and admits the human to a session.
func TestScenario02_MachineEnrolledThenVerified(t *testing.T) {
	f := newFixture(t, nil)

	// Move the machine into the "enrolled" (unverified) state
	err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID == f.machineID {
				st.Machines[i].State = "enrolled"
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("update state to enrolled: %v", err)
	}

	fm := f.connectMachine(fakeMachineBehavior{})

	// An attempt to connect a human to a machine in the "enrolled" state
	c1, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer c1.Close()

	ch1, reqs1, err := c1.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go discardSSHRequests(reqs1)

	resp1 := readAll(t, ch1, 2*time.Second)
	if !strings.Contains(resp1, "Access to this machine is currently unavailable") {
		t.Fatalf("expected a refusal for an unverified machine, got: %q", resp1)
	}
	if fm.doorEverOpened() {
		t.Fatal("the door was opened for an unverified machine")
	}

	// Now the machine transitions to "verified"
	err = f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID == f.machineID {
				st.Machines[i].State = "verified"
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("update state to verified: %v", err)
	}

	// Reconnect the human — access should now be permitted
	c2, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial 2: %v", err)
	}
	defer c2.Close()

	hs2 := openHumanSession(t, c2)
	hs2.shell(t)

	const marker = "verified-probe-ok"
	if _, err := hs2.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readUntil(t, hs2.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("no echo received after the transition to verified: %q", got)
	}
	_ = hs2.ch.Close()

	if !fm.doorEverOpened() {
		t.Fatal("the door never opened after the machine transitioned to verified")
	}
}

// 3. Open the door, enter, record, close.
//
// Assertion: the full end-to-end happy path:
// 1) a confirmed door.open opens the door and installs the key;
// 2) the human enters, sees the recording banner, and their commands echo back;
// 3) the session ends, a confirmed door.close removes the door key;
// 4) the .cast recording file and .txt transcript are created;
// 5) RECORDING CONTENTS: what is displayed on screen is present in the recording;
// 6) the recording contains no extraneous data / untyped input.
// IAMT-96: State "verified" alone is not permission to open a door. A
// previous gateway may have left that state behind before OS-user proof was
// introduced; its pending verdict and missing verifiedOsUser must still stop
// a human before the first door.open. The legacy record has no
// requestedOsUser, so needsSSHDProbe cannot run on its tunnel and overwrite
// this test premise.
func TestIAMT96_VerifiedMachineWithPendingOSUserIsDeniedBeforeDoorOpen(t *testing.T) {
	f := newFixture(t, nil)

	configured := false
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID != f.machineID {
				continue
			}
			// State must stay verified: an "enrolled" state would only prove
			// the older guard rather than IAMT-96's OS-user guard.
			st.Machines[i].State = "verified"
			st.Machines[i].RequestedOSUser = ""
			st.Machines[i].OSUserStatus = state.OSUserStatusPending
			st.Machines[i].VerifiedOSUser = nil
			configured = true
			return nil
		}
		return nil
	}); err != nil {
		t.Fatalf("test setup error: transition the verified machine into pending OS-user proof: %v", err)
	}
	if !configured {
		t.Fatalf("test setup error: the fixture has no machine %q", f.machineID)
	}
	configuredState := f.store.Get()
	if m, ok := configuredState.MachineByID(f.machineID); !ok || m.State != "verified" || m.RequestedOSUser != "" || m.OSUserStatus != state.OSUserStatusPending || m.VerifiedOSUser != nil {
		t.Fatalf("test setup error: the fixture machine does not have state verified/empty/pending/nil: %+v", m)
	}

	fm := f.connectMachine(fakeMachineBehavior{})
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("test setup error: connect the human: %v", err)
	}
	defer client.Close()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("test setup error: open the human session channel: %v", err)
	}
	defer ch.Close()
	go discardSSHRequests(reqs)

	response := readAll(t, ch, 2*time.Second)
	if !strings.Contains(response, "Access to this machine is currently unavailable") {
		t.Fatalf("IAMT-96 assertion: verified machine with pending OS user admitted a human instead of refusing: %q", response)
	}
	if fm.doorEverOpened() {
		t.Fatal("IAMT-96 assertion: door opened for a verified machine whose OS user is still pending")
	}

	drops, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
	if err != nil {
		t.Fatalf("test setup error: read the session.drop log: %v", err)
	}
	deniedAsUnverified := false
	for _, drop := range drops {
		if drop.Actor == f.person && drop.Object == f.machineID && drop.Result == acl.DenyMachineUnverified.String() {
			deniedAsUnverified = true
			break
		}
	}
	if !deniedAsUnverified {
		t.Fatalf("IAMT-96 assertion: pending OS-user refusal was not recorded as %s", acl.DenyMachineUnverified)
	}
}

// IAMT-96: once a user is proved, the nested SSH login must use that proved
// name rather than the mutable/requested OSUser field. This test writes the
// distinct proof before connecting the tunnel; osUserStatus is already
// verified, so needsSSHDProbe does not run and cannot supply that proof.
func TestIAMT96_HumanSessionUsesVerifiedOSUser(t *testing.T) {
	f := newFixture(t, nil)
	requestedUser := `MACHINE\requested`
	provedUser := `MACHINE\proved`

	configured := false
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID != f.machineID {
				continue
			}
			st.Machines[i].State = "verified"
			st.Machines[i].OSUser = requestedUser
			st.Machines[i].RequestedOSUser = requestedUser
			st.Machines[i].VerifiedOSUser = &provedUser
			st.Machines[i].OSUserStatus = state.OSUserStatusVerified
			configured = true
			return nil
		}
		return nil
	}); err != nil {
		t.Fatalf("test setup error: set distinct requested and proved OS users: %v", err)
	}
	if !configured {
		t.Fatalf("test setup error: the fixture has no machine %q", f.machineID)
	}
	configuredState := f.store.Get()
	if m, ok := configuredState.MachineByID(f.machineID); !ok || m.State != "verified" || m.OSUser != requestedUser || m.RequestedOSUser != requestedUser || m.OSUserStatus != state.OSUserStatusVerified || m.VerifiedOSUser == nil || *m.VerifiedOSUser != provedUser {
		t.Fatalf("test setup error: the fixture machine does not store distinct requested and proved users: %+v", m)
	}

	f.connectMachine(fakeMachineBehavior{})
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("test setup error: connect the human: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client)
	hs.shell(t)
	const marker = "iamt-96-verified-os-user"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("test setup error: write the marker through the human session: %v", err)
	}
	if got := readUntil(t, hs.ch, marker); !strings.Contains(got, marker) {
		t.Fatalf("IAMT-96 assertion: human session under the proved OS user did not reach the target sshd: %q", got)
	}
	_ = hs.ch.Close()

	users := f.sshd.authenticatedUsers()
	if len(users) != 1 {
		t.Fatalf("test setup error: the fake target sshd recorded %d accepted nested logins, need exactly 1", len(users))
	}
	if users[0] != provedUser {
		t.Fatalf("IAMT-96 assertion: human session reached target sshd as %q, want verified OS user %q (not requested %q)", users[0], provedUser, requestedUser)
	}
}

func TestScenario03_DoorOpenEnterRecordClose(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()

	hs := openHumanSession(t, client)
	hs.shell(t)

	// Check the recording banner (SPEC §5.1)
	banner := readUntil(t, hs.ch, "This session is recorded")
	if !strings.Contains(banner, "This session is recorded") {
		t.Fatalf("recording banner missing; got: %q", banner)
	}

	const marker = "command-exec-scenario-3-marker-42"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readUntil(t, hs.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("marker echo not received: %q", got)
	}

	// The door must be installed while the session is active
	installed, _ := fm.doorInstalled()
	if !installed {
		t.Fatal("door not installed during the active session")
	}

	// Close the human session
	_ = hs.ch.Close()

	// The door must close after the session ends
	waitUntil(t, "door did not close after the session ended", func() bool {
		inst, _ := fm.doorInstalled()
		return !inst
	})

	// Check the transcript file (.txt)
	txt := waitForTranscript(t, f.recordingsDir())
	if !strings.Contains(txt, marker) {
		t.Fatalf("transcript does not contain the marker %q; got: %q", marker, txt)
	}

	// Check the asciicast file (.cast)
	cast := waitForCast(t, f.recordingsDir())
	if !strings.Contains(cast, marker) {
		t.Fatalf("asciicast .cast does not contain the marker %q; got: %q", marker, cast)
	}

	// Content check: verify the absence of anything that was never on screen
	const untypedSecret = "super-secret-password-never-typed-xyz987"
	if strings.Contains(txt, untypedSecret) || strings.Contains(cast, untypedSecret) {
		t.Fatalf("the recording contains data that was never on screen!")
	}

	// SPEC §6.5: asciicast v2 must not contain input ("i") events, only output ("o")
	lines := strings.Split(cast, "\n")
	for _, l := range lines {
		if strings.Contains(l, `,"i",`) {
			t.Fatalf("asciicast contains an 'i' input event, forbidden by SPEC §6.5: %s", l)
		}
	}
}

// 4. Replaying the enrolment code is refused.
//
// Assertion: the enrolment code is single-use; presenting the same
// code a second time is refused. This is the first scenario made
// possible after IAMT-90: the enrol code is now stored in state.json
// as EnrolPending, and "enrol" successfully burns it in a single
// atomic write.
//
// Here we:
//  1. Obtain an enrol code through the real gateway
//     (cmdMachinesEnrolCode).
//  2. Call enrol the first time — success, the machine becomes enrolled.
//  3. Read state.json and confirm that this machine's enrolPending is
//     gone (§3.2: "in a single atomic write, creates the enrolled
//     machine and removes the temporary public key").
//  4. Call enrol a second time with the same code — refused already
//     at the SSH handshake level, because after the secret is burned
//     the key is no longer known to the gateway (it lived in
//     EnrolPending.PublicKey).
func TestScenario04_ReplayEnrolCodeRejected(t *testing.T) {
	f := newFixture(t, nil)

	// An admin is needed to issue the enrol code. This is the first
	// (and only) time this scenario touches people.add — it is not
	// part of the assertion, but without an admin we cannot even
	// issue the code.
	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)}, "root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()

	// The scenario enrols a machine under the name f.machineID (steps
	// 4 and 5 count records by that name). As of 1.3, an in-use name
	// is refused at enrolment, so the fixture-seeded record is
	// removed here — exactly what an admin does with the machines
	// remove command before reinstalling a machine.
	forgetSeededMachine(t, f)

	// 1. Admin issues the code. Right after issuance, an invitation
	//    should appear in state.json. As of 1.3, it does not name the
	//    machine: the machine reports its own name and account at
	//    enrolment time (SPEC §3.4), so there is nothing to pass here.
	code, _, err := root.MachinesInvite(f.machineID)
	if err != nil {
		t.Fatalf("machines.enrol-code: %v", err)
	}
	parsed, err := config.ParseEnrolCode(code)
	if err != nil {
		t.Fatalf("parse enrol code: %v", err)
	}
	if parsed.Secret == "" {
		t.Fatal("enrol code has empty secret")
	}

	// Sanity check: right after issuance, the invitation is still
	// present in state.json (this is not yet a "replay"). As of 1.3
	// it lives in the shared pendingEnrolments list, not on the
	// machine record.
	rawState, rerr := os.ReadFile(filepath.Join(f.dir, "state.json"))
	if rerr != nil {
		t.Fatalf("read state.json: %v", rerr)
	}
	if !strings.Contains(string(rawState), `"pendingEnrolments"`) {
		t.Fatalf("state.json after machines.enrol-code does not contain pendingEnrolments:\n%s", string(rawState))
	}

	// 2. First presentation through the real enrol wire protocol: a
	//    real SSH session with the ephemeral ed25519 key (HKDF from
	//    the secret), a real "enrol" exec, a real response per §6.
	machineKey := genSigner(t)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(machineKey.PublicKey())))

	ephemeral, err := config.DeriveEphemeralSigner(parsed.Secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral signer: %v", err)
	}
	enrolResp := doEnrol(t, f, ephemeral, parsed.Secret, "", `MACHINE\svc`, pubLine)
	if !strings.Contains(enrolResp, `"state":"enrolled"`) {
		t.Fatalf("first enrol did not return state=enrolled: %q", enrolResp)
	}

	// 3. After a successful enrol, the invitation must NOT be present
	//    in state.json — §3.2 (the secret is burned). Checked on
	//    disk, not from the gateway's response.
	//    We look for secretHash: the one field that belongs to the
	//    invitation and appears nowhere else.
	rawState, rerr = os.ReadFile(filepath.Join(f.dir, "state.json"))
	if rerr != nil {
		t.Fatalf("read state.json: %v", rerr)
	}
	if strings.Contains(string(rawState), `"secretHash"`) {
		t.Fatalf("after a successful enrol, state.json still has the invitation:\n%s", string(rawState))
	}

	// 4. Presenting the same secret again. The SSH handshake refuses
	//    at PublicKeyCallback, because EnrolPending has already been
	//    cleared: the key is no longer known to the gateway. So here
	//    we treat the "replay" as refused already at the handshake
	//    level, with E_ENROL_SECRET_USED coming back through the SSH
	//    layer as an inability to authenticate. That is enough: the
	//    replayed secret does not create a second machine and leaves
	//    no trace in state.json (see above).
	ephemeral2, err := config.DeriveEphemeralSigner(parsed.Secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral 2: %v", err)
	}
	ephPub := ephemeral2.PublicKey()
	_, _, derr := dialEnrol(t, f, ephemeral2)
	if derr == nil {
		t.Fatal("replaying the enrol code passed the SSH handshake; a replay must not be possible")
	}
	if !strings.Contains(derr.Error(), "unable to authenticate") &&
		!strings.Contains(derr.Error(), "handshake failed") &&
		!strings.Contains(derr.Error(), "no auth methods") {
		t.Fatalf("the replay refusal came back with an unexpected error: %v", derr)
	}
	_ = ephPub

	// 5. Finally — state.json still has no invitation and exactly one
	//    machine, the one enrolled by the first attempt.
	rawState, rerr = os.ReadFile(filepath.Join(f.dir, "state.json"))
	if rerr != nil {
		t.Fatalf("read state.json (final): %v", rerr)
	}
	if strings.Contains(string(rawState), `"secretHash"`) {
		t.Fatalf("an invitation appeared in state.json after the replay:\n%s", string(rawState))
	}
	if strings.Count(string(rawState), `"id": "`+f.machineID+`"`) != 1 {
		t.Fatalf("expected exactly one machine with id=%q, state.json:\n%s", f.machineID, string(rawState))
	}
}

// addPersonForE2E is the e2e-fixture's twin of internal/gateway's
// addPerson: a helper that puts a person (with a known key) into the
// state store directly, so an admin command can be driven against a
// real gateway without going through people.add on the wire.
func addPersonForE2E(t *testing.T, f *fixture, name, role string, key ssh.Signer) {
	t.Helper()
	if err := f.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: name, Role: role,
			Keys: []state.Key{{
				Fingerprint: fingerprintOf(t, key.PublicKey()),
				Pub:         authorizedLine(key.PublicKey()),
				Added:       state.NewZonedTime(f.clock.Now()),
			}},
		})
		return nil
	}); err != nil {
		t.Fatalf("add person %s: %v", name, err)
	}
}

// gatewayFingerprintE2E returns the gateway host-key fingerprint as
// the canonical "SHA256:..." string, the only form admin.Peer accepts.
func gatewayFingerprintE2E(f *fixture) string {
	sum := sha256.Sum256(f.gw.HostKey().PublicKey().Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// dialEnrol opens an SSH session as username "enrol" with the given
// (ephemeral) signer. Returns the underlying client and the session
// channel; the caller is responsible for closing both.
func dialEnrol(t *testing.T, f *fixture, signer ssh.Signer) (*ssh.Client, ssh.Channel, error) {
	t.Helper()
	conn, err := ssh.Dial("tcp", f.addr, &ssh.ClientConfig{
		User:            "enrol",
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

// doEnrol runs the enrol exec and returns the response body (one JSON
// line). On wire-level errors the test is failed; on protocol-level
// refusals the body still comes back, so the caller can inspect the
// error code.
func doEnrol(t *testing.T, f *fixture, ephemeral ssh.Signer, secret, machine, osUser, machineKey string) string {
	t.Helper()
	conn, ch, err := dialEnrol(t, f, ephemeral)
	if err != nil {
		t.Fatalf("enrol dial: %v", err)
	}
	defer conn.Close()
	defer ch.Close()
	ok, err := ch.SendRequest("exec", true, ssh.Marshal(struct {
		Cmd string
	}{"enrol"}))
	if err != nil || !ok {
		t.Fatalf("send exec: ok=%v err=%v", ok, err)
	}
	body, _ := json.Marshal(map[string]any{
		"proto":      1,
		"secret":     secret,
		"machine":    machine,
		"osUser":     osUser,
		"machineKey": machineKey,
	})
	if _, err := ch.Write(body); err != nil {
		t.Fatalf("write enrol body: %v", err)
	}
	_ = ch.CloseWrite()
	// Read until EOF or timeout. ssh.Channel does not expose a read
	// deadline, so a short overall budget is used instead. The server
	// closes the channel as soon as it has written the JSON response.
	buf := make([]byte, 8192)
	var acc strings.Builder
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.Conn // nothing
		n, rerr := ch.Read(buf)
		if n > 0 {
			acc.Write(buf[:n])
			// A single JSON object terminated by '\n' is the full response.
			if acc.Len() > 0 && strings.Contains(acc.String(), "\n") {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	return acc.String()
}

// ============================================================================
// WHO GETS IN
// ============================================================================

// 5. Eight keys presented, the correct one last — admitted.
//
// Assertion: the SSH client presents 7 unknown keys, and only the 8th is
// the person's registered key. A gateway with ServerConfig.MaxAuthTries = 32
// does not cut the session off after 6 attempts (OpenSSH's default), and
// successfully authenticates the human on the 8th key.
func TestScenario05_EightKeysPresentedLastKeySucceeds(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})

	// Generate 7 bogus keys, none registered with the gateway
	keys := make([]ssh.Signer, 8)
	for i := 0; i < 7; i++ {
		keys[i] = genSigner(t)
	}
	// The 8th key is Alice's correct, registered key
	keys[7] = f.personKey

	client, err := dialHuman(t, f.addr, f.person, f.machineID, keys...)
	if err != nil {
		t.Fatalf("authentication with 8 keys (correct one last) failed: %v", err)
	}
	defer client.Close()

	hs := openHumanSession(t, client)
	hs.shell(t)

	const marker = "eight-keys-success"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readUntil(t, hs.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("no echo received: %q", got)
	}
	_ = hs.ch.Close()
}

// 6. Two different people on one machine.
//
// Assertion: Alice and Bob connect to the same vm1 machine at the same
// time. Exactly one shared door opens. When Alice disconnects, the door
// stays open because Bob's session is still active. The door closes only
// after Bob disconnects. Each person gets their own independent recording.
func TestScenario06_TwoHumansShareOneDoor(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})

	// Alice connects
	cAlice, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("alice dial: %v", err)
	}
	defer cAlice.Close()
	hsAlice := openHumanSession(t, cAlice)
	hsAlice.shell(t)

	// Bob connects
	cBob, err := dialHuman(t, f.addr, f.bob, f.machineID, f.bobKey)
	if err != nil {
		t.Fatalf("bob dial: %v", err)
	}
	defer cBob.Close()
	hsBob := openHumanSession(t, cBob)
	hsBob.shell(t)

	// Both sessions run in parallel
	const aliceMarker = "alice-session-6"
	const bobMarker = "bob-session-6"

	if _, err := hsAlice.ch.Write([]byte(aliceMarker + "\n")); err != nil {
		t.Fatalf("alice write: %v", err)
	}
	if _, err := hsBob.ch.Write([]byte(bobMarker + "\n")); err != nil {
		t.Fatalf("bob write: %v", err)
	}

	if !strings.Contains(readUntil(t, hsAlice.ch, aliceMarker), aliceMarker) {
		t.Fatal("no echo received for Alice")
	}
	if !strings.Contains(readUntil(t, hsBob.ch, bobMarker), bobMarker) {
		t.Fatal("no echo received for Bob")
	}

	// Alice closes her session
	_ = hsAlice.ch.Close()

	// The door MUST stay open, since Bob's session is still active
	time.Sleep(50 * time.Millisecond)
	installed, _ := fm.doorInstalled()
	if !installed {
		t.Fatal("the door closed while Bob's session was still active!")
	}

	// Bob closes his session
	_ = hsBob.ch.Close()

	// Now the door should close
	waitUntil(t, "the door did not close after both users disconnected", func() bool {
		inst, _ := fm.doorInstalled()
		return !inst
	})
}

// 7. A tampered key blob is refused.
//
// Assertion: if the client sends the user's valid public key but signs the
// request with a different/mismatched private key, the gateway refuses
// authentication; the machine's door never opens.
func TestScenario07_TamperedKeyBlobRejected(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})

	// Build a tampered signer: Alice's public key, but signed with a stranger's key
	strangerKey := genSigner(t)
	tamperedSigner := &tamperedSignerHelper{
		pub:  f.personKey.PublicKey(),
		priv: strangerKey,
	}

	client, err := dialHuman(t, f.addr, f.person, f.machineID, tamperedSigner)
	if err == nil {
		_ = client.Close()
		t.Fatal("the gateway admitted a client with a tampered key/signature!")
	}

	if fm.doorEverOpened() {
		t.Fatal("the door was opened for a tampered-key login attempt!")
	}
}

type tamperedSignerHelper struct {
	pub  ssh.PublicKey
	priv ssh.Signer
}

func (s *tamperedSignerHelper) PublicKey() ssh.PublicKey { return s.pub }
func (s *tamperedSignerHelper) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.priv.Sign(rand, data)
}

// 8. A wrong machine sshd host key is refused.
//
// Assertion: if the target sshd on the machine presents a host key that
// does not match the sshdHostKey pinned in state.json, the gateway
// immediately tears down the nested connection, the human gets refused
// with "Access to this machine is currently unavailable", and no session
// to the target shell is opened.
func TestScenario08_WrongMachineSSHDHostKeyRejected(t *testing.T) {
	// The wrong host key is set by the fixture's CONSTRUCTOR: the fake
	// sshd presents it from the very first connection (IAMT-105). The
	// previous order — newFixture, then assigning f.sshd.signer =
	// wrongSigner — raced the field against the live conn goroutine
	// (the race detector caught this on Linux), and the worst outcome
	// was not a panic but a silently green scenario: if conn managed
	// to read the old key first, the machine would present a key
	// matching the pinned one, leaving nothing to refuse.
	wrongSigner := genSigner(t)
	f := newFixtureOpts(t, fixtureOpts{SSHDPresentedKey: wrongSigner}, nil)

	f.connectMachine(fakeMachineBehavior{})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()

	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go discardSSHRequests(reqs)

	resp := readAll(t, ch, 2*time.Second)
	if !strings.Contains(resp, "Access to this machine is currently unavailable") {
		t.Fatalf("expected a refusal on host key mismatch, got: %q", resp)
	}
}

// 9. A second server on the same machine is refused.
//
// Assertion: per SPEC §3.2 and PROTOCOL §5 ("A second live instance of the
// same machine is refused with E_MACHINE_ALREADY_ONLINE; a reconnect
// confirmed as the same machine displaces the old conn..."), an attempt to
// run a second simultaneous server for the same machine should be refused.
//
// IMPLEMENTATION DEFECT: in the current internal/gateway/machine_role.go code:
//
//	if old, had := g.reg.register(mc); had {
//	    old.teardown("reconnect")
//	}
//
// the gateway unconditionally treats ANY new connection as a reconnect and
// displaces the old connection, never returning a refusal to the second server.
func TestScenario09_SecondServerSameMachineRejected(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})

	raw, err := net.DialTimeout("tcp", f.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial duplicate machine: %v", err)
	}
	defer raw.Close()
	duplicate, _, _, err := ssh.NewClientConn(raw, f.addr, &ssh.ClientConfig{
		User:            "machine:" + f.machineID,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(f.machineKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		defer duplicate.Close()
		waitUntil(t, "second machine transport was not closed", func() bool {
			_, _, requestErr := duplicate.SendRequest("keepalive@iamtunnel", true, nil)
			return requestErr != nil
		})
	}

	waitUntil(t, "duplicate rejection was not written to the journal", func() bool {
		eventsFound, _, readErr := f.log.Read(events.Filter{Types: []events.EventType{events.EventMachineRejected}})
		if readErr != nil {
			t.Fatalf("read event log: %v", readErr)
		}
		for _, event := range eventsFound {
			if event.Actor == f.machineID && event.Result == "E_MACHINE_ALREADY_ONLINE" {
				return true
			}
		}
		return false
	})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial through original machine: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client)
	hs.shell(t)
	const marker = "first-machine-remained-online"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write through original machine: %v", err)
	}
	if got := readUntil(t, hs.ch, marker); !strings.Contains(got, marker) {
		t.Fatalf("original machine stopped serving traffic after duplicate: %q", got)
	}
}

// ============================================================================
// WHEN TO STOP ADMITTING
// ============================================================================

// 10. Grant expires during the session.
//
// Assertion: per SPEC §6.4 and acl/acl.go ("SweepExpired runs on the gateway's
// one-second timer... SPEC 6.4 wants expiry to bite without noticeable delay"),
// when a grant's validity expires during an active session, the session
// must be closed by the gateway immediately.
//
// IMPLEMENTATION DEFECT: gateway.go lacks a background ticker that calls
// acl.Engine.SweepExpired(now). Because of this, the session is not closed
// automatically when the deadline arrives.
func TestScenario10_GrantExpiresDuringSession(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client)
	hs.shell(t)

	// No request, connection change, or admin action follows this point: the
	// gateway's own timer is the only event that may close the live session.
	f.clock.Advance(2 * time.Hour)
	text := readAll(t, hs.ch, 3*time.Second)
	if !strings.Contains(text, "grant expired") {
		t.Fatalf("expiry did not close the human session with a clear reason: %q", text)
	}
	// The transcript appears only when the recorder has finalized; a merely
	// abandoned in-memory recording would leave no completed artifact.
	_ = waitForTranscript(t, f.recordingsDir())
	waitUntil(t, "door stayed open after grant expiry", func() bool {
		installed, _ := fm.doorInstalled()
		return !installed
	})
	waitUntil(t, "expiry reason was not written to the journal", func() bool {
		eventsFound, _, readErr := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
		if readErr != nil {
			t.Fatalf("read event log: %v", readErr)
		}
		for _, event := range eventsFound {
			if event.Actor == f.person && event.Object == f.machineID && event.Result == "access expired" {
				return true
			}
		}
		return false
	})
	closeDone := make(chan error, 1)
	go func() { closeDone <- f.gw.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Gateway.Close after expiry sweep: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Gateway.Close did not stop the expiry worker promptly")
	}
}

// 11. Access is revoked during the session.
//
// Assertion: revoking a grant during an active session closes it immediately.
//
// The scenario follows the same path as a real administrator: a separate
// TCP+SSH connection with the admin role and an exec "grants.revoke"
// command through admin.Conn (PROTOCOL §1.2). No direct calls into
// acl.Engine, no f.store.Update from the test, other than to pre-seed
// people/grants.
//
// Covers items 4-7 of this scenario:
//   - "immediately" = one or two hops inside the gateway; revoke is
//     synchronous (Engine.Revoke marks the grant and kills sessions
//     under a single mutex, see internal/gateway/acl/acl.go), the
//     notification runs on a separate goroutine and writes to the
//     human's channel, so the test checks that readAll completes
//     within 3 seconds — otherwise the test **fails on timeout**
//     rather than hanging.
//     This is **faster** than the expiry timer's `sweepExpired`
//     (1-second period, IAMT-81): revoke is a synchronous event,
//     expiry is an event the ticker must notice;
//   - "distinguish revocation from expiry": the human sees "access
//     revoked" (not "...expired"), and the journal shows
//     Result = "access revoked by administrator";
//   - cascade: Alice is revoked, Bob keeps working — the door does not
//     close until Bob disconnects;
//   - session recording: .cast and .txt are finalized, not truncated,
//     and contain the data that was on screen (the marker), not garbage.
func TestScenario11_RevokeDuringSession(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})

	// Alice opens a live session and writes a marker — it will land in her recording.
	cAlice, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("alice dial: %v", err)
	}
	defer cAlice.Close()
	hsAlice := openHumanSession(t, cAlice)
	hsAlice.shell(t)

	const aliceMarker = "alice-marker-before-revoke-11"
	if _, err := hsAlice.ch.Write([]byte(aliceMarker + "\n")); err != nil {
		t.Fatalf("alice write: %v", err)
	}
	if got := readUntil(t, hsAlice.ch, aliceMarker); !strings.Contains(got, aliceMarker) {
		t.Fatalf("alice did not receive her marker echo before revoke: %q", got)
	}

	// Bob opens his own live session in parallel — the cascading revoke must
	// not touch him (IAMT-72 covers this for person/machine.removed; here we
	// check that a direct grants.revoke also does not close someone else's session).
	cBob, err := dialHuman(t, f.addr, f.bob, f.machineID, f.bobKey)
	if err != nil {
		t.Fatalf("bob dial: %v", err)
	}
	defer cBob.Close()
	hsBob := openHumanSession(t, cBob)
	hsBob.shell(t)

	const bobMarker = "bob-marker-before-revoke-11"
	if _, err := hsBob.ch.Write([]byte(bobMarker + "\n")); err != nil {
		t.Fatalf("bob write: %v", err)
	}
	if got := readUntil(t, hsBob.ch, bobMarker); !strings.Contains(got, bobMarker) {
		t.Fatalf("bob did not receive his marker echo before revoke: %q", got)
	}

	// Wait for both sessions to become live — observed via the journal: the
	// fixture writes session.start, and that is the public way to "learn a
	// session is live", the same one available to an administrator through
	// sessions.active. Without this we would be testing revoke against a
	// session not yet registered in the Engine.
	waitUntil(t, "alice/bob sessions did not become active", func() bool {
		evs, _, rerr := f.log.Read(events.Filter{
			Types: []events.EventType{events.EventSessionStart},
		})
		if rerr != nil {
			return false
		}
		aliceLive, bobLive := false, false
		for _, ev := range evs {
			if ev.Object != f.machineID {
				continue
			}
			switch ev.Actor {
			case f.person:
				aliceLive = true
			case f.bob:
				bobLive = true
			}
		}
		return aliceLive && bobLive
	})

	// Add admin root and open a separate admin connection — through the same
	// client the real "iamtunnel admin grants revoke" CLI uses.
	rootKey := genSigner(t)
	if err := f.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "root", Role: "admin",
			Keys: []state.Key{{Fingerprint: fingerprintOf(t, rootKey.PublicKey()), Pub: authorizedLine(rootKey.PublicKey()), Added: state.NewZonedTime(f.clock.Now())}},
		})
		return nil
	}); err != nil {
		t.Fatalf("add admin root: %v", err)
	}
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: auth.Fingerprint(f.hostKey.PublicKey())},
		"root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial as root: %v", err)
	}
	defer root.Close()

	// Revoke through a real exec channel, as an administrator would.
	killed, err := root.GrantsRevoke(f.person, f.machineID)
	if err != nil {
		t.Fatalf("grants.revoke: %v", err)
	}
	if killed != 1 {
		t.Fatalf("grants.revoke terminatedSessions = %d, want 1 (alice only)", killed)
	}

	// As soon as GrantsRevoke returns, the gateway has already sent out
	// notifications; readAll waits for EOF on the channel with a 3-second
	// timeout — this is the "immediately" bound we justify above (see the
	// test's comment).
	text := readAll(t, hsAlice.ch, 3*time.Second)
	if !strings.Contains(text, "grant was revoked") {
		t.Fatalf("alice did not receive a clear revocation message; got: %q", text)
	}
	if strings.Contains(text, "grant expired") {
		t.Fatalf("alice received an expiry message instead of a revocation one; got: %q", text)
	}

	// Alice's session recording is finalized — revocation is a normal event,
	// not a crash, so the recording closes cleanly: .cast and .txt exist
	// (waitFor* guarantees the file appears on disk) and contain the data
	// that was on screen (Alice's marker), not garbage.
	cast := waitForCastContaining(t, f.recordingsDir(), aliceMarker)
	if !strings.Contains(cast, aliceMarker) {
		t.Fatalf("alice's recording does not contain her marker %q: %s", aliceMarker, cast)
	}
	txt := waitForTranscriptContaining(t, f.recordingsDir(), aliceMarker)
	if !strings.Contains(txt, aliceMarker) {
		t.Fatalf("alice's transcript does not contain her marker %q: %s", aliceMarker, txt)
	}

	// The journal contains a session.drop for Alice with reason "revoked", not "expired".
	waitUntil(t, "no session.drop for alice with Result=\"access revoked by administrator\" in the journal", func() bool {
		evs, _, rerr := f.log.Read(events.Filter{
			Types: []events.EventType{events.EventSessionDrop},
			Actor: f.person,
		})
		if rerr != nil {
			t.Fatalf("read event log: %v", rerr)
		}
		for _, ev := range evs {
			if ev.Object == f.machineID && ev.Result == acl.DenyGrantRevoked.String() {
				return true
			}
		}
		return false
	})

	// Bob keeps working (the cascade is not broken): traffic still flows,
	// the marker echoes back; the door is still installed because Bob is
	// still inside.
	const bobMarkerAfter = "bob-marker-after-revoke-of-alice"
	if _, err := hsBob.ch.Write([]byte(bobMarkerAfter + "\n")); err != nil {
		t.Fatalf("bob write after revoke: %v", err)
	}
	if got := readUntil(t, hsBob.ch, bobMarkerAfter); !strings.Contains(got, bobMarkerAfter) {
		t.Fatalf("bob did not receive an echo after alice's revoke: %q", got)
	}
	if installed, _ := fm.doorInstalled(); !installed {
		t.Fatal("the door closed while bob was still in his session")
	}

	// Bob disconnects — now the door closes.
	_ = hsBob.ch.Close()
	waitUntil(t, "the door did not close after bob disconnected", func() bool {
		installed, _ := fm.doorInstalled()
		return !installed
	})

	// Revoking the same (now already-revoked) grant again — a clean
	// E_NOT_FOUND, not a panic and not a silent success (extra protection
	// against double handling in the product code).
	if _, err := root.GrantsRevoke(f.person, f.machineID); err == nil {
		t.Fatal("repeat grants.revoke on an already-revoked grant: expected a refusal, got success")
	}
}

// 12. Keepalive timeout.
//
// Assertion: if the machine stops responding to keepalive@iamtunnel, once
// the allowed number of misses is exceeded the gateway tears down the
// connection to the machine, closes the human's session, and removes the
// machine from the active registry.
func TestScenario12_KeepaliveTimeoutClosesSession(t *testing.T) {
	f := newFixture(t, func(cfg *gateway.Config) {
		cfg.Keepalive = sshx.Keepalive{Interval: 80 * time.Millisecond, MaxMisses: 2}
	})
	// The machine responds to keepalive at first: otherwise the gateway's
	// deadline (80ms x 2) races the session setup itself, rather than
	// exercising it.
	fm := f.connectMachine(fakeMachineBehavior{})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	hs := openHumanSession(t, client)
	hs.shell(t)

	// Now the machine stops responding — while the session is live.
	fm.goSilent()

	// Once keepalive expires (80ms * 2 = ~160-200ms), the human's session should tear down
	waitUntil(t, "the human session did not close on keepalive timeout", func() bool {
		_, err := hs.ch.SendRequest("window-change", true, sshx0())
		return err != nil
	})
}

// ============================================================================
// WHEN SOMETHING BREAKS
// ============================================================================

// 13. The tunnel drops mid-session.
//
// Assertion: on a sudden TCP connection failure between the machine and the
// gateway, the human's session does not hang forever, but ends immediately.
func TestScenario13_TunnelDropMidSessionCleansUp(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	hs := openHumanSession(t, client)
	hs.shell(t)

	// Tear down the machine's transport mid-session
	fm.close()

	// The human's channel must close immediately
	waitUntil(t, "the human session hung after the machine's tunnel dropped", func() bool {
		_, err := hs.ch.SendRequest("window-change", true, sshx0())
		return err != nil
	})
}

// 14. The machine reconnects: the old connection is evicted, no dead lines
// remain in the key file.
//
// Assertion: on a machine reconnect, the old transport connection is
// evicted and closed by the gateway; the new connection starts by checking
// door.status, and no dangling door keys remain on the machine.
func TestScenario14_MachineReconnectEvictsOldCleanKeys(t *testing.T) {
	f := newFixture(t, nil)
	fm1 := f.connectMachine(fakeMachineBehavior{})

	// Reconnect the same machine
	fm1.close()
	waitUntil(t, "the old machine connection did not end before the reconnect", func() bool {
		eventsFound, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventMachineDisconnected}})
		if err != nil {
			t.Fatalf("read event log: %v", err)
		}
		return len(eventsFound) > 0
	})
	fm2 := f.connectMachine(fakeMachineBehavior{})
	waitUntil(t, "the reconnect was not distinguishably recorded in the journal", func() bool {
		eventsFound, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventMachineConnected}})
		if err != nil {
			t.Fatalf("read event log: %v", err)
		}
		for _, event := range eventsFound {
			if event.Actor == f.machineID && event.Result == "reconnected" {
				return true
			}
		}
		return false
	})

	// The first connection's transport must be closed by the gateway
	waitUntil(t, "the old machine connection was not closed on reconnect", func() bool {
		_, _, err := fm1.conn.SendRequest("keepalive@iamtunnel", true, nil)
		return err != nil
	})

	// On the new connection, door keys must be clean
	installed, _ := fm2.doorInstalled()
	if installed {
		t.Fatal("an installed door key remained on the machine after reconnect!")
	}

	// The new connection is fully functional for the human
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial after reconnect: %v", err)
	}
	defer client.Close()

	hs := openHumanSession(t, client)
	hs.shell(t)

	const marker = "reconnect-human-traffic-ok"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readUntil(t, hs.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("no echo received through the reconnected machine: %q", got)
	}
	_ = hs.ch.Close()
}

// 15. The state file is corrupt — transitions to read-only mode.
//
// Assertion: if state.json is corrupt (invalid JSON), state.Open opens the
// store in read-only mode (IsReadOnly() == true), returns a
// CorruptStateError, and any write attempts (Update/Set) fail with
// ErrReadOnly, protecting the corrupt file from being overwritten.
func TestScenario15_CorruptStateTransitionsToReadOnly(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, state.StateFileName)

	// Write a broken state file
	if err := os.WriteFile(statePath, []byte(`{"schema": 1, "invalid-json-content`), 0600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}

	store, err := state.Open(dir)
	if store != nil {
		defer store.Close()
	}
	if err == nil {
		t.Fatal("state.Open on a corrupt file returned a nil error")
	}
	var corruptErr *state.CorruptStateError
	if !errors.As(err, &corruptErr) {
		t.Fatalf("expected a CorruptStateError, got: %v", err)
	}
	if !store.IsReadOnly() {
		t.Fatal("the store did not transition to read-only mode")
	}

	// A write attempt must fail with ErrReadOnly
	updErr := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "eve", Role: "user"})
		return nil
	})
	if !errors.Is(updErr, state.ErrReadOnly) {
		t.Fatalf("expected an ErrReadOnly error, got: %v", updErr)
	}
}

// 16. The disk is full — a refusal, not a silent loss.
//
// Assertion: when the session recording cannot be created (NewRecording
// error / disk full), the gateway immediately refuses the human's
// connection, allowing not a single unrecorded byte through (principle 3:
// the bastion does not admit without an honest recording).
func TestScenario16_DiskFullRefusesSession(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start func(ssh.Channel)
	}{
		{
			name: "pty_then_shell",
			start: func(ch ssh.Channel) {
				// The request pair is sent without waiting for a success reply:
				// NewRecording must fail at pty-req, so a normal client would
				// observe channel close before it could send shell. Sending both
				// here proves the queued shell is not forwarded either.
				_, _ = ch.SendRequest("pty-req", false, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
				_, _ = ch.SendRequest("shell", false, nil)
			},
		},
		{
			name: "exec_without_pty",
			start: func(ch ssh.Channel) {
				_, _ = ch.SendRequest("exec", false, sshx.MarshalExec(sshx.Exec{Command: "cmd /c echo should-not-run"}))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diskFullErr := errors.New("ENOSPC: disk is full")
			f := newFixture(t, func(cfg *gateway.Config) {
				cfg.NewRecording = func(gateway.SessionInfo) (core.Recording, error) { return nil, diskFullErr }
			})
			f.connectMachine(fakeMachineBehavior{})
			client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer client.Close()
			ch, reqs, err := client.OpenChannel("session", nil)
			if err != nil {
				t.Fatalf("open session: %v", err)
			}
			go discardSSHRequests(reqs)
			tc.start(ch)
			resp := readAll(t, ch, 2*time.Second)
			if !strings.Contains(resp, "Access to this machine is currently unavailable") {
				t.Fatalf("IAMT-163 round-3 canary: the human did not get refused on a recording failure after the startup request: %q", resp)
			}
			if got := f.sshd.startedRequests(); len(got) != 0 {
				t.Fatalf("IAMT-163 round-3 canary: NewRecording failure must stop shell/exec before target, got %v", got)
			}
		})
	}
}

// A session channel that never supplies pty-req, shell or exec must not hold
// an ACL session indefinitely. The product maps the setup timeout to its
// single non-enumerating human-facing denial line, then closes the channel.
func TestScenario16_SilentSessionSetupTimesOut(t *testing.T) {
	f := newFixture(t, func(cfg *gateway.Config) { cfg.SessionSetupTimeout = 100 * time.Millisecond })
	f.connectMachine(fakeMachineBehavior{})
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go discardSSHRequests(reqs)
	resp := readAll(t, ch, time.Second)
	if !strings.Contains(resp, "Access to this machine is currently unavailable") {
		t.Fatalf("IAMT-163 round-3 canary: silent session setup must close with generic denial after timeout, got %q", resp)
	}
	if got := f.sshd.startedRequests(); len(got) != 0 {
		t.Fatalf("IAMT-163 round-3 canary: silent setup must not start shell or exec on target, got %v", got)
	}
}

// ============================================================================
// WHAT MUST REMAIN
// ============================================================================

// 17. A window resize made it into the recording.
//
// Assertion: a window-change request with dimensions 120x35, sent by the
// client, is relayed by the gateway and recorded in the asciicast (.cast)
// as a resize event of the form [t, "r", "120x35"].
func TestScenario17_WindowChangeRecorded(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	hs := openHumanSession(t, client)
	hs.shell(t)

	// Send window-change with a non-standard size
	ok, err := hs.ch.SendRequest("window-change", true, sshx.MarshalWindow(sshx.WindowChange{
		Columns: 120,
		Rows:    35,
	}))
	if err != nil || !ok {
		t.Fatalf("window-change failed: ok=%v, err=%v", ok, err)
	}

	const marker = "window-change-verification"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = readUntil(t, hs.ch, marker)
	_ = hs.ch.Close()

	// Read the .cast recording and look for the resize event
	cast := waitForCast(t, f.recordingsDir())
	if !strings.Contains(cast, `"120x35"`) {
		t.Fatalf("asciicast does not contain a record of the 120x35 window resize: %s", cast)
	}
	if !strings.Contains(cast, `,"r",`) {
		t.Fatalf("asciicast does not contain an 'r'-type event: %s", cast)
	}
}

// 18. File transfer, port forwarding, and key forwarding are refused.
//
// Assertion: the gateway strictly blocks SFTP/subsystem, direct-tcpip,
// tcpip-forward, and the SSH agent (SPEC §5.1, PROTOCOL §4.1).
func TestScenario18_ProhibitedChannelsAndRequestsRejected(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// 1. direct-tcpip port forwarding (local port forwarding) — refused
	directPayload := ssh.Marshal(struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{
		DestAddr:   "127.0.0.1",
		DestPort:   8080,
		OriginAddr: "127.0.0.1",
		OriginPort: 12345,
	})
	_, _, err = client.OpenChannel("direct-tcpip", directPayload)
	if err == nil {
		t.Fatal("the gateway allowed a direct-tcpip channel to be opened!")
	}

	// 2. tcpip-forward port forwarding (remote port forwarding) — refused
	forwardPayload := ssh.Marshal(struct {
		BindAddr string
		BindPort uint32
	}{
		BindAddr: "0.0.0.0",
		BindPort: 8080,
	})
	ok, _, err := client.SendRequest("tcpip-forward", true, forwardPayload)
	if ok || err != nil {
		// ok should be false on a request failure
		t.Fatalf("the gateway did not refuse tcpip-forward: ok=%v, err=%v", ok, err)
	}

	// Open a session to check requests inside the session channel
	hs := openHumanSession(t, client)

	// 3. File transfer via the SFTP subsystem — refused
	subsystemPayload := ssh.Marshal(struct {
		Subsystem string
	}{
		Subsystem: "sftp",
	})
	ok, err = hs.ch.SendRequest("subsystem", true, subsystemPayload)
	if err != nil {
		t.Fatalf("sftp subsystem request: the channel died instead of being refused: %v", err)
	}
	if ok {
		t.Fatal("the gateway allowed an sftp subsystem request!")
	}

	// 4. SSH agent forwarding (auth-agent-req@openssh.com) — refused
	ok, err = hs.ch.SendRequest("auth-agent-req@openssh.com", true, nil)
	if err != nil {
		t.Fatalf("ssh-agent forwarding request: the channel died instead of being refused: %v", err)
	}
	if ok {
		t.Fatal("the gateway allowed an ssh-agent forwarding request!")
	}

	// 5. X11 forwarding (x11-req) — refused
	x11Payload := ssh.Marshal(struct {
		SingleConnection bool
		AuthProtocol     string
		AuthCookie       string
		ScreenNumber     uint32
	}{
		SingleConnection: true,
		AuthProtocol:     "MIT-MAGIC-COOKIE-1",
		AuthCookie:       "deadbeef",
		ScreenNumber:     0,
	})
	ok, err = hs.ch.SendRequest("x11-req", true, x11Payload)
	if err != nil {
		t.Fatalf("x11-req request: the channel died instead of being refused: %v", err)
	}
	if ok {
		t.Fatal("the gateway allowed an x11-req request!")
	}

	_ = hs.ch.Close()
}

// 19. Session count limits are enforced.
//
// Assertion: with ACLLimits.PerPerson = 1 configured, a second attempt by
// the same person to open a session is refused by the gateway.
func TestScenario19_SessionLimitsEnforced(t *testing.T) {
	f := newFixture(t, func(cfg *gateway.Config) {
		cfg.ACLLimits = acl.Limits{
			PerPerson:  1,
			PerMachine: 2,
		}
	})
	f.connectMachine(fakeMachineBehavior{})

	// Alice's first session — opens successfully
	c1, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("alice dial 1: %v", err)
	}
	defer c1.Close()

	hs1 := openHumanSession(t, c1)
	hs1.shell(t)

	// Alice's second session — should be refused under the PerPerson limit
	c2, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("alice dial 2: %v", err)
	}
	defer c2.Close()

	ch2, reqs2, err := c2.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	go discardSSHRequests(reqs2)

	resp := readAll(t, ch2, 2*time.Second)
	if !strings.Contains(resp, "Access to this machine is currently unavailable") {
		t.Fatalf("the second session was not refused under the limit: %q", resp)
	}

	// Close the first session
	_ = hs1.ch.Close()

	// Now that the first session is closed, a new session for Alice should be allowed
	waitUntil(t, "the limit did not free up after the first session closed", func() bool {
		c3, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
		if err != nil {
			return false
		}
		defer c3.Close()
		ch3, reqs3, err := c3.OpenChannel("session", nil)
		if err != nil {
			return false
		}
		go discardSSHRequests(reqs3)
		ok, _ := ch3.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
		_ = ch3.Close()
		return ok
	})
}

// 20. A corrupted marker -> door.sanitize, a repeat status without the line.
//
// A scenario named explicitly by SPEC §8 that did not exist before this
// commit (IAMT-99). This is the area where the critical finding IAMT-86
// turned up: a corrupted door marker was not removed by any of the four
// removal mechanisms. Fixed at the module level, but there was no
// end-to-end run.
//
// Assertions:
//  1. The gateway sees the corrupted marker through `door.status`, sends
//     `door.sanitize(reason:"corrupted")`.
//  2. After sanitize, the **bytes** of the administrators_authorized_keys
//     file change: the corrupted line is removed, the foreign line
//     (someone else's admin entry) is preserved **byte-for-byte** in its
//     original position.
//  3. A repeated `door.status` (which the gateway issues itself after
//     sanitize, via reconcile) returns installed:false.
//  4. The first invariant holds: **foreign keys lose not a single byte**.
//
// The test runs against a real key file in a temp directory — not an
// in-memory string.
//
// The gateway issues sanitize on its own after the first door.status with
// a corrupted id — no manual driveOne call is needed. This is the same
// core branch from §5.2, "closed + installed:true without a valid doorId"
// -> "door.sanitize".
func TestScenario20_CorruptedMarkerSanitizedThenStatusClean(t *testing.T) {
	f := newFixture(t, nil)

	// A real key file in a temp directory. Inside: a foreign entry
	// (someone else's) and a corrupted marker (our prefix, but the id is not 32-hex).
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("administrators_authorized_keys")
	foreignLine := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRealForeignKeyBytes123456789012345 user@home"
	corruptLine := `restrict,pty,from="127.0.0.1"` + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA iamtunnel-door=not-a-valid-id"
	originalBytes := []byte(foreignLine + "\r\n" + corruptLine + "\r\n")
	tree.WriteKeyFile(t, "administrators_authorized_keys", originalBytes)

	// The seed invariant MUST be checked BEFORE connectMachine: as soon
	// as the fake machine connects, the gateway runs the initial
	// status, sees the corrupted marker, and immediately sends
	// door.sanitize. By the time connectMachine would return, the
	// corrupted line would already be removed from disk — exactly the
	// behavior the scenario is supposed to prove, not disprove.
	seed, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("seed read before machine connect: %v", err)
	}
	if !bytes.Contains(seed, []byte(corruptLine)) {
		t.Fatalf("seed file missing the corrupted line before machine connect: %q", seed)
	}
	if !bytes.Contains(seed, []byte(foreignLine)) {
		t.Fatalf("seed file missing the foreign line before machine connect: %q", seed)
	}
	if !bytes.Equal(seed, originalBytes) {
		t.Fatalf("seed file is not byte-for-byte what we wrote.\n got: %q\nwant: %q",
			seed, originalBytes)
	}

	// A fake machine, but with a real key file. reportForeignDoor makes
	// the first status return the exact corrupted id the gateway must
	// send to sanitize. For door.sanitize and door.status, the fake
	// machine answers based on the file's actual contents — after
	// sanitize the corrupted line is gone and the second status
	// returns installed:false.
	f.connectMachine(fakeMachineBehavior{
		reportForeignDoor: "not-a-valid-id",
		keyFile:           keyFile,
	})

	// Wait for the gateway to run the full cycle:
	//   initial status -> sanitize(reason:"corrupted") -> success ->
	//   reconcile status -> installed:false.
	// The journal is the only monotonic barrier: a single door.sanitize record.
	waitUntil(t, "door.sanitize event was never written to the journal", func() bool {
		evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventDoorSanitize}})
		if err != nil {
			return false
		}
		return len(evs) == 1
	})

	// File bytes: the foreign line stayed in place, the corrupted one was removed.
	waitUntil(t, "sanitize did not remove the corrupted line from the real key file", func() bool {
		got, err := os.ReadFile(keyFile)
		if err != nil {
			return false
		}
		return !bytes.Contains(got, []byte("iamtunnel-door=not-a-valid-id"))
	})

	// The first invariant: the foreign line is preserved **byte-for-byte**
	// in its original position. This is IAMT-103's "foreign keys lose
	// not a single byte" invariant, checked within this test.
	after, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("post-sanitize read: %v", err)
	}
	if !bytes.Equal(after, []byte(foreignLine+"\r\n")) {
		t.Fatalf("sanitize altered a foreign line.\n got: %q\nwant: %q",
			after, foreignLine+"\r\n")
	}

	// Journal: a single door.sanitize record with Result: "ok", with
	// Details["removed"] == 1 (one corrupted line) and
	// Details["reason"] == "corrupted". This is the exact record IAMT-103
	// requires from sanitize — checked here via the end-to-end run of
	// SPEC §8. The outcome ("ok", "refused", "timeout") lives in the
	// Result field, per the dictionary convention (auth.failure,
	// session.drop — IAMT-104 for door.*).
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventDoorSanitize}})
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected exactly one door.sanitize event, got %d: %+v", len(evs), evs)
	}
	got0 := evs[0]
	if got0.Object != f.machineID {
		t.Fatalf("door.sanitize.Object = %q, want %q", got0.Object, f.machineID)
	}
	if got0.Result != "ok" {
		t.Fatalf("door.sanitize.Result = %q, want %q", got0.Result, "ok")
	}
	if got0.Details["reason"] != "corrupted" {
		t.Fatalf("door.sanitize.Details[reason] = %v, want %q",
			got0.Details["reason"], "corrupted")
	}
	rmv, ok := got0.Details["removed"].(float64)
	if !ok {
		t.Fatalf("door.sanitize.Details[removed] is not a number: %T", got0.Details["removed"])
	}
	if int(rmv) != 1 {
		t.Fatalf("door.sanitize.Details[removed] = %v, want 1 (one corrupted door line)", rmv)
	}
}

// 21. A door that closed on its own must be able to open again.
//
// IAMT-21: "in an early version the door could only be opened
// once, and a second connection silently failed to work." This test pins
// down the full life cycle "open -> work -> auto-close via idleClose ->
// open again -> work again" in a single run.
//
// Assertions:
//  1. After the last session ends, the machine received a door.close
//     command (not just "sessions ended": idleClose must send door.close
//     when both sessions and reservations are 0).
//  2. The same grant, on a second connection, leads to a new door.open
//     command and a working session — the door does not stick in Closed
//     after the first cycle.
//
// The test must go through a real close: between the two connections the
// door actually closes (a separate waitUntil on the door.close counter,
// not just "something happened afterward"). The test must actually go
// through the close.
//
// The order of checks was restructured for round 2: both assertions go
// red BEFORE the harness has a chance to die on timeout.
//
//   - Assertion 1 waits for `doorCloseCount() == 1` (not
//     `doorInstalled() == false`): it's specifically the missing
//     door.close command that canary A breaks, and this check must be
//     the one to go red first when idleClose is broken. The
//     doorInstalled check stays in the harness as a "strong fact," but
//     does not duplicate the guard: on the fake machine,
//     doorInstalled()==false is caught by the same waitUntil line and
//     adds nothing.
//
//   - Assertion 2 waits for `doorOpenCount() == 2` AFTER openHumanSession
//     (which is what triggers serveHumanSession -> mc.reserve ->
//     closedReserve -> startOpen -> door.open to the machine), but
//     BEFORE shell(): with a broken door, reserve will hang until
//     SessionSetupTimeout, the channel will fall apart, and the test
//     will die earlier — but the first red text must be our own
//     "no second door.open command arrived," not "pty-req: ok=false
//     err=EOF" from hs2.shell.
func TestScenario21_DoorReopensAfterAutoClose(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})

	// Harness starting invariant: after connectMachine, the machine went
	// through the initial door.status, but neither door.open nor
	// door.close has happened yet.
	if got := fm.doorOpenCount(); got != 0 {
		t.Fatalf("test setup error: %d door.open commands already present at start, expected 0", got)
	}
	if got := fm.doorCloseCount(); got != 0 {
		t.Fatalf("test setup error: %d door.close commands already present at start, expected 0", got)
	}

	// ---- Step 1: first human connection ----
	c1, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("test setup error: first human connection: %v", err)
	}
	defer c1.Close()

	hs1 := openHumanSession(t, c1)
	hs1.shell(t)

	const firstMarker = "iamt-21-first-cycle-marker"
	if _, err := hs1.ch.Write([]byte(firstMarker + "\n")); err != nil {
		t.Fatalf("test setup error: write the first-cycle marker: %v", err)
	}
	if got := readUntil(t, hs1.ch, firstMarker); !strings.Contains(got, firstMarker) {
		t.Fatalf("test setup error: first-cycle echo not received: %q", got)
	}
	if got := fm.doorOpenCount(); got != 1 {
		t.Fatalf("test setup error: expected 1 door.open command after the first cycle; got %d", got)
	}

	// ---- Step 2: the session ends ----
	_ = hs1.ch.Close()

	// ---- Assertion 1: the door closed on its own, and the close went through door.close ----
	// Wait for the door.close counter to grow, not just for the key to
	// disappear from the machine: it's specifically the missing
	// door.close command that canary A breaks (removing idleClose from
	// FinishSession). Making this check first gets us our own red text
	// before the harness has a chance to die.
	waitUntil(t, "the door stayed open with no sessions and no door.close command: expected 1 door.close command after the first session", func() bool {
		return fm.doorCloseCount() == 1
	})

	// ---- Step 3: the same human connects AGAIN while the grant is still valid ----
	// dialHuman by itself does not fail on refusal: ssh.Dial completes
	// the SSH handshake on the person's key, and the decision to refuse
	// is made by the gateway inside mc.reserve — only after
	// SessionSetupTimeout (3 seconds in the fixture). So after
	// dialHuman the channel has not yet fallen apart, and we have time
	// to measure the door's state before reserve hangs.
	c2, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("test setup error: second human connection: %v", err)
	}
	defer c2.Close()

	// openHumanSession triggers the gateway: handleHuman accepts the
	// channel and calls serveHumanSession, which calls mc.reserve ->
	// closedReserve -> startOpen -> mc.drive(door.open). The point
	// where the reservation has already been requested but the channel
	// has not yet fallen apart is right after openHumanSession
	// returns: either startOpen has already sent door.open (in which
	// case the counter is already growing), or closedReserve silently
	// returns nil and reserve hangs until the timeout.
	hs2 := openHumanSession(t, c2)

	// ---- Assertion 2: the second door.open command was sent and reached the machine ----
	// Wait for the counter to grow BEFORE hs2.shell(t): with a broken
	// door, reserve will hang for 3 seconds and fail on
	// SessionSetupTimeout — but the first red text must be our own
	// "no second door.open command arrived," not "pty-req: ok=false
	// err=EOF" from the harness.
	waitUntil(t, "the door did not reopen: no second door.open command arrived", func() bool {
		return fm.doorOpenCount() == 2
	})

	hs2.shell(t)

	const secondMarker = "iamt-21-second-cycle-marker"
	if _, err := hs2.ch.Write([]byte(secondMarker + "\n")); err != nil {
		t.Fatalf("test setup error: write the second-cycle marker: %v", err)
	}
	if got := readUntil(t, hs2.ch, secondMarker); !strings.Contains(got, secondMarker) {
		t.Fatalf("test setup error: second-cycle echo not received: %q", got)
	}
	_ = hs2.ch.Close()

	// Final symmetry check: the second cycle also closes normally.
	waitUntil(t, "the door stayed open with no sessions after the second cycle: expected 2 door.close commands", func() bool {
		return fm.doorCloseCount() == 2
	})
}

// ---- Helpers ----------------------------------------------------------------

func dialHumanRaw(addr, username string, signer ssh.Signer) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	c, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = c
	_ = chans
	_ = reqs
	return raw, nil
}

// waitForCastContaining returns the contents of the first .cast file under
// dir whose body contains needle. Used by tests that have multiple live
// sessions (one recording per session) and need to inspect the recording of
// a specific one; waitForCast's "first .cast" heuristic cannot tell which
// session produced which file.
func waitForCastContaining(t *testing.T, dir, needle string) string {
	t.Helper()
	var found string
	waitUntil(t, "no .cast recording containing "+strconv.Quote(needle)+" appeared under "+dir, func() bool {
		var hit string
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".cast") {
				if b, rerr := os.ReadFile(path); rerr == nil && strings.Contains(string(b), needle) {
					hit = path
				}
			}
			return nil
		})
		if hit == "" {
			return false
		}
		b, err := os.ReadFile(hit)
		if err != nil {
			return false
		}
		found = string(b)
		return true
	})
	return found
}

// waitForTranscriptContaining returns the contents of the first .txt file
// under dir whose body contains needle — same reason as waitForCastContaining.
func waitForTranscriptContaining(t *testing.T, dir, needle string) string {
	t.Helper()
	var found string
	waitUntil(t, "no .txt transcript containing "+strconv.Quote(needle)+" appeared under "+dir, func() bool {
		var hit string
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".txt") {
				if b, rerr := os.ReadFile(path); rerr == nil && strings.Contains(string(b), needle) {
					hit = path
				}
			}
			return nil
		})
		if hit == "" {
			return false
		}
		b, err := os.ReadFile(hit)
		if err != nil {
			return false
		}
		found = string(b)
		return true
	})
	return found
}
