package gateway

// pairing_role_test.go: the PIN-pairing trust bootstrap (PROTOCOL §3.4,
// IAMT-323/IAMT-325) against the same three seams the rest of this package
// tests at:
//
//   - the live wire (iamt143Exec): a real "pairing"-login SSH connection
//     running the one admin.pair exec;
//   - the SSH-layer callbacks (publicKeyCallback / pairingKeyCallback), for
//     the refusals that happen before any exec exists;
//   - runPairing directly, for the rate-limit arithmetic, whose identity is
//     an (addr, fingerprint) pair a test must control. Over the wire every
//     dial brings its own ephemeral source port, so a wire test can never
//     accumulate three failures on one "address" - the same per-connection
//     granularity the main limiter has always had (see the §1.4 tests, which
//     also drive RecordFailure with literal addresses).
//
// Everything runs against newFixture's real gateway: real state store, real
// journal, real SSH handshakes, fake clock. The pairing numbers are the
// setDefaults ones (6-digit PIN, 2-minute window, 3 wrong PINs → 3-minute
// ban), because those numbers are part of what IAMT-325 pins.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// ---- helpers ---------------------------------------------------------------

// seedPairingWindow plants a pairing window whose PIN the test knows, expiring
// ttl from the fixture's (fake) now. The window is the same shape
// cmdAdminPairingStart writes - only the PIN is chosen here instead of drawn.
func seedPairingWindow(t *testing.T, f *fixture, pin string, ttl time.Duration) {
	t.Helper()
	hash := state.HashEnrolSecret(f.gw.enrolHMAC, []byte(pin))
	if err := f.store.Update(func(st *state.State) error {
		st.PairingPending = &state.PairingPending{
			SecretHash: hash,
			Expires:    state.NewZonedTime(f.clock.Now().Add(ttl)),
		}
		return nil
	}); err != nil {
		t.Fatalf("seed pairing window: %v", err)
	}
}

// pairingWindowHash is the hash currently stored in the state, for comparing
// against the hash of a PIN a test holds.
func pairingWindowHash(t *testing.T, f *fixture) [32]byte {
	t.Helper()
	st := f.store.Get()
	if st.PairingPending == nil {
		t.Fatalf("pairing window is gone, expected one open")
	}
	return st.PairingPending.SecretHash
}

// requirePairingWindowOpen asserts the window survived whatever just happened.
// Several refusals are specified to leave it open (wrong PIN, duplicate key,
// malformed pubkey); this is the assertion that pins that.
func requirePairingWindowOpen(t *testing.T, f *fixture, stage string) {
	t.Helper()
	if f.store.Get().PairingPending == nil {
		t.Fatalf("%s: pairing window was burned, want it left open", stage)
	}
}

// runPairingAt grades one admin.pair attempt at a fixed (addr, fingerprint)
// identity - the seam servePairingSession calls after decoding the body.
// The direct entry is bound to whatever window is open now (F-12), which is
// the window a wire connection admitted at the same moment would carry; no
// window open means no binding, and runPairing skips the check for the
// empty bound.
func runPairingAt(f *fixture, addr, fp, pin, pubkey string) (any, *cmdError) {
	raw, err := json.Marshal(pairingRequest{Proto: 1, Pin: pin, Pubkey: pubkey})
	if err != nil {
		f.t.Fatalf("marshal pairing body: %v", err)
	}
	return f.gw.runPairing(raw, addr, fp, pairingWindowBindingHex(f.store.Get().PairingPending), f.clock.Now())
}

// wantPairingRefusal asserts an attempt failed with exactly the given wire
// code and exit status - not merely "some error".
func wantPairingRefusal(t *testing.T, stage string, cerr *cmdError, code string, exit int) {
	t.Helper()
	if cerr == nil {
		t.Fatalf("%s: got success, want refusal %s (exit %d)", stage, code, exit)
	}
	if cerr.code != code || cerr.exit != exit {
		t.Fatalf("%s: refusal = %s (exit %d), want %s (exit %d)", stage, cerr.code, cerr.exit, code, exit)
	}
}

// pairingStartDirect runs the pairing.start command table handler the way
// admin_role.go invokes it and returns the typed result.
func pairingStartDirect(t *testing.T, f *fixture, person string) pairingStartResult {
	t.Helper()
	raw, err := json.Marshal(map[string]int{"proto": 1})
	if err != nil {
		t.Fatalf("marshal pairing.start body: %v", err)
	}
	res, cerr := cmdAdminPairingStart(f.gw, person, f.clock.Now(), raw)
	if cerr != nil {
		t.Fatalf("pairing.start: %v", cerr)
	}
	start, ok := res.(pairingStartResult)
	if !ok {
		t.Fatalf("pairing.start returned %T, want pairingStartResult", res)
	}
	return start
}

// pairingStopDirect runs the pairing.stop command table handler and returns
// whether a window was actually closed.
func pairingStopDirect(t *testing.T, f *fixture, person string) bool {
	t.Helper()
	raw, err := json.Marshal(map[string]int{"proto": 1})
	if err != nil {
		t.Fatalf("marshal pairing.stop body: %v", err)
	}
	res, cerr := cmdAdminPairingStop(f.gw, person, f.clock.Now(), raw)
	if cerr != nil {
		t.Fatalf("pairing.stop: %v", cerr)
	}
	stopped, ok := res.(map[string]bool)
	if !ok {
		t.Fatalf("pairing.stop returned %T, want map[string]bool", res)
	}
	return stopped["stopped"]
}

// pairingDialErr dials the gateway with the byte-exact "pairing" username and
// reports why the handshake failed; nil means the key was accepted (window
// open). The SSH layer refuses a closed window with the unknown-key rendering
// - what that means for an outside observer is the subject of the
// indistinguishability test below.
func pairingDialErr(t *testing.T, addr string, signer ssh.Signer) error {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "pairing",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if client != nil {
		_ = client.Close()
	}
	return err
}

// pairingAuthFailures returns the journal's auth.failure events for one key
// fingerprint - the only operator-visible trace of a refused handshake -
// once at least want of them have landed.
//
// The wait is not decoration (IAMT-332 round 10). A refused handshake is
// observed by the client the moment the transport closes, but the journal
// line is appended by the gateway on its own goroutine AFTER that, so a
// test that dials, returns and reads immediately is racing a writer it
// never synchronised with. On Windows the race happened to be lost by the
// reader often enough never to be noticed; on Linux it is lost by the
// writer almost every time, and the caller saw one event where two had
// been earned. That is a defect of this helper, not of the gateway: the
// product has no obligation to have written the line before the dial
// returns, and the test's business is to wait for what it asked about.
//
// After the count is reached the journal is read once more, so an
// UNEXPECTED extra event still reaches the caller instead of being cut off
// by an early return - the callers assert an exact count, and a wait that
// returned the instant it saw enough would quietly turn "exactly two" into
// "at least two".
func pairingAuthFailures(t *testing.T, f *fixture, fp string, want int) []events.Event {
	t.Helper()
	read := func() []events.Event {
		evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
		if err != nil {
			t.Fatalf("read auth.failure journal: %v", err)
		}
		var out []events.Event
		for _, e := range evs {
			if e.Fingerprint == fp {
				out = append(out, e)
			}
		}
		return out
	}
	waitUntil(t, fmt.Sprintf("the journal never reached %d auth.failure events for %s", want, fp), func() bool {
		return len(read()) >= want
	})
	return read()
}

// iamt143PairingShell opens a pairing-login session and sends a "shell"
// request instead of an exec - the request the pairing role must answer with
// E_EXEC_UNKNOWN on the channel (the counterpart of bootstrap's rule, and of
// the "whoami" case the bootstrap tests pin).
func iamt143PairingShell(t *testing.T, addr string, signer ssh.Signer) (iamt143WireEnvelope, uint32) {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "pairing",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("pairing shell dial: %v", err)
	}
	defer client.Close()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("pairing shell open session: %v", err)
	}
	defer ch.Close()

	exits := make(chan uint32, 1)
	go func() {
		for req := range reqs {
			if req.Type == "exit-status" {
				if status, perr := sshx.ParseExitStatus(req.Payload); perr == nil {
					select {
					case exits <- status.Status:
					default:
					}
				}
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()

	ok, err := ch.SendRequest("shell", true, nil)
	if err != nil {
		t.Fatalf("pairing shell request: %v", err)
	}
	if ok {
		t.Fatalf("pairing shell request answered ok=true, want the handler to refuse it")
	}

	type shellRead struct {
		raw []byte
		err error
	}
	readDone := make(chan shellRead, 1)
	go func() {
		raw, rerr := io.ReadAll(ch)
		readDone <- shellRead{raw: raw, err: rerr}
	}()
	var read shellRead
	select {
	case read = <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("pairing shell produced no response")
	}
	if read.err != nil {
		t.Fatalf("pairing shell read response: %v", read.err)
	}

	var envelope iamt143WireEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(read.raw), &envelope); err != nil {
		t.Fatalf("pairing shell response is not JSON: %v; raw=%q", err, read.raw)
	}
	var status uint32
	select {
	case status = <-exits:
	case <-time.After(5 * time.Second):
		t.Fatalf("pairing shell response had no exit-status")
	}
	return envelope, status
}

// iamt143PairingRawExec runs one exec on a pairing login and tolerates the
// exec REQUEST itself being answered false. That is what every role's
// handler does for a command it does not recognise (bootstrap_role.go and
// pairing_role.go reply false and then still write the error envelope on the
// channel), while iamt143Exec - written for the recognised commands - treats
// a false reply as "the handler never ran". This variant reads the envelope
// either way and reports what the request reply was, so a test can assert
// both.
func iamt143PairingRawExec(t *testing.T, addr string, signer ssh.Signer, command string, body any) (iamt143WireEnvelope, uint32, bool) {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "pairing",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("pairing raw exec dial: %v", err)
	}
	defer client.Close()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("pairing raw exec open session: %v", err)
	}
	defer ch.Close()

	exits := make(chan uint32, 1)
	go func() {
		for req := range reqs {
			if req.Type == "exit-status" {
				if status, perr := sshx.ParseExitStatus(req.Payload); perr == nil {
					select {
					case exits <- status.Status:
					default:
					}
				}
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()

	rawBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("pairing raw exec encode body: %v", err)
	}
	requestOK, err := ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command}))
	if err != nil {
		t.Fatalf("pairing raw exec request: %v", err)
	}
	// A declined request (every role declines unknown commands with
	// reply=false before writing the error envelope) is not sent a body: the
	// handler has already closed the channel past this point.
	if requestOK {
		if _, err := ch.Write(rawBody); err != nil {
			t.Fatalf("pairing raw exec write body: %v", err)
		}
		if err := ch.CloseWrite(); err != nil {
			t.Fatalf("pairing raw exec close body: %v", err)
		}
	}

	type rawRead struct {
		raw []byte
		err error
	}
	readDone := make(chan rawRead, 1)
	go func() {
		raw, rerr := io.ReadAll(ch)
		readDone <- rawRead{raw: raw, err: rerr}
	}()
	var read rawRead
	select {
	case read = <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("pairing raw exec produced no response")
	}
	if read.err != nil {
		t.Fatalf("pairing raw exec read response: %v", read.err)
	}
	var envelope iamt143WireEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(read.raw), &envelope); err != nil {
		t.Fatalf("pairing raw exec response is not JSON: %v; raw=%q", err, read.raw)
	}
	var status uint32
	select {
	case status = <-exits:
	case <-time.After(5 * time.Second):
		t.Fatalf("pairing raw exec response had no exit-status")
	}
	return envelope, status, requestOK
}

// ---- the window controls (pairing.start / pairing.stop) ---------------------

// TestIAMT325_PairingStartSeedsWindowAndKeepsPinOutOfJournal pins what
// "the operator sees" means for pairing.start: a 6-digit PIN, a window in
// state whose stored hash is the hash of the PIN that was printed, a ref of
// the host:port#fingerprint shape, and a journal that records the expiry but
// never the PIN - the PIN exists only in the answer and in the state's HMAC.
func TestIAMT325_PairingStartSeedsWindowAndKeepsPinOutOfJournal(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.PublicHost = "gw.test"; c.PublicPort = 2222 })

	start := pairingStartDirect(t, f, "alice")

	if !validPin(start.Pin, 6) {
		t.Fatalf("pairing.start PIN = %q, want exactly 6 decimal digits (leading zeros allowed)", start.Pin)
	}
	expires, err := time.Parse(time.RFC3339, start.Expires)
	if err != nil {
		t.Fatalf("pairing.start Expires %q is not RFC3339: %v", start.Expires, err)
	}
	if want := f.clock.Now().Add(2 * time.Minute); !expires.Equal(want) {
		t.Fatalf("pairing.start expires at %s, want %s (the 2-minute window)", expires, want)
	}

	bareFp := strings.TrimPrefix(auth.Fingerprint(f.gw.cfg.HostKey.PublicKey()), "SHA256:")
	if want := "gw.test:2222#" + bareFp; start.Ref != want {
		t.Fatalf("pairing.start ref = %q, want %q", start.Ref, want)
	}

	st := f.store.Get()
	if st.PairingPending == nil {
		t.Fatalf("pairing.start left no window in the state")
	}
	if !st.PairingPending.Expires.Equal(expires) {
		t.Fatalf("state window expires at %s, want %s", st.PairingPending.Expires, expires)
	}
	// The stored secret must be the hash of the PIN that was printed - that
	// correspondence is the whole operator contract: the code on the admin's
	// screen is the code the gateway will grade.
	if want := state.HashEnrolSecret(f.gw.enrolHMAC, []byte(start.Pin)); st.PairingPending.SecretHash != want {
		t.Fatalf("stored window hash does not match HMAC(printed PIN)")
	}

	// The journal: the expiry is public, the PIN is not. Read the raw file so
	// even a details field nobody remembered would be caught. A 6-digit PIN
	// cannot collide with the journal's timestamps (their longest digit run
	// is the 4-digit year), so a substring hit is meaningful.
	rawLog, err := os.ReadFile(f.logPath)
	if err != nil {
		t.Fatalf("read events.jsonl: %v", err)
	}
	if bytes.Contains(rawLog, []byte(start.Pin)) {
		t.Fatalf("the pairing PIN %q leaked into the journal", start.Pin)
	}
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}})
	if err != nil {
		t.Fatalf("read admin.op journal: %v", err)
	}
	found := false
	for _, e := range evs {
		if e.Result != "pairing.start:ok" {
			continue
		}
		found = true
		if e.Actor != "alice" || e.Object != "pairing" {
			t.Fatalf("pairing.start event actor/object = %q/%q, want alice/pairing", e.Actor, e.Object)
		}
		if logged, _ := e.Details["expires"].(string); logged != start.Expires {
			t.Fatalf("pairing.start event logs expires %v, want %q", e.Details["expires"], start.Expires)
		}
	}
	if !found {
		t.Fatalf("pairing.start wrote no admin.op:pairing.start:ok event")
	}
}

// TestIAMT325_PairingStopIsIdempotent pins the stop contract: the first stop
// reports that a window was open, the second reports there was nothing to
// close, and after either the pairing login is refused at the handshake.
func TestIAMT325_PairingStopIsIdempotent(t *testing.T) {
	f := newFixture(t, nil)

	if pairingStopDirect(t, f, "alice") {
		t.Fatalf("pairing.stop with no window reported stopped=true, want false")
	}

	seedPairingWindow(t, f, "424242", time.Hour)
	if !pairingStopDirect(t, f, "alice") {
		t.Fatalf("pairing.stop with an open window reported stopped=false, want true")
	}
	if stopped := pairingStopDirect(t, f, "alice"); stopped {
		t.Fatalf("second pairing.stop reported stopped=true, want false")
	}

	if err := pairingDialErr(t, f.addr, genSigner(t)); err == nil {
		t.Fatalf("pairing dial after pairing.stop succeeded, want a handshake refusal")
	}
	if f.store.Get().PairingPending != nil {
		t.Fatalf("pairing.stop left a window in the state")
	}
}

// TestIAMT325_PairingStartReplacesOpenWindow pins the one-window rule: a
// start while a window is open replaces it in one write - the old PIN stops
// grading, the new one grades, and no second window ever exists.
func TestIAMT325_PairingStartReplacesOpenWindow(t *testing.T) {
	f := newFixture(t, nil)

	first := pairingStartDirect(t, f, "alice")
	second := first
	for i := 0; i < 10 && second.Pin == first.Pin; i++ {
		second = pairingStartDirect(t, f, "alice")
	}
	if second.Pin == first.Pin {
		t.Fatalf("ten pairing.start calls returned the same PIN %q - replacement unprovable", first.Pin)
	}
	if want := state.HashEnrolSecret(f.gw.enrolHMAC, []byte(second.Pin)); pairingWindowHash(t, f) != want {
		t.Fatalf("state still holds the hash of the old PIN, want the hash of the replacement")
	}

	// The old PIN no longer grades - but the window is open, so the handshake
	// succeeds and the refusal is the PIN one, on the wire.
	oldKey := genSigner(t)
	env, status := iamt143Exec(t, f.addr, "pairing", oldKey, "admin.pair", pairingRequest{
		Proto: 1, Pin: first.Pin, Pubkey: authorizedLine(oldKey.PublicKey()),
	})
	if env.OK || env.Error == nil || env.Error.Code != "E_PAIRING_PIN_INVALID" {
		t.Fatalf("replaced window still graded the old PIN: %+v", env)
	}
	if status != 2 {
		t.Fatalf("old-PIN refusal exit status = %d, want 2", status)
	}
	requirePairingWindowOpen(t, f, "old-PIN attempt")

	// The replacement grades.
	newKey := genSigner(t)
	env, status = iamt143Exec(t, f.addr, "pairing", newKey, "admin.pair", pairingRequest{
		Proto: 1, Pin: second.Pin, Pubkey: authorizedLine(newKey.PublicKey()),
	})
	if !env.OK {
		t.Fatalf("replacement PIN refused: %+v", env)
	}
	if status != 0 {
		t.Fatalf("successful pair exit status = %d, want 0", status)
	}
	if f.store.Get().PairingPending != nil {
		t.Fatalf("successful pair left the (replaced) window open")
	}
}

// ---- the happy path ----------------------------------------------------------

// TestIAMT325_PairingHappyPathCreatesAdminAndBurnsWindow is the scenario the
// feature exists for: a correct PIN over the wire permanently registers the
// client's own key as an admin and burns the window in the same breath, so
// the same PIN can never pair anyone else.
func TestIAMT325_PairingHappyPathCreatesAdminAndBurnsWindow(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "424242", 2*time.Minute)

	newKey := genSigner(t)
	env, status := iamt143Exec(t, f.addr, "pairing", newKey, "admin.pair", pairingRequest{
		Proto: 1, Pin: "424242", Pubkey: authorizedLine(newKey.PublicKey()),
	})
	if !env.OK {
		t.Fatalf("correct PIN refused: %+v", env)
	}
	if status != 0 {
		t.Fatalf("successful pair exit status = %d, want 0", status)
	}
	var res pairingResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatalf("pair result is not JSON: %v; raw=%s", err, env.Result)
	}

	fp := fingerprintOf(t, newKey.PublicKey())
	if res.Person != "admin" {
		t.Fatalf("pair person = %q, want the readable fallback admin (SPEC §3.3: admin first, admin2 only when admin is taken)", res.Person)
	}
	if res.Role != "admin" {
		t.Fatalf("pair role = %q, want admin", res.Role)
	}

	// The state: exactly one new person, admin, carrying the presented key -
	// and no window.
	st := f.store.Get()
	if len(st.People) != 2 {
		t.Fatalf("people count after pair = %d, want 2 (alice + the new admin)", len(st.People))
	}
	var created *state.Person
	for i := range st.People {
		if st.People[i].Name == res.Person {
			created = &st.People[i]
		}
	}
	if created == nil {
		t.Fatalf("pair person %q not in the state", res.Person)
	}
	if created.Role != "admin" {
		t.Fatalf("created person role = %q, want admin", created.Role)
	}
	if len(created.Keys) != 1 || created.Keys[0].Fingerprint != fp {
		t.Fatalf("created person keys = %+v, want exactly the presented key %s", created.Keys, fp)
	}
	if st.PairingPending != nil {
		t.Fatalf("successful pair left the window open - a replayed PIN would pair another device")
	}

	// The same key and PIN replayed: the handshake itself is refused now (the
	// window is gone), rendering the replay indistinguishable from key spray
	// against a gateway with no pairing feature at all.
	if err := pairingDialErr(t, f.addr, newKey); err == nil {
		t.Fatalf("replayed pairing login succeeded after the window burned, want handshake refusal")
	}

	// The journal: the pair is auditable, by person name - never by PIN.
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}})
	if err != nil {
		t.Fatalf("read admin.op journal: %v", err)
	}
	found := false
	for _, e := range evs {
		if e.Result != "admin.pair:ok" {
			continue
		}
		found = true
		if e.Actor != "pairing" || e.Object != res.Person {
			t.Fatalf("admin.pair event actor/object = %q/%q, want pairing/%q", e.Actor, e.Object, res.Person)
		}
		if logged, _ := e.Details["fingerprint"].(string); logged != fp {
			t.Fatalf("admin.pair event logs fingerprint %v, want %q", e.Details["fingerprint"], fp)
		}
	}
	if !found {
		t.Fatalf("successful pair wrote no admin.op:admin.pair:ok event")
	}
}

// ---- PIN grading and the rate limiter ---------------------------------------

// TestIAMT325_WrongPinLocksAddressThenRecovers drives the §1.5 numbers end to
// end at the seam whose (addr, fingerprint) identity a test controls: three
// wrong PINs from one address answer E_PAIRING_PIN_INVALID, the fourth learns
// nothing but E_PAIRING_LOCKED, a different address pairs straight through
// the ban, and after the 3-minute ban the original address is back - graded
// as a plain wrong PIN again, not locked.
func TestIAMT325_WrongPinLocksAddressThenRecovers(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "111111", time.Hour)

	const bannedAddr = "203.0.113.7:40000"
	attackerKey := genSigner(t)
	attackerFP := fingerprintOf(t, attackerKey.PublicKey())
	attackerLine := authorizedLine(attackerKey.PublicKey())

	for i := 1; i <= 3; i++ {
		_, cerr := runPairingAt(f, bannedAddr, attackerFP, "999999", attackerLine)
		wantPairingRefusal(t, "wrong PIN", cerr, "E_PAIRING_PIN_INVALID", 2)
		requirePairingWindowOpen(t, f, "wrong-PIN attempt")
	}

	// The address is spent: the limiter answers before the PIN is compared,
	// so the fourth attempt learns nothing (not even that 111111 is wrong).
	_, cerr := runPairingAt(f, bannedAddr, attackerFP, "999999", attackerLine)
	wantPairingRefusal(t, "fourth wrong PIN", cerr, "E_PAIRING_LOCKED", 2)
	requirePairingWindowOpen(t, f, "locked-out attempt")
	// The same refusal at the handshake layer - a locked address does not
	// even get a pairing login to speak on.
	if _, cbErr := f.gw.pairingKeyCallback(bannedAddr, attackerFP, f.clock.Now()); cbErr == nil || !strings.Contains(cbErr.Error(), "rate limited") {
		t.Fatalf("pairing handshake for the banned address = %v, want a rate-limit refusal", cbErr)
	}

	// A different address is untouched: the ban is the address's, not the
	// window's.
	victimKey := genSigner(t)
	_, cerr = runPairingAt(f, "198.51.100.9:1", fingerprintOf(t, victimKey.PublicKey()), "111111", authorizedLine(victimKey.PublicKey()))
	if cerr != nil {
		t.Fatalf("pairing from a different address refused while another address was locked: %v", cerr)
	}

	// Recovery: past the 3-minute ban the original address pairs again. The
	// wrong PIN it sends first must be graded (PIN_INVALID) - a fresh lockout
	// would mean the ban never lifted.
	f.clock.Advance(4 * time.Minute)
	seedPairingWindow(t, f, "222333", time.Hour)
	_, cerr = runPairingAt(f, bannedAddr, attackerFP, "999999", attackerLine)
	wantPairingRefusal(t, "wrong PIN after the ban expired", cerr, "E_PAIRING_PIN_INVALID", 2)
	_, cerr = runPairingAt(f, bannedAddr, attackerFP, "222333", attackerLine)
	if cerr != nil {
		t.Fatalf("correct PIN from the banned address refused after the ban expired: %v", cerr)
	}
}

// TestIAMT325_MalformedPinCountsAsWrong pins the grading rule that keeps the
// shape check from being a free oracle: a PIN that is not six decimal digits
// is not answered with a shape error - it is a wrong PIN, on the same
// per-address counter, with the same code.
func TestIAMT325_MalformedPinCountsAsWrong(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "111111", time.Hour)

	const addr = "203.0.113.7:40001"
	key := genSigner(t)
	fp := fingerprintOf(t, key.PublicKey())
	line := authorizedLine(key.PublicKey())

	for _, pin := range []string{"12ab45", "12345", "1234567"} {
		_, cerr := runPairingAt(f, addr, fp, pin, line)
		wantPairingRefusal(t, "malformed PIN "+pin, cerr, "E_PAIRING_PIN_INVALID", 2)
		requirePairingWindowOpen(t, f, "malformed-PIN attempt")
	}
	// Three graded failures: the next wrong PIN is the lockout, not another
	// grade - proof that the malformed shapes were counted.
	_, cerr := runPairingAt(f, addr, fp, "000000", line)
	wantPairingRefusal(t, "wrong PIN after three malformed ones", cerr, "E_PAIRING_LOCKED", 2)
}

// TestIAMT325_InactiveAndExpiredRecordNoFailure pins the boundary of the
// counter: with no window (or an expired one) there is no PIN to grade, so
// the refusals - E_PAIRING_INACTIVE and E_PAIRING_EXPIRED - must not bill the
// address. The proof is arithmetic: three INACTIVE refusals and one EXPIRED
// would exhaust the 3-failure threshold if any of them counted, and the next
// wrong PIN would be a lockout. It grades instead.
func TestIAMT325_InactiveAndExpiredRecordNoFailure(t *testing.T) {
	f := newFixture(t, nil)

	const addr = "203.0.113.7:40002"
	key := genSigner(t)
	fp := fingerprintOf(t, key.PublicKey())
	line := authorizedLine(key.PublicKey())

	// No window at all.
	for i := 0; i < 3; i++ {
		_, cerr := runPairingAt(f, addr, fp, "999999", line)
		wantPairingRefusal(t, "admin.pair with no window", cerr, "E_PAIRING_INACTIVE", 2)
	}

	// An expired window (the state that a window that timed out between the
	// handshake and this exec leaves behind).
	seedPairingWindow(t, f, "111111", -time.Second)
	_, cerr := runPairingAt(f, addr, fp, "999999", line)
	wantPairingRefusal(t, "admin.pair with an expired window", cerr, "E_PAIRING_EXPIRED", 2)

	// The arithmetic proof: a fresh window, one wrong PIN - graded, not
	// locked. Four recorded failures would have made this a lockout.
	seedPairingWindow(t, f, "111111", time.Hour)
	_, cerr = runPairingAt(f, addr, fp, "999999", line)
	wantPairingRefusal(t, "wrong PIN after un-billed refusals", cerr, "E_PAIRING_PIN_INVALID", 2)
	_, cerr = runPairingAt(f, addr, fp, "111111", line)
	if cerr != nil {
		t.Fatalf("correct PIN refused after un-billed refusals: %v", cerr)
	}
}

// ---- the closed window is nobody's business ---------------------------------

// TestIAMT325_ClosedWindowIndistinguishableFromUnknownKey pins the recon
// property at both layers where it is observable. At the callback layer, a
// pairing login against a closed window is refused with the byte-identical
// rendering an unregistered key gets - a probe cannot tell whether the
// gateway has a pairing feature that is off, or no pairing feature at all.
// Over the wire, what reaches the journal carries the same plain
// unknown-key rendering for both logins - no pairing-specific wording, no
// pairing-specific limiter billing. (Since R4 F-11 the refusals of one
// host fold into one line per quiet period, which is why the wire layer
// pins the rendering of the folded line rather than a line per dial; the
// refusal words themselves are pinned above at the callback layer, where
// they are compared byte for byte.) The one honest asymmetry - with a
// window OPEN the pairing login is accepted - is pinned in the middle, so
// the test cannot pass on a gateway that simply refuses every pairing
// login.
func TestIAMT325_ClosedWindowIndistinguishableFromUnknownKey(t *testing.T) {
	f := newFixture(t, nil)
	probeKey := genSigner(t)
	probeFP := fingerprintOf(t, probeKey.PublicKey())

	metaPair := fakeMeta{user: "pairing"}
	metaAlice := fakeMeta{user: "alice"}

	// Callback layer, closed window: identical refusals, both wrapping
	// auth.ErrUnknownKey.
	_, errPair := f.gw.publicKeyCallback(metaPair, probeKey.PublicKey())
	_, errAlice := f.gw.publicKeyCallback(metaAlice, probeKey.PublicKey())
	if errPair == nil || errAlice == nil {
		t.Fatalf("closed-window callbacks: pairing err=%v, alice err=%v, want both refused", errPair, errAlice)
	}
	if errPair.Error() != errAlice.Error() {
		t.Fatalf("closed-window pairing refusal %q differs from the unknown-key refusal %q - a probe can tell the difference", errPair, errAlice)
	}
	if !strings.HasSuffix(errPair.Error(), probeFP) {
		t.Fatalf("closed-window pairing refusal %q does not even name the probed key's fingerprint %q", errPair, probeFP)
	}
	if !errors.Is(errPair, auth.ErrUnknownKey) {
		t.Fatalf("closed-window pairing refusal %q does not wrap auth.ErrUnknownKey", errPair)
	}

	// The honest asymmetry: with a window open, the pairing login is accepted
	// while the same key stays unknown for alice.
	seedPairingWindow(t, f, "424242", time.Minute)
	if perm, err := f.gw.publicKeyCallback(metaPair, probeKey.PublicKey()); err != nil || perm == nil {
		t.Fatalf("pairing handshake refused with a window open: perm=%v err=%v", perm, err)
	}
	if _, err := f.gw.publicKeyCallback(metaAlice, probeKey.PublicKey()); err == nil {
		t.Fatalf("alice's login accepted an unregistered key while the window was open")
	}

	// Wire layer, closed window again: two dials, one key, both refused.
	// pairing.stop is the operator's own way to close the window mid-flight.
	pairingStopDirect(t, f, "alice")
	reconKey := genSigner(t)
	reconFP := fingerprintOf(t, reconKey.PublicKey())
	if err := pairingDialErr(t, f.addr, reconKey); err == nil {
		t.Fatalf("pairing dial with a stopped window succeeded, want handshake refusal")
	}
	// The same key offered to the admin login it could never have: refused
	// with (journal-wise) the same words.
	if client, derr := dialHuman(t, f.addr, "alice", "vm1", reconKey); derr == nil {
		_ = client.Close()
		t.Fatalf("human dial with an unregistered key succeeded, want handshake refusal")
	}

	// What the journal says: both dials fall in one host-and-kind bucket of
	// the refusal fold (R4 F-11), so one line - and it carries the plain
	// unknown-key rendering, no pairing-specific word. A probe reading the
	// journal learns exactly what any unknown key earns.
	fails := pairingAuthFailures(t, f, reconFP, 1)
	if len(fails) != 1 {
		t.Fatalf("journal has %d auth.failure events for the probe key, want exactly 1 (the folded line of one quiet period)", len(fails))
	}
	if !strings.HasPrefix(fails[0].Result, "auth: unknown key: ") {
		t.Fatalf("journal refusal reason = %q, want the plain unknown-key rendering", fails[0].Result)
	}
}

// ---- what a trusted client may and may not do -------------------------------

// TestIAMT325_DuplicateFingerprintKeepsWindowOpen pins the re-pairing rule:
// a key that is already somebody's is refused with E_CONFLICT, and the
// refusal does not spend the PIN - the window stays open, the operator may
// still be waiting to pair a different device with the same code.
func TestIAMT325_DuplicateFingerprintKeepsWindowOpen(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "424242", time.Hour)

	// alice's own key is already registered; pairing it must be a conflict.
	env, status := iamt143Exec(t, f.addr, "pairing", f.personKey, "admin.pair", pairingRequest{
		Proto: 1, Pin: "424242", Pubkey: authorizedLine(f.personKey.PublicKey()),
	})
	if env.OK || env.Error == nil || env.Error.Code != "E_CONFLICT" {
		t.Fatalf("re-pairing an already-registered key: %+v, want E_CONFLICT", env)
	}
	if status != 2 {
		t.Fatalf("duplicate-key refusal exit status = %d, want 2", status)
	}
	requirePairingWindowOpen(t, f, "duplicate-key refusal")
	st := f.store.Get()
	if len(st.People) != 1 {
		t.Fatalf("people count after the duplicate refusal = %d, want 1 (no person created)", len(st.People))
	}

	// The same PIN still grades a genuinely new key.
	freshKey := genSigner(t)
	env, status = iamt143Exec(t, f.addr, "pairing", freshKey, "admin.pair", pairingRequest{
		Proto: 1, Pin: "424242", Pubkey: authorizedLine(freshKey.PublicKey()),
	})
	if !env.OK {
		t.Fatalf("correct PIN refused after an earlier duplicate-key refusal: %+v", env)
	}
	if status != 0 {
		t.Fatalf("successful pair exit status = %d, want 0", status)
	}
}

// TestIAMT325_GarbagePubkeyAfterCorrectPinKeepsWindow pins the validation
// order: the pubkey is examined only after the PIN has compared equal, so a
// client that knows the PIN but sends a malformed key gets E_JSON_INVALID -
// and has not burned anything: the window and the same PIN still work for a
// corrected retry. (A client with a WRONG pin gets the PIN answer, never a
// pubkey opinion - TestIAMT325_WrongPinLocksAddressThenRecovers shows wrong
// PINs grading before any key handling.)
func TestIAMT325_GarbagePubkeyAfterCorrectPinKeepsWindow(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "424242", time.Hour)

	key := genSigner(t)
	env, status := iamt143Exec(t, f.addr, "pairing", key, "admin.pair", pairingRequest{
		Proto: 1, Pin: "424242", Pubkey: "definitely not a public key",
	})
	if env.OK || env.Error == nil || env.Error.Code != "E_JSON_INVALID" {
		t.Fatalf("garbage pubkey with a correct PIN: %+v, want E_JSON_INVALID", env)
	}
	if status != 3 {
		t.Fatalf("garbage-pubkey refusal exit status = %d, want 3", status)
	}
	requirePairingWindowOpen(t, f, "garbage-pubkey refusal")

	// The same PIN, a well-formed key: accepted. Nothing was spent.
	env, status = iamt143Exec(t, f.addr, "pairing", key, "admin.pair", pairingRequest{
		Proto: 1, Pin: "424242", Pubkey: authorizedLine(key.PublicKey()),
	})
	if !env.OK {
		t.Fatalf("corrected pubkey refused on the same window: %+v", env)
	}
	if status != 0 {
		t.Fatalf("successful pair exit status = %d, want 0", status)
	}
}

// TestIAMT325_PairingLoginOnlyRunsAdminPair pins the one-command rule: on a
// pairing login, everything except "admin.pair" - whoami, the bootstrap
// role's admin.claim, and even the admin role's own pairing.start - is
// E_EXEC_UNKNOWN with exit 2, and none of it burns the window.
func TestIAMT325_PairingLoginOnlyRunsAdminPair(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "424242", time.Hour)
	key := genSigner(t)

	for _, command := range []string{"whoami", "admin.claim", "pairing.start"} {
		env, status, requestOK := iamt143PairingRawExec(t, f.addr, key, command, map[string]int{"proto": 1})
		// The unrecognised exec request is answered false - the handler ran
		// and declined it - and the structured refusal still lands on the
		// channel as an envelope.
		if requestOK {
			t.Fatalf("pairing login accepted the exec request for %q, want it declined before the envelope", command)
		}
		if env.OK || env.Error == nil || env.Error.Code != "E_EXEC_UNKNOWN" {
			t.Fatalf("pairing login ran %q: %+v, want E_EXEC_UNKNOWN", command, env)
		}
		if status != 2 {
			t.Fatalf("%q on a pairing login: exit status = %d, want 2", command, status)
		}
	}

	// Not even a shell: a session channel that asks for a shell instead of an
	// exec is answered with the same E_EXEC_UNKNOWN on the channel.
	env, status := iamt143PairingShell(t, f.addr, key)
	if env.OK || env.Error == nil || env.Error.Code != "E_EXEC_UNKNOWN" {
		t.Fatalf("pairing shell request: %+v, want E_EXEC_UNKNOWN", env)
	}
	if status != 2 {
		t.Fatalf("pairing shell request exit status = %d, want 2", status)
	}

	requirePairingWindowOpen(t, f, "foreign-command attempts")

	// And the legit command still grades the same window afterwards.
	env, status = iamt143Exec(t, f.addr, "pairing", key, "admin.pair", pairingRequest{
		Proto: 1, Pin: "424242", Pubkey: authorizedLine(key.PublicKey()),
	})
	if !env.OK {
		t.Fatalf("admin.pair refused after foreign-command attempts: %+v", env)
	}
	if status != 0 {
		t.Fatalf("successful pair exit status = %d, want 0", status)
	}
}

// TestIAMT325_SuccessDoesNotClearThePinCounter pins the §1.4 rule the pairing
// limiter inherits: a successful pair records nothing AND clears nothing -
// the address's earlier wrong PINs stay counted and age out on their own.
// The scenario: two wrong PINs, a correct one (window burned), a fresh
// window, then two more wrong PINs from the same address. The first grades,
// the second is the lockout - the success in the middle did not reset
// anything. (SPEC §6.1's sentence about success and the counter is ambiguous;
// the pairing path follows PROTOCOL §1.4's explicit rule for the main
// limiter, and the docs commit under IAMT-328 aligns the wording with this
// test.)
func TestIAMT325_SuccessDoesNotClearThePinCounter(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "111111", time.Hour)

	const addr = "203.0.113.7:40004"
	key := genSigner(t)
	fp := fingerprintOf(t, key.PublicKey())
	line := authorizedLine(key.PublicKey())

	for i := 0; i < 2; i++ {
		_, cerr := runPairingAt(f, addr, fp, "999999", line)
		wantPairingRefusal(t, "wrong PIN before the success", cerr, "E_PAIRING_PIN_INVALID", 2)
	}
	// The success itself: same address, same key, correct PIN.
	_, cerr := runPairingAt(f, addr, fp, "111111", line)
	if cerr != nil {
		t.Fatalf("correct PIN refused: %v", cerr)
	}

	// A fresh window, same address: the two old failures must still count.
	seedPairingWindow(t, f, "222333", time.Hour)
	_, cerr = runPairingAt(f, addr, fp, "999999", line)
	wantPairingRefusal(t, "third wrong PIN (counter survived the success)", cerr, "E_PAIRING_PIN_INVALID", 2)
	_, cerr = runPairingAt(f, addr, fp, "999999", line)
	wantPairingRefusal(t, "fourth wrong PIN (counter reached the threshold)", cerr, "E_PAIRING_LOCKED", 2)
}

// ---- the two limiters do not talk -------------------------------------------

// TestIAMT325_PairingLimiterIndependentOfHandshakeLimiter pins why a second
// RateLimiter instance exists at all: a pairing ban and a handshake ban live
// in different maps. An address locked out of pairing still logs in as
// itself over the wire, and an address the handshake limiter has banned for
// key spray still pairs with a correct PIN - neither limiter's counters may
// reach the other's decisions.
func TestIAMT325_PairingLimiterIndependentOfHandshakeLimiter(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "424242", time.Hour)

	const lockedAddr = "203.0.113.7:40003"
	key := genSigner(t)
	fp := fingerprintOf(t, key.PublicKey())
	line := authorizedLine(key.PublicKey())

	// Spend the pairing address: three wrong PINs and the pairing ban is on.
	for i := 0; i < 3; i++ {
		if _, cerr := runPairingAt(f, lockedAddr, fp, "999999", line); cerr == nil {
			t.Fatalf("warm-up wrong PIN #%d unexpectedly succeeded", i+1)
		}
	}
	if _, cerr := runPairingAt(f, lockedAddr, fp, "999999", line); cerr == nil || cerr.code != "E_PAIRING_LOCKED" {
		t.Fatalf("setup: address not locked out of pairing (%v)", cerr)
	}

	// The pairing ban says nothing about the person's own login: alice dials
	// over the wire with her registered key and the handshake - the main
	// limiter's Allow and the pure callback - accepts her.
	client, err := dialHuman(t, f.addr, "alice", "vm1", f.personKey)
	if err != nil {
		t.Fatalf("alice's own login refused while her address was locked out of pairing: %v", err)
	}
	_ = client.Close()

	// The reverse: an address the HANDSHAKE limiter has banned (10 unknown
	// keys, the fixture's threshold) still pairs with a correct PIN.
	const sprayedAddr = "198.51.100.77:9"
	for i := 0; i < 10; i++ {
		f.gw.rate.RecordFailure(sprayedAddr, fp, false, f.clock.Now())
	}
	if d := f.gw.rate.Allow(sprayedAddr, fp, f.clock.Now()); d.Allow {
		t.Fatalf("setup: sprayed address not banned on the handshake limiter")
	}
	pairKey := genSigner(t)
	_, cerr := runPairingAt(f, sprayedAddr, fingerprintOf(t, pairKey.PublicKey()), "424242", authorizedLine(pairKey.PublicKey()))
	if cerr != nil {
		t.Fatalf("correct PIN refused from an address the handshake limiter banned: %v", cerr)
	}
}
