package e2e

// enrol_failure_modes_test.go answers questions 3, 5 and 7:
//
//   - Q3: an expired enrol code is refused with its own code
//     E_ENROL_SECRET_EXPIRED, not the generic "invalid", and the
//     expired entry is not consumed by the attempt.
//   - Q5: the journal distinguishes "wrong code" (invalid) from "code
//     already used" (replay) from "code expired" (expired) — the
//     replay kind is the leak indicator the owner must be able to
//     spot without reading the response body.
//   - Q7: a second admin.claim against an already-set-up gateway is
//     refused with E_BOOTSTRAP_USED even when the token is still on
//     disk, and no second admin appears.

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// journalRecord is one line of events.jsonl, far enough to read the
// enrol failure classification.
type journalRecord struct {
	Type    string `json:"type"`
	Object  string `json:"object"`
	Result  string `json:"result"`
	Details struct {
		Reason  string `json:"reason"`
		ErrCode string `json:"errCode"`
	} `json:"details"`
}

// readJournal loads every record of the fixture's events.jsonl.
func readJournal(t *testing.T, f *fixture) []journalRecord {
	t.Helper()
	file, err := os.Open(f.dir + "/events.jsonl")
	if err != nil {
		t.Fatalf("open events.jsonl: %v", err)
	}
	defer file.Close()
	var out []journalRecord
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec journalRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode journal line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read events.jsonl: %v", err)
	}
	return out
}

// enrolFailureKinds returns the result kinds of every enrol.failed
// event in the journal.
func enrolFailureKinds(t *testing.T, f *fixture) map[string]int {
	t.Helper()
	kinds := map[string]int{}
	for _, rec := range readJournal(t, f) {
		if rec.Type == "enrol.failed" {
			kinds[rec.Result]++
		}
	}
	return kinds
}

// TestEnrol_WrongSecretDoesNotConsumeCode: a wrong secret is the
// "invalid" refusal, it does not consume the pending entry, and the
// right secret still enrols afterwards.
func TestEnrol_WrongSecretDoesNotConsumeCode(t *testing.T) {
	f := newFixture(t, nil)

	const secret = "correct-horse-battery-secret-0123456789"
	eph := seedEnrolPending(t, f, secret)

	pubLine := authorizedLine(genSigner(t).PublicKey())
	resp := doEnrol(t, f, eph, "wrong-secret-presented-by-attacker", e2eFreshMachine, `MACHINE\svc`, pubLine)
	if !strings.Contains(resp, "E_ENROL_SECRET_INVALID") {
		t.Fatalf("wrong secret must be refused with E_ENROL_SECRET_INVALID, got: %q", resp)
	}
	// Specifically NOT the replay code. Since 1.3 the lookup is by
	// secret hash alone, so a wrong secret finds nothing — exactly what
	// a redeemed one finds — and the classification has to come from
	// somewhere else (runEnrolFromPending asks whether this caller's
	// own invitation is still on file). Getting this wrong would report
	// every mistyped paste as a leaked invitation.
	if strings.Contains(resp, "E_ENROL_SECRET_USED") {
		t.Fatalf("a wrong secret was reported as a replay — the one signal that means an invitation leaked: %q", resp)
	}

	// The entry survived the wrong attempt...
	rawState, err := readFile(f.dir + "/state.json")
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if !strings.Contains(string(rawState), `"pendingEnrolments"`) {
		t.Fatalf("a wrong secret consumed the pending entry; state.json:\n%s", string(rawState))
	}

	// ...and the right secret still works.
	if !strings.Contains(doEnrol(t, f, eph, secret, e2eFreshMachine, `MACHINE\svc`, pubLine), `"state":"enrolled"`) {
		t.Fatalf("the right secret no longer enrols after a wrong attempt")
	}
}

// TestEnrol_ExpiredCodeRejectedDistinctly: expiry has its own refusal
// code, distinct from invalid and used, and the attempt does not
// consume the entry.
func TestEnrol_ExpiredCodeRejectedDistinctly(t *testing.T) {
	f := newFixture(t, nil)

	const secret = "expired-code-secret-0123456789abcdefghij"
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}
	ephPub := authorizedLine(eph.PublicKey())
	if err := f.store.Update(func(st *state.State) error {
		st.PendingEnrolments = append(st.PendingEnrolments, state.PendingEnrolment{
			Name:       e2eFreshMachine,
			SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(secret)),
			PublicKey:  ephPub,
			// Issued sixteen minutes ago, died a minute ago.
			Expires: state.NewZonedTime(f.clock.Now().Add(-time.Minute)),
		})
		return nil
	}); err != nil {
		t.Fatalf("seed expired pending: %v", err)
	}

	pubLine := authorizedLine(genSigner(t).PublicKey())
	resp := doEnrol(t, f, eph, secret, e2eFreshMachine, `MACHINE\svc`, pubLine)
	if !strings.Contains(resp, "E_ENROL_SECRET_EXPIRED") {
		t.Fatalf("expired code must be refused with E_ENROL_SECRET_EXPIRED, got: %q", resp)
	}
	if strings.Contains(resp, "E_ENROL_SECRET_INVALID") || strings.Contains(resp, "E_ENROL_SECRET_USED") {
		t.Fatalf("expired code must not be hidden behind a generic refusal: %q", resp)
	}

	rawState, err := readFile(f.dir + "/state.json")
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	if !strings.Contains(string(rawState), `"pendingEnrolments"`) {
		t.Fatalf("the expired attempt consumed the pending entry; state.json:\n%s", string(rawState))
	}
}

// TestEnrol_FailureKindsAreDistinguishableInTheJournal runs the three
// failure modes and requires the journal to tell them apart. The
// "replay" case is made deterministic: the SSH handshake completes
// while the pending entry still exists, then the test removes the
// machine from state BEFORE the exec body is presented — exactly the
// window a real replay (or an admin removal) races through — so the
// exec layer answers E_ENROL_SECRET_USED and the journal records the
// replay kind.
func TestEnrol_FailureKindsAreDistinguishableInTheJournal(t *testing.T) {
	f := newFixture(t, nil)

	const secret = "journal-kinds-secret-0123456789abcdefgh"
	eph := seedEnrolPending(t, f, secret)
	pubLine := authorizedLine(genSigner(t).PublicKey())

	// 1. invalid: wrong secret, with the invitation still on file.
	resp := doEnrol(t, f, eph, "deliberately-wrong-secret", e2eFreshMachine, `MACHINE\svc`, pubLine)
	if !strings.Contains(resp, "E_ENROL_SECRET_INVALID") {
		t.Fatalf("invalid case did not answer E_ENROL_SECRET_INVALID: %q", resp)
	}

	// 2. expired: the entry's expiry moved into the past.
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.PendingEnrolments {
			st.PendingEnrolments[i].Expires = state.NewZonedTime(f.clock.Now().Add(-time.Minute))
		}
		return nil
	}); err != nil {
		t.Fatalf("expire pending: %v", err)
	}
	resp = doEnrol(t, f, eph, secret, e2eFreshMachine, `MACHINE\svc`, pubLine)
	if !strings.Contains(resp, "E_ENROL_SECRET_USED") && !strings.Contains(resp, "E_ENROL_SECRET_EXPIRED") {
		t.Fatalf("expired case did not answer an enrol-specific code: %q", resp)
	}

	// 3. replay/used: pending exists at handshake time, is gone by the
	// time the exec body arrives.
	conn, ch, derr := dialEnrol(t, f, eph)
	if derr != nil {
		t.Fatalf("replay dial: %v", derr)
	}
	// Whip the invitation away between the handshake and the body —
	// what a real replay races through, and what an admin revoking one
	// would do. Since 1.3 the invitation, not the machine record, is
	// what has to go: nothing but its absence makes this a replay
	// rather than a mistyped secret.
	if err := f.store.Update(func(st *state.State) error {
		st.Machines = nil
		st.PendingEnrolments = nil
		return nil
	}); err != nil {
		t.Fatalf("remove the invitation: %v", err)
	}
	ok, serr := ch.SendRequest("exec", true, ssh.Marshal(struct{ Cmd string }{"enrol"}))
	if serr != nil || !ok {
		t.Fatalf("replay exec request: ok=%v err=%v", ok, serr)
	}
	body, _ := json.Marshal(map[string]any{
		"proto":      1,
		"secret":     secret,
		"machine":    e2eFreshMachine,
		"osUser":     `MACHINE\svc`,
		"machineKey": pubLine,
	})
	if _, err := ch.Write(body); err != nil {
		t.Fatalf("write replay body: %v", err)
	}
	_ = ch.CloseWrite()
	replayResp := readChannelUntilNewline(t, ch)
	_ = conn.Close()
	if !strings.Contains(replayResp, "E_ENROL_SECRET_USED") {
		t.Fatalf("replay case did not answer E_ENROL_SECRET_USED: %q", replayResp)
	}

	// The journal must carry all three kinds, each with its own code.
	kinds := enrolFailureKinds(t, f)
	if kinds["invalid"] != 1 || kinds["expired"] != 1 || kinds["replay"] != 1 {
		t.Fatalf("journal does not distinguish the failure modes; got kinds %v, want one of each invalid/expired/replay", kinds)
	}
	wantCode := map[string]string{
		"invalid": "E_ENROL_SECRET_INVALID",
		"expired": "E_ENROL_SECRET_EXPIRED",
		"replay":  "E_ENROL_SECRET_USED",
	}
	for _, rec := range readJournal(t, f) {
		if rec.Type != "enrol.failed" {
			continue
		}
		if rec.Details.ErrCode != wantCode[rec.Result] {
			t.Fatalf("journal kind %q carries errCode %q, want %q", rec.Result, rec.Details.ErrCode, wantCode[rec.Result])
		}
	}
}

// runAdminClaim performs one admin.claim exec as username "bootstrap"
// with the given ephemeral signer and body fields, and returns the raw
// response envelope.
func runAdminClaim(t *testing.T, f *fixture, eph ssh.Signer, token, pubkey string) string {
	t.Helper()
	conn, ch, err := dialBootstrap(t, f, eph)
	if err != nil {
		t.Fatalf("bootstrap dial: %v", err)
	}
	defer conn.Close()
	defer ch.Close()
	ok, err := ch.SendRequest("exec", true, ssh.Marshal(struct{ Cmd string }{"admin.claim"}))
	if err != nil || !ok {
		t.Fatalf("admin.claim exec request: ok=%v err=%v", ok, err)
	}
	body, _ := json.Marshal(map[string]any{
		"proto":     1,
		"bootstrap": token,
		"pubkey":    pubkey,
	})
	if _, err := ch.Write(body); err != nil {
		t.Fatalf("write admin.claim body: %v", err)
	}
	_ = ch.CloseWrite()
	return readChannelUntilNewline(t, ch)
}

// countAdminsInState counts role:"admin" people in the fixture's
// state.json on disk.
func countAdminsInState(t *testing.T, f *fixture) int {
	t.Helper()
	var got state.State
	if err := readStateJSON(f.dir, &got); err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	n := 0
	for _, p := range got.People {
		if p.Role == "admin" {
			n++
		}
	}
	return n
}

// TestBootstrap_SecondClaimOnConfiguredGatewayIsRefused answers
// question 7: bootstrap is one-shot. After the first admin exists, a
// second claim is refused with E_BOOTSTRAP_USED — even if the token
// file survived and the pending entry is (re)created — and no second
// admin is created.
func TestBootstrap_SecondClaimOnConfiguredGatewayIsRefused(t *testing.T) {
	f := newFixture(t, nil)

	const token = "bootstrap-second-claim-token-0123456789"
	bootstrapSigner, err := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	if err != nil {
		t.Fatalf("derive bootstrap signer: %v", err)
	}
	bsPub := authorizedLine(bootstrapSigner.PublicKey())

	seedBootstrap := func(expires time.Time) {
		t.Helper()
		if err := f.store.Update(func(st *state.State) error {
			st.BootstrapPending = &state.BootstrapPending{
				SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(token)),
				PublicKey:  bsPub,
				Expires:    state.NewZonedTime(expires),
			}
			return nil
		}); err != nil {
			t.Fatalf("seed bootstrap pending: %v", err)
		}
	}

	// First claim: succeeds, creates the first admin, burns the token.
	seedBootstrap(f.clock.Now().Add(24 * time.Hour))
	adminKey1 := genSigner(t)
	resp := runAdminClaim(t, f, bootstrapSigner, token, authorizedLine(adminKey1.PublicKey()))
	if !strings.Contains(resp, `"role":"admin"`) {
		t.Fatalf("first admin.claim did not succeed: %q", resp)
	}
	if n := countAdminsInState(t, f); n != 1 {
		t.Fatalf("after first claim there are %d admins, want 1", n)
	}

	// Second claim with the SAME token and a DIFFERENT key, with the
	// token's pending entry recreated (the token file survived on
	// disk). HasAnyAdmin must refuse before the hash is even compared.
	seedBootstrap(f.clock.Now().Add(24 * time.Hour))
	adminKey2 := genSigner(t)
	resp = runAdminClaim(t, f, bootstrapSigner, token, authorizedLine(adminKey2.PublicKey()))
	if !strings.Contains(resp, "E_BOOTSTRAP_USED") {
		t.Fatalf("second admin.claim must be refused with E_BOOTSTRAP_USED, got: %q", resp)
	}
	if n := countAdminsInState(t, f); n != 1 {
		t.Fatalf("second admin.claim created an admin: %d admins in state, want 1", n)
	}

	// And with no pending entry at all (token already burned): the
	// ephemeral key is no longer known to the gateway, so the refusal
	// comes at the SSH layer — the token holder cannot even reach the
	// exec that would tell them anything (same shape as the enrol
	// replay refusal of scenario 04). No second admin either way.
	if err := f.store.Update(func(st *state.State) error {
		st.BootstrapPending = nil
		return nil
	}); err != nil {
		t.Fatalf("clear bootstrap pending: %v", err)
	}
	if conn, ch, derr := dialBootstrap(t, f, bootstrapSigner); derr == nil {
		_ = ch.Close()
		_ = conn.Close()
		t.Fatalf("admin.claim without a pending token passed the SSH handshake; the burned bootstrap key is still accepted")
	}
	if n := countAdminsInState(t, f); n != 1 {
		t.Fatalf("third admin.claim created an admin: %d admins in state, want 1", n)
	}
}

// TestBootstrap_ExpiredTokenRejectedDistinctly: the bootstrap token has
// its own expiry refusal, distinct from "used".
func TestBootstrap_ExpiredTokenRejectedDistinctly(t *testing.T) {
	f := newFixture(t, nil)

	const token = "bootstrap-expired-token-0123456789abcdefgh"
	bootstrapSigner, err := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	if err != nil {
		t.Fatalf("derive bootstrap signer: %v", err)
	}
	if err := f.store.Update(func(st *state.State) error {
		st.BootstrapPending = &state.BootstrapPending{
			SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(token)),
			PublicKey:  authorizedLine(bootstrapSigner.PublicKey()),
			Expires:    state.NewZonedTime(f.clock.Now().Add(-time.Hour)),
		}
		return nil
	}); err != nil {
		t.Fatalf("seed expired bootstrap: %v", err)
	}

	adminKey := genSigner(t)
	resp := runAdminClaim(t, f, bootstrapSigner, token, authorizedLine(adminKey.PublicKey()))
	if !strings.Contains(resp, "E_BOOTSTRAP_EXPIRED") {
		t.Fatalf("expired token must be refused with E_BOOTSTRAP_EXPIRED, got: %q", resp)
	}
	if strings.Contains(resp, "E_BOOTSTRAP_USED") {
		t.Fatalf("expired token must not be hidden behind E_BOOTSTRAP_USED: %q", resp)
	}
	if countAdminsInState(t, f) != 0 {
		t.Fatal("an expired admin.claim created an admin")
	}
}

// TestBootstrap_ClaimEventsAreJournaled: both the success and the
// refusal of admin.claim reach the journal, so the owner can see that
// somebody presented a bootstrap token after the gateway was set up.
func TestBootstrap_ClaimEventsAreJournaled(t *testing.T) {
	f := newFixture(t, nil)

	const token = "bootstrap-journal-token-0123456789abcdef"
	bootstrapSigner, err := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	if err != nil {
		t.Fatalf("derive bootstrap signer: %v", err)
	}
	bsPub := authorizedLine(bootstrapSigner.PublicKey())
	if err := f.store.Update(func(st *state.State) error {
		st.BootstrapPending = &state.BootstrapPending{
			SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(token)),
			PublicKey:  bsPub,
			Expires:    state.NewZonedTime(f.clock.Now().Add(24 * time.Hour)),
		}
		return nil
	}); err != nil {
		t.Fatalf("seed bootstrap pending: %v", err)
	}

	adminKey := genSigner(t)
	if resp := runAdminClaim(t, f, bootstrapSigner, token, authorizedLine(adminKey.PublicKey())); !strings.Contains(resp, `"role":"admin"`) {
		t.Fatalf("claim did not succeed: %q", resp)
	}
	// A refused claim afterwards: the token's pending entry is
	// recreated (the token file survived on disk) and a second key
	// tries to claim. HasAnyAdmin refuses at the exec layer, and THAT
	// refusal is what the journal must expose.
	if err := f.store.Update(func(st *state.State) error {
		st.BootstrapPending = &state.BootstrapPending{
			SecretHash: state.HashEnrolSecret(f.store.EnrolHMACKey(), []byte(token)),
			PublicKey:  bsPub,
			Expires:    state.NewZonedTime(f.clock.Now().Add(24 * time.Hour)),
		}
		return nil
	}); err != nil {
		t.Fatalf("re-seed bootstrap pending: %v", err)
	}
	if resp := runAdminClaim(t, f, bootstrapSigner, token, authorizedLine(genSigner(t).PublicKey())); !strings.Contains(resp, "E_BOOTSTRAP_USED") {
		t.Fatalf("second claim was not refused: %q", resp)
	}

	var okSeen, replaySeen bool
	for _, rec := range readJournal(t, f) {
		if rec.Type != "admin.op" || rec.Object != "admin.claim" {
			continue
		}
		switch rec.Result {
		case "bootstrap:ok":
			okSeen = true
		case "bootstrap:replay":
			replaySeen = true
		}
	}
	if !okSeen || !replaySeen {
		t.Fatalf("journal does not tell the claim success from the refused second claim (ok=%v, replay=%v)", okSeen, replaySeen)
	}
}
