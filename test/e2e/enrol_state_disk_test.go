package e2e

// enrol_state_disk_test.go answers questions 1-2 by reading
// state.json FROM DISK, not from memory: after machines.enrol-code the
// file must hold the HMAC-SHA-256 of the secret under the gateway's
// enrol-hmac.key — never the raw secret, never a plain SHA-256, never
// any other substitute. This is also the standing assertion the deleted
// enrol_mutation_test.go tried to prove with its product-code hook: a
// regression that stores the raw secret bytes as the hash turns this
// test red without any help from shipped code.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
)

func TestEnrol_StateJsonStoresHashNotSecret(t *testing.T) {
	f := newFixture(t, nil)

	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)},
		"root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	code, _, err := root.MachinesInvite("vm-disk")
	if err != nil {
		t.Fatalf("enrol-code: %v", err)
	}
	_ = root.Close()
	parsed, err := config.ParseEnrolCode(code)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Read the file the gateway actually wrote.
	rawState, err := readFile(f.dir + "/state.json")
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}

	// 1. The wire-format secret must not appear anywhere in state.json
	// as text (a regression storing it as a string field is caught
	// here; the base64url alphabet makes a false positive impossible
	// — the hash is stored as a JSON byte array).
	if strings.Contains(string(rawState), parsed.Secret) {
		t.Fatalf("state.json contains the raw enrol secret:\n%s", string(rawState))
	}

	// 2. The stored hash must be exactly 32 bytes.
	// Since 1.3 the invitation is unbound and lives in the top-level
	// pendingEnrolments list, not on a machine record (IAMT-336). The
	// invariant this test exists for is unchanged by that move: what
	// reaches disk is the keyed hash, never the secret.
	var got struct {
		PendingEnrolments []struct {
			SecretHash []byte `json:"secretHash"`
			PublicKey  string `json:"publicKey"`
			Expires    string `json:"expires"`
		} `json:"pendingEnrolments"`
	}
	if err := json.Unmarshal(rawState, &got); err != nil {
		t.Fatalf("decode state.json: %v", err)
	}
	if len(got.PendingEnrolments) != 1 {
		t.Fatalf("state.json holds %d pending enrolments, want exactly the one just minted:\n%s", len(got.PendingEnrolments), string(rawState))
	}
	pending := got.PendingEnrolments[0].SecretHash
	if len(pending) != 32 {
		t.Fatalf("pendingEnrolments[0].secretHash is %d bytes, want exactly 32; state.json:\n%s", len(pending), string(rawState))
	}

	// 3. Not the raw bytes passed through (the regression the deleted
	// hook test tried to plant): the first 32 base64url characters of
	// the secret are ASCII, the HMAC output is uniformly random — they
	// cannot coincide.
	if bytes.Equal(pending, []byte(parsed.Secret)[:32]) {
		t.Fatalf("state.json holds the raw secret bytes as the hash (raw pass-through regression):\n%s", string(rawState))
	}

	// 4. Not a plain SHA-256 either: the invariant is keyed HMAC under
	// enrol-hmac.key, so state.json alone must be useless to an
	// attacker who never reads that key file.
	plain := sha256.Sum256([]byte(parsed.Secret))
	if bytes.Equal(pending, plain[:]) {
		t.Fatalf("state.json holds an unkeyed SHA-256 of the secret instead of the HMAC:\n%s", string(rawState))
	}

	// 5. Positive check: it IS HMAC-SHA-256(secret) under the key file
	// the gateway created next to state.json.
	hmacKey := f.store.EnrolHMACKey()
	want := hmac.New(sha256.New, hmacKey[:])
	want.Write([]byte(parsed.Secret))
	if !bytes.Equal(pending, want.Sum(nil)) {
		t.Fatalf("state.json secretHash is not HMAC-SHA-256(enrolHMACKey, secret):\n%s", string(rawState))
	}
}
