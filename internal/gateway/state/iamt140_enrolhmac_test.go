package state_test

// iamt140_enrolhmac_test.go — IAMT-140 round two.
//
// The class of bug this file pins down is "store handed back to the
// caller without the enrol HMAC key loaded", which used to be
// possible because Open loaded the key only on the "existing state"
// branch. The "new state" branch returned early with a zero key.
// Then writeBootstrapPending called HashEnrolSecret with that zero
// key, got plausible-looking bytes, and gateway run reopened the
// store, loaded the REAL random key, and the very first
// admin.claim never matched.
//
// The canary mutations to apply are:
//
//   - "return early in creation branch": put `return s, nil` back
//     between saveAtomicLocked and any future LoadOrCreateEnrolHMACKey
//     call. The fix removes that possibility (see store.go::Open), so
//     this file's first test fails the moment a future round reverts
//     the load-before-branch order.
//
//   - "bypass LoadOrCreateEnrolHMACKey" by any means (assigning the
//     zero value, dropping the assignment, returning before the call).
//     HashEnrolSecret panics on a zero key, so the test that hashes a
//     secret immediately after Open fails the moment the key is zero.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestIAMT140_Open_PopulatesEnrolHMACKeyOnCreation is the headline
// test: opening a brand-new data directory (state.json absent) must
// produce a Store whose EnrolHMACKey() is non-zero AND whose underlying
// file enrol-hmac.key exists on disk right there.
//
// This is the exact property that IAMT-140 names as broken. The
// pre-fix Open returned a Store with EnrolHMACKey{} (zero) and no
// enrol-hmac.key file at all; writeBootstrapPending then hashed the
// bootstrap token under the zero key, and the very first admin.claim
// could never match.
//
// With the fix in place (LoadOrCreateEnrolHMACKey runs BEFORE any
// state.json branch, and its result is assigned to s.enrolHMAC
// before the new-store branch returns), this assertion is green.
// With the canary mutation "return early in creation branch" applied
// — by reintroducing `return s, nil` between saveAtomicLocked and the
// load call — this test fails: the file is missing AND the key is
// zero. The failure message names the file and the property so it can
// be matched to the canary prediction.
func TestIAMT140_Open_PopulatesEnrolHMACKeyOnCreation(t *testing.T) {
	dir := t.TempDir()

	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	defer s.Close()

	key := s.EnrolHMACKey()
	if key.IsZero() {
		t.Fatalf("first Open returned a Store with the zero EnrolHMACKey — state.Open skipped LoadOrCreateEnrolHMACKey on the new-store branch (IAMT-140). enrol-hmac.key may be missing on disk too; check that %s exists and is 32 bytes.", filepath.Join(dir, state.EnrolHMACKeyFileName))
	}

	keyPath := filepath.Join(dir, state.EnrolHMACKeyFileName)
	data, rerr := os.ReadFile(keyPath)
	if rerr != nil {
		t.Fatalf("first Open did not leave %s on disk: %v — enrol HMAC key must be persisted immediately so a subsequent gateway run (which loads the SAME key) can verify what install hashed", keyPath, rerr)
	}
	if len(data) != 32 {
		t.Fatalf("enrol HMAC key file %s is %d bytes, want 32", keyPath, len(data))
	}

	var onDisk state.EnrolHMACKey
	copy(onDisk[:], data)
	if onDisk != key {
		t.Fatalf("enrol HMAC key from EnrolHMACKey() does not match the on-disk file (file=%x, returned=%x) — Store.Open and the on-disk file must agree, otherwise gateway run after gateway install would derive a different hash from the one install wrote", onDisk, key)
	}
}

// TestIAMT140_Open_KeyStableAcrossReopens is the persistence
// guarantee: opening the same data directory twice must hand back the
// SAME EnrolHMACKey, because the key on disk is the single source of
// truth and install + first run must agree on it. Without that
// agreement, every secret hashed at install time is un-redeemable
// after the first restart.
//
// With the pre-fix code, the first Open returned a zero key (because
// the load happened only after parseStateBytes succeeded) and the
// second Open returned a random key — those two disagree by
// construction. The fix loads the key on both branches, so the test
// is green either way; the canary mutation "return early in creation
// branch" reintroduces the disagreement and lands here.
func TestIAMT140_Open_KeyStableAcrossReopens(t *testing.T) {
	dir := t.TempDir()

	first, err := state.Open(dir)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	keyA := first.EnrolHMACKey()
	if err := first.Close(); err != nil {
		t.Fatalf("close after first Open: %v", err)
	}

	second, err := state.Open(dir)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer second.Close()
	keyB := second.EnrolHMACKey()

	if keyA.IsZero() {
		t.Fatalf("first Open returned a zero EnrolHMACKey — IAMT-140: state.Open skipped LoadOrCreateEnrolHMACKey on the new-store branch")
	}
	if keyB.IsZero() {
		t.Fatalf("second Open returned a zero EnrolHMACKey — that means state.Open is not loading the key on either branch; check that LoadOrCreateEnrolHMACKey runs before any return")
	}
	if keyA != keyB {
		t.Fatalf("EnrolHMACKey changed between two Opens of the same directory (A=%x B=%x) — the on-disk enrol-hmac.key must be the single source of truth, otherwise secrets hashed at install time are un-redeemable after the first restart", keyA, keyB)
	}
}

// TestIAMT140_HashEnrolSecret_RoundTripsAcrossReopen is the actual
// property the user-visible bug broke: a secret hashed at first Open
// must verify after the store is closed and reopened. This is the
// "install wrote a hash, gateway run needs to verify it" path that
// was silently broken by the zero-key bug: install hashed with the
// zero key, gateway run hashed with the random key, and the first
// admin.claim never matched.
//
// With the fix, both Opens see the same key, the hash on disk was
// produced by the same key the second Open loaded, and the equality
// holds. With the canary mutation "return early in creation branch"
// applied, the first Open's key is zero and the hash computed below
// is hmac(zero, secret); the second Open's key is random and the
// hash on disk does NOT match a fresh hash under that random key.
// The test fails with the canary mutation and passes without it.
func TestIAMT140_HashEnrolSecret_RoundTripsAcrossReopen(t *testing.T) {
	dir := t.TempDir()

	first, err := state.Open(dir)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	const secret = "bootstrap-secret-roundtrip"
	hashedAtCreate := state.HashEnrolSecret(first.EnrolHMACKey(), []byte(secret))
	if err := first.Close(); err != nil {
		t.Fatalf("close after first Open: %v", err)
	}

	second, err := state.Open(dir)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer second.Close()

	// The post-reopen Store must produce the SAME bytes for the same
	// secret. We do the comparison the way state.json would: byte
	// equality on the 32-byte sums (the runtime side uses hmac.Equal
	// for constant-time, but for this off-disk test the goal is to
	// detect a wrong key, not to defend against a local timing
	// channel).
	hashedAfterReopen := state.HashEnrolSecret(second.EnrolHMACKey(), []byte(secret))
	if !bytes.Equal(hashedAtCreate[:], hashedAfterReopen[:]) {
		t.Fatalf("hash of the same secret differs between two Opens (at-create=%x after-reopen=%x) — IAMT-140: install hashed with key X, gateway run loaded key Y; admin.claim will never match. The on-disk enrol-hmac.key is the single source of truth and must agree across Opens", hashedAtCreate, hashedAfterReopen)
	}
}

// TestIAMT140_HashEnrolSecret_PanicsOnZeroKey is the guard-rail for
// the second half of the fix: a zero EnrolHMACKey is a programming
// error and HashEnrolSecret refuses to silently produce plausible
// bytes under it. Without the panic, the regression that IAMT-140
// names would still ship "valid-looking" hashes, and only an attacker
// who knew the zero key would notice.
//
// The test expects a panic with a message that names the function and
// the IAMT-140 invariant. The recover() block turns the panic into a
// normal failure: the test fails if HashEnrolSecret does NOT panic,
// and passes with the documented message. A regression that replaces
// the panic with a silent return is caught here; a regression that
// changes the message is caught too — the assertion below checks the
// substring "EnrolHMACKey" so any wording that keeps the function
// name and the key type still passes.
func TestIAMT140_HashEnrolSecret_PanicsOnZeroKey(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("HashEnrolSecret(EnrolHMACKey{}, ...) did not panic — a zero key must be refused loudly, not silently turned into a meaningless HMAC. The whole point of IAMT-140 is that this regression cannot hide.")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("HashEnrolSecret panicked with non-string value %T (%v); the panic message must be a plain string so the operator sees the IAMT-140 invariant name in the trace", r, r)
		}
		if !contains(msg, "EnrolHMACKey") {
			t.Fatalf("HashEnrolSecret panic message %q does not name the key type; readers need to know IAMT-140 is the contract that was violated", msg)
		}
	}()
	_ = state.HashEnrolSecret(state.EnrolHMACKey{}, []byte("anything"))
}

// TestIAMT140_EnrolHMACKey_IsZeroMatchesZeroValue pins the predicate
// the panic check relies on. If a future regression makes IsZero
// return false for the zero value (or true for a non-zero value), the
// panic stops firing precisely when it should — that would be the
// worst possible failure mode for this guard rail, so the test
// asserts both directions: zero is zero, anything else is not.
func TestIAMT140_EnrolHMACKey_IsZeroMatchesZeroValue(t *testing.T) {
	var zero state.EnrolHMACKey
	if !zero.IsZero() {
		t.Fatalf("EnrolHMACKey{}.IsZero() returned false; the predicate the HashEnrolSecret panic relies on is wrong")
	}

	nonZero := state.EnrolHMACKey{}
	nonZero[0] = 1
	if nonZero.IsZero() {
		t.Fatalf("EnrolHMACKey{[0]=1}.IsZero() returned true; IsZero must recognise any non-zero byte as making the key non-zero")
	}
}

// contains is the strings.Contains shim so this file does not need
// to import "strings" just for one check. The panic-message substring
// check is the only place it's used.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
