package state

// enrol_hmac.go: the gateway's HMAC key for enrol/bootstrap secret
// hashing (PROTOCOL §3.2 / §3.3). The raw enrol-secret is never
// persisted; only HMAC-SHA-256(enrolHMACKey, raw-secret) is, and the
// same hash is the only thing the gateway can later compare against.
//
// The key lives in its own file (mode 0600) under the gateway data
// directory. Generating it at install time and never writing it
// anywhere else is what gives this scheme its secrecy: anyone who can
// read state.json still cannot recover a usable enrol secret without
// also reading enrol-hmac.key. state.json alone, the most likely
// thing to leak (backups, accidental copies, file-share audits), does
// not suffice.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
)

// EnrolHMACKeyFileName is the file that holds the 32-byte HMAC key in
// the gateway data directory. Created on first call with mode 0600.
const EnrolHMACKeyFileName = "enrol-hmac.key"

// EnrolHMACKey is a 32-byte HMAC key. It is never logged, never
// returned to callers by string, and never marshaled to JSON.
type EnrolHMACKey [32]byte

// IsZero reports whether k is the all-zero byte string. The zero value
// is NOT a valid HMAC key: anyone who can read state.json knows the
// "key" and can verify guesses offline (IAMT-140 round two).
// LoadOrCreateEnrolHMACKey only ever returns a key that has been filled
// by crypto/rand, so the all-zero value should never appear in a real
// Store; this method is the guard rail that catches the case in code
// review and, through HashEnrolSecret's panic, at runtime.
func (k EnrolHMACKey) IsZero() bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

// HashEnrolSecret returns the HMAC-SHA-256 of raw under k, exactly the
// value state.json will later compare a presented secret against.
// Compares with hmac.Equal on the consumer side; this function itself
// is not the side that decides accept/reject, only the byte string
// the comparison runs over.
//
// Panics on a zero key. A HMAC under the all-zero "key" is not a
// keyed hash at all: an attacker who can read state.json can
// recompute it offline, defeating the entire protection enrolhmac.go
// promises. The only way a zero key reaches this function is a
// regression in Open that bypasses LoadOrCreateEnrolHMACKey — the
// exact bug IAMT-140 round two fixes in store.go. Panicking is the
// loud, in-our-face signal that fits the "this should never happen"
// contract; silently returning a value would hide the regression and
// let protection erode again. There is no caller in the product that
// can produce a zero key on purpose; tests that want to assert the
// panic can call this directly.
func HashEnrolSecret(k EnrolHMACKey, raw []byte) [32]byte {
	if k.IsZero() {
		panic("state.HashEnrolSecret: refusing to hash with a zero EnrolHMACKey (this means state.Open skipped LoadOrCreateEnrolHMACKey; see IAMT-140)")
	}
	mac := hmac.New(sha256.New, k[:])
	mac.Write(raw)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// LoadOrCreateEnrolHMACKey reads the HMAC key from dir/EnrolHMACKeyFileName,
// creating it (with mode 0600) if it does not exist. A file that exists
// but is the wrong length is a configuration error and refused — there
// is no "guess and proceed" path, because proceeding with the wrong key
// would silently render every issued enrol code un-redeemable.
//
// dir is whatever the gateway code resolves to, so this function never
// hard-codes a location the caller did not choose.
func LoadOrCreateEnrolHMACKey(dir string) (EnrolHMACKey, error) {
	if dir == "" {
		return EnrolHMACKey{}, errors.New("enrol HMAC: empty directory")
	}
	path := dir + "/" + EnrolHMACKeyFileName
	if k, err := readEnrolHMACKey(path); err == nil {
		return k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return EnrolHMACKey{}, err
	}
	// First-time creation. 32 random bytes is plenty; rand.Read on
	// every supported platform pulls from a CSPRNG (Windows:
	// CryptGenRandom; Linux: getrandom(2)).
	var k EnrolHMACKey
	if _, err := rand.Read(k[:]); err != nil {
		return EnrolHMACKey{}, fmt.Errorf("enrol HMAC: generate key: %w", err)
	}
	// O_EXCL: only the creator wins the name, so two concurrent
	// first-time creators cannot truncate each other's key, and a
	// planted file at this path is never overwritten. The loser reads
	// the winner's key below.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return readEnrolHMACKey(path)
		}
		return EnrolHMACKey{}, fmt.Errorf("enrol HMAC: create %s: %w", path, err)
	}
	if _, err := f.Write(k[:]); err != nil {
		_ = f.Close()
		return EnrolHMACKey{}, fmt.Errorf("enrol HMAC: write %s: %w", path, err)
	}
	// The fresh key carries the creating process's account: a root-run
	// "gateway pair" over a gateway whose key was missing would leave it
	// owned by root, and the unprivileged service could never hash
	// another enrol secret (IAMT-332). Adopt the data directory's owner
	// on the open descriptor, before the key is released.
	if err := adoptOwnership(f, ""); err != nil {
		_ = f.Close()
		return EnrolHMACKey{}, fmt.Errorf("enrol HMAC: %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return EnrolHMACKey{}, fmt.Errorf("enrol HMAC: close %s: %w", path, err)
	}
	return k, nil
}

// readEnrolHMACKey reads and validates the key file at path. The read
// goes through the no-symlink open (IAMT-332 round three): the key file
// is the one file whose CONTENT the service trusts blindly, so a link
// planted at its name is refused, never read through. The
// os.ErrNotExist of the underlying open is returned unwrapped so the
// caller can distinguish "must create" from every other failure.
func readEnrolHMACKey(path string) (EnrolHMACKey, error) {
	f, err := OpenExistingDataFile(path, os.O_RDONLY)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return EnrolHMACKey{}, err
		}
		return EnrolHMACKey{}, fmt.Errorf("enrol HMAC: read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(f)
	if err != nil {
		return EnrolHMACKey{}, fmt.Errorf("enrol HMAC: read %s: %w", path, err)
	}
	if len(data) != 32 {
		return EnrolHMACKey{}, fmt.Errorf("enrol HMAC: %s is %d bytes, want 32", path, len(data))
	}
	var k EnrolHMACKey
	copy(k[:], data)
	return k, nil
}
