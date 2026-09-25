package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// keyFile is the file name of the person's own private key inside the
// client data directory (mirrors config.Dirs.ClientKey's "key" name).
// SPEC §3.1 also allows an ssh-agent key or ~/.ssh/id_ed25519; this build
// only implements the client's own generated key, so the real ssh
// folder is never opened.
const keyFile = "key"

// KeyPath returns the path EnsureKey reads and writes inside dir.
func KeyPath(dir string) string { return filepath.Join(dir, keyFile) }

// EnsureKey loads the person's ed25519 key from dir, generating and
// saving a new one (PEM, owner-only) the first time it is needed. The
// path is always dir-derived, never ~/.ssh: the person's key lives only
// where the client role already keeps its own state.
//
// The first run is create-if-absent, never a replace (M-9c, code review
// 23.09.2026, review F-09): the window and the CLI can be first runs at
// the same moment, and a replace would let the second overwrite the
// first while each caller kept its own pair — see createKeyIfAbsent.
// An existing file is read as it always was, and a file that does not
// parse is an error naming the file, never a regeneration.
//
// An existing key file is also checked for other accounts' access and
// refused when they have it: on Unix its world- or group-readable mode
// bits (OpenSSH's "UNPROTECTED PRIVATE KEY FILE" rule), on Windows its
// access list (M-9d). The check and the read go through the
// same opened file on both — the mode bits from its fstat, the access
// list from its handle (R1-CX F-14) — so a swap between the check and
// the read cannot slip a different file under us.
func EnsureKey(dir string) (ssh.Signer, error) {
	path := KeyPath(dir)
	f, info, err := openKeyFile(path)
	switch {
	case err == nil:
		defer f.Close()
		return loadKeyFile(path, f, info)
	case os.IsNotExist(err):
		return createKeyIfAbsent(dir, path)
	default:
		return nil, classifyPathErr(err, path)
	}
}

// loadKeyFile turns an already-open key file into a signer: the Unix
// permission check, the read and the parse, all on the descriptor the
// caller opened (so the file that was checked is the file that is read).
// Every failure is classified and names the path — a corrupt or
// unreadable key is a thing the person has to act on, not a reason to
// write a new one over it.
func loadKeyFile(path string, f *os.File, info os.FileInfo) (ssh.Signer, error) {
	if perr := checkKeyFilePerms(path, f, info); perr != nil {
		return nil, perr
	}
	data, rerr := io.ReadAll(f)
	if rerr != nil {
		return nil, classifyPathErr(rerr, path)
	}
	raw, perr := ssh.ParseRawPrivateKey(data)
	if perr != nil {
		return nil, classifyPathErr(fmt.Errorf("does not parse as a private key (%w) — remove it and run \"client connect-string\" again to generate a new one", perr), path)
	}
	signer, serr := ssh.NewSignerFromKey(raw)
	if serr != nil {
		return nil, classifyPathErr(fmt.Errorf("is not a supported key type (%w)", serr), path)
	}
	return signer, nil
}

// createKeyIfAbsent generates the person's key and publishes it at path
// WITHOUT ever replacing a file that is already there (M-9c, code
// review 23.09.2026, review F-09).
//
// The window and the CLI can both be a first run at the same moment.
// Each used to find no key, generate its own pair and land it with an
// atomic REPLACE — so the second overwrote the first and every caller
// was handed ITS OWN key (on Windows the two replaces even collided,
// and one of them failed with "Access is denied"). The disk then kept a
// key nobody had returned, and the public half the person was told to
// register belonged to a private key that existed nowhere any more.
//
// datafile.Create is O_CREATE|O_EXCL: exactly one caller can win the
// name, and only a plain regular file already there comes back as
// os.ErrExist. The loser generates nothing — it reads the winner's file
// and hands back THAT key, so every concurrent first run returns the key
// the disk holds. An entry at the name that is not a regular file of
// ours (a symlink, a FIFO, a hard link) is refused in words by the same
// primitive, and such a refusal is never turned into a regeneration.
func createKeyIfAbsent(dir, path string) (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("client: generate key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "iamtunnel client key")
	if err != nil {
		return nil, fmt.Errorf("client: marshal key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, classifyPathErr(err, dir)
	}
	// The bytes are ready BEFORE the name is claimed: what remains
	// between Create returning and the file being complete is one write,
	// which is the whole of the window the loser has to wait out.
	pemBytes := pem.EncodeToMemory(block)
	f, err := createKeyFile(path)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Another first run won the name while we were generating:
			// its key is the one on disk, so its key is the one to hand
			// back. Ours was never written anywhere and is dropped.
			return readWinnersKey(path)
		}
		return nil, classifyPathErr(err, path)
	}
	// We won the name. createKeyFile is datafile's create-or-refuse
	// primitive, the one the rest of the program uses — never the flat
	// path+".tmp" this function used before IAMT-332 round 9 (that name
	// was predictable, and a planted symlink or hard link aimed the PEM
	// write at somebody else's file). The client directory is not
	// exempt: every admin verb and every --data-dir can aim a
	// privileged run at it (SPEC §3.1).
	//
	// The file is protected from the moment it exists, before the key
	// material lands in it: 0600 on Unix, and on Windows its own access
	// list set in the create itself (R1-CX F-14). A list set a step later
	// left a moment in which the file carried its folder's inherited
	// list, and on a shared --data-dir another account could open it then
	// and read the key once it was written (M-9d, review F-08).
	if werr := writeNewKeyFile(f, pemBytes); werr != nil {
		return nil, classifyPathErr(werr, path)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("client: signer from generated key: %w", err)
	}
	return signer, nil
}

// writeNewKeyFile fills the file createKeyIfAbsent has just claimed. A
// failure leaves the name where it is: removing it would be a second
// writer racing the loser's read of the winner's key. The next run reads
// what is there and refuses a file that does not parse, which is the
// honest outcome of a key that never finished being written.
func writeNewKeyFile(f *os.File, data []byte) error {
	n, err := f.Write(data)
	if err != nil {
		f.Close()
		return err
	}
	if n != len(data) {
		f.Close()
		return io.ErrShortWrite
	}
	return f.Close()
}

// readWinnersKey reads the key another first run has just published.
//
// The winner claims the name and THEN writes into it — there is no
// portable create-with-content — so a loser reading in that gap sees an
// empty file. An empty file is not a corrupt key, it is a key being
// born, and the answer is to wait for the writer that owns the name.
// The wait is bounded: a file that is still empty after half a second is
// genuinely broken, and the honest answer then is the parse refusal
// loadKeyFile gives (this program never writes an empty key file).
func readWinnersKey(path string) (ssh.Signer, error) {
	const (
		attempts = 250
		pause    = 2 * time.Millisecond
	)
	for i := 0; ; i++ {
		f, info, err := openKeyFile(path)
		if err != nil {
			return nil, classifyPathErr(err, path)
		}
		if info.Size() > 0 || i == attempts {
			defer f.Close()
			return loadKeyFile(path, f, info)
		}
		f.Close()
		time.Sleep(pause)
	}
}

// openKeyFile opens path for reading and returns both the handle and
// the stat of THAT handle. Caller must Close the handle. The single
// open + the single fstat close the TOCTOU window between the
// permission check and the read: an attacker who replaces the file
// after we open it does not change the file we are about to read.
//
// The open itself is datafile.OpenExisting (IAMT-332 round 9): the
// client directory may be attacker-controlled whenever a privileged
// command is aimed at it (SPEC §3.1), so a symlink or FIFO planted at
// the key's name is refused outright instead of being read through or
// wedged on. A missing name keeps the raw error, so EnsureKey's
// first-run branch is unchanged.
func openKeyFile(path string) (*os.File, os.FileInfo, error) {
	f, err := datafile.OpenExisting(path, os.O_RDONLY)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}
