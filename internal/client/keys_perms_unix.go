//go:build !windows

package client

import (
	"fmt"
	"os"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// checkKeyFilePerms refuses an existing key file whose mode allows any
// access for group or other. The owner's ed25519 private key is what an
// attacker needs to impersonate the person (SPEC §3.1); OpenSSH ships
// the same refusal under the name "UNPROTECTED PRIVATE
// KEY FILE" for exactly this reason. We surface it as a clear env-class
// error (the path is configured) with a chmod 600 hint, not as a generic
// ClassUser "permission denied" — a Linux session inherits no such DACL
// and an empty error here is how someone forgets to lock the key.
//
// On non-Windows the mode bits come from the file's stat. We deliberately
// do NOT call os.Chmod to "fix" it: a wrong key in a shared-readable
// file is a security event the user must acknowledge, not a typo the
// tool silently papers over.
func checkKeyFilePerms(path string, _ *os.File, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return classifyPathErr(fmt.Errorf(
			"is readable by group or other (%o); fix with: chmod 600 %q — refusing to use an unprotected private key file",
			info.Mode().Perm(), path), path)
	}
	return nil
}

// createKeyFile claims the key's name for writing: datafile.Create, 0600
// with O_EXCL, so the file can never have carried anything wider (M-9d).
// Windows has no mode bits - a new file there would inherit its folder's
// access list - so there the key's own list is part of the create
// (keys_perms_windows.go).
func createKeyFile(path string) (*os.File, error) { return datafile.Create(path, 0o600) }
