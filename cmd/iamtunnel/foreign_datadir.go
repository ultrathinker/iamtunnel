package main

// IAMT-333 (P1.6): the foreign-data-directory gate. An elevated command
// that is about to write into a data directory somebody else owns is the
// IAMT-315 class still open one level up from the datafile contract: the
// contract keeps every individual write from following a plant at a name,
// but a directory owned by another account is a place where that other
// account can aim the writes in the first place — swap the directory
// itself, not a name inside it. So the command refuses BEFORE the first
// write (a refusal that fires after the key exists leaves a live secret
// behind — IAMT-315's lesson), names the owner, and names the one flag
// that overrides it: --accept-foreign-data-dir, for a directory the
// operator has verified themselves.
//
// What never refuses: a directory that does not exist yet (a first run is
// legitimate — creating it is the command's job), a directory owned by
// this process's own account, a directory owned by root (POSIX) or by
// Administrators/SYSTEM/TrustedInstaller (Windows) — the system locations
// the product uses by default — and, entirely, a command that is not
// elevated: a process without elevated rights cannot write into somebody
// else's directory anyway, so there is nothing for the gate to say. A
// probe that cannot answer (permissions, an exotic owner) refuses too:
// "cannot verify" is not the state in which a privileged command writes.
//
// The client data directory is where this gate stands (the gateway and
// server custom directories already carry their own stricter checks —
// IAMT-308's root-ancestors rule on install; the client directory is the
// one every client, admin and GUI action writes and the one preserved
// HOME, IAMTUNNEL_DATA_DIR, --data-dir /tmp/x and another admin's
// elevated console all reach).

import (
	"fmt"

	"github.com/ultrathinker/iamtunnel/internal/elevate"
)

// dataDirOwnerForeign is the platform probe: given a directory, it returns
// the human-readable reason the directory belongs to an account this
// process is not ("" — including for a missing directory — means pass).
// The phrase is spoken verbatim in the refusal, which is why the platform
// files build it whole.
var dataDirOwnerForeign = dataDirOwnerForeignOS

// foreignDirElevation is the elevation source for callers that have no
// streams to carry one — the window's action wrappers (gui_actions.go).
// The CLI verbs pass their streams and use the same seam every other
// elevation gate uses (requireServerElevation), which is what the test
// driver drives.
var foreignDirElevation = elevate.IsElevated

// dropToInvoker is IAMT-333 P2.8 (IAMT-504): the other answer to a foreign
// data directory, for the one case where the right owner is known. A
// client or admin verb that somebody ran under sudo by habit, against
// their OWN directory, has no use for root at all -- every write it is
// about to make belongs to the person who typed sudo. So instead of
// refusing, the command gives root up for good, becomes that person, and
// carries on; the writes land as theirs, and none of them is made by
// root inside a directory root does not own.
//
// It reports whether it dropped. false with a nil error is "not this
// case" and leaves the refusal standing; an error is a drop that began
// and could not be completed, which refuses too. Only the CLI verbs reach
// it (clientDataDir): the window is a long-lived process that may still
// need its rights for the server it starts, and keeps the plain refusal.
var dropToInvoker = dropToInvokerOS

// refuseForeignDataDir is the gate itself. accept is the command's
// --accept-foreign-data-dir verdict; the GUI wrappers pass false — the
// window has no flag to pass, and its ordinary process is not elevated,
// which is the state the gate stays silent in.
func refuseForeignDataDir(s *streams, path, dir string, accept bool) error {
	check := foreignDirElevation
	if s != nil && s.isElevated != nil {
		check = s.isElevated
	}
	elevated, eerr := check()
	if eerr != nil || !elevated {
		return nil
	}
	if accept {
		return nil
	}
	reason, oerr := dataDirOwnerForeign(dir)
	if oerr != nil {
		return deniedErrf("iamtunnel %s: cannot verify the owner of the data directory %s: %v — pass --accept-foreign-data-dir if you have verified the directory yourself.", path, dir, oerr)
	}
	if reason == "" {
		return nil
	}
	return deniedErrf("iamtunnel %s: %s is %s. Run the command as that account, or pass --accept-foreign-data-dir if you have verified the directory yourself.", path, dir, reason)
}

// clientDataDir resolves the client role's data directory for a command
// and stands the foreign-owner gate in front of whatever the command
// writes next (the key, the saved connection). Every client verb and both
// admin write paths (runAdminVerb, admin pair) resolve the client
// directory through here, so a new verb inherits the gate by using the
// one resolver rather than by remembering a second check.
func clientDataDir(s *streams, path string, o cfgOpts, fs *flagSet) (string, error) {
	_, dir, err := loadConfig(s, "client", o)
	if err != nil {
		return "", err
	}
	if err := refuseForeignDataDir(s, path, dir, fs.has("accept-foreign-data-dir")); err != nil {
		var env map[string]string
		if s != nil {
			env = s.env
		}
		dropped, derr := dropToInvoker(env, dir)
		if derr != nil {
			return "", deniedErrf("iamtunnel %s: %s could not give up root to act as the owner of %s: %v", path, path, dir, derr)
		}
		if !dropped {
			return "", err
		}
		if s != nil && s.errs != nil {
			fmt.Fprintf(s.errs, "iamtunnel %s: %s belongs to the account that ran sudo; running this command as that account, without root.\n", path, dir)
		}
	}
	return dir, nil
}
