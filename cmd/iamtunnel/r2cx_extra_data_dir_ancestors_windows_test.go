package main

// R2 supplementary round, found while fixing R2-CX F-07, F-12 and F-13: locking a data
// directory - its DACL, its owner, everything in it - says nothing about
// the folder it sits in. Whoever may rename that folder, or delete and
// rename what is in it, moves the locked directory aside and puts one of
// their own in its place: the gateway service takes that one for its
// own at its next start, and a machine's enrol writes its key into it.
// %ProgramData% lets every signed-in user create folders, so
// %ProgramData%\iamtunnel - the parent of the default gateway directory -
// is anybody's to make first; a --data-dir anywhere is under whatever
// folders happen to be above it. The owner of such a folder can always
// grant themselves the right to delete what is in it.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// r2cxExtraRefusedNamingGuests fails unless err is a denied-class refusal
// that names the Guests-owned folder's owner.
func r2cxExtraRefusedNamingGuests(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted under a folder %s owns - they can move the locked directory aside and put their own in its place", what, r2cxGuests)
	}
	if !strings.Contains(err.Error(), "Guests") && !strings.Contains(err.Error(), r2cxGuests) {
		t.Fatalf("%s: refused, but without naming who can change the folder above it: %v", what, err)
	}
	var ce *cliError
	if !errors.As(err, &ce) || ce.code != exitDenied {
		t.Fatalf("%s: refused as %v, want the denied class (exit %d): the operator's to fix, like a foreign owner", what, err, exitDenied)
	}
}

func TestR2CXExtra_AGatewayDataDirectoryUnderAFolderAnotherAccountOwnsIsRefused(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "iamtunnel")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	r2cxSetOwner(t, parent, r2cxGuests)
	release, err := hardenGatewayDataDirForService(filepath.Join(parent, "gateway"), false, nil)
	if err == nil {
		release()
	}
	r2cxExtraRefusedNamingGuests(t, "the gateway data directory", err)
}

func TestR2CXExtra_AMachineDataDirectoryUnderAFolderAnotherAccountOwnsIsRefused(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "iamt")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	r2cxSetOwner(t, parent, r2cxGuests)
	r2cxExtraRefusedNamingGuests(t, "the machine data directory", hardenServerDir(filepath.Join(parent, "server"), false))
}
