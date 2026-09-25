package main

// R2-CX F-05: on Windows, gateway install created the data directory with
// whatever its parent handed down - under %ProgramData% that is read access
// for every signed-in user - wrote the host key, the bootstrap token,
// enrol-hmac.key and state.json into it, printed the bootstrap reference,
// and only then, inside the service half, gave the directory its own
// protected DACL. Anyone who could read the parent could read the secrets
// in between, and if the service half failed they stayed that way.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// r2cxF05Secrets are the files install writes that nobody but the
// gateway may read.
var r2cxF05Secrets = []string{hostkeyFileName, bootstrapFileName, state.EnrolHMACKeyFileName, state.StateFileName}

func r2cxF05Held(listing []string) []string {
	var held []string
	for _, name := range listing {
		for _, secret := range r2cxF05Secrets {
			if strings.EqualFold(name, secret) {
				held = append(held, name)
			}
		}
	}
	return held
}

func r2cxF05List(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestR2CX_F05_TheDataDirectoryIsLockedBeforeTheFirstSecretIsWritten(t *testing.T) {
	rec := withFakeGatewayService(t)
	dir := t.TempDir()
	if _, errs, code := drive(t, "gateway", "install", "--public-host", "gw.example.test", "--data-dir", dir); code != exitOK {
		t.Fatalf("gateway install: code %d: %s", code, errs)
	}
	if len(rec.presentAtHarden) == 0 {
		t.Fatal("install never locked the data directory")
	}
	if held := r2cxF05Held(rec.presentAtHarden[0]); len(held) > 0 {
		t.Fatalf("the data directory was first locked when it already held %v: those were written, readable to whatever its parent allows, before it had a DACL of its own", held)
	}
}

func TestR2CX_F05_AnInstallThatCannotLockTheDataDirectoryWritesAndPrintsNoSecret(t *testing.T) {
	rec := withFakeGatewayService(t)
	rec.hardenResult = errors.New("access denied")
	dir := t.TempDir()
	out, _, code := drive(t, "gateway", "install", "--public-host", "gw.example.test", "--data-dir", dir)
	if code == exitOK {
		t.Fatal("gateway install succeeded without locking its data directory")
	}
	if strings.Contains(out, "bootstrap reference") {
		t.Errorf("the bootstrap reference was printed by an install that could not lock the directory it lives in:\n%s", out)
	}
	if held := r2cxF05Held(r2cxF05List(t, dir)); len(held) > 0 {
		t.Fatalf("an install that could not lock its data directory left %v in it, readable to whatever its parent allows", held)
	}
}

// r2cxF05ACE is one entry of a DACL as the test reads it.
type r2cxF05ACE struct {
	sid       string
	inherited bool
}

// r2cxF05ACEs reads every entry of path's DACL, inherited ones included.
func r2cxF05ACEs(t *testing.T, path string) []r2cxF05ACE {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s has no DACL: %v", path, err)
	}
	var out []r2cxF05ACE
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		out = append(out, r2cxF05ACE{sid: sid.String(), inherited: ace.Header.AceFlags&windows.INHERITED_ACE != 0})
	}
	return out
}

// The directory a fresh install writes its secrets into is created with
// its own DACL - not created, then locked a moment later.
func TestR2CX_F05_AFreshDataDirectoryIsCreatedWithItsOwnDACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gateway")
	if err := createGatewayDataDirLocked(dir); err != nil {
		t.Fatal(err)
	}
	protected, err := winkeys.DACLProtected(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !protected {
		t.Error("the fresh data directory's DACL is not protected: whatever its parent hands down reaches it")
	}
	service, err := serviceAccountSID(gatewayServiceName)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"S-1-5-32-544": true, "S-1-5-18": true, service.String(): true}
	aces := r2cxF05ACEs(t, dir)
	for _, a := range aces {
		if a.inherited || !want[a.sid] {
			t.Errorf("the fresh data directory carries %+v - only SYSTEM, Administrators and the service account, none of them inherited, belong there", a)
		}
		delete(want, a.sid)
	}
	if len(want) > 0 {
		t.Errorf("the fresh data directory is missing %v", want)
	}
	// A directory that is already there is left to the hardening that follows.
	if err := createGatewayDataDirLocked(dir); err != nil {
		t.Fatalf("a second call on an existing directory: %v", err)
	}
}
