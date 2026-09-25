//go:build (windows || linux || darwin) && !nogui

package main

// r4_f14_new_person_gui_test.go — R4 F-14, the window's half.
//
// Adding a person needs their public key; a person's key appeared in the
// window only after they saved a connection string; and the product gave
// a connection string only for a person who already existed. The way out
// of the circle was to build "iamtunnel://host:port/name#fingerprint" by
// hand from the documents. Now the Key sub-tab shows the key on a machine
// that has saved nothing yet, and "Add person" answers with the string
// the administrator hands back.

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
)

func TestR4F14_TheKeyIsShownBeforeAnyConnectionIsSaved(t *testing.T) {
	key := guiClientPublicKey(t.TempDir())
	if !strings.HasPrefix(key, "ssh-ed25519 ") {
		t.Fatalf("R4 F-14: a machine with no saved connection shows no key (%q) — the person has nothing to give the administrator", key)
	}
}

func TestR4F14_AddPersonAnswersWithTheirConnectionString(t *testing.T) {
	tg := startTestGateway(t, "alice")
	_, portStr, err := net.SplitHostPort(tg.addr.String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	cDir := t.TempDir()
	writeClientKeyPEM(t, cDir, tg.adminPriv)
	if err := client.SaveConnection(cDir, config.ConnString{Host: "127.0.0.1", Port: port, Person: "alice", Fingerprint: tg.hostFP}, false); err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}
	msg, err := guiAdminPeopleAdd(cDir, "bob", "user", pubKeyLine(t))
	if err != nil {
		t.Fatalf("guiAdminPeopleAdd: %v", err)
	}
	if !strings.Contains(msg, "iamtunnel://") || !strings.Contains(msg, "/bob#") {
		t.Fatalf("R4 F-14: Add person does not give the administrator bob's connection string: %q", msg)
	}
}

// review finding R4 N-01, the window's half: opening the window must not create a
// key in a data directory somebody else owns (IAMT-333) - an elevated
// window configured with another account's client_dir used to write it.
func TestR4F14_TheWindowWritesNoKeyIntoAForeignDataDir(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, "owned by another account", nil)
	stubGUIElevation(t, true)
	if key := guiClientPublicKey(dir); key != "" {
		t.Fatalf("review finding R4 N-01: an elevated window showed (and so created) a key in a foreign directory: %q", key)
	}
	if _, err := os.Stat(client.KeyPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("the window wrote the private key into a foreign directory (%v)", err)
	}
}

// review finding R4 recheck of N-01: two more window actions wrote into the client
// data directory before the foreign-directory gate - the admin Forget
// (drops the saved connection) and the agent prompt (writes
// agent_known_hosts). Both now refuse first, like every other action.
func TestR4CXN01_EveryWindowWriteIntoTheClientDirPassesTheGate(t *testing.T) {
	dir := iamt333SeedDir(t)
	stubOwnerProbe(t, dir, "owned by another account", nil)
	stubGUIElevation(t, true)
	if _, err := guiAdminForget(dir); err == nil || !strings.Contains(err.Error(), "--accept-foreign-data-dir") {
		t.Fatalf("review finding R4 N-01: the window's Forget acted on a foreign client directory (err=%v)", err)
	}
	if _, err := guiAgentPrompt(dir, "vm1"); err == nil || !strings.Contains(err.Error(), "--accept-foreign-data-dir") {
		t.Fatalf("review finding R4 N-01: the window's agent prompt acted on a foreign client directory (err=%v)", err)
	}
}
