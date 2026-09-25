//go:build (windows || linux || darwin) && !nogui

package main

// gui_admin_pair_test.go pins the GUI pairing card's LOCAL refusals — the
// checks guiAdminPair makes before any network is touched, so a typo
// cannot burn one of the gateway's three wrong-PIN attempts per address
// (and a malformed reference cannot even start the machine's key). The
// proof that nothing ran is the client directory itself: EnsureKey (the
// first step with a side effect) creates it, so a refusal that happened
// before it leaves the directory nonexistent.

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testPairingRef builds a well-formed pairing reference pointing at a
// closed loopback port: parsing must accept it, dialing must refuse it.
func testPairingRef(t *testing.T) string {
	t.Helper()
	fp := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	return "127.0.0.1:1#" + fp
}

func TestGuiAdminPairRefusesABadReferenceBeforeAnythingElse(t *testing.T) {
	root := t.TempDir()
	clientDir := filepath.Join(root, "client")

	_, err := guiAdminPair(clientDir, "gw.example.net:2022", "123456")

	if err == nil {
		t.Fatalf("guiAdminPair accepted a reference without the '#' fingerprint part")
	}
	if _, statErr := os.Stat(clientDir); !os.IsNotExist(statErr) {
		t.Errorf("client directory exists after a refused reference — the machine's key must not be created for a reference that cannot parse")
	}
}

func TestGuiAdminPairRefusesABadPinShapeBeforeCreatingTheKey(t *testing.T) {
	root := t.TempDir()
	clientDir := filepath.Join(root, "client")

	for _, pin := range []string{"12345", "1234567", "12a456", ""} {
		_, err := guiAdminPair(clientDir, testPairingRef(t), pin)
		if err == nil {
			t.Fatalf("guiAdminPair accepted PIN %q", pin)
		}
		if !strings.Contains(err.Error(), "6 decimal digits") {
			t.Errorf("guiAdminPair(%q) error = %v, want the six-digits sentence", pin, err)
		}
	}
	if _, statErr := os.Stat(clientDir); !os.IsNotExist(statErr) {
		t.Errorf("client directory exists after refused PINs — a wrong-shaped PIN must not create the machine's key, let alone reach the gateway")
	}
}

func TestGuiAdminPairReachesTheDialWithAWellFormedRefAndPin(t *testing.T) {
	root := t.TempDir()
	clientDir := filepath.Join(root, "client")

	// 127.0.0.1:1 is a closed port: the dial fails locally, fast, with
	// nothing but the loopback involved. The leading-zero PIN proves the
	// shape check passes what the gateway itself would print.
	_, err := guiAdminPair(clientDir, testPairingRef(t), "000123")

	if err == nil {
		t.Fatalf("guiAdminPair paired with a closed port")
	}
	if !strings.Contains(err.Error(), "could not reach the gateway at 127.0.0.1:1") {
		t.Errorf("error = %v, want the dial refusal naming the address", err)
	}
	if _, statErr := os.Stat(clientDir); statErr != nil {
		t.Errorf("client directory not created: %v — the pairing key is the machine's own persistent key and must exist once the shape checks pass", statErr)
	}
}

func TestGuiAdminPeopleAddRefusesBadShapesLocally(t *testing.T) {
	root := t.TempDir()
	clientDir := filepath.Join(root, "client")
	for _, tc := range []struct{ name, role, key, want string }{
		{"bob", "sudo", "ssh-ed25519 AAAA test", `the role must be "user" or "admin"`},
		{"b o b", "user", "ssh-ed25519 AAAA test", "name"},
		{"bob", "user", "not a key at all", "key"},
	} {
		_, err := guiAdminPeopleAdd(clientDir, tc.name, tc.role, tc.key)
		if err == nil {
			t.Fatalf("guiAdminPeopleAdd(%q, %q, %q) succeeded", tc.name, tc.role, tc.key)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("guiAdminPeopleAdd(%q, %q, %q) error = %v, want it to mention %q", tc.name, tc.role, tc.key, err, tc.want)
		}
	}
	if _, statErr := os.Stat(clientDir); !os.IsNotExist(statErr) {
		t.Errorf("client directory exists after local refusals — nothing should have been created")
	}
}

// TestGuiAdminMachineEnrolCodeWithoutAnIdentityCreatesNothing replaces
// the local shape-refusal test that stood here. That one fed
// guiAdminMachineEnrolCode a malformed machine name and a malformed OS
// user and required both to be refused before the network was touched.
// Since 1.3 the function takes neither (SPEC 3.4): the invitation names
// no machine, so there is no shape left to get wrong locally. What still
// matters, and is what that test was really protecting, is that a
// failure on the way out leaves no half-made client directory behind --
// here the failure is having no admin identity at all.
func TestGuiAdminMachineEnrolCodeWithoutAnIdentityCreatesNothing(t *testing.T) {
	root := t.TempDir()
	clientDir := filepath.Join(root, "client")
	if _, _, err := guiAdminMachineEnrolCode(clientDir, "office-pc"); err == nil {
		t.Fatal("guiAdminMachineEnrolCode succeeded with no admin identity saved at all")
	}
	if _, statErr := os.Stat(clientDir); !os.IsNotExist(statErr) {
		t.Errorf("client directory exists after a refusal -- nothing should have been created")
	}
}

// TestPairDialErrorDistinguishesRefusedKeyFromUnreachable pins that
// guiAdminPair printed "could not reach the gateway" on a refused key
// — the gateway was perfectly reachable. The claim string already
// separates the two cases; repeat the separation. It exercises
// pairDialError directly with the two error shapes that matter — a
// real transport failure (dial refused/timed out) and an SSH auth
// failure (the shape golang.org/x/crypto/ssh actually returns when a
// pairing key is refused, matching claimDialError's own IAMT-356
// check) — rather than standing up a live pairing window, since the
// function under test takes exactly (addr, error) and the distinction
// is made on err.Error()'s text alone.
func TestPairDialErrorDistinguishesRefusedKeyFromUnreachable(t *testing.T) {
	unreachable := errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	if err := pairDialError("gw.example.net:2022", unreachable); !strings.Contains(err.Error(), "could not reach the gateway") {
		t.Errorf("a real transport failure lost its \"could not reach the gateway\" wording: %v", err)
	}

	refused := errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")
	err := pairDialError("gw.example.net:2022", refused)
	if err == nil {
		t.Fatal("pairDialError returned nil for a refused key")
	}
	if strings.Contains(err.Error(), "could not reach the gateway") {
		t.Errorf("a refused pairing key was still reported as \"could not reach the gateway\" — an administrator would be sent chasing a network outage that never happened: %v", err)
	}
	if !strings.Contains(err.Error(), "pairing window") {
		t.Errorf("refused-key error does not mention the pairing window as the likely cause: %v", err)
	}
}
