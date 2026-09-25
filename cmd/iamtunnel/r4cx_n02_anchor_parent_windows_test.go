//go:build windows

package main

// r4cx_n02_anchor_parent_windows_test.go — review finding R4 N-02.
//
// The anchor lives at %ProgramData%\iamtunnel\anchors\<SID>\. Its write
// checked the folders above %ProgramData%\iamtunnel — not that folder
// itself, which an ordinary account can create first or be given rights
// on, and from which it can move "anchors" aside. And the elevated start
// read the anchor back trusting it outright. Now the write checks every
// folder from "anchors" up, and the read runs the same check before the
// anchor is believed.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

func TestR4CXN02_TheAnchorWriteChecksTheIamtunnelFolderItself(t *testing.T) {
	env := testsupport.PlatformDataEnvAt(t, t.TempDir())
	var asked string
	saved := anchorAncestorCheck
	anchorAncestorCheck = func(dir string) error { asked = dir; return nil }
	t.Cleanup(func() { anchorAncestorCheck = saved })

	if err := writeMachineEnrolmentAnchorWindows(env, gatewayRecord{Host: "gw", Port: 2222, Fingerprint: "fp", MachineID: "m1"}); err != nil {
		t.Fatalf("write anchor: %v", err)
	}
	path := f04AnchorPath(t, env)
	// dataDirAncestorWriters(dir) walks from dir's PARENT up: to cover
	// %ProgramData%\iamtunnel it must be handed a folder below it.
	iamtunnelDir := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	if filepath.Dir(asked) != iamtunnelDir && filepath.Dir(filepath.Dir(asked)) != iamtunnelDir {
		t.Fatalf("review finding R4 N-02: the anchor write checked the folders above %q; %q itself is left out", asked, iamtunnelDir)
	}
}

func TestR4CXN02_TheElevatedStartDoesNotBelieveAnAnchorAnyoneCanMove(t *testing.T) {
	env := testsupport.PlatformDataEnvAt(t, t.TempDir())
	saved := anchorAncestorCheck
	anchorAncestorCheck = func(string) error { return nil }
	if err := writeMachineEnrolmentAnchorWindows(env, gatewayRecord{Host: "gw", Port: 2222, Fingerprint: "fp", MachineID: "m1"}); err != nil {
		t.Fatalf("write anchor: %v", err)
	}
	anchorAncestorCheck = saved
	planted := errors.New("the anchors folder can be renamed by another account")
	savedTree := anchorTreeCheck
	anchorTreeCheck = func(string) error { return planted }
	t.Cleanup(func() { anchorTreeCheck = savedTree })
	savedElev := anchorReadElevated
	anchorReadElevated = func() (bool, error) { return true, nil }
	t.Cleanup(func() { anchorReadElevated = savedElev })
	t.Cleanup(func() { anchorAncestorCheck = saved })

	if _, err := readMachineEnrolmentAnchorWindows(env); !errors.Is(err, planted) {
		t.Fatalf("review finding R4 N-02: the anchor was believed although the folders above it can be changed by another account (err=%v)", err)
	}
}

// The anchor tree's own folders do not trust the running account: the
// attacker in F-04 IS that account's unelevated process, so a
// %ProgramData%\iamtunnel it created before enrol must be refused, not
// passed because it is "ours".
func TestR4CXN02_TheAnchorTreeDoesNotTrustTheRunningAccount(t *testing.T) {
	iamtunnelDir := filepath.Join(t.TempDir(), "iamtunnel")
	anchorDir := filepath.Join(iamtunnelDir, "anchors", "S-1-5-21-0")
	if err := os.MkdirAll(anchorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	self, serr := currentUserSIDString()
	if serr != nil {
		t.Fatalf("current account: %v", serr)
	}
	// This box's temp folders carry other groups' rights too, so a refusal
	// alone proves nothing: the running account itself must be named on
	// the iamtunnel level - the owner the attacker would be.
	want := accountName(self) + " (on " + iamtunnelDir + ")"
	err := refuseAnchorTreeAncestors(anchorDir)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("review finding R4 N-02: %q, created by this very account, passed as trusted — the refusal does not name %q (err=%v)", iamtunnelDir, want, err)
	}
}
