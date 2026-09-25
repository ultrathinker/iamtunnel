//go:build !nogui

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A fresh machine where a gateway has never existed must be named
// fresh.
//
// 22.09.2026, the maintainer's live check. They copied the program onto
// a clean Windows VM, opened the Gateway tab and read: "this computer
// is set up as a gateway but is not responding", with an offer to
// "stop being a gateway". There was no gateway, no service, no host
// key there.
//
// The cause: the window derived "a gateway is installed" from the TEXT
// of the command's output — it looked for the phrase "no host key",
// which the command never printed (it prints "host key: not generated
// yet"). There was never a match, so Installed was always true.
//
// The lesson is not "fix the string". Prose is written for a human and
// gets rewritten whenever a phrase reads poorly; a program that derives
// a boolean from it silently changes its mind when somebody improves
// the wording. So the status now reads the same places the command
// itself does: the host key file and the state lock.
//
// The test drives the real guiGatewayStatus on a really empty
// directory — no substitute strings, otherwise it would be checking
// the same guess.
func TestGuiGatewayStatus_FreshMachineIsNotAGateway(t *testing.T) {
	dir := t.TempDir()
	env := gatewayTestEnv(dir)

	st, err := guiGatewayStatus(env, false)
	if err != nil {
		t.Fatalf("status on an empty data dir: %v", err)
	}
	if st.Installed {
		t.Error("on a machine without a host key the window says \"a gateway is installed\" — and offers to remove a service that does not exist")
	}
	if st.Running {
		t.Error("the window says the gateway is responding, on a directory where one has never existed")
	}
	if st.Unknown {
		t.Errorf("an empty directory is the answer \"no gateway\", not \"could not read\"; detail=%q", st.Detail)
	}
	if st.Fingerprint != "" {
		t.Errorf("fingerprint %q appeared where there is no key", st.Fingerprint)
	}
	if st.Claim != "" {
		t.Errorf("first-admin line %q appeared where there is no gateway", st.Claim)
	}
	if st.DataDir == "" {
		t.Error("the screen did not name the data directory — a person has nothing to check what this is even about")
	}
}

// Both halves of the screen must look into ONE directory (R2,
// 24.09.2026). The upper one — the facts (host key, state lock,
// journal) — took the directory from config.DirsFor, and that one knows
// only the platform default: /var/lib/iamtunnel on Linux,
// %ProgramData%\iamtunnel\gateway on Windows. It silently ignored
// IAMTUNNEL_DATA_DIR (and the gateway_dir key from the settings file),
// while the lower half — the command text going through loadConfig —
// honoured them honestly. A window started with IAMTUNNEL_DATA_DIR
// showed a status assembled from one directory and a detail line from
// another; on POSIX the upper half was meanwhile reading a fixed system
// path that belongs to someone else.
func TestGuiGatewayStatus_BothHalvesLookAtTheSameDirectory(t *testing.T) {
	dir := t.TempDir()
	env := gatewayTestEnv(dir)

	st, err := guiGatewayStatus(env, false)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.DataDir != dir {
		t.Errorf("the screen named directory %q although IAMTUNNEL_DATA_DIR points at %q — the screen's facts were gathered from a different directory than the detail line", st.DataDir, dir)
	}
}

// And the converse: as soon as a host key appears, the window must see
// it. Without this half the previous test would pass on a function that
// always answers "no gateway".
//
// The key is placed in a directory resolved the same way the screen
// itself resolves it (gatewayDirFromEnv), not config.DirsFor: after the
// R2 fix the screen reads IAMTUNNEL_DATA_DIR, and on POSIX DirsFor
// would point at the fixed /var/lib/iamtunnel — the test would be
// writing the key into a real system path.
func TestGuiGatewayStatus_SeesAGatewayOnceItExists(t *testing.T) {
	dir := t.TempDir()
	env := gatewayTestEnv(dir)
	dir, derr := gatewayDirFromEnv(env)
	if derr != nil {
		t.Fatal(derr)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The same file, made the same way the install makes it.
	if _, err := loadOrGenerateSigner(hostkeyPath(dir)); err != nil {
		t.Fatalf("host key: %v", err)
	}

	st, err := guiGatewayStatus(env, false)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Installed {
		t.Fatal("the host key is in place but the window says there is no gateway — then the first test checks nothing")
	}
	if st.Fingerprint == "" {
		t.Error("a gateway was found but no fingerprint is shown — it is compared over the phone")
	}
	if st.Running {
		t.Error("nobody ever started a gateway, yet the window says it is responding")
	}
}

// gatewayTestEnv points every role's data dir at one temp root, so the
// test never touches the real %ProgramData% or /var/lib.
func gatewayTestEnv(root string) map[string]string {
	env := map[string]string{"IAMTUNNEL_DATA_DIR": root}
	switch runtime.GOOS {
	case "windows":
		env["ProgramData"] = root
		env["LOCALAPPDATA"] = filepath.Join(root, "local")
		env["ProgramFiles"] = filepath.Join(root, "pf")
	default:
		env["HOME"] = root
		env["XDG_DATA_HOME"] = filepath.Join(root, "share")
	}
	return env
}
