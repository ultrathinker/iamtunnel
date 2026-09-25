package main

// iamt131_bootstrap_install_test.go — IAMT-131.
//
//	DESCRIPTION (IAMT-131)
//	  gateway install never wrote bootstrapPending to state.json, so
//	  "iamtunnel admin claim" could not succeed against any install
//	  done by the product itself. The bug hid because every E2E test
//	  for bootstrap seeded bootstrapPending through f.store.Update,
//	  bypassing the product path entirely.
//
//	WHAT THIS TEST DOES
//	  TestIAMT131_InstallWritesBootstrapPendingToState asserts the
//	  install side wrote bootstrapPending to state.json with the three
//	  observable properties bootstrap_role.go relies on (32-byte
//	  HMAC, ssh-ed25519 PublicKey, 24h Expires).
//
//	  TestIAMT131_InstallAcceptsClaimThroughGateway walks the chain
//	  install → claim → first admin → enrol-code → enrol through the
//	  product's CLI for install and real SSH+exec for the rest. The
//	  install side goes through the CLI; nothing on the gateway side
//	  is seeded through store.Update anywhere in this chain any more
//	  (IAMT-203): machines.enrol-code for a name state has never seen
//	  creates the pending entry itself, so a regression in either the
//	  bootstrap write or the enrol-code path cannot hide behind a
//	  hand-seeded state.Machines entry.
//
//	  Two canaries pin the failure modes below:
//	  - TestIAMT131_Canary_DropInstallWriteBreaksClaim — fails at
//	    state.json's missing bootstrapPending when the install-side
//	    writeBootstrapPending call is removed.
//	  - TestIAMT131_Canary_DropOneShotBreaksReplay — fails at the
//	    second-claim success when the one-shot guard (HasAnyAdmin and
//	    BootstrapPending burn) is removed.
//
// Platform-aware: gateway install runs on every host with a service half
// — Linux systemd, Windows SCM service and macOS LaunchDaemon (SPEC §3.5,
// §3.5.1) — each through its substituted seam, so the install-asserting
// path runs everywhere.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// gatewayInstallSucceedsOnThisHost reports whether `gateway install` runs a
// real service half — and therefore exits exitOK — on the host running the
// test: Linux (systemd, IAMT-177), Windows (SCM service, IAMT-258) and macOS
// (LaunchDaemon, IAMT-259). On any other Unix install still does the
// local-file half (state.json, bootstrap token, hostkey) and then refuses
// with exitEnv, naming the three systems it does support.
//
// IAMT-286: this predicate exists because five checks across this file and
// iamt180 listed the platforms by hand as "linux || windows" — true when
// they were written, false since IAMT-259 implemented the macOS half, and
// nothing failed loudly enough to notice: the tests simply went on asserting
// a refusal the product had outgrown. One predicate, so the next platform
// lands in one place.
func gatewayInstallSucceedsOnThisHost() bool {
	switch runtime.GOOS {
	case "linux", "windows", "darwin":
		return true
	default:
		return false
	}
}

// genEd25519Signer creates a fresh ed25519 SSH signer for tests
// that need a real public/private key pair (the first admin's
// own key, the machine's long-term key, etc.). Local to this file
// rather than reaching into another test's helpers, so the type
// stays close to its only call site and the import surface stays
// self-contained.
func genEd25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh signer from ed25519: %v", err)
	}
	return s
}

// hostKeyOnDisk reads <dir>/hostkey and returns the gateway's
// public key in ssh.PublicKey form (the FixedHostKey parameter).
// Distinct from hostkeyFingerprintOnDisk in gateway_status_live_test.go
// — that returns the fingerprint string, this returns the
// ssh.PublicKey. Both are needed in this test because the
// connection-string side carries the fingerprint (PER §3.1) while
// the dial side pins the ssh.PublicKey directly.
func hostKeyOnDisk(t *testing.T, dir string) ssh.PublicKey {
	t.Helper()
	data, err := os.ReadFile(hostkeyPath(dir))
	if err != nil {
		t.Fatalf("read the host key file: %v", err)
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		t.Fatalf("parse the host key file: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		t.Fatalf("signer from the host key file: %v", err)
	}
	return signer.PublicKey()
}

// readBootstrapPending decodes state.json and returns its
// BootstrapPending entry (or nil). Failures here are setup errors,
// not the test's own assertion — the caller wraps them with the
// specific property the test cares about.
func readBootstrapPending(t *testing.T, data []byte) *state.BootstrapPending {
	t.Helper()
	var doc struct {
		BootstrapPending *state.BootstrapPending `json:"bootstrapPending"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("state.json does not parse: %v — install must produce a parseable state.json, not just a token file", err)
	}
	return doc.BootstrapPending
}

// readAdminCount returns how many role:"admin" people are in
// state.json. Used by the chain test to confirm claim persisted.
func readAdminCount(t *testing.T, data []byte) int {
	t.Helper()
	var doc struct {
		People []struct {
			Role string `json:"role"`
		} `json:"people"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("state.json does not parse: %v", err)
	}
	n := 0
	for _, p := range doc.People {
		if p.Role == "admin" {
			n++
		}
	}
	return n
}

// readFirstAdminName returns the name of the first role:"admin"
// person in state.json. Used by the chain test to dial as the
// newly-claimed admin (SSH username is the person's own name).
func readFirstAdminName(t *testing.T, data []byte) string {
	t.Helper()
	var doc struct {
		People []struct {
			Name string `json:"name"`
			Role string `json:"role"`
		} `json:"people"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("state.json does not parse: %v", err)
	}
	for _, p := range doc.People {
		if p.Role == "admin" {
			return p.Name
		}
	}
	return ""
}

// readChannelUntilNewline reads from ch until '\n' is seen
// (the boundary PROTOCOL §1.2 promises), then returns what it
// read. Mirrors the helper in test/e2e/enrol_admin_test.go so
// this file does not pull in the e2e harness's helpers.
func readChannelUntilNewline(t *testing.T, ch ssh.Channel, maxWait time.Duration) string {
	t.Helper()
	type result struct {
		body string
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, 8192)
		var acc strings.Builder
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				acc.Write(buf[:n])
				if strings.Contains(acc.String(), "\n") {
					done <- result{acc.String()}
					return
				}
			}
			if err != nil {
				done <- result{acc.String()}
				return
			}
		}
	}()
	select {
	case r := <-done:
		return r.body
	case <-time.After(maxWait):
		t.Logf("readChannelUntilNewline: timeout, no newline in %s", maxWait)
		return ""
	}
}

// gatewayServeForChain is the chain test's launcher. It mirrors
// gatewayServe (cmd/iamtunnel/gateway.go) but sets PublicHost on
// the gateway config so admin commands which embed a dialable URL
// (machines.enrol-code, people.connection-string) hand out a
// parseable code. The live-gateway status tests do not need it
// and still use gatewayServe; the chain test does, hence the
// duplication.
//
// Returns the listener address, the gateway's public host key,
// and a cleanup function the caller registers with t.Cleanup.
func gatewayServeForChain(t *testing.T, dir, publicHost string) (net.Addr, ssh.PublicKey, func()) {
	t.Helper()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("setup: open state: %v", err)
	}
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		_ = store.Close()
		t.Fatalf("setup: open events log: %v", err)
	}
	hostSigner, err := loadOrGenerateSigner(hostkeyPath(dir))
	if err != nil {
		_ = store.Close()
		_ = log.Close()
		t.Fatalf("setup: host key: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = store.Close()
		_ = log.Close()
		t.Fatalf("setup: listen: %v", err)
	}
	addr := ln.Addr()
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		_ = store.Close()
		_ = log.Close()
		_ = ln.Close()
		t.Fatalf("setup: listener address is not a TCPAddr: %T", addr)
	}

	gw, err := gateway.New(gateway.Config{
		Store:            store,
		Log:              log,
		HostKey:          hostSigner,
		PublicHost:       publicHost,
		PublicPort:       tcpAddr.Port,
		RecordingBaseDir: filepath.Join(dir, "recordings"),
	})
	if err != nil {
		_ = store.Close()
		_ = log.Close()
		_ = ln.Close()
		t.Fatalf("setup: gateway.New: %v", err)
	}

	serveErr := make(chan error, 1)
	stop := make(chan struct{})
	go func() { serveErr <- gw.Serve(ln) }()
	cleanup := func() {
		close(stop)
		_ = gw.Close()
		<-serveErr
		_ = store.Close()
		_ = log.Close()
	}
	return addr, hostSigner.PublicKey(), cleanup
}

// execAdminCommand dials the gateway as `user` (typically a person
// name for admin commands, or "enrol" for the enrol half of the
// chain), opens a session channel, sends an "exec" with command
// and JSON body, and returns the response line. The dial pins the
// host key, so a fingerprint mismatch or unknown-key still produces
// an error from ssh.Dial and the test fails at setup rather than at
// the response-shape check.
//
// This is the wire-level peer of internal/admin.Conn.Exec; the chain
// test uses this directly so the failure modes are named at the line
// that produced them (instead of going through the admin client,
// whose own errors would hide which layer refused).
func execAdminCommand(t *testing.T, addr string, hostPub ssh.PublicKey, user string, signer ssh.Signer, command string, body []byte) string {
	t.Helper()
	conn, derr := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         5 * time.Second,
	})
	if derr != nil {
		t.Fatalf("setup: dial as %q: %v", user, derr)
	}
	defer conn.Close()
	ch, chReqs, oerr := conn.OpenChannel("session", nil)
	if oerr != nil {
		t.Fatalf("setup: open session channel as %q: %v", user, oerr)
	}
	defer ch.Close()
	go func() {
		for r := range chReqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	ok, rerr := ch.SendRequest("exec", true, ssh.Marshal(struct {
		Cmd string
	}{command}))
	if rerr != nil || !ok {
		t.Fatalf("setup: exec %q as %q: ok=%v err=%v", command, user, ok, rerr)
	}
	if _, werr := ch.Write(body); werr != nil {
		t.Fatalf("setup: write %q body as %q: %v", command, user, werr)
	}
	_ = ch.CloseWrite()
	return readChannelUntilNewline(t, ch, 3*time.Second)
}

// TestIAMT131_InstallWritesBootstrapPendingToState pins down that
// the CLI install writes bootstrapPending to state.json with the
// three observable properties bootstrap_role.go relies on (32-byte
// HMAC, ssh-ed25519 PublicKey, 24h Expires). The failure messages
// name each property by its exact assertion, so readers can route
// any future regression to the matching property directly.
//
// The test exercises the public product CLI exactly the way an
// administrator would: drive, assert on the artefact. Nothing in the
// chain reaches through internal package APIs.
//
// This test is also canary 1's anchor: when canary 1's mutation
// (remove writeBootstrapPending from cmd/iamtunnel/gateway.go) is
// applied, install no longer creates state.json, and this test fails
// at the "state.json does not exist" assertion below.
func TestIAMT131_InstallWritesBootstrapPendingToState(t *testing.T) {
	// IAMT-177: on Linux install now performs the systemd half; from a
	// test binary it must go through the seam fake, not into a real
	// systemctl. IAMT-258: the Windows half (the SCM service) is
	// substituted with its own fake — on Windows install legitimately
	// goes through it (SPEC §3.5.1).
	withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	// On Linux: install succeeds (exitOK) — the systemd unit, service
	// user and enable/start step run through the substituted seam.
	//
	// On Windows (IAMT-258) and macOS (IAMT-259): install also succeeds
	// (exitOK) — the SCM service half and the LaunchDaemon half of
	// SPEC §3.5.1 each run through their own substituted seam. The
	// local-file setup — the host key, the bootstrap-token file, and the
	// bootstrapPending entry in state.json — runs BEFORE the service half
	// on every platform (gateway.go: writeBootstrapPending precedes the
	// platform switch), so state.json and the entry exist on disk
	// regardless of platform. Skipping the test on non-Linux was the
	// original mistake ("Finding 2"): it dropped the only place that
	// proves install actually wrote the bridge between the CLI and
	// admin claim on Windows.
	if gatewayInstallSucceedsOnThisHost() {
		if code != exitOK {
			t.Fatalf("gateway install on %s: code=%d out=%q errs=%q", runtime.GOOS, code, out, errs)
		}
	} else {
		if code == exitOK {
			t.Fatalf("gateway install on %s: expected exitEnv for the service-half refusal, got exitOK; if this host no longer refuses, the documented envErrf in gateway.go was changed and this test must be re-read", runtime.GOOS)
		}
		if !strings.Contains(errs, "supports Linux, Windows and macOS") {
			t.Fatalf("gateway install on %s: the refusal must name the supported OSes so an operator can tell the local-file setup from the service half; got errs=%q", runtime.GOOS, errs)
		}
	}

	statePath := filepath.Join(dir, state.StateFileName)
	raw, rerr := os.ReadFile(statePath)
	if rerr != nil {
		t.Fatalf("install did not create %s: %v — the §3.3 SSO bridge from CLI install to admin claim is still missing, exactly the blocker IAMT-131 names", statePath, rerr)
	}
	entry := readBootstrapPending(t, raw)
	if entry == nil {
		t.Fatalf("install recorded no bootstrapPending in %s; the CLI left state.json without an admin-claim bridge. State bytes:\n%s", statePath, string(raw))
	}

	// 1) SecretHash: 32 bytes (HMAC-SHA-256 envelope bootstrap_role.go
	//    compares with hmac.Equal against the same length).
	if len(entry.SecretHash) != 32 {
		t.Fatalf("install wrote bootstrapPending.SecretHash of length %d; bootstrap_role.go's hmac.Equal reads 32 bytes — install did not produce the §3.3 hash", len(entry.SecretHash))
	}

	// 2) PublicKey: parses as an SSH public key of an authorized-keys
	//    line, and is ed25519 (PROTOCOL §3.3). The product stores and
	//    reads this field via state.DecodeKeyBlob (authorized_keys
	//    format: "ssh-ed25519 <base64-of-blob> [comment]"), so the
	//    test must parse it the same way. ssh.ParsePublicKey expects
	//    the raw SSH wire-format blob directly — passing the
	//    authorized_keys line as-is hits parseString("ssh-ed25519 ..."),
	//    treats "ssh-" as a 4-byte big-endian length, and reports
	//    "ssh: short read". The product-side reader (lookup.go calling
	//    ComputeFingerprint) DOES NOT have that bug; the product works.
	//    This assertion is a *contract* check, not a parser check: the
	//    field must round-trip through the same reader the gateway
	//    uses, and the blob inside must carry ssh-ed25519.
	if entry.PublicKey == "" {
		t.Fatal("install wrote bootstrapPending.PublicKey empty — lookup.go cannot resolve the bootstrap key; admin claim cannot reach the exec layer")
	}
	blob, derr := state.DecodeKeyBlob(entry.PublicKey)
	if derr != nil {
		t.Fatalf("install wrote a PublicKey that state.DecodeKeyBlob cannot parse (the format the gateway reads back): %v (key=%q) — the field is in a shape lookup.go cannot consume", derr, entry.PublicKey)
	}
	pub, perr := ssh.ParsePublicKey(blob)
	if perr != nil {
		t.Fatalf("install wrote a PublicKey whose decoded blob does not parse as SSH: %v (key=%q, blob=%x)", perr, entry.PublicKey, blob)
	}
	if pub.Type() != "ssh-ed25519" {
		t.Fatalf("install wrote a %q PublicKey; PROTOCOL §3.3 binds the bootstrap key to ssh-ed25519", pub.Type())
	}

	// 3) Expires: SPEC §3.3 "lives for 24 h". A 25h or 23h drift is
	//    also wrong, not just an "Expires in the past" failure.
	now := time.Now().UTC()
	if !entry.Expires.After(now) {
		t.Fatalf("install wrote bootstrapPending.Expires = %s, which is not in the future (now = %s); bootstrap_role.go would always reject it as E_BOOTSTRAP_USED", entry.Expires, now)
	}
	delta := entry.Expires.Sub(now)
	if delta > 25*time.Hour {
		t.Fatalf("install wrote bootstrapPending.Expires = %s; SPEC §3.3 caps the bootstrap window at 24h, so 25h violates the contract", entry.Expires)
	}
	if delta < 23*time.Hour {
		t.Fatalf("install wrote bootstrapPending.Expires = %s; SPEC §3.3 caps the bootstrap window at 24h, so %s is too short", entry.Expires, delta)
	}

	// 4) Sanity cross-check: the install-time bootstrap-token file
	//    holds the raw secret. Tied to the entry above, not via
	//    internal-store dereference (which would re-create the very
	//    self-referential test this one replaces).
	tokenBytes, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil {
		t.Fatalf("install did not leave %s next to state.json: %v", bootstrapFileName, terr)
	}
	if len(tokenBytes) == 0 {
		t.Fatalf("install wrote an empty %s — admin claim will reject this token for being too short", bootstrapFileName)
	}
}

// TestIAMT131_InstallAcceptsClaimThroughGateway walks the chain
//
//	install → claim → first admin → enrol-code → enrol
//
// through the product's CLI for install and through real SSH+exec
// for the rest. The install side goes through the CLI; nothing on
// the gateway side is seeded through store.Update anywhere in this
// chain any more (IAMT-203): machines.enrol-code issues a pending
// code for a name state.Machines has never held, and the real
// "enrol" exec is what creates the machine record — so a regression
// in either the bootstrap write or the enrol-code path cannot hide
// behind a hand-seeded state.Machines entry.
//
// The failure modes are named for the exact spec invariant they
// break.
//
// Not Linux-only any more (round two, "Finding 2"): install's
// documented refusal on a host without a service half (exitEnv) does
// not stop the local-file setup. state.json is on disk after install
// on Windows and macOS too, and the chain that follows depends only on
// what install wrote, not on the systemd step. Running the chain there
// therefore proves the same property the Linux run proves.
func TestIAMT131_InstallAcceptsClaimThroughGateway(t *testing.T) {
	// IAMT-177: install's systemd half goes through the seam fake (see
	// above); IAMT-258: the Windows half (the SCM service) goes through
	// its own fake.
	withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	// Step 1: install via the CLI. We rely on the prior test for
	// state.json's shape; here we trust that shape to set up the
	// rest of the chain. It is the chain itself, not the on-disk
	// bytes of bootstrapPending, that this test proves.
	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	// Platform-aware exit-code expectation, same reasoning as the
	// prior test, extended by IAMT-258 and IAMT-259: Linux, Windows and
	// macOS get exitOK (each through its own substituted service seam);
	// other hosts get exitEnv (3) and the named refusal listing the
	// supported OSes.
	if gatewayInstallSucceedsOnThisHost() {
		if code != exitOK {
			t.Fatalf("gateway install on %s: code=%d out=%q errs=%q", runtime.GOOS, code, out, errs)
		}
	} else {
		if code == exitOK {
			t.Fatalf("gateway install on %s: expected exitEnv for the service-half refusal, got exitOK", runtime.GOOS)
		}
		if !strings.Contains(errs, "supports Linux, Windows and macOS") {
			t.Fatalf("gateway install on %s: the refusal must name the supported OSes; got errs=%q", runtime.GOOS, errs)
		}
	}

	// Step 2: the machine name for the enrol-code/enrol steps below.
	// IAMT-203: machines.enrol-code no longer requires this name to
	// already exist in state.Machines — the pending code it issues
	// for a fresh name is what step 6 exercises, and step 7's real
	// "enrol" exec is what creates the machine record. Nothing is
	// seeded through store.Update anywhere in this chain any more.
	const machineID = "vm1"
	machineSigner := genEd25519Signer(t)

	// Step 3: start a real gateway in this same data dir so the
	// claim path runs against the product (not a fixture that
	// may already have bootstrap entries). The chain test needs
	// PublicHost set so that admin commands which embed a dialable
	// URL (machines.enrol-code) hand out a parseable code; the
	// live-gateway status tests don't need it and still use
	// gatewayServe.
	addr, hostPub, stop := gatewayServeForChain(t, dir, "127.0.0.1")
	t.Cleanup(stop)

	// Step 4: claim through a real SSH session, the way
	// test/e2e/enrol_admin_test.go does for the rest of the suite.
	// The handshake is the gate: if install's PublicKey is missing
	// or wrong, the SSH layer itself rejects the bootstrap login,
	// before any exec body is decoded.
	tokenBytes, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil {
		t.Fatalf("read bootstrap-token: %v", terr)
	}
	token := strings.TrimSpace(string(tokenBytes))
	bs, err := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	if err != nil {
		t.Fatalf("derive bootstrap key: %v", err)
	}
	adminSigner := genEd25519Signer(t)
	adminPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(adminSigner.PublicKey())))

	claimBody, _ := json.Marshal(map[string]any{
		"proto":     1,
		"bootstrap": token,
		"pubkey":    adminPubLine,
	})
	claimResp := execAdminCommand(t, addr.String(), hostPub, "bootstrap", bs, "admin.claim", claimBody)
	if !strings.Contains(claimResp, `"role":"admin"`) {
		t.Fatalf("admin.claim refused: %q — install did not populate the gate bootstrap_role.go expects (one of: missing bootstrapPending, hash mismatch, key mismatch, expiry)", claimResp)
	}
	if !strings.Contains(claimResp, `"person":`) {
		t.Fatalf("admin.claim answered without naming the first admin: %q", claimResp)
	}

	// Step 5: state.json must show the first admin and a burned
	// bootstrapPending (SPEC §3.3, "one attempt").
	finalRaw, rerr := os.ReadFile(filepath.Join(dir, state.StateFileName))
	if rerr != nil {
		t.Fatalf("read state.json after claim: %v", rerr)
	}
	admins := readAdminCount(t, finalRaw)
	if admins != 1 {
		t.Fatalf("admin.claim reported success but state.json has %d role:admin people, want 1", admins)
	}
	post := readBootstrapPending(t, finalRaw)
	if post != nil {
		t.Fatal("bootstrapPending survived admin.claim; the token is now usable a second time — E_BOOTSTRAP_USED guard failed")
	}
	adminName := readFirstAdminName(t, finalRaw)
	if adminName == "" {
		t.Fatalf("admin.claim reported role=admin but state.json has no role:admin person; cannot dial as the first admin for the enrol-code step")
	}

	// machinePubLine is the long-term key the "enrol" exec (step 7)
	// submits as the machine's own identity; derived here once and
	// reused for the enrol body below.
	machinePubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(machineSigner.PublicKey())))

	// Step 6: the first admin runs machines.enrol-code through
	// the same SSH+exec path the rest of the suite uses. The
	// enrol code it hands back must parse (PublicHost was set
	// above, otherwise the URL would have an empty host).
	// The body carries the NAME the administrator chose and nothing
	// else (1.4, SPEC §3.4). It carries no OS account: the machine
	// reports that about itself in step 7's enrol body, because it is
	// the one fact only the machine knows. The gateway's decoder
	// refuses unknown fields, so sending the old `machine`/`osUser`
	// pair here would be answered with E_JSON_FIELD_UNKNOWN rather
	// than quietly ignored.
	enrolCodeBody, _ := json.Marshal(map[string]any{
		"proto": 1,
		"name":  machineID,
	})
	enrolCodeResp := execAdminCommand(t, addr.String(), hostPub, adminName, adminSigner, "machines.enrol-code", enrolCodeBody)
	if !strings.Contains(enrolCodeResp, `"enrolCode":`) {
		t.Fatalf("machines.enrol-code did not return an enrolCode: %q", enrolCodeResp)
	}
	// execAdminCommand hands back the RAW exec response, envelope and
	// all: {"proto":1,"caps":[],"ok":true,"result":{...}}. So the
	// enrolCode lives one level down, under "result". (admin.Conn.Exec
	// strips that envelope itself, which is why the IAMT-123 tests must
	// NOT have this layer and these must — the two helpers differ, and
	// mixing them up has now cost this task two rounds.)
	var enrolCodeResult struct {
		Result struct {
			EnrolCode string `json:"enrolCode"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(enrolCodeResp), &enrolCodeResult); err != nil {
		t.Fatalf("machines.enrol-code response did not parse: %v — body=%q", err, enrolCodeResp)
	}
	if enrolCodeResult.Result.EnrolCode == "" {
		t.Fatalf("machines.enrol-code returned an empty enrolCode: %q", enrolCodeResp)
	}
	parsed, perr := config.ParseEnrolCode(enrolCodeResult.Result.EnrolCode)
	if perr != nil {
		t.Fatalf("ParseEnrolCode(%q): %v — install's gateway has PublicHost set, so the code should be parseable; a failure here means PublicHost leaked empty into the URL", enrolCodeResult.Result.EnrolCode, perr)
	}

	// Step 7: the machine dials as username "enrol" with the
	// ephemeral key derived from the enrol secret (PROTOCOL §3.2),
	// then runs the real "enrol" exec with the secret and its
	// long-term key. The gateway's runEnrol replaces the pending
	// entry and flips the machine to "enrolled" in one atomic
	// store.Update (internal/gateway/enrol_role.go).
	eph, eerr := config.DeriveEphemeralSigner(parsed.Secret, config.EnrolKeySalt)
	if eerr != nil {
		t.Fatalf("derive enrol ephemeral: %v", eerr)
	}
	enrolBody, _ := json.Marshal(map[string]any{
		"proto":      1,
		"secret":     parsed.Secret,
		"machine":    machineID,
		"osUser":     `MACHINE\svc`,
		"machineKey": machinePubLine,
	})
	enrolResp := execAdminCommand(t, addr.String(), hostPub, "enrol", eph, "enrol", enrolBody)
	if !strings.Contains(enrolResp, `"state":"enrolled"`) {
		t.Fatalf("enrol response missing state=enrolled: %q — admin issued a code that did not register the machine, breaking the chain at its last link", enrolResp)
	}
	if !strings.Contains(enrolResp, `"machine":"`+machineID+`"`) {
		t.Fatalf("enrol response missing machine id %q: %q", machineID, enrolResp)
	}

	// Step 8: state.json now has the machine with the long-term
	// key the enrol body just submitted (not the ephemeral one).
	//
	// The reload comes FIRST. finalRaw still holds the snapshot taken
	// right after the claim, i.e. before enrol wrote anything; asserting
	// against it made the test report the SEEDED state ("verified")
	// instead of the state enrol had just written ("enrolled"), and read
	// as a product defect when the product was correct. The enrol
	// response itself was already checked above and said "enrolled".
	finalRaw, rerr = os.ReadFile(filepath.Join(dir, state.StateFileName))
	if rerr != nil {
		t.Fatalf("read state.json after enrol: %v", rerr)
	}
	var got state.State
	if err := json.Unmarshal(finalRaw, &got); err != nil {
		t.Fatalf("parse final state.json after enrol: %v", err)
	}
	m, ok := got.MachineByID(machineID)
	if !ok {
		t.Fatalf("machine %q not in state.json after enrol", machineID)
	}
	if m.State != "enrolled" {
		t.Fatalf("enrolled machine state = %q, want %q", m.State, "enrolled")
	}
	if m.EnrolPending != nil {
		t.Fatalf("EnrolPending must be cleared after enrol: %+v", m.EnrolPending)
	}
	if m.MachineKey != machinePubLine {
		t.Fatalf("enrolled machineKey = %q, want %q", m.MachineKey, machinePubLine)
	}
}

// TestIAMT131_Canary_DropInstallWriteBreaksClaim is the first of the
// two canaries. It runs the full install → claim chain against the
// live product and pinpoints the
// line at which the canary 1 mutation (remove or comment-out the
// writeBootstrapPending call in cmd/iamtunnel/gateway.go around line
// 157) breaks the chain.
//
// With the fix in place, install creates state.json with a usable
// bootstrapPending and the bootstrap dial succeeds. With the canary
// mutation applied, install skips state.json entirely (no error —
// the rest of install's local-file setup runs as normal), and the
// first real assertion fails with a message that names the exact
// invariant and the file:line of the missing write.
//
// The test deliberately does not bypass install's write by deleting
// state.json after the fact: that would test the wrong gate (it
// would still pass with the canary mutation applied) and defeat the
// whole purpose of the canary.
//
// Not Linux-only any more (round two, "Finding 2"): install
// writes the local files (state.json, bootstrap-token, hostkey) on
// every platform; only the systemd half refuses on non-Linux. The
// canary tests the file-creation gate, which is platform-independent.
func TestIAMT131_Canary_DropInstallWriteBreaksClaim(t *testing.T) {
	// IAMT-177: install's systemd half goes through the seam fake (see
	// above); IAMT-258: the Windows half (the SCM service) goes through
	// its own fake.
	withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	// Step 1: install runs the full CLI.
	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	// Platform-aware exit-code expectation: Linux gets exitOK; a host
	// with no service half gets exitEnv (3) and the documented refusal in
	// stderr. The file-creation gate this canary tests sits BEFORE that
	// refusal, so the canary is meaningful regardless of which code path
	// install takes on the service half.
	// IAMT-258/259: the Windows and macOS halves of install are
	// legitimate (SPEC §3.5.1) — there install reaches exitOK just as it
	// does on Linux with the seam substituted.
	if gatewayInstallSucceedsOnThisHost() {
		if code != exitOK {
			t.Fatalf("setup: install failed on %s: code=%d out=%q errs=%q", runtime.GOOS, code, out, errs)
		}
	} else {
		if code == exitOK {
			t.Fatalf("setup: install on %s returned exitOK — the service-half refusal was removed; re-check the install path before trusting this test", runtime.GOOS)
		}
		if !strings.Contains(errs, "supports Linux, Windows and macOS") {
			t.Fatalf("setup: install on %s did not name the supported OSes; got errs=%q", runtime.GOOS, errs)
		}
	}

	// Step 2 (CANARY 1, anchor assertion): state.json MUST exist
	// after install. With the canary mutation (writeBootstrapPending
	// removed from cmd/iamtunnel/gateway.go around line 157), install
	// succeeds but never creates state.json, and this assertion is
	// the one that fails. The failure text names the file:line of
	// the missing write so it can be matched against the canary 1
	// mutation prediction.
	statePath := filepath.Join(dir, state.StateFileName)
	raw, rerr := os.ReadFile(statePath)
	if rerr != nil {
		t.Fatalf("canary 1: install did not create %s — the install side never wired bootstrapPending into state.json. Canary 1 mutation: remove the call to writeBootstrapPending that follows the §3.3 SSO-bridge comment in cmd/iamtunnel/gateway.go (around the runGatewayInstall function, line ~157). err=%v", statePath, rerr)
	}

	// Step 3 (CANARY 1, deeper assertion): the entry must also be
	// populated, not merely present. A regression that creates
	// state.json but skips the entry (e.g. an early-return path
	// in writeBootstrapPending) lands here.
	entry := readBootstrapPending(t, raw)
	if entry == nil {
		t.Fatalf("canary 1: install created %s but with no bootstrapPending — the install side wrote state.json but skipped the bootstrapPending entry. Canary 1 mutation: remove the body of writeBootstrapPending in cmd/iamtunnel/gateway.go (the assignment st.BootstrapPending = ... inside the Update callback). state bytes:\n%s", statePath, string(raw))
	}

	// Step 4 (positive direction): bootstrap dial must succeed
	// against the entry install wrote. A regression that writes
	// the entry but with the wrong PublicKey (e.g. off-by-one in
	// the salt) lands here.
	ready := make(chan net.Addr, 1)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := gatewayServe(dir, 0, func(a net.Addr) { ready <- a }, stop)
		done <- err
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})
	var addr net.Addr
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("setup: gatewayServe failed before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("setup: gatewayServe did not report ready within 10s")
	}

	tokenBytes, _ := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	token := strings.TrimSpace(string(tokenBytes))
	bs, berr := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	if berr != nil {
		t.Fatalf("setup: derive ephemeral: %v", berr)
	}
	hostPub := hostKeyOnDisk(t, dir)
	sshConn, derr := ssh.Dial("tcp", addr.String(), &ssh.ClientConfig{
		User:            "bootstrap",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(bs)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         3 * time.Second,
	})
	if derr != nil {
		t.Fatalf("canary 1: bootstrap dial FAILED despite state.json carrying bootstrapPending — the install-side PublicKey does not match the ephemeral key derived from the same token, OR the canary 1 mutation was not actually applied; err=%v", derr)
	}
	_ = sshConn.Close()
}

// TestIAMT131_Canary_DropOneShotBreaksReplay is the second canary.
// It walks the chain to a successful first claim, then attempts a
// SECOND claim with a different admin
// public key (simulating an attacker who has the token).
//
// The one-shot guard is held in TWO places simultaneously:
//
//	internal/gateway/bootstrap_role.go:166  st.HasAnyAdmin() refuses
//	internal/gateway/bootstrap_role.go:222  st.BootstrapPending = nil
//
// Removing only one of them leaves the other in place and the
// canary is silent. Removing BOTH — the canary 2 mutation — is
// what flips this test from green to red: the second claim now
// produces a second admin instead of returning E_BOOTSTRAP_USED.
//
// Not Linux-only any more (round two, "Finding 2"): the one-shot
// guard lives in bootstrap_role.go (gateway runtime), not in the
// install path, and it operates on the state install wrote. The canary
// tests a runtime gate, not a platform one; running on non-Linux is
// just as meaningful as running on Linux.
func TestIAMT131_Canary_DropOneShotBreaksReplay(t *testing.T) {
	// IAMT-177: install's systemd half goes through the seam fake (see
	// above); IAMT-258: the Windows half (the SCM service) goes through
	// its own fake.
	withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	// Step 1: install runs the full CLI (the install-side fix is
	// tested by canary 1; this test only asserts the one-shot
	// guard, so a passing install is just a setup step).
	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	// Platform-aware exit-code expectation, same reasoning as canary 1.
	// IAMT-258/259: the Windows and macOS halves of install are
	// legitimate (SPEC §3.5.1) — there install reaches exitOK just as it
	// does on Linux with the seam substituted.
	if gatewayInstallSucceedsOnThisHost() {
		if code != exitOK {
			t.Fatalf("setup: install failed on %s: code=%d out=%q errs=%q", runtime.GOOS, code, out, errs)
		}
	} else {
		if code == exitOK {
			t.Fatalf("setup: install on %s returned exitOK — the service-half refusal was removed; re-check the install path before trusting this test", runtime.GOOS)
		}
		if !strings.Contains(errs, "supports Linux, Windows and macOS") {
			t.Fatalf("setup: install on %s did not name the supported OSes; got errs=%q", runtime.GOOS, errs)
		}
	}

	// Step 2: start the gateway.
	ready := make(chan net.Addr, 1)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, gerr := gatewayServe(dir, 0, func(a net.Addr) { ready <- a }, stop)
		done <- gerr
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})
	var addr net.Addr
	select {
	case addr = <-ready:
	case gerr := <-done:
		t.Fatalf("setup: gatewayServe failed before ready: %v", gerr)
	case <-time.After(10 * time.Second):
		t.Fatal("setup: gatewayServe did not report ready within 10s")
	}

	tokenBytes, _ := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	token := strings.TrimSpace(string(tokenBytes))
	bs, _ := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	hostPub := hostKeyOnDisk(t, dir)

	// Step 3: first claim with one admin key. The product path
	// (install → claim) succeeds — that is what the chain test
	// already proved. Here we only use it to set up the post-
	// claim state the canary actually inspects.
	adminSigner := genEd25519Signer(t)
	adminPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(adminSigner.PublicKey())))
	firstBody, _ := json.Marshal(map[string]any{
		"proto":     1,
		"bootstrap": token,
		"pubkey":    adminPubLine,
	})
	firstResp := execAdminClaimForCanary(t, addr.String(), hostPub, bs, firstBody)
	if !strings.Contains(firstResp, `"role":"admin"`) {
		t.Fatalf("setup: first admin.claim did not succeed: %q", firstResp)
	}

	// Step 4 (CANARY 2, anchor assertion): a second claim with a
	// DIFFERENT admin key MUST be refused.
	//
	// The product has TWO redundant one-shot guards in
	// internal/gateway/bootstrap_role.go:
	//
	//	line 166:  if st.HasAnyAdmin() { return errBootstrapUsed(...) }
	//	line 222:  st.BootstrapPending = nil   (the "burn")
	//
	// The SSH handshake's lookup (lookup.go) only recognises `bs` as
	// a bootstrap key while BootstrapPending is non-nil, so as soon as
	// the first claim runs the burn (line 222), the second dial is
	// already refused at the SSH layer with "no supported methods
	// remain" — the app-layer HasAnyAdmin guard (line 166) never even
	// runs. That is itself a form of one-shot enforcement: the SSH
	// rejection IS the product refusing the replay.
	//
	// With the canary 2 mutation (remove BOTH guards), the second
	// dial now reaches the app layer and a second admin is created.
	// Removing only ONE guard keeps the other in place and the refusal
	// still happens (either at the SSH layer via the burn, or at the
	// app layer via E_BOOTSTRAP_USED). Either way: exactly one
	// admin in state.json, the canary stays silent for partial
	// removal, and only "both removed" trips the anchor assertion.
	//
	// tryExecAdminClaimForCanary is the non-fatal dial variant: it
	// returns the SSH dial error so the caller can treat SSH-layer
	// refusal (the burn catching the second dial) and app-layer
	// refusal (the HasAnyAdmin guard catching it) as the SAME
	// outcome — both are the one-shot enforcement winning. The
	// previously-fatalled-on-dial execAdminClaimForCanary is still
	// right for the first claim, where dial success is setup, not
	// assertion.
	adminSigner2 := genEd25519Signer(t)
	adminPubLine2 := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(adminSigner2.PublicKey())))
	secondBody, _ := json.Marshal(map[string]any{
		"proto":     1,
		"bootstrap": token,
		"pubkey":    adminPubLine2,
	})
	secondResp, secondErr := tryExecAdminClaimForCanary(t, addr.String(), hostPub, bs, secondBody)
	if secondErr == nil {
		// SSH accepted the second dial. That means BootstrapPending
		// was NOT burned — i.e. line 222's burn is gone. The app
		// layer's HasAnyAdmin guard (line 166) is what stands
		// between this dial and a second admin.
		if strings.Contains(secondResp, `"role":"admin"`) {
			t.Fatalf("canary 2: second admin.claim SUCCEEDED — the bootstrap token is replayable; the one-shot guard was dropped. Canary 2 mutation: remove BOTH internal/gateway/bootstrap_role.go:166 (HasAnyAdmin guard) AND internal/gateway/bootstrap_role.go:222 (BootstrapPending = nil burn). Response: %q", secondResp)
		}
		if !strings.Contains(secondResp, "E_BOOTSTRAP_USED") {
			t.Fatalf("canary 2: second admin.claim was refused without E_BOOTSTRAP_USED (body=%q); the one-shot guard's error code is part of the protocol contract and must not drift", secondResp)
		}
	}
	// secondErr != nil: SSH rejected the bootstrap key (the burn
	// guard is active). That is one valid form of one-shot
	// enforcement; the assertion below (exactly one admin in
	// state.json) covers the case where some future code path lets
	// the dial through while still refusing the replay.

	// Step 5: state.json still has exactly one admin after the
	// refused second claim. A regression that "refuses" the
	// second claim but accidentally still appends an admin lands
	// here.
	rawBytes, rerr := os.ReadFile(filepath.Join(dir, state.StateFileName))
	if rerr != nil {
		t.Fatalf("canary: read state.json: %v", rerr)
	}
	if n := readAdminCount(t, rawBytes); n != 1 {
		t.Fatalf("canary 2: state.json has %d role:admin people after a refused second claim, want 1 — the refused second claim silently appended an admin, defeating the protocol", n)
	}
}

// execAdminClaimForCanary opens an SSH+session channel as
// "bootstrap" with the ephemeral bootstrap signer, sends an
// "admin.claim" exec, writes body to it, and returns the
// response line. Kept local to the canaries — the chain test
// uses execAdminCommand (a more general helper) so a future
// canary that needs a different exec command does not have to
// duplicate the dial dance.
func execAdminClaimForCanary(t *testing.T, addr string, hostPub ssh.PublicKey, bs ssh.Signer, body []byte) string {
	t.Helper()
	conn, derr := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "bootstrap",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(bs)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         3 * time.Second,
	})
	if derr != nil {
		t.Fatalf("canary: bootstrap dial: %v", derr)
	}
	defer conn.Close()
	ch, chReqs, oerr := conn.OpenChannel("session", nil)
	if oerr != nil {
		t.Fatalf("canary: open session: %v", oerr)
	}
	defer ch.Close()
	go func() {
		for r := range chReqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	ok, rerr := ch.SendRequest("exec", true, ssh.Marshal(struct {
		Cmd string
	}{"admin.claim"}))
	if rerr != nil || !ok {
		t.Fatalf("canary: admin.claim exec request: ok=%v err=%v", ok, rerr)
	}
	if _, werr := ch.Write(body); werr != nil {
		t.Fatalf("canary: write admin.claim body: %v", werr)
	}
	_ = ch.CloseWrite()
	return readChannelUntilNewline(t, ch, 3*time.Second)
}

// tryExecAdminClaimForCanary is the non-fatal twin of
// execAdminClaimForCanary: same dial + admin.claim dance, but
// SSH dial errors (and downstream SSH-layer errors) are RETURNED
// rather than fail-fatal'd. The canary 2 test calls this for the
// SECOND admin.claim — there, an SSH-layer refusal (the burn
// guard at bootstrap_role.go:222 removing BootstrapPending so the
// SSH PublicKeyCallback no longer recognises `bs`) is a valid
// form of one-shot enforcement. Failing the test on a successful
// dial that returned E_BOOTSTRAP_USED, AND on a dial that SSH
// itself refused, captures both guards of the redundant pair.
func tryExecAdminClaimForCanary(t *testing.T, addr string, hostPub ssh.PublicKey, bs ssh.Signer, body []byte) (string, error) {
	t.Helper()
	conn, derr := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "bootstrap",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(bs)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         3 * time.Second,
	})
	if derr != nil {
		return "", derr
	}
	defer conn.Close()
	ch, chReqs, oerr := conn.OpenChannel("session", nil)
	if oerr != nil {
		return "", oerr
	}
	defer ch.Close()
	go func() {
		for r := range chReqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	ok, rerr := ch.SendRequest("exec", true, ssh.Marshal(struct {
		Cmd string
	}{"admin.claim"}))
	if rerr != nil || !ok {
		return "", rerr
	}
	if _, werr := ch.Write(body); werr != nil {
		return "", werr
	}
	_ = ch.CloseWrite()
	return readChannelUntilNewline(t, ch, 3*time.Second), nil
}
