package main

// iamt180_rebootstrap_test.go — IAMT-180 (G10 of the earlier summary):
// `gateway install --rebootstrap` is the only legitimate way to touch
// bootstrapPending AFTER the first install. The fresh-gateway trap
// scenario: a token was issued, nobody ran the admin claim within 24
// hours, a repeat install without the flag leaves state.json untouched
// (SPEC §3.5) — forever. With the flag a FRESH token is issued, the
// binding in state.json is overwritten, the event lands in the journal,
// and the admin claim goes through the live gateway.

import (
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
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// expectInstallExit — the platform-dependent expected outcome of install
// (as in iamt131): where install has a real service half — Linux
// (systemd, IAMT-177), Windows (SCM, IAMT-258) and macOS (LaunchDaemon,
// IAMT-259) — a substituted seam makes it exitOK; the other hosts get
// exitEnv with a refusal naming all three supported OSes (the local
// half did run; state.json is on disk).
//
// The platform list here is no longer rewritten by hand: IAMT-286 found
// exactly this bug — five such checks in iamt131 and here had stayed on
// "linux || windows" since before the macOS halves existed and kept
// demanding a refusal the product had already outgrown. The single
// source of truth is gatewayInstallSucceedsOnThisHost() in
// iamt131_bootstrap_install_test.go.
func expectInstallExit(t *testing.T, out, errs string, code int, step string) {
	t.Helper()
	if gatewayInstallSucceedsOnThisHost() {
		if code != exitOK {
			t.Fatalf("%s: install on %s: code=%d out=%q errs=%q", step, runtime.GOOS, code, out, errs)
		}
		return
	}
	if code != exitEnv || !strings.Contains(errs, "supports Linux, Windows and macOS") {
		t.Fatalf("%s: install on %s: code=%d errs=%q — expected exitEnv with a refusal naming the supported OSes", step, runtime.GOOS, code, errs)
	}
}

// TestIAMT180_RebootstrapReissuesExpiredPendingAndClaimSucceeds — the
// main chain: install → expiry → a repeat WITHOUT the flag fixes
// nothing → --rebootstrap issues a fresh token and window → the admin
// claim goes through.
//
// Canaries:
//   - drop the rebootstrap branch in runGatewayInstall (reduce
//     everything to writeBootstrapPending) — the "Expires is in the
//     future again" assertion turns red: without the flag the expiry
//     survives any number of repeat installs;
//   - unlink the token file from the write (do not rewrite
//     bootstrap-token) — the DeriveEphemeralSigner(token).PublicKey vs
//     entry.PublicKey comparison turns red: a claim with the old token
//     would be rejected at the handshake;
//   - drop the event append — the grep for "result":"rebootstrap" in
//     events.jsonl turns red.
func TestIAMT180_RebootstrapReissuesExpiredPendingAndClaimSucceeds(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t) // IAMT-258: the Windows half of install also goes through the fake
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	// 1. The first install: bootstrapPending with a future Expires.
	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "first install")

	raw, rerr := os.ReadFile(filepath.Join(dir, state.StateFileName))
	if rerr != nil {
		t.Fatalf("the first install did not create state.json: %v", rerr)
	}
	if entry := readBootstrapPending(t, raw); entry == nil {
		t.Fatal("the first install did not write bootstrapPending")
	}

	// 2. Expiry: 24 quiet hours compressed into a single Expires rewrite.
	past := time.Now().UTC().Add(-time.Hour)
	store, serr := state.Open(dir)
	if serr != nil {
		t.Fatalf("open state for the expiry: %v", serr)
	}
	if uerr := store.Update(func(st *state.State) error {
		if st.BootstrapPending == nil {
			t.Fatal("bootstrapPending disappeared before the expiry")
		}
		st.BootstrapPending.Expires = state.NewZonedTime(past)
		return nil
	}); uerr != nil {
		t.Fatalf("expire bootstrapPending: %v", uerr)
	}
	if cerr := store.Close(); cerr != nil {
		t.Fatalf("close state after the expiry: %v", cerr)
	}

	// 3. A repeat install WITHOUT the flag: state.json untouched (SPEC §3.5).
	out, errs, code = drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "repeat install without the flag")
	raw, _ = os.ReadFile(filepath.Join(dir, state.StateFileName))
	entry := readBootstrapPending(t, raw)
	if entry == nil {
		t.Fatal("a repeat install without the flag DELETED bootstrapPending — SPEC §3.5 forbids touching state.json")
	}
	if !entry.Expires.Before(time.Now().UTC()) {
		t.Fatalf("a repeat install without the flag refreshed Expires (%s) — SPEC §3.5: state.json is not touched; only --rebootstrap remedies this", entry.Expires)
	}

	// 4. --rebootstrap: a fresh record and a fresh token.
	out, errs, code = drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test", "--rebootstrap")
	expectInstallExit(t, out, errs, code, "install --rebootstrap")
	if strings.Contains(errs, "already has an administrator") {
		t.Fatalf("--rebootstrap refused although there is no admin: %q", errs)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, state.StateFileName))
	entry = readBootstrapPending(t, raw)
	if entry == nil {
		t.Fatal("install --rebootstrap did not write bootstrapPending")
	}
	now := time.Now().UTC()
	delta := entry.Expires.Sub(now)
	if delta < 23*time.Hour || delta > 25*time.Hour {
		t.Fatalf("install --rebootstrap wrote Expires=%s (from now %s) — the window must be 24h", entry.Expires, delta)
	}

	// 5. The token file was reissued and bound to the record in exactly
	// the way bootstrap_role will verify it: the ephemeral key from the
	// file matches the record's PublicKey.
	tokenBytes, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil {
		t.Fatalf("read the reissued bootstrap-token: %v", terr)
	}
	token := strings.TrimSpace(string(tokenBytes))
	bs, derr := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	if derr != nil {
		t.Fatalf("derive the ephemeral key from the token: %v", derr)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(bs.PublicKey())))
	if entry.PublicKey != pubLine {
		t.Fatalf("bootstrap-token and bootstrapPending are bound by different keys:\nfile:   %s\nrecord: %s — the claim would be rejected at the SSH handshake", pubLine, entry.PublicKey)
	}

	// 6. The event in the journal: admin.op result:"rebootstrap" (no new
	// types — the dictionary is closed, gate 12).
	evRaw, eerr := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if eerr != nil {
		t.Fatalf("install --rebootstrap did not create events.jsonl: %v", eerr)
	}
	if !strings.Contains(string(evRaw), `"result":"rebootstrap"`) || !strings.Contains(string(evRaw), `"type":"admin.op"`) {
		t.Fatalf("events.jsonl has no reissue event (admin.op result:rebootstrap):\n%s", string(evRaw))
	}

	// 7. The admin claim goes through the live gateway — the same path
	// as iamt131: a guest key with a pin, exec admin.claim from the
	// fresh token.
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
		t.Fatalf("gatewayServe did not come up: %v", gerr)
	case <-time.After(10 * time.Second):
		t.Fatal("gatewayServe did not report ready within 10s")
	}

	adminSigner := genEd25519Signer(t)
	adminPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(adminSigner.PublicKey())))
	claimBody, _ := json.Marshal(map[string]any{
		"proto":     1,
		"bootstrap": token,
		"pubkey":    adminPubLine,
	})
	claimResp := execAdminCommand(t, addr.String(), hostKeyOnDisk(t, dir), "bootstrap", bs, "admin.claim", claimBody)
	if !strings.Contains(claimResp, `"role":"admin"`) {
		t.Fatalf("admin.claim with the reissued token was refused: %q — the expired window is still in the claim's way", claimResp)
	}

	// 8. After the claim the record is burned (the reissue did not break single use).
	raw, _ = os.ReadFile(filepath.Join(dir, state.StateFileName))
	if post := readBootstrapPending(t, raw); post != nil {
		t.Fatal("bootstrapPending survived a successful claim — the token became reusable")
	}
}

// TestIAMT180_RebootstrapRefusedWhenAdminExists — a reissue on a gateway
// that already has an administrator would be a second path to a "first
// admin"; such a path does not exist: a class-2 refusal (user error),
// with text saying where to go next.
//
// Canary: drop the HasAnyAdmin check from rebootstrapPending — the
// exitUser/text assertion turns red (and with it the point: a fresh
// token on a managed gateway would open a second door into admin).
func TestIAMT180_RebootstrapRefusedWhenAdminExists(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t) // IAMT-258: the Windows half of install also goes through the fake
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	// out/errs must reach expectInstallExit: it is errs that carries the
	// service half's refusal on hosts without integration (fail() prints
	// the reason to stderr, cmd/iamtunnel/main.go:186+); empty strings
	// used to be passed here, and the test complained about an "empty
	// stderr" that was never there.
	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")

	// A snapshot of the record BEFORE the refusal: the first install
	// writes a future Expires, and the "not rewritten" check below
	// compares for immutability, not for expiry.
	rawBefore, _ := os.ReadFile(filepath.Join(dir, state.StateFileName))
	before := readBootstrapPending(t, rawBefore)
	if before == nil {
		t.Fatal("the first install did not write bootstrapPending — no snapshot to compare immutability against")
	}

	// The administrator appears through the ordinary claim path — a
	// direct write is enough here: what is tested is install's refusal,
	// not the claim path.
	adminKey := genEd25519Signer(t)
	adminPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(adminKey.PublicKey())))
	fp, ferr := state.ComputeFingerprint(adminPubLine)
	if ferr != nil {
		t.Fatalf("fingerprint: %v", ferr)
	}
	store, serr := state.Open(dir)
	if serr != nil {
		t.Fatalf("open state: %v", serr)
	}
	if uerr := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "owner", Role: "admin",
			Keys: []state.Key{{Fingerprint: fp, Pub: adminPubLine, Added: state.NewZonedTime(time.Now().UTC())}},
		})
		return nil
	}); uerr != nil {
		t.Fatalf("seed admin: %v", uerr)
	}
	if cerr := store.Close(); cerr != nil {
		t.Fatalf("close state: %v", cerr)
	}

	out, errs, code = drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test", "--rebootstrap")
	if code != exitUser {
		t.Fatalf("reissue with a live admin: code=%d (expected exitUser=2), out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(errs, "already has an administrator") {
		t.Fatalf("the refusal names neither the reason nor the way forward: %q", errs)
	}

	// And the record is not rewritten: the refusal happened BEFORE the
	// transaction — Expires is bit-for-bit the one from the pre-refusal
	// snapshot (not "in the past": the first install honestly wrote a
	// future window, and the refusal is not obliged to spoil it).
	rawAfter, _ := os.ReadFile(filepath.Join(dir, state.StateFileName))
	after := readBootstrapPending(t, rawAfter)
	if after == nil {
		t.Fatal("the refused reissue DELETED bootstrapPending — the refusal was obliged to happen before any write")
	}
	if !after.Expires.Time.Equal(before.Expires.Time) || after.SecretHash != before.SecretHash || after.PublicKey != before.PublicKey {
		t.Fatalf("the refused reissue changed bootstrapPending: before=%+v after=%+v", before, after)
	}
}
