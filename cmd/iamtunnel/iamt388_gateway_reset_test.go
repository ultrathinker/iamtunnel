package main

// iamt388_gateway_reset_test.go — IAMT-388: `gateway reset` — one command
// instead of five manual ones (stop the service, wipe the data, install
// afresh, issue a claim). The card's contract:
//
//   - a reset yields a CLEAN gateway: people=0, machines=0, grants=0,
//     session recordings, the journal and the enrol-HMAC wiped, the
//     bootstrap token reissued (a new claim line printed);
//   - the host key stays as-is without --new-hostkey (the gateway's
//     identity for already handed-out connection strings does not change)
//     and is replaced along with it;
//   - without --yes the command shows WHAT will be lost and destroys
//     nothing (the standard confirmation for destructive commands);
//   - the card's canary: a real admin who worked before the reset is
//     refused by the live gateway after it.
//
// Canaries:
//   - drop the wiping of any file from the list (state.json,
//     bootstrap-token, events.jsonl, enrol-hmac.key, recordings/) — the
//     corresponding "after the reset" check turns red;
//   - show the confirmation BEFORE counting the losses or drop the
//     counters from the consequence — the refusal-without---yes test
//     ("shows what will be lost") turns red;
//   - swap the journal entry (admin.op result:"reset" — no new type, the
//     vocabulary is closed, gate 12) or lose the people/machines/grants
//     counters — parsing the fresh journal's first line turns red;
//   - wipe the hostkey without --new-hostkey — the byte-level key check
//     turns red;
//   - keep the hostkey under --new-hostkey — the "the key changed" check
//     turns red;
//   - skip stopping the service or wipe the data under a live state lock —
//     the busy-lock refusal test and the integrity check turn red.

import (
	"bytes"
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

// expectResetExit — the platform-dependent expected reset outcome (a
// mirror of iamt180's expectInstallExit: on hosts with a service half —
// exitOK under the substituted seam; elsewhere — exitEnv with a refusal
// naming all three supported OSes, and the refusal happens BEFORE the
// data is wiped).
func expectResetExit(t *testing.T, out, errs string, code int, step string) {
	t.Helper()
	if gatewayInstallSucceedsOnThisHost() {
		if code != exitOK {
			t.Fatalf("%s: reset on %s: code=%d out=%q errs=%q", step, runtime.GOOS, code, out, errs)
		}
		return
	}
	if code != exitEnv || !strings.Contains(errs, "supports Linux, Windows and macOS") {
		t.Fatalf("%s: reset on %s: code=%d errs=%q — wanted exitEnv with a refusal about the supported OSes", step, runtime.GOOS, code, errs)
	}
}

// serveResetGateway brings up a real gateway in this same process (as in
// iamt180) and returns the address and a stop function: the first live
// gateway must be stopped manually BEFORE the reset (it holds the state
// lock), the second is shut down via t.Cleanup.
func serveResetGateway(t *testing.T, dir string) (net.Addr, func()) {
	t.Helper()
	ready := make(chan net.Addr, 1)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, gerr := gatewayServe(dir, 0, func(a net.Addr) { ready <- a }, stop)
		done <- gerr
	}()
	cleanup := func() {
		close(stop)
		<-done
	}
	select {
	case addr := <-ready:
		return addr, cleanup
	case gerr := <-done:
		t.Fatalf("gatewayServe did not come up: %v", gerr)
	case <-time.After(10 * time.Second):
		t.Fatal("gatewayServe did not report ready within 10s")
	}
	return nil, func() {}
}

// dialAdminError dials the gateway as an admin and RETURNS the error
// instead of t.Fatalf: the outcome under test here is precisely the
// handshake refusal.
func dialAdminError(addr string, hostPub ssh.PublicKey, user string, signer ssh.Signer) error {
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostPub),
		Timeout:         5 * time.Second,
	})
	return err
}

// readResetEvent decodes the journal's FIRST line into the reset event.
func readResetEvent(t *testing.T, dir string) (typ, result string, details map[string]interface{}) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("read the fresh events.jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		t.Fatalf("the fresh journal is empty — the reset event was not written")
	}
	var line struct {
		Type    string                 `json:"type"`
		Result  string                 `json:"result"`
		Details map[string]interface{} `json:"details"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &line); err != nil {
		t.Fatalf("the journal's first line is not an event: %q: %v", lines[0], err)
	}
	return line.Type, line.Result, line.Details
}

// num reads a numeric counter out of an event's details.
func num(details map[string]interface{}, key string) float64 {
	if details == nil {
		return -1
	}
	v, ok := details[key].(float64)
	if !ok {
		return -1
	}
	return v
}

// TestIAMT388_ResetGivesCleanGatewayAndNewClaim — the main chain:
// install → a live admin via claim → extra ballast (a person, a machine,
// a grant, a session recording) → reset --yes → a clean gateway, the old
// hostkey, a new claim line, a journal entry with the reason and loss
// counters → the old admin refused by the live gateway (the card's
// canary).
func TestIAMT388_ResetGivesCleanGatewayAndNewClaim(t *testing.T) {
	withFakeSystemd(t)
	svc := withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	// 1. The first install.
	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")
	// The service is now installed: the seam must answer "present",
	// otherwise the teardown during reset will honestly see "nothing to
	// stop".
	svc.existsResult = true

	hostkeyBefore, herr := os.ReadFile(filepath.Join(dir, hostkeyFileName))
	if herr != nil {
		t.Fatalf("read the hostkey before the reset: %v", herr)
	}
	tokenBefore, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil {
		t.Fatalf("read the bootstrap-token before the reset: %v", terr)
	}
	enrolBefore, eerr := os.ReadFile(filepath.Join(dir, state.EnrolHMACKeyFileName))
	if eerr != nil {
		t.Fatalf("read enrol-hmac.key before the reset (the first live gateway creates it): %v", eerr)
	}

	// 2. A real first admin through the live gateway (the same path as in
	// iamt180): claim against the bootstrap token. Without this the "old
	// admin refused" check is worthless — a junk key would be refused
	// just the same.
	addr, stopGateway := serveResetGateway(t, dir)
	token := strings.TrimSpace(string(tokenBefore))
	bs, derr := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	if derr != nil {
		t.Fatalf("derive the ephemeral key from the token: %v", derr)
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
		t.Fatalf("admin.claim before the reset was refused: %q", claimResp)
	}
	stopGateway() // the gateway holds the state lock — shut it down before the reset

	raw, rerr := os.ReadFile(filepath.Join(dir, state.StateFileName))
	if rerr != nil {
		t.Fatalf("read state.json before the reset: %v", rerr)
	}
	adminName := readFirstAdminName(t, raw)
	if adminName == "" {
		t.Fatal("the claimed admin is not found in state.json before the reset")
	}

	// 3. Loss ballast: a second person, a machine, a grant and a recording artefact.
	store, serr := state.Open(dir)
	if serr != nil {
		t.Fatalf("open the state for the ballast: %v", serr)
	}
	mkLine := pubKeyLine(t)
	mkFP, ferr := state.ComputeFingerprint(mkLine)
	if ferr != nil {
		t.Fatalf("the machine key's fingerprint: %v", ferr)
	}
	if uerr := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "colleague", Role: "user"})
		st.Machines = append(st.Machines, state.Machine{ID: "m-1", Name: "m-1", State: "enrolled", MachineKey: mkLine, OSUser: "svc-ops"})
		st.Grants = append(st.Grants, state.Grant{Person: adminName, Machine: "m-1", MachineKeyFingerprint: mkFP, Caps: []string{"shell"}})
		return nil
	}); uerr != nil {
		t.Fatalf("append the ballast: %v", uerr)
	}
	if cerr := store.Close(); cerr != nil {
		t.Fatalf("close the state after the ballast: %v", cerr)
	}
	recDir := filepath.Join(dir, "recordings")
	if mkerr := os.MkdirAll(filepath.Join(recDir, "m-1", "2026-09-24"), 0o700); mkerr != nil {
		t.Fatalf("create recordings: %v", mkerr)
	}
	if werr := os.WriteFile(filepath.Join(recDir, "m-1", "2026-09-24", "120000-alice.cast"), []byte("{\"version\":2}\n"), 0o600); werr != nil {
		t.Fatalf("write the recording artefact: %v", werr)
	}

	// 4. Check the losses BEFORE the reset: exactly 2/1/1 — otherwise the
	// journal counters further down have nothing to be checked against.
	pre, perr := state.OpenForRead(dir)
	if perr != nil {
		t.Fatalf("OpenForRead before the reset: %v", perr)
	}
	preSt := pre.Get()
	if len(preSt.People) != 2 || len(preSt.Machines) != 1 || len(preSt.Grants) != 1 {
		pre.Close()
		t.Fatalf("before the reset people=%d machines=%d grants=%d, wanted 2/1/1", len(preSt.People), len(preSt.Machines), len(preSt.Grants))
	}
	pre.Close()

	if !gatewayInstallSucceedsOnThisHost() {
		// On a host without a service half reset refuses BEFORE wiping.
		_, errs, code = drive(t, "gateway", "reset", "--data-dir", dir, "--public-host", "gw.example.test", "--yes")
		if code != exitEnv || !strings.Contains(errs, "supports Linux, Windows and macOS") {
			t.Fatalf("reset on %s: code=%d errs=%q — wanted a refusal before wiping", runtime.GOOS, code, errs)
		}
		if _, err := os.Stat(filepath.Join(dir, state.StateFileName)); err != nil {
			t.Fatalf("reset on an unsupported host wiped state.json: %v", err)
		}
		return
	}

	// 5. The reset with --yes.
	out, errs, code = drive(t, "gateway", "reset", "--data-dir", dir, "--public-host", "gw.example.test", "--yes")
	expectResetExit(t, out, errs, code, "reset --yes")

	// 6a. The card's clean state: people/machines/grants at zero, the
	// fresh bootstrap window in place.
	after, aerr := state.OpenForRead(dir)
	if aerr != nil {
		t.Fatalf("OpenForRead after the reset: %v", aerr)
	}
	afterSt := after.Get()
	after.Close()
	if len(afterSt.People) != 0 || len(afterSt.Machines) != 0 || len(afterSt.Grants) != 0 {
		t.Fatalf("after the reset people=%d machines=%d grants=%d — the card's canary: wanted 0/0/0",
			len(afterSt.People), len(afterSt.Machines), len(afterSt.Grants))
	}
	rawAfter, rerr := os.ReadFile(filepath.Join(dir, state.StateFileName))
	if rerr != nil {
		t.Fatalf("read state.json after the reset: %v", rerr)
	}
	if entry := readBootstrapPending(t, rawAfter); entry == nil {
		t.Fatal("no fresh bootstrapPending after the reset — the claim line has nothing to stand on")
	}

	// 6b. The hostkey is the same (byte for byte), the token reissued, the
	// enrol-HMAC replaced: the gateway's identity lives in the key, not in
	// the secrets.
	hostkeyAfter, herr := os.ReadFile(filepath.Join(dir, hostkeyFileName))
	if herr != nil {
		t.Fatalf("read the hostkey after the reset: %v", herr)
	}
	if !bytes.Equal(hostkeyBefore, hostkeyAfter) {
		t.Fatal("reset without --new-hostkey changed the host key — already handed-out connection strings would stop matching by fingerprint")
	}
	tokenAfter, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil {
		t.Fatalf("read the bootstrap-token after the reset: %v", terr)
	}
	if bytes.Equal(tokenBefore, tokenAfter) {
		t.Fatal("reset kept the old bootstrap-token — there is no new claim line, no reissue happened")
	}
	enrolAfter, eerr := os.ReadFile(filepath.Join(dir, state.EnrolHMACKeyFileName))
	if eerr != nil {
		t.Fatalf("read enrol-hmac.key after the reset: %v", eerr)
	}
	if bytes.Equal(enrolBefore, enrolAfter) {
		t.Fatal("enrol-hmac.key survived the reset — the old secret hashes must go together with state.json")
	}

	// 6c. A new claim line is printed and carries the old host and the old
	// key fingerprint.
	if !strings.Contains(out, "bootstrap reference") {
		t.Fatalf("reset printed no claim line: out=%q", out)
	}
	if !strings.Contains(out, "gw.example.test") {
		t.Fatalf("the claim line has no public host: out=%q", out)
	}
	wantFP := hostkeyFingerprintOnDisk(t, dir)
	if !strings.Contains(out, strings.TrimPrefix(wantFP, "SHA256:")) {
		t.Fatalf("the claim line does not carry the old key's fingerprint %s: out=%q", wantFP, out)
	}

	// 6d. The journal: the fresh file opens with the reset event (admin.op
	// result:"reset" — no new type, the vocabulary is closed, gate 12)
	// carrying the reason and the loss counters 2/1/1.
	typ, result, details := readResetEvent(t, dir)
	if typ != "admin.op" || result != "reset" {
		t.Fatalf("the fresh journal's first line: type=%q result=%q — wanted admin.op result:\"reset\"", typ, result)
	}
	if num(details, "people") != 2 || num(details, "machines") != 1 || num(details, "grants") != 1 {
		t.Fatalf("the loss counters in the journal: %v — wanted people=2 machines=1 grants=1", details)
	}
	if reason, _ := details["reason"].(string); reason == "" {
		t.Fatalf("the reset event carries no reason: %v", details)
	}

	// 6e. The session recordings are wiped together with the directory.
	if _, serr := os.Stat(recDir); !os.IsNotExist(serr) {
		t.Fatalf("the recordings directory survived the reset: %v", serr)
	}

	// 6f. The service half: the service was removed and installed afresh
	// (the Windows recorder; on other hosts the data evidence above is
	// enough).
	if runtime.GOOS == "windows" {
		if len(svc.deleteCalls) != 1 {
			t.Fatalf("service removals across install+reset: %d, wanted 1 — reset did not stop the service", len(svc.deleteCalls))
		}
		if len(svc.startCalls) != 2 {
			t.Fatalf("service starts across install+reset: %d, wanted 2 — reset did not reinstall the service", len(svc.startCalls))
		}
	}

	// 7. The card's canary: the old admin is refused by the live gateway.
	addr2, stopGateway2 := serveResetGateway(t, dir)
	if derr := dialAdminError(addr2.String(), hostKeyOnDisk(t, dir), adminName, adminSigner); derr == nil {
		stopGateway2()
		t.Fatal("the old admin got into the reset gateway — the people were not wiped")
	} else if !strings.Contains(derr.Error(), "unable to authenticate") {
		stopGateway2()
		t.Fatalf("the old admin was refused for a reason other than the key: %v", derr)
	}
	stopGateway2() // the gateway holds the state lock — shut it down before check 8

	// 8. The refusal resurrected nothing.
	after2, aerr := state.OpenForRead(dir)
	if aerr != nil {
		t.Fatalf("OpenForRead after the refusal: %v", aerr)
	}
	after2St := after2.Get()
	after2.Close()
	if len(after2St.People) != 0 {
		t.Fatalf("after the old admin's refusal people=%d — the gateway brought someone back", len(after2St.People))
	}
}

// TestIAMT388_ResetWithoutYesShowsLossesAndDestroysNothing — without
// --yes the command names the losses (people/machines/grants, session
// recordings) and asks for --yes; interactively it asks a question and
// cancels on "no"; under both refusals not a single file is touched.
func TestIAMT388_ResetWithoutYesShowsLossesAndDestroysNothing(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")

	// The losses are seeded by writing directly: a live admin is not
	// needed here — what is checked is the confirmation text, not the key
	// refusal.
	store, serr := state.Open(dir)
	if serr != nil {
		t.Fatalf("open the state: %v", serr)
	}
	mkLine := pubKeyLine(t)
	mkFP, ferr := state.ComputeFingerprint(mkLine)
	if ferr != nil {
		t.Fatalf("the machine key's fingerprint: %v", ferr)
	}
	if uerr := store.Update(func(st *state.State) error {
		st.People = append(st.People,
			state.Person{Name: "old-admin", Role: "admin"},
			state.Person{Name: "colleague", Role: "user"})
		st.Machines = append(st.Machines, state.Machine{ID: "m-1", Name: "m-1", State: "enrolled", MachineKey: mkLine, OSUser: "svc-ops"})
		st.Grants = append(st.Grants, state.Grant{Person: "old-admin", Machine: "m-1", MachineKeyFingerprint: mkFP, Caps: []string{"shell"}})
		return nil
	}); uerr != nil {
		t.Fatalf("seed the losses: %v", uerr)
	}
	if cerr := store.Close(); cerr != nil {
		t.Fatalf("close the state: %v", cerr)
	}
	recDir := filepath.Join(dir, "recordings")
	if mkerr := os.MkdirAll(recDir, 0o700); mkerr != nil {
		t.Fatalf("create recordings: %v", mkerr)
	}
	tokenBefore, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil {
		t.Fatalf("read the bootstrap-token: %v", terr)
	}

	if !gatewayInstallSucceedsOnThisHost() {
		t.Skip("no service half on this host — the no---yes refusal is indistinguishable from the platform one")
	}

	// 1. Non-interactively without --yes: a refusal listing the losses and asking for --yes.
	out, errs, code = drive(t, "gateway", "reset", "--data-dir", dir, "--public-host", "gw.example.test")
	if code != exitUser {
		t.Fatalf("reset without --yes: code=%d out=%q errs=%q — wanted exitUser", code, out, errs)
	}
	for _, must := range []string{"people=2", "machines=1", "grants=1", "recordings", "--yes"} {
		if !strings.Contains(errs, must) {
			t.Fatalf("the refusal without --yes does not show the loss %q: errs=%q", must, errs)
		}
	}

	// 2. Interactively: the question is asked, "no" cancels.
	out, errs, code = driveIn(t, "no\n", true, "gateway", "reset", "--data-dir", dir, "--public-host", "gw.example.test")
	if code != exitUser {
		t.Fatalf("reset with the answer no: code=%d out=%q errs=%q — wanted exitUser", code, out, errs)
	}
	if !strings.Contains(errs, `Type "yes"`) || !strings.Contains(errs, "cancelled") {
		t.Fatalf("the interactive question was not asked / not cancelled: errs=%q", errs)
	}
	if !strings.Contains(errs, "people=2") {
		t.Fatalf("the question does not name the losses: errs=%q", errs)
	}

	// 3. Nothing is touched under either refusal.
	raw, rerr := os.ReadFile(filepath.Join(dir, state.StateFileName))
	if rerr != nil {
		t.Fatalf("state.json vanished under the refusal: %v", rerr)
	}
	if got := readAdminCount(t, raw); got != 1 {
		t.Fatalf("after the refusals there are %d admins, wanted 1 — the refusal does wipe after all", got)
	}
	intact, ierr := state.OpenForRead(dir)
	if ierr != nil {
		t.Fatalf("OpenForRead after the refusals: %v", ierr)
	}
	intactSt := intact.Get()
	intact.Close()
	if len(intactSt.People) != 2 || len(intactSt.Machines) != 1 || len(intactSt.Grants) != 1 {
		t.Fatalf("after the refusals people=%d machines=%d grants=%d — wanted 2/1/1, the refusal does wipe after all",
			len(intactSt.People), len(intactSt.Machines), len(intactSt.Grants))
	}
	if _, serr := os.Stat(recDir); serr != nil {
		t.Fatalf("recordings vanished under the refusal: %v", serr)
	}
	tokenAfter, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil || !bytes.Equal(tokenBefore, tokenAfter) {
		t.Fatalf("the bootstrap-token was touched under the refusal: %v", terr)
	}
}

// TestIAMT388_ResetNewHostkeyReplacesKey — with --new-hostkey the host
// key is replaced: the file's bytes differ, the printed claim line
// carries the new fingerprint.
func TestIAMT388_ResetNewHostkeyReplacesKey(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")

	hostkeyBefore, herr := os.ReadFile(filepath.Join(dir, hostkeyFileName))
	if herr != nil {
		t.Fatalf("read the hostkey before the reset: %v", herr)
	}

	if !gatewayInstallSucceedsOnThisHost() {
		t.Skip("no service half on this host")
	}

	out, errs, code = drive(t, "gateway", "reset", "--data-dir", dir, "--public-host", "gw.example.test", "--new-hostkey", "--yes")
	expectResetExit(t, out, errs, code, "reset --new-hostkey")

	hostkeyAfter, herr := os.ReadFile(filepath.Join(dir, hostkeyFileName))
	if herr != nil {
		t.Fatalf("read the hostkey after the reset: %v", herr)
	}
	if bytes.Equal(hostkeyBefore, hostkeyAfter) {
		t.Fatal("--new-hostkey kept the old host key")
	}
	wantFP := hostkeyFingerprintOnDisk(t, dir)
	if !strings.Contains(out, strings.TrimPrefix(wantFP, "SHA256:")) {
		t.Fatalf("the claim line does not carry the NEW key's fingerprint %s: out=%q", wantFP, out)
	}
}

// TestIAMT388_ResetRequiresPublicHost — reset without --public-host
// refuses BEFORE any action (the same IAMT-202 lesson as install): the
// claim line has nowhere to put the address, and the data must not be
// wiped over that.
func TestIAMT388_ResetRequiresPublicHost(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")
	tokenBefore, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil {
		t.Fatalf("read the bootstrap-token: %v", terr)
	}

	_, errs, code = drive(t, "gateway", "reset", "--data-dir", dir)
	if code != exitUser || !strings.Contains(errs, "--public-host") {
		t.Fatalf("reset without --public-host: code=%d errs=%q — wanted exitUser naming the flag", code, errs)
	}
	if _, serr := os.Stat(filepath.Join(dir, state.StateFileName)); serr != nil {
		t.Fatalf("reset without --public-host wiped state.json: %v", serr)
	}
	tokenAfter, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil || !bytes.Equal(tokenBefore, tokenAfter) {
		t.Fatalf("the bootstrap-token was touched under the refusal: %v", terr)
	}
}

// TestIAMT388_ResetRefusesWhileStateLocked — a gateway started NOT as a
// service (a console `gateway run`) holds the state lock; reset must
// refuse BEFORE wiping and name the lock, not wipe the data out from
// under a live process.
func TestIAMT388_ResetRefusesWhileStateLocked(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")

	store, serr := state.Open(dir)
	if serr != nil {
		t.Fatalf("take the state lock: %v", serr)
	}
	t.Cleanup(func() { _ = store.Close() })

	if !gatewayInstallSucceedsOnThisHost() {
		t.Skip("no service half on this host")
	}

	out, errs, code = drive(t, "gateway", "reset", "--data-dir", dir, "--public-host", "gw.example.test", "--yes")
	if code == exitOK {
		t.Fatalf("reset went through with the state lock held: out=%q", out)
	}
	if !strings.Contains(errs, "state lock") {
		t.Fatalf("the refusal does not name the state lock: errs=%q", errs)
	}
	raw, rerr := os.ReadFile(filepath.Join(dir, state.StateFileName))
	if rerr != nil {
		t.Fatalf("state.json wiped with the lock held: %v", rerr)
	}
	var doc struct {
		People []json.RawMessage `json:"people"`
	}
	if jerr := json.Unmarshal(raw, &doc); jerr != nil {
		t.Fatalf("state.json is corrupt: %v", jerr)
	}
	if len(doc.People) != 0 {
		t.Fatalf("state.json was rewritten under the refusal: %d people, wanted 0 (a fresh file)", len(doc.People))
	}
}
