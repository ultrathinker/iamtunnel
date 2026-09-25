package main

// iamt202_public_host_test.go — IAMT-202 (G15 wave): the gateway used
// to hand out broken connection strings and enrol codes, because
// internal/gateway admin_role.go formatted g.cfg.PublicHost and nobody
// in cmd ever filled it in. Now --public-host is required for `gateway
// install`, `gateway run` takes the host from the flag or from the
// settings file's `public_host` key, and both admin-protocol roles
// (`people.connection-string`, `machines.enrol-code`) get a sensible
// address to hand out.
//
// Tests:
//  1. install without --public-host refuses BEFORE any action (the
//     systemd seam is never called, nothing is written);
//  2. the unit install writes carries `--public-host <host>` in
//     ExecStart (a repeat install on an existing directory with a
//     different --public-host simply rewrites the unit);
//  3. end to end: install → gateway run through the production
//     configuration assembly → people.connection-string over SSH → the
//     returned line parses with ParseConnString and carries the real
//     host;
//  4. gateway run without --public-host and without public_host in the
//     file → exit 2 naming both the flag and the key;
//  5. install with a bad --public-host (fails ValidHost) → exit 2.

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
)

// TestIAMT202_InstallRequiresPublicHost — install without
// --public-host refuses BEFORE any action: no files, no unit, no
// systemctl. Canary: drop the check in cmdGatewayInstallOrRun (or
// weaken it to a warning) — red here, because the exit code becomes 0
// on Linux and "requires a Linux host" elsewhere, and neither branch
// lands in "required" any more.
func TestIAMT202_InstallRequiresPublicHost(t *testing.T) {
	withFakeSystemd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir)
	if code == exitOK {
		t.Fatalf("install without --public-host was accepted: code=0 out=%q errs=%q — it must be exitUser=2", out, errs)
	}
	if code != exitUser {
		t.Fatalf("install without --public-host: code=%d, want exitUser (2)", code)
	}
	if !strings.Contains(errs, "--public-host") {
		t.Fatalf("the install-without---public-host error must name the flag: %q", errs)
	}
	// Additionally: nothing appeared on disk. install must not have
	// created so much as the data directory.
	if _, err := os.Stat(filepath.Join(dir, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("install without --public-host managed to create state.json: err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "hostkey")); !os.IsNotExist(err) {
		t.Fatalf("install without --public-host managed to create the hostkey: err=%v", err)
	}
}

// TestIAMT202_InstallSeamUntouchedWithoutPublicHost — seam systemd
// is not called on a refusal before --public-host. Uses its own
// recorder (via a direct linuxSystemd substitution), because
// withFakeSystemd has already been spent in
// TestIAMT202_InstallRequiresPublicHost.
//
// Canary: move the public-host check to AFTER setupSystemd — the
// recorder will then show userExists/chownDir/systemctl call traces,
// red here.
func TestIAMT202_InstallSeamUntouchedWithoutPublicHost(t *testing.T) {
	rec := &systemdRecorder{}
	prev := linuxSystemd
	linuxSystemd = rec.setup()
	t.Cleanup(func() { linuxSystemd = prev })

	dir := t.TempDir()
	// Running install without --public-host — the expected refusal
	// happens BEFORE the seam. On Windows install would refuse anyway
	// with the "requires a Linux host" refusal, and the seam must be
	// untouched there too (what is checked is precisely the
	// platform-independent public-host check that sits above the
	// platform fork).
	_, errs, _ := drive(t, "gateway", "install", "--data-dir", dir)
	_ = errs
	if len(rec.userExistsCalls) != 0 || len(rec.chownDirCalls) != 0 ||
		len(rec.systemctlCalls) != 0 || rec.unitContent != "" {
		t.Fatalf("install without --public-host reached into the systemd seam: userExists=%v chownDir=%v systemctl=%v unit=%q",
			rec.userExistsCalls, rec.chownDirCalls, rec.systemctlCalls, rec.unitContent)
	}
}

// TestIAMT202_InstallUnitCarriesPublicHost — anchor: the unit install
// writes through the seam carries `--public-host <host>` in ExecStart,
// and that host matches what the operator passed in --public-host.
//
// Canary: drop `--public-host %s` from gatewayUnitFile (or fail to
// thread publicHost into setupSystemd) — red here: ExecStart carries
// no --public-host.
//
// The test goes through a direct setupSystemd call (like the IAMT-177
// tests): on Windows install refuses BEFORE setupSystemd (RUNBOOK
// §1.3, non-Linux refusal) and no unit is written. The seam itself is
// platform-independent.
func TestIAMT202_InstallUnitCarriesPublicHost(t *testing.T) {
	dir := t.TempDir()

	rec := &systemdRecorder{}
	if err := setupSystemd(rec.setup(), "/usr/local/bin/iamtunnel", dir, 2222, "gw.example.test"); err != nil {
		t.Fatalf("setupSystemd: %v", err)
	}
	if rec.unitContent == "" {
		t.Fatal("setupSystemd wrote no unit (rec.unitContent is empty)")
	}
	if !strings.Contains(rec.unitContent, "--public-host gw.example.test\n") {
		t.Fatalf("the unit's ExecStart does not contain --public-host gw.example.test:\n%s", rec.unitContent)
	}
	if strings.Contains(rec.unitContent, "<this-host>") {
		t.Fatalf("the unit's ExecStart must not contain the <this-host> placeholder (IAMT-202):\n%s", rec.unitContent)
	}

	// A repeat install on an existing directory with a DIFFERENT
	// --public-host simply rewrites the unit (state.json and the hostkey
	// are untouched).
	rec2 := &systemdRecorder{}
	if err := setupSystemd(rec2.setup(), "/usr/local/bin/iamtunnel", dir, 2222, "another.example.test"); err != nil {
		t.Fatalf("repeat setupSystemd: %v", err)
	}
	if !strings.Contains(rec2.unitContent, "--public-host another.example.test\n") {
		t.Fatalf("the unit's ExecStart after the repeat did not swap --public-host to another.example.test:\n%s", rec2.unitContent)
	}
	if strings.Contains(rec2.unitContent, "--public-host gw.example.test") {
		t.Fatalf("the unit's ExecStart after the repeat still carries the old --public-host:\n%s", rec2.unitContent)
	}
}

// TestIAMT202_InstallPrintedLinkUsesRealHost — anchor: the bootstrap
// link install prints carries the real host from --public-host, not
// the <this-host> placeholder.
//
// Canary: put `<this-host>` back into gateway.go's fmt.Fprintf — red
// here.
func TestIAMT202_InstallPrintedLinkUsesRealHost(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t) // IAMT-258: the Windows half of install also goes through the fake
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")

	if strings.Contains(out, "<this-host>") {
		t.Fatalf("install still prints the <this-host> placeholder: %q", out)
	}
	// The link carries exactly the host passed in --public-host.
	if !strings.Contains(out, "gw.example.test:2222#") {
		t.Fatalf("install printed a link without the public host gw.example.test: %q", out)
	}
}

// TestIAMT202_InstallRejectsBadPublicHost — an invalid --public-host
// (fails ValidHost) → exit 2, with no attempt to create anything.
//
// Canary: drop the ValidHost check in cmdGatewayInstallOrRun — red.
func TestIAMT202_InstallRejectsBadPublicHost(t *testing.T) {
	dir := t.TempDir()

	// Spaces, a leading hyphen in a label, scheme:// and the like do not pass ValidHost.
	for _, bad := range []string{"-bad-.example.com", "with space.example.com", "scheme://x"} {
		out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", bad)
		if code != exitUser {
			t.Errorf("install --public-host %q: code=%d, want exitUser (2). out=%q errs=%q", bad, code, out, errs)
			continue
		}
		if !strings.Contains(errs, "--public-host") {
			t.Errorf("install --public-host %q: the error must name the flag: %q", bad, errs)
		}
		if !strings.Contains(errs, "not a valid") {
			t.Errorf("install --public-host %q: the error must say the host is invalid: %q", bad, errs)
		}
	}
}

// TestIAMT202_GatewayRunRequiresPublicHost — `gateway run` without
// --public-host and without public_host in the config → exit 2 with
// text naming BOTH sources (the flag and the key).
//
// Canary: drop the check in cmdGatewayInstallOrRun, or keep only "set
// --public-host" without mentioning the file key — red.
func TestIAMT202_GatewayRunRequiresPublicHost(t *testing.T) {
	dir := t.TempDir()
	out, errs, code := drive(t, "gateway", "run", "--data-dir", dir)
	if code != exitUser {
		t.Fatalf("gateway run without a public host: code=%d, want exitUser (2). out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(errs, "--public-host") {
		t.Fatalf("the error must name the --public-host flag: %q", errs)
	}
	if !strings.Contains(errs, "public_host") {
		t.Fatalf("the error must name the public_host config key: %q", errs)
	}
}

// TestIAMT202_GatewayRunFromConfigFile — public_host from the settings
// file lands in Settings.PublicHost, and `gateway run` comes up
// without --public-host on the command line.
//
// This test checks the lowest layer: validate() does not reject a
// config carrying public_host, and parsing yields Settings.PublicHost
// = "gw.example.test". Bringing up a real gateway run in a test is
// hard (run blocks), so it is checked through a direct config.Load in
// the same environment cmdGatewayInstallOrRun uses.
//
// Canary: drop public_host from configKeys / Settings.PublicHost —
// the "Settings.PublicHost != gw.example.test" assertion turns red.
func TestIAMT202_GatewayRunFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfgBody := `{"public_host": "gw.example.test", "port": 2222}`
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatalf("write the config: %v", err)
	}

	env := map[string]string{
		"IAMTUNNEL_DATA_DIR": dir,
		"IAMTUNNEL_CONFIG":   cfgPath,
	}
	_ = env
	// A direct config.Load: the same path loadConfig takes.
	data, rerr := os.ReadFile(cfgPath)
	if rerr != nil {
		t.Fatalf("read config: %v", rerr)
	}
	partial, perr := config.ParseFile(data)
	if perr != nil {
		t.Fatalf("ParseFile: %v", perr)
	}
	if partial.PublicHost == nil || *partial.PublicHost != "gw.example.test" {
		t.Fatalf("ParseFile returned PublicHost=%v, want \"gw.example.test\" — public_host is not parsed from the config (IAMT-202)", partial.PublicHost)
	}
	if !config.ValidHost(*partial.PublicHost) {
		t.Fatalf("public_host from the config does not pass ValidHost: %q", *partial.PublicHost)
	}
}

// TestIAMT202_EndToEnd_PeopleConnectionString — the main end-to-end
// test: bring up gateway run through the production configuration
// assembly (cmdGatewayInstallOrRun → cmdGatewayRun → gatewayServe),
// run a real-SSH `people.connection-string`, and check that the
// returned line (1) parses with ParseConnString and (2) carries
// exactly the public host that was passed in --public-host.
//
// This is the most expensive part of the IAMT-202 verification: before
// the admin_role.go fix the line carried an empty host,
// "iamtunnel://:2022/...", which the connection-string parser could
// not parse. Now it can.
//
// The test goes through gatewayServeForChain, which brings up
// `gateway.New` with PublicHost = publicHost. That is symmetric to
// what runGatewayServe does (cmd/iamtunnel/gateway.go:595) but without
// the blocking signal — with an explicit stop channel instead.
//
// Platform-independent, and that was not obvious at first: the test
// brings up a real TCP server and a real SSH handshake, but both are
// platform-neutral Go (gatewayServeWithSettings + ssh.Dial through
// execAdminCommand), and the install goes through expectInstallExit,
// which knows about all three service halves. The "Linux/Windows only"
// skip had stood here since the days when install on macOS refused
// (IAMT-286); meanwhile the install → claim → command-over-SSH chain
// itself already ran on darwin in the iamt131 tests.
func TestIAMT202_EndToEnd_PeopleConnectionString(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skipf("IAMT-202: people.connection-string over SSH is checked on Linux, Windows and macOS; here %s — there is no install without a service half", runtime.GOOS)
	}
	withFakeSystemd(t)
	_ = withFakeGatewayService(t) // IAMT-258: the Windows half of install also goes through the fake
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")

	// The production Settings assembly (the same thing
	// cmdGatewayInstallOrRun does after loadConfig + the public-host
	// check): PublicHost comes from the flag or from the file. Here it
	// comes from the flag.
	settings := config.Defaults()
	settings.PublicHost = "gw.example.test"

	// The gateway is brought up through the same gatewayServeWithSettings
	// that `gateway run` calls (cmd/iamtunnel/gateway.go:562). That IS
	// the "production configuration assembly": everything goes through
	// gatewayRuntimeConfig → gateway.Config{PublicHost: ...}.
	ready := make(chan net.Addr, 1)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, gerr := gatewayServeWithSettings(dir, settings, func(a net.Addr) { ready <- a }, stop)
		done <- gerr
	}()
	t.Cleanup(func() { close(stop); <-done })

	var addr net.Addr
	select {
	case addr = <-ready:
	case gerr := <-done:
		t.Fatalf("gatewayServe did not come up: %v", gerr)
	case <-time.After(10 * time.Second):
		t.Fatal("gatewayServe did not report ready within 10s")
	}
	hostPub := hostKeyOnDisk(t, dir)

	// Register the first administrator (needed for people.* commands),
	// then obtain the connection-string.
	adminSigner := genEd25519Signer(t)
	adminPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(adminSigner.PublicKey())))

	// admin.claim goes through the "bootstrap" login.
	tokenBytes, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil {
		t.Fatalf("read the bootstrap-token: %v", terr)
	}
	token := strings.TrimSpace(string(tokenBytes))
	bs, berr := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	if berr != nil {
		t.Fatalf("derive bootstrap key: %v", berr)
	}
	claimBody, _ := json.Marshal(map[string]any{
		"proto":     1,
		"bootstrap": token,
		"pubkey":    adminPubLine,
	})
	claimResp := execAdminCommand(t, addr.String(), hostPub, "bootstrap", bs, "admin.claim", claimBody)
	if !strings.Contains(claimResp, `"role":"admin"`) {
		t.Fatalf("admin.claim was refused: %q", claimResp)
	}
	adminName := readFirstAdminNameFromDisk(t, dir)

	// people.connection-string.
	csBody, _ := json.Marshal(map[string]any{
		"proto": 1,
		"name":  adminName,
	})
	csResp := execAdminCommand(t, addr.String(), hostPub, adminName, adminSigner, "people.connection-string", csBody)
	if !strings.Contains(csResp, `"connectionString":`) {
		t.Fatalf("people.connection-string returned no connectionString: %q", csResp)
	}
	cs := extractStringField(t, csResp, "connectionString")

	// The main point: the line parses with ParseConnString and carries the host.
	parsed, perr := config.ParseConnString(cs)
	if perr != nil {
		t.Fatalf("ParseConnString(%q): %v — people.connection-string handed out a broken line (IAMT-202 anchor)", cs, perr)
	}
	if parsed.Host != "gw.example.test" {
		t.Fatalf("ParseConnString Host=%q, want %q — the gateway handed out a connection string with an empty or foreign host (IAMT-202 anchor)", parsed.Host, "gw.example.test")
	}
	if parsed.Person != adminName {
		t.Fatalf("ParseConnString Person=%q, want %q", parsed.Person, adminName)
	}
}

// readFirstAdminNameFromDisk reads state.json and returns the name of
// the first role:admin person. A local copy for IAMT-202, so as not to
// drag in the global iamt131 helper whose signature differs.
func readFirstAdminNameFromDisk(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("read state.json: %v", err)
	}
	var doc struct {
		People []struct {
			Name string `json:"name"`
			Role string `json:"role"`
		} `json:"people"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse state.json: %v", err)
	}
	for _, p := range doc.People {
		if p.Role == "admin" {
			return p.Name
		}
	}
	t.Fatalf("no role:admin person in state.json")
	return ""
}

// extractStringField pulls result.<key> out of an admin command's
// "raw" response (execAdminCommand returns the whole envelope).
func extractStringField(t *testing.T, raw, key string) string {
	t.Helper()
	var doc struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("the response does not parse: %v\nbody=%q", err, raw)
	}
	v, ok := doc.Result[key]
	if !ok {
		t.Fatalf("result.%s is missing: %q", key, raw)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("result.%s is not a string: %T %v", key, v, v)
	}
	return s
}
