package main

// iamt200_install_bootstrap_link_prefix_test.go — IAMT-200 (G15 wave):
// install used to print the bootstrap link with a "SHA256:" prefix in
// the fingerprint, while `iamtunnel admin claim` (ParseClaimRef) cut on
// the FIRST ':' after '#' — so the real fingerprint landed in the token
// slot and the token failed the shape check. The test pins that
// install's canonical form carries no prefix, and that ParseClaimRef
// parses both formats into the same thing.

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// iamt200BootstrapLineRe catches one line of the form
// "<host>:<port>#<fingerprint-or-fp>:<token>"
// in install's output. After IAMT-202 install prints the real public
// host (not the <this-host> placeholder), so the host in the first
// group is what the operator passed to --public-host.
var iamt200BootstrapLineRe = regexp.MustCompile(`(?m)^\s*(\S+):(\d+)#(\S+):(\S+)\s*$`)

// iamt200ExtractBootstrapLink takes install's output and returns the
// printed link line (ready for ParseClaimRef) together with the parsed
// parts: the real host, the port, the fingerprint (without the prefix)
// and the token.
func iamt200ExtractBootstrapLink(t *testing.T, out string) (link, printedHost, fpBare, token string, port int) {
	t.Helper()
	m := iamt200BootstrapLineRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("install's output has no bootstrap-link line of the form \"<host>:<port>#<fp>:<token>\":\n%s", out)
	}
	printedHost = m[1]
	portStr := m[2]
	var err error
	if port, err = strconv.Atoi(portStr); err != nil {
		t.Fatalf("the port in the bootstrap link does not parse as a number: %q: %v", portStr, err)
	}
	// If install still prints the <this-host> placeholder, that is an
	// IAMT-202 regression; it is left as is and ParseClaimRef is allowed
	// to complain about the invalid host (part of the same regression
	// guard).
	link = m[1] + ":" + m[2] + "#" + m[3] + ":" + m[4]
	return link, printedHost, m[3], m[4], port
}

// iamt200ReadOnDiskFingerprint reads the hostkey from dir and returns
// the fingerprint in the canonical "SHA256:<base64>" form — the same
// one ParseClaimRef normalizes into ClaimRef.Fingerprint.
func iamt200ReadOnDiskFingerprint(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "hostkey"))
	if err != nil {
		t.Fatalf("read the hostkey from %s: %v", dir, err)
	}
	raw, perr := ssh.ParseRawPrivateKey(data)
	if perr != nil {
		t.Fatalf("the hostkey from %s does not parse: %v", dir, perr)
	}
	signer, serr := ssh.NewSignerFromKey(raw)
	if serr != nil {
		t.Fatalf("ssh.NewSignerFromKey(hostkey): %v", serr)
	}
	sum := sha256.Sum256(signer.PublicKey().Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// TestIAMT200_InstallPrintsLinkWithoutSHA256Prefix — the main canary:
// install prints the bootstrap link with a bare 43-character
// fingerprint, no "SHA256:" prefix. A prefix in that position broke
// ParseClaimRef (IAMT-200); install now emits the canonical form, and
// ParseClaimRef accepts both for backward compatibility.
//
// Canary: put `fp` (with the prefix) back into the fmt.Fprintf at
// gateway.go:204 — the pinned printout then contains "SHA256:" right
// before the 43-character base64 block, and the "no prefix" assertion
// turns red.
func TestIAMT200_InstallPrintsLinkWithoutSHA256Prefix(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t) // IAMT-258: the Windows half of install also goes through the fake
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")

	// The "SHA256:" substring in install's output is either the normal
	// "fingerprint SHA256:…" line or the old (broken) link. We check
	// that the bootstrap-link line carries no prefix.
	m := iamt200BootstrapLineRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("install's output contains no bootstrap link:\n%s", out)
	}
	if strings.Contains(m[3], ":") {
		t.Fatalf("the fingerprint in the bootstrap link still contains ':' (IAMT-200): %q\noutput:\n%s", m[3], out)
	}
	// The "fingerprint SHA256:…" line is still there — it is not a link
	// but a human-readable summary.
	if !strings.Contains(out, "fingerprint SHA256:") {
		t.Fatalf("install stopped printing the human-readable \"fingerprint SHA256:…\" line, but that line is not a link and its format is kept deliberately:\n%s", out)
	}
}

// TestIAMT200_InstallPrintedLinkParsesAndMatchesDisk — an end-to-end
// test: install's output (through the seam, in t.TempDir()) is fed to
// ParseClaimRef after substituting `<this-host>`, and the parsed
// fingerprint + token match what lies on disk in the data directory.
// This proves print and parse agree: an operator who copied the link
// gets a valid enrolment.
//
// Canary: restore the gateway.go:204 printout with the `SHA256:`
// prefix (the wrong form) — the printout contains the prefix, yet this
// end-to-end test would still pass, because ParseClaimRef strips it
// anyway after IAMT-200. That is why the anchor assertion here is the
// separate "the fingerprint in the printed line contains no ':'",
// which turns red on the wrong printed form; plus the parsed-fp vs
// disk comparison.
func TestIAMT200_InstallPrintedLinkParsesAndMatchesDisk(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t) // IAMT-258: the Windows half of install also goes through the fake
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")

	link, printedHost, fpBare, token, port := iamt200ExtractBootstrapLink(t, out)
	if printedHost == "<this-host>" {
		t.Fatalf("install still prints the <this-host> placeholder in the bootstrap link — an IAMT-202 regression")
	}
	if printedHost != "gw.example.test" {
		t.Logf("install printed host %q (the test passed --public-host gw.example.test)", printedHost)
	}
	if port != 2222 {
		// install without --port uses 2222 (Defaults).
		t.Fatalf("install printed port %d, want 2222 (defaults)", port)
	}

	// ParseClaimRef: it must parse without errors, and the fingerprint
	// must match what lies on disk in the hostkey.
	cr, perr := config.ParseClaimRef(link)
	if perr != nil {
		t.Fatalf("ParseClaimRef refused the fresh install link: %v\nlink=%q", perr, link)
	}
	if cr.Host != printedHost {
		t.Fatalf("ParseClaimRef Host=%q, want %q (the printed host)", cr.Host, printedHost)
	}
	if cr.Port != port {
		t.Fatalf("ParseClaimRef Port=%d, want %d", cr.Port, port)
	}
	diskFP := iamt200ReadOnDiskFingerprint(t, dir)
	if cr.Fingerprint != diskFP {
		t.Fatalf("ParseClaimRef fingerprint=%q, want %q (per the on-disk hostkey)", cr.Fingerprint, diskFP)
	}

	// The token is the bootstrap-token file's contents (whitespace trimmed).
	tokenBytes, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil {
		t.Fatalf("read the bootstrap-token: %v", terr)
	}
	diskToken := strings.TrimSpace(string(tokenBytes))
	if cr.Token != diskToken {
		t.Fatalf("ParseClaimRef token=%q, want %q (the bootstrap-token contents)", cr.Token, diskToken)
	}
	// The printed fingerprint is a bare 43-character block (IAMT-200),
	// without the "SHA256:" prefix. Checked right in the link text.
	if strings.Contains(fpBare, ":") {
		t.Fatalf("the printed fingerprint still contains ':' (IAMT-200): %q", fpBare)
	}
	// The printed token matches what lies in the on-disk bootstrap-token.
	if token != diskToken {
		t.Fatalf("the printed token %q does not match the bootstrap-token %q", token, diskToken)
	}
}

// TestIAMT200_RebootstrapPrintedLinkParsesAndMatchesDisk — the
// end-to-end test for the --rebootstrap branch: the new bootstrap link
// printed by install --rebootstrap is also in canonical form (no
// prefix), and ParseClaimRef parses it into a fingerprint/token that
// match the refreshed disk (the hostkey stays the same, the new token
// is fresh).
//
// Canary: restore the prefixed printout only in install --rebootstrap —
// the anchor assertion about the absence of ':' in the link's
// fingerprint turns red.
func TestIAMT200_RebootstrapPrintedLinkParsesAndMatchesDisk(t *testing.T) {
	withFakeSystemd(t)
	_ = withFakeGatewayService(t) // IAMT-258: the Windows half of install also goes through the fake
	_ = withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "first install")

	out, errs, code = drive(t, "gateway", "install", "--rebootstrap", "--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install --rebootstrap")

	link, _, fpBare, token, _ := iamt200ExtractBootstrapLink(t, out)
	cr, perr := config.ParseClaimRef(link)
	if perr != nil {
		t.Fatalf("ParseClaimRef refused the fresh --rebootstrap link: %v\nlink=%q", perr, link)
	}
	diskFP := iamt200ReadOnDiskFingerprint(t, dir)
	if cr.Fingerprint != diskFP {
		t.Fatalf("ParseClaimRef fingerprint after --rebootstrap=%q, want %q (the hostkey does not change)", cr.Fingerprint, diskFP)
	}
	tokenBytes, terr := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil {
		t.Fatalf("read the bootstrap-token after --rebootstrap: %v", terr)
	}
	diskToken := strings.TrimSpace(string(tokenBytes))
	if cr.Token != diskToken {
		t.Fatalf("ParseClaimRef token after --rebootstrap=%q, want %q (the new bootstrap-token)", cr.Token, diskToken)
	}
	// Boundary: the fingerprint in the --rebootstrap link also carries no prefix.
	if strings.Contains(fpBare, ":") {
		t.Fatalf("the fingerprint in the --rebootstrap link contains ':' (IAMT-200): %q", fpBare)
	}
	if token != diskToken {
		t.Fatalf("the printed --rebootstrap token %q does not match the bootstrap-token %q", token, diskToken)
	}
}

// TestIAMT200_ParseClaimRefAcceptsLegacyPrefix — backward compatibility:
// a link with the old "SHA256:" prefix (issued by install before
// IAMT-200) parses into the SAME ClaimRef as the canonical prefixless
// form.
//
// Canary: remove strings.TrimPrefix(fpToken, "SHA256:") in
// internal/config/parse.go before the cut — a prefixed link is then cut
// at the first ':' (fp=SHA256, token=<base64>:<token>),
// parseTargetFingerprint("SHA256") rejects it over "43 base64
// characters", and this test goes red.
func TestIAMT200_ParseClaimRefAcceptsLegacyPrefix(t *testing.T) {
	const bare = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const host = "203.0.113.10"
	const token = "bootstrapTOKEN-1"

	withPref, errWithPref := config.ParseClaimRef(host + ":2222#SHA256:" + bare + ":" + token)
	if errWithPref != nil {
		t.Fatalf("ParseClaimRef refused the legacy SHA256: prefix form: %v", errWithPref)
	}
	bareParsed, errBare := config.ParseClaimRef(host + ":2222#" + bare + ":" + token)
	if errBare != nil {
		t.Fatalf("ParseClaimRef refused the prefixless (canonical) form: %v", errBare)
	}
	if withPref.Host != bareParsed.Host ||
		withPref.Port != bareParsed.Port ||
		withPref.Fingerprint != bareParsed.Fingerprint ||
		withPref.Token != bareParsed.Token {
		t.Fatalf("ParseClaimRef with and without the legacy prefix produced different ClaimRefs:\n  with prefix: %+v\n  without prefix: %+v",
			withPref, bareParsed)
	}
	if withPref.Fingerprint != "SHA256:"+bare {
		t.Fatalf("ParseClaimRef returned fingerprint=%q, want \"SHA256:%s\"", withPref.Fingerprint, bare)
	}
	if withPref.Token != token {
		t.Fatalf("ParseClaimRef token=%q, want %q", withPref.Token, token)
	}
}

// TestIAMT200_ParseClaimRefStillRejectsBadShapes — the boundary: the
// token is still shape-checked, and the bare form still complains about
// a missing secret. Insurance against a "strip the prefix and break
// everything else" regression.
func TestIAMT200_ParseClaimRefStillRejectsBadShapes(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// With the prefix, but no token.
		{"gw:2222#SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "missing the token"},
		// Without the prefix, but the token is too short — that is the
		// shape check; the prefix has nothing to do with it.
		{"gw:2222#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:tok", "wrong shape"},
	}
	for _, tc := range cases {
		if _, err := config.ParseClaimRef(tc.in); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseClaimRef(%q): want error containing %q, got %v", tc.in, tc.want, err)
		}
	}
}
