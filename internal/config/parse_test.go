package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// mustPub marshals a public key into the one-line authorized_keys form.
func mustPub(t *testing.T, key any) string {
	t.Helper()
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func ed25519Pub(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return mustPub(t, pub)
}

const fpr43 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 43 base64 chars

func TestParseConnStringOK(t *testing.T) {
	cases := []struct {
		in                string
		host, person, fpr string
		port              int
	}{
		{"iamtunnel://gw.example.com:2222/alice#" + fpr43, "gw.example.com", "alice", "SHA256:" + fpr43, 2222},
		{"IAMTUNNEL://GW.example.COM:22/bob01" + "#" + fpr43, "GW.example.COM", "bob01", "SHA256:" + fpr43, 22},
		{"iamtunnel://[2001:db8::1]:2222/carol._-x#" + fpr43, "[2001:db8::1]", "carol._-x", "SHA256:" + fpr43, 2222},
		{"  iamtunnel://gw:1/dave9#" + fpr43 + "  ", "gw", "dave9", "SHA256:" + fpr43, 1},
	}
	for _, tc := range cases {
		got, err := ParseConnString(tc.in)
		if err != nil {
			t.Errorf("ParseConnString(%q): %v", tc.in, err)
			continue
		}
		if got.Host != tc.host || got.Port != tc.port || got.Person != tc.person || got.Fingerprint != tc.fpr {
			t.Errorf("ParseConnString(%q) = %+v, want host=%s port=%d person=%s fpr=%s", tc.in, got, tc.host, tc.port, tc.person, tc.fpr)
		}
	}
}

func TestParseConnStringErrors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://gw:2222/alice#" + fpr43, `must start with "iamtunnel://"`},
		{"iamtunnel://gw:2222/alice", "missing"},                    // no '#'
		{"iamtunnel://gw:2222#" + fpr43, "missing"},                 // no '/'
		{"iamtunnel://gw:2222/alice#a#b" + fpr43, "more than one"},  // two '#'
		{"iamtunnel://gw:2222/alice/bob#" + fpr43, "more than one"}, // two '/'
		{"iamtunnel://gw:2222/Alice#" + fpr43, "not a valid name"},  // uppercase person
		{"iamtunnel://gw:2222/" + strings.Repeat("a", 33) + "#" + fpr43, "not a valid name"},
		{"iamtunnel://gw:0/alice#" + fpr43, "1 to 65535"},
		{"iamtunnel://gw:foo/alice#" + fpr43, "1 to 65535"},
		{"iamtunnel://gw/alice#" + fpr43, `not <host>:<port>`}, // no port
		{"iamtunnel://-bad:2222/alice#" + fpr43, "not a valid hostname"},
		{"iamtunnel://gw:2222/alice#deadbeef", "43 base64 characters"}, // too short
		{"iamtunnel://gw:2222/alice#SHA256:" + fpr43, `without the "SHA256:" prefix`},
		{"iamtunnel://gw:2222/alice#" + fpr43 + "=", "43 base64 characters"}, // padding
	}
	for _, tc := range cases {
		_, err := ParseConnString(tc.in)
		if err == nil {
			t.Errorf("ParseConnString(%q): want error containing %q, got nil", tc.in, tc.want)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseConnString(%q): error %q lacks %q", tc.in, err, tc.want)
		}
		var ce *Error
		if !errors.As(err, &ce) || ce.Class != ClassUser {
			t.Errorf("ParseConnString(%q): error %T is not a class-user error", tc.in, err)
		}
	}
}

func TestParseEnrolCodeOK(t *testing.T) {
	secret := "s3cret-token_~-x9"
	got, err := ParseEnrolCode("iamtunnel-enrol://gw.example.com:2222#" + fpr43 + ":" + secret)
	if err != nil {
		t.Fatalf("ParseEnrolCode: %v", err)
	}
	if got.Host != "gw.example.com" || got.Port != 2222 || got.Fingerprint != "SHA256:"+fpr43 || got.Secret != secret {
		t.Errorf("ParseEnrolCode = %+v", got)
	}
}

func TestParseEnrolCodeErrors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"iamtunnel://gw:2222#" + fpr43 + ":secret01", `must start with "iamtunnel-enrol://"`},
		{"iamtunnel-enrol://gw:2222#" + fpr43, "missing the secret"},
		{"iamtunnel-enrol://gw:2222#" + fpr43 + ":short", "wrong shape"}, // secret < 8 chars
		{"iamtunnel-enrol://gw:2222#" + fpr43 + ":has space 123", "wrong shape"},
		{"iamtunnel-enrol://gw:2222#deadbeef:secret01", "43 base64 characters"},
		{"iamtunnel-enrol://gw:2222#SHA256:" + fpr43 + ":secret01", `is not a SHA-256 key fingerprint`},
		{"iamtunnel-enrol://gw:2222:2222#" + fpr43 + ":secret01", "not a valid hostname"},
	}
	for _, tc := range cases {
		_, err := ParseEnrolCode(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseEnrolCode(%q): err=%v, want containing %q", tc.in, err, tc.want)
		}
	}
}

func TestParseClaimRefOK(t *testing.T) {
	cases := []struct {
		in          string
		host        string
		port        int
		fingerprint string
		token       string
	}{
		// Canonical form (no "SHA256:" prefix): install's normal output
		// since IAMT-200.
		{"gw.example.com:2222#" + fpr43 + ":bootstrapTOKEN-1", "gw.example.com", 2222, "SHA256:" + fpr43, "bootstrapTOKEN-1"},
		// Legacy form WITH "SHA256:" prefix: tolerated for back-compat
		// with links an operator may have copied off an older VPS or the
		// pre-IAMT-200 RUNBOOK. Must resolve to the same ClaimRef.
		{"gw.example.com:2222#SHA256:" + fpr43 + ":bootstrapTOKEN-1", "gw.example.com", 2222, "SHA256:" + fpr43, "bootstrapTOKEN-1"},
	}
	for _, tc := range cases {
		got, err := ParseClaimRef(tc.in)
		if err != nil {
			t.Errorf("ParseClaimRef(%q): %v", tc.in, err)
			continue
		}
		if got.Host != tc.host || got.Port != tc.port || got.Fingerprint != tc.fingerprint || got.Token != tc.token {
			t.Errorf("ParseClaimRef(%q) = %+v, want host=%s port=%d fpr=%s token=%s",
				tc.in, got, tc.host, tc.port, tc.fingerprint, tc.token)
		}
	}
}

func TestParseClaimRefErrors(t *testing.T) {
	cases := []struct{ in, want string }{
		{"iamtunnel://gw:2222#" + fpr43 + ":token123", "takes no URI scheme"},
		{"gw:2222#" + fpr43, "missing the token"},
		{"gw:2222#" + fpr43 + ":tok", "wrong shape"},
		{"gw:2222#deadbeef:token123", "43 base64 characters"},
		{"gw#" + fpr43 + ":token123", "not <host>:<port>"},
		{"gw:99999#" + fpr43 + ":token123", "1 to 65535"},
	}
	for _, tc := range cases {
		_, err := ParseClaimRef(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseClaimRef(%q): err=%v, want containing %q", tc.in, err, tc.want)
		}
	}
}

func TestValidName(t *testing.T) {
	ok := []string{"a", "0", "alice", "win01", "a.b_c-d", strings.Repeat("z", 32)}
	for _, s := range ok {
		if !ValidName(s) {
			t.Errorf("ValidName(%q) = false, want true", s)
		}
	}
	bad := []string{"", "Alice", ".lead", "-lead", "_lead", "sp ace", "slash/s", "cryllic-\u043a\u0438\u0440\u0438\u043b\u043b\u0438\u0446\u0430", strings.Repeat("z", 33), "colon:x"}
	for _, s := range bad {
		if ValidName(s) {
			t.Errorf("ValidName(%q) = true, want false", s)
		}
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	if got, err := NormalizeFingerprint("SHA256:" + fpr43); err != nil || got != "SHA256:"+fpr43 {
		t.Errorf("with prefix: got %q, %v", got, err)
	}
	if got, err := NormalizeFingerprint(fpr43); err != nil || got != "SHA256:"+fpr43 {
		t.Errorf("without prefix: got %q, %v", got, err)
	}
	for _, s := range []string{"", "deadbeef", fpr43 + "=", strings.Repeat("A", 42)} {
		if _, err := NormalizeFingerprint(s); err == nil {
			t.Errorf("NormalizeFingerprint(%q): want error, got nil", s)
		}
	}
}

func TestCheckPublicKey(t *testing.T) {
	ed := ed25519Pub(t)
	if _, err := CheckPublicKey(ed); err != nil {
		t.Errorf("ed25519 key rejected: %v", err)
	}
	if _, err := CheckPublicKey(ed + " alice@host"); err != nil {
		t.Errorf("ed25519 with comment rejected: %v", err)
	}

	// RSA at exactly 3072 bits is the minimum (SPEC §6.1).
	k3072, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa 3072: %v", err)
	}
	if _, err := CheckPublicKey(mustPub(t, &k3072.PublicKey)); err != nil {
		t.Errorf("rsa 3072 rejected: %v", err)
	}

	k2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa 2048: %v", err)
	}
	_, err = CheckPublicKey(mustPub(t, &k2048.PublicKey))
	if err == nil || !strings.Contains(err.Error(), "3072") {
		t.Errorf("rsa 2048: err=%v, want a 3072-bit message", err)
	}

	for _, line := range []string{"", "garbage", "ssh-ed25519 notbase64!!", ed + "\n" + ed} {
		if _, err := CheckPublicKey(line); err == nil {
			t.Errorf("CheckPublicKey(%q): want error, got nil", line)
		}
	}
}

func TestParseUntil(t *testing.T) {
	ok := []string{"2027-01-31T18:00:00Z", "2027-01-31T21:00:00+03:00", "2026-02-28T23:59:59-08:00"}
	for _, s := range ok {
		if _, err := ParseUntil(s); err != nil {
			t.Errorf("ParseUntil(%q): %v", s, err)
		}
	}
	bad := []string{"", "2027-01-31", "2027-01-31T18:00:00", "tomorrow", "2027-13-01T00:00:00Z", "2027-01-31 18:00:00Z"}
	for _, s := range bad {
		if _, err := ParseUntil(s); err == nil {
			t.Errorf("ParseUntil(%q): want error, got nil", s)
		} else if !strings.Contains(err.Error(), "ISO-8601") {
			t.Errorf("ParseUntil(%q): error %q lacks the wanted shape", s, err)
		}
	}
}

func TestValidOSUserAndSessionID(t *testing.T) {
	// IAMT-271: ValidOSUser accepts BOTH forms (Windows principal OR
	// POSIX local name); the per-OS gate is in ValidateOSUser, not
	// here.
	for _, s := range []string{
		`CONTOSO\alice`, `WIN01\Administrator`, `a\b`,
		"alice", "win01", "svc_account", "u-1", "u_1",
	} {
		if !ValidOSUser(s) {
			t.Errorf("ValidOSUser(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		`CONTOSO\`, `\alice`, `a\b\c`, `DOmain\has space`, "",
		// Out-of-shape POSIX: starts with digit, has comma, has
		// whitespace, has equals, leading dash, 33-char length,
		// uppercase.
		"1alice", "alice,bob", "alice bob", "alice=bob", "-alice",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Alice",
	} {
		if ValidOSUser(s) {
			t.Errorf("ValidOSUser(%q) = true, want false", s)
		}
	}
	if !ValidSessionID("b1f0e2a4-session-0001") {
		t.Error("ValidSessionID rejected a good id")
	}
	if ValidSessionID("short") || ValidSessionID("has space 1234") || ValidSessionID("") {
		t.Error("ValidSessionID accepted a bad id")
	}
}

func TestParsePortAndScreen(t *testing.T) {
	if p, err := ParsePort("2222", 1); err != nil || p != 2222 {
		t.Errorf("ParsePort(2222) = %d, %v", p, err)
	}
	if _, err := ParsePort("80", 1024); err == nil {
		t.Error("ParsePort(80, min 1024): want error")
	}
	if _, err := ParsePort("x", 1); err == nil {
		t.Error("ParsePort(x): want error")
	}
	for _, s := range []string{"Client", "SETUP", "admin"} {
		got, err := ParseScreen(s)
		if err != nil || got != strings.ToLower(s) {
			t.Errorf("ParseScreen(%q) = %q, %v", s, got, err)
		}
	}
	_, err := ParseScreen("lobby")
	if err == nil || !strings.Contains(err.Error(), `"client"`) {
		t.Errorf("ParseScreen(lobby): err=%v, want the list of screens", err)
	}
}
