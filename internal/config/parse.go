package config

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// goos is a tiny indirection so we can swap the platform at
// test time if a future test wants to drive ValidateOSUser
// across platforms from a single test binary.
var goos = func() string { return runtime.GOOS }

// The grammars here come from SPEC §3.1 (connection string), §3.4 (enrol
// code), §3.3 (claim reference), §4.3 (names, ISO-8601 times) and §6.1
// (accepted key types, RSA >= 3072). Everything returns errors that say
// what was wrong and what the wanted shape looks like.

// nameMaxLen is the length limit of the §4.3 name grammar.
const nameMaxLen = 32

// ValidName reports whether s matches the SPEC §4.3 name grammar
// [a-z0-9][a-z0-9._-]{0,31}. Persons, machines and machine ids use it.
func ValidName(s string) bool {
	if len(s) == 0 || len(s) > nameMaxLen {
		return false
	}
	c := s[0]
	if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '.', '_', '-':
		default:
			return false
		}
	}
	return true
}

// NameError is the standard rejection for a bad name value.
func NameError(what, s string) error {
	return userErrorf("%s %q is not a valid name — names are [a-z0-9][a-z0-9._-]{0,31} (SPEC §4.3), e.g. \"alice\", \"win01\".", what, s)
}

// ValidToken reports whether s is a well-formed opaque token: 8..256
// characters of [A-Za-z0-9._~-]. Used for enrol secrets, claim tokens and
// session ids (the session id additionally allows ':').
func ValidToken(s string) bool {
	return validTokenCharset(s, false)
}

func validTokenCharset(s string, allowColon bool) bool {
	if len(s) < 8 || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '~', c == '-':
		case c == ':' && allowColon:
		default:
			return false
		}
	}
	return true
}

// ValidSessionID reports whether s is a well-formed session id token.
func ValidSessionID(s string) bool {
	return len(s) >= 8 && len(s) <= 128 && validTokenCharset(s, true)
}

// ValidHost reports whether s is a bracketed IPv6 address, an IPv4
// address or a DNS-style hostname (letters, digits, '-', '_'; labels of
// up to 63 characters, total up to 253).
func ValidHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if strings.HasPrefix(s, "[") || strings.HasSuffix(s, "]") {
		if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
			return false
		}
		inner := s[1 : len(s)-1]
		ip := net.ParseIP(inner)
		return ip != nil && strings.Contains(inner, ":")
	}
	if strings.ContainsAny(s, "[]") {
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() != nil // bare IPv6 must use the [bracketed] form
	}
	for label := range strings.SplitSeq(strings.ToLower(s), ".") {
		if label == "" || len(label) > 63 ||
			strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
				continue
			}
			return false
		}
	}
	return true
}

// NormalizeFingerprint validates a SHA-256 key fingerprint and returns it
// in the canonical "SHA256:<43 base64 characters>" form. The "SHA256:"
// prefix is optional on input.
func NormalizeFingerprint(s string) (string, error) {
	f := strings.TrimPrefix(s, "SHA256:")
	raw, err := base64.RawStdEncoding.DecodeString(f)
	if err != nil || len(raw) != 32 {
		return "", userErrorf("fingerprint %q is not a SHA-256 key fingerprint — want %q plus 43 base64 characters, exactly as the admin command printed it", s, "SHA256:")
	}
	return "SHA256:" + f, nil
}

// parseTargetFingerprint validates the fingerprint part embedded in a
// connection string, enrol code or claim reference. There the "SHA256:"
// prefix is not allowed: the ':' would collide with the secret separator.
func parseTargetFingerprint(s string) (string, error) {
	if strings.Contains(s, ":") {
		return "", userErrorf("fingerprint %q must be the 43 base64 characters without the \"SHA256:\" prefix at this position (the ':' would collide with the following part)", s)
	}
	return NormalizeFingerprint(s)
}

// splitHostPort splits "<host>:<port>" with bracketed IPv6 support and
// validates both parts.
func splitHostPort(s string) (string, int, error) {
	var host, portStr string
	if i := strings.Index(s, "]"); i >= 0 {
		if !strings.HasPrefix(s, "[") || i == len(s)-1 || s[i+1] != ':' {
			return "", 0, userErrorf("%q is not <host>:<port> — a bracketed IPv6 address must look like \"[2001:db8::1]:2222\"", s)
		}
		host, portStr = s[:i+1], s[i+2:]
	} else {
		i := strings.LastIndex(s, ":")
		if i < 0 {
			return "", 0, userErrorf("%q is not <host>:<port> — the port is required, e.g. \"gw.example.com:2222\"", s)
		}
		host, portStr = s[:i], s[i+1:]
	}
	if !ValidHost(host) {
		return "", 0, userErrorf("host %q is not a valid hostname or IP address", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, userErrorf("port %q must be a number from 1 to 65535", portStr)
	}
	return host, port, nil
}

// ConnString is a parsed §3.1 connection string.
type ConnString struct {
	Host        string
	Port        int
	Person      string
	Fingerprint string // canonical "SHA256:…" form
}

// ParseConnString parses the connection string of SPEC §3.1:
//
//	iamtunnel://<host>:<port>/<person>#<sha256 of the gateway host key>
func ParseConnString(s string) (ConnString, error) {
	var zero ConnString
	s = strings.TrimSpace(s)
	const scheme = "iamtunnel://"
	if len(s) < len(scheme) || !strings.EqualFold(s[:len(scheme)], scheme) {
		return zero, userErrorf("connection string must start with %q — copy the whole line the admin gave you", scheme)
	}
	rest := s[len(scheme):]
	body, fp, err := cutOnce(rest, '#', "the gateway key fingerprint")
	if err != nil {
		return zero, err
	}
	hostport, person, err := cutOnce(body, '/', "the person name")
	if err != nil {
		return zero, err
	}
	if !ValidName(person) {
		return zero, userErrorf("person %q in the connection string is not a valid name — names are [a-z0-9][a-z0-9._-]{0,31} (SPEC §4.3)", person)
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return zero, err
	}
	fpr, err := parseTargetFingerprint(fp)
	if err != nil {
		return zero, err
	}
	return ConnString{Host: host, Port: port, Person: person, Fingerprint: fpr}, nil
}

// EnrolCode is a parsed §3.4 enrol code.
type EnrolCode struct {
	Host        string
	Port        int
	Fingerprint string // canonical "SHA256:…" form
	Secret      string
}

// ParseEnrolCode parses the enrol code of SPEC §3.4:
//
//	iamtunnel-enrol://<host>:<port>#<sha256>:<secret>
func ParseEnrolCode(s string) (EnrolCode, error) {
	var zero EnrolCode
	s = strings.TrimSpace(s)
	const scheme = "iamtunnel-enrol://"
	if len(s) < len(scheme) || !strings.EqualFold(s[:len(scheme)], scheme) {
		return zero, userErrorf("enrol code must start with %q — copy the whole line \"iamtunnel admin machines enrol-code\" printed", scheme)
	}
	rest := s[len(scheme):]
	body, fpSecret, err := cutOnce(rest, '#', "the gateway key fingerprint")
	if err != nil {
		return zero, err
	}
	i := strings.Index(fpSecret, ":")
	if i < 0 {
		return zero, userErrorf("enrol code is missing the secret part — want <host>:<port>#<fingerprint>:<secret>")
	}
	fp, secret := fpSecret[:i], fpSecret[i+1:]
	// The fingerprint is checked before the secret: the ':' inside a
	// "SHA256:" prefix would otherwise be reported as a bad secret.
	fpr, err := parseTargetFingerprint(fp)
	if err != nil {
		return zero, err
	}
	if !ValidToken(secret) {
		return zero, userErrorf("enrol secret has a wrong shape — want 8..256 characters of [A-Za-z0-9._~-]; copy the code without changes")
	}
	host, port, err := splitHostPort(body)
	if err != nil {
		return zero, err
	}
	return EnrolCode{Host: host, Port: port, Fingerprint: fpr, Secret: secret}, nil
}

// ClaimRef is a parsed §3.3 bootstrap reference.
type ClaimRef struct {
	Host        string
	Port        int
	Fingerprint string // canonical "SHA256:…" form
	Token       string
}

// ParseClaimRef parses the bootstrap reference of SPEC §3.3:
//
//	<host>:<port>#<fingerprint>:<token>
//
// The fingerprint part is 43 base64 characters WITHOUT the "SHA256:"
// prefix — the ':' would otherwise be cut as the secret separator and
// "SHA256" would land in the fingerprint slot, the real base64 in the
// token slot, and the token's shape check would fail.
//
// IAMT-200: older versions of "gateway install" printed the fingerprint
// WITH the "SHA256:" prefix on the bootstrap link. Such links are
// accepted here — the prefix is stripped before the split — so any
// reference an operator copied off an older VPS or the previous RUNBOOK
// (the latter also kept the prefix in §1.3 until this commit) still
// resolves to the same ClaimRef. New install output no longer carries
// the prefix.
func ParseClaimRef(s string) (ClaimRef, error) {
	var zero ClaimRef
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		return zero, userErrorf("claim reference %q takes no URI scheme — want <host>:<port>#<fingerprint>:<token>; only the connection string and the enrol code start with \"iamtunnel", s)
	}
	body, fpToken, err := cutOnce(s, '#', "the gateway key fingerprint")
	if err != nil {
		return zero, err
	}
	// IAMT-200: back-compat for the legacy "SHA256:" prefix on the
	// fingerprint position. The prefix is stripped BEFORE the secret
	// cut, so the next ':' lands at the right boundary. The bare
	// canonical form (no prefix) still works.
	fpToken = strings.TrimPrefix(fpToken, "SHA256:")
	i := strings.Index(fpToken, ":")
	if i < 0 {
		return zero, userErrorf("claim reference is missing the token part — want <host>:<port>#<fingerprint>:<token>")
	}
	fp, token := fpToken[:i], fpToken[i+1:]
	if !ValidToken(token) {
		return zero, userErrorf("bootstrap token has a wrong shape — want 8..256 characters of [A-Za-z0-9._~-]; copy the reference \"gateway install\" printed without changes")
	}
	host, port, err := splitHostPort(body)
	if err != nil {
		return zero, err
	}
	fpr, err := parseTargetFingerprint(fp)
	if err != nil {
		return zero, err
	}
	return ClaimRef{Host: host, Port: port, Fingerprint: fpr, Token: token}, nil
}

// PairingRef is a parsed §3.4 pairing reference (IAMT-323).
type PairingRef struct {
	Host        string
	Port        int
	Fingerprint string // canonical "SHA256:…" form
}

// ParsePairingRef parses the pairing reference that "iamtunnel gateway
// pair" and "iamtunnel admin pairing start" print (SPEC §3.4):
//
//	<host>:<port>#<fingerprint>
//
// There is no token part — the PIN is the secret and the operator types
// it next to the reference, so the reference itself carries nothing
// sensitive. The legacy "SHA256:" prefix on the fingerprint is accepted
// and stripped, as in ParseClaimRef; a URI scheme is rejected — this is
// a bare pair, only the connection string and the enrol code carry a
// scheme.
func ParsePairingRef(s string) (PairingRef, error) {
	var zero PairingRef
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		return zero, userErrorf("pairing reference %q takes no URI scheme — want <host>:<port>#<fingerprint>; only the connection string and the enrol code start with \"iamtunnel", s)
	}
	body, fp, err := cutOnce(s, '#', "the gateway key fingerprint")
	if err != nil {
		return zero, err
	}
	host, port, err := splitHostPort(body)
	if err != nil {
		return zero, err
	}
	fpr, err := parseTargetFingerprint(strings.TrimPrefix(fp, "SHA256:"))
	if err != nil {
		return zero, err
	}
	return PairingRef{Host: host, Port: port, Fingerprint: fpr}, nil
}

// cutOnce splits s at the single separator sep; zero or more than one
// occurrence is an error naming the missing part.
func cutOnce(s string, sep byte, part string) (string, string, error) {
	n := strings.Count(s, string(sep))
	if n == 0 {
		return "", "", userErrorf("missing %q part (the %c separator) — the wanted shape has exactly one", part, sep)
	}
	if n > 1 {
		return "", "", userErrorf("more than one %c separator — the %s part appears exactly once; copy the string without changes", sep, part)
	}
	a, b, _ := strings.Cut(s, string(sep))
	return a, b, nil
}

// allowedKeyTypes lists the public key types the gateway accepts (SPEC
// §6.1): ed25519 by default, RSA >= 3072, modern ECDSA; dsa and
// ecdsa-sha1 are rejected.
var allowedKeyTypes = map[string]bool{
	"ssh-ed25519":         true,
	"ssh-rsa":             true,
	"ecdsa-sha2-nistp256": true,
	"ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true,
}

// CheckPublicKey validates one OpenSSH public key line ("<type>
// <base64> [comment]"). It enforces the §6.1 policy: allowed type and,
// for RSA, at least 3072 bits.
func CheckPublicKey(line string) (ssh.PublicKey, error) {
	line = strings.TrimRight(strings.TrimSpace(line), "\r\n")
	if line == "" {
		return nil, userErrorf("public key is empty — pass the one-line OpenSSH public key, e.g. the output of \"ssh-keygen -y -f <private key>\"")
	}
	if strings.ContainsAny(line, "\n\r") {
		return nil, userErrorf("public key must be a single line — pass only the \"<type> <base64> [comment]\" line")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, userErrorf("public key does not parse as an OpenSSH public key (%v) — want the one-line \"<type> <base64> [comment]\" form, e.g. \"ssh-ed25519 AAAA… user@host\"", err)
	}
	t := pub.Type()
	if !allowedKeyTypes[t] {
		return nil, userErrorf("key type %s is not accepted — use ssh-ed25519, ssh-rsa or ecdsa-sha2-nistp256/384/521 (dsa and ecdsa-sha1 are rejected, SPEC §6.1)", t)
	}
	if t == "ssh-rsa" {
		if c, ok := pub.(ssh.CryptoPublicKey); ok {
			if rk, ok := c.CryptoPublicKey().(*rsa.PublicKey); ok && rk.N.BitLen() < 3072 {
				return nil, userErrorf("RSA key is %d bits — the minimum accepted key strength is 3072 bits (SPEC §6.1); generate a new key with \"ssh-keygen -t rsa -b 3072\"", rk.N.BitLen())
			}
		}
	}
	return pub, nil
}

// ParseUntil validates the <until> value of "grants grant": an ISO-8601
// date-time with an explicit zone (SPEC §4.3). Whether the moment is in
// the past is the gateway's call — its clock is the only time authority
// (SPEC §6.4) — so only the shape is checked here.
func ParseUntil(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, userErrorf("%q is not an ISO-8601 date-time with a zone — want e.g. \"2027-01-31T18:00:00Z\" or \"2027-01-31T21:00:00+03:00\" (SPEC §4.3)", s)
	}
	return t, nil
}

// ValidOSUser reports whether s matches one of the two OS-user
// shapes settled on (IAMT-271, PROTOCOL §1, SPEC §3.2.1):
//
//	(a) Windows principal — "DOMAIN\name" or "MACHINE\name";
//	    exactly one backslash, both parts non-empty, ASCII letters,
//	    digits, dot, _, -, @, $; length 1..64 per part.
//
//	(b) POSIX local name — Linux/macOS only; lowercase ASCII
//	    matching ^[a-z_][a-z0-9_-]{0,31}$ (start must be a letter
//	    or underscore; digits and dashes only after the first
//	    char).
//
// ValidOSUser does not consult the platform — both forms are
// accepted syntactically; per-OS selection happens at the
// ValidateOSUser gate. The cross-platform admin / gateway paths
// pass strings across boundaries (admin machines enrol-code
// sends a string the server must accept, server start validates
// it on its own OS), so accepting either shape up front keeps
// the protocol unchanged.
func ValidOSUser(s string) bool {
	return validOSUserWindows(s) || validOSUserPOSIX(s)
}

// validOSUserWindows matches shape (a). Exactly one backslash,
// both halves non-empty, ASCII-only, length 1..64 per half.
// The half-chars are the same set ValidOSUser used to allow
// (letters, digits, dot, _, -, @, $) — see validAccountPart.
func validOSUserWindows(s string) bool {
	domain, name, ok := strings.Cut(s, `\`)
	if !ok || domain == "" || name == "" {
		return false
	}
	if strings.Contains(name, `\`) {
		return false
	}
	return validAccountPart(domain) && validAccountPart(name)
}

// validOSUserPOSIX matches shape (b). Lowercase ASCII only,
// ^[a-z_][a-z0-9_-]{0,31}$ — start must be a letter or
// underscore; digits and dashes only after the first char.
// The set is deliberately the POSIX "login name" subset: no
// uppercase, no comma, no equals, no whitespace, no leading
// dash. A 33-char name is rejected (the bound is 32).
func validOSUserPOSIX(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	c := s[0]
	if !(c >= 'a' && c <= 'z' || c == '_') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func validAccountPart(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == '@', c == '$':
		default:
			return false
		}
	}
	return true
}

// ValidateOSUser is the per-OS gate. On Windows only shape (a)
// is acceptable (no POSIX local names — the Administrators
// member is named as a Windows principal); on Linux/macOS only
// shape (b) is acceptable (no DOMAIN\ prefix — Linux accounts do
// not have one). The function returns nil on success and an
// error naming both shapes so an operator copying a Windows
// enrol code into a a Linux machine (or vice versa) sees the
// fix immediately.
//
// This is the IAMT-271 hook that PROTOCOL §1 / SPEC §3.2.1
// document: the protocol accepts both shapes (the cross-platform
// shape is the union), but the per-machine gate is the OS.
func ValidateOSUser(s string) error {
	if !ValidOSUser(s) {
		return fmt.Errorf("os user %q matches neither Windows principal (DOMAIN\\name or MACHINE\\name, ASCII letters/digits/./_/-/@/$, 1..64 chars per part) nor POSIX local name (lowercase ^[a-z_][a-z0-9_-]{0,31}$)", s)
	}
	switch goos() {
	case "windows":
		if !validOSUserWindows(s) {
			return fmt.Errorf("on Windows os user must be a DOMAIN\\name or MACHINE\\name (got %q — POSIX local names are Linux/macOS only)", s)
		}
	case "linux", "darwin":
		if !validOSUserPOSIX(s) {
			return fmt.Errorf("on %s os user must be a POSIX local name matching ^[a-z_][a-z0-9_-]{0,31}$ (got %q — DOMAIN\\name is the Windows form)", runtime.GOOS, s)
		}
	}
	return nil
}

// ParsePort parses a decimal port and enforces min..65535.
func ParsePort(s string, minPort int) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < minPort || p > 65535 {
		return 0, userErrorf("port %q must be a number from %d to 65535", s, minPort)
	}
	return p, nil
}

// screens lists the GUI screens "shot" accepts (SPEC §7.1 tab list).
// It is deliberately unexported: an exported slice is a package variable
// any importer can rewrite, and this one decides which arguments are
// accepted. ScreenNames hands out a copy for help text and tests.
//
// ALL EIGHT, since 21.09.2026. It held five, and the window had eight:
// guide, session and history could not be drawn at all, and the first of
// those is the screen a new person sees first. The list had simply not
// been extended when tabs were added -- Session in 1.5, History today --
// because nothing failed when it was not.
//
// Something does now: every screen is expected to produce a picture,
// and three of them had no way to. The gap also made the two
// lists disagree with each other, "shot" accepting five names while
// --tab accepted six, so the same window had two different vocabularies
// depending on which door you came through.
var screens = [...]string{"guide", "setup", "client", "server", "gateway", "session", "admin", "history", "settings"}

// ScreenNames returns the accepted screen names, in order.
func ScreenNames() []string {
	out := make([]string, len(screens))
	copy(out, screens[:])
	return out
}

// ParseScreen validates the <screen> argument of "shot", case
// insensitively, and returns the canonical lowercase name.
func ParseScreen(s string) (string, error) {
	l := strings.ToLower(s)
	for _, sc := range screens {
		if l == sc {
			return l, nil
		}
	}
	return "", userErrorf("screen %q is not one of %s", s, strings.Join(quoteEach(screens[:]...), " | "))
}

func quoteEach(ss ...string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strconv.Quote(s)
	}
	return out
}
