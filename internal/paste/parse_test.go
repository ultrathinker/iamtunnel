package paste

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// The fixtures are the shapes internal/config already enforces: 43 base64
// characters of fingerprint, an 8..256 character token of [A-Za-z0-9._~-],
// six decimal digits of PIN with a leading zero (SPEC §3.3 — the leading
// zero is part of the code, and a test whose PIN starts with 1 would never
// notice a parser that treated it as a number).
const (
	fpr43   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fprCan  = "SHA256:" + fpr43
	token   = "bootstrap-token-9x"
	secret  = "enrol~secret_42"
	pin     = "012345"
	gwHost  = "203.0.113.10"
	gwPort  = 2022
	gwAddr  = gwHost + ":2022"
	pairRef = gwAddr + "#" + fpr43
)

// want is the expected parse, field by field.
type want struct {
	kind        Kind
	host        string
	port        int
	fingerprint string
	secret      string
	person      string
}

// check compares a Parsed with the expectation field by field and fails
// loudly on the first difference — the whole point of the table tests is
// that a field quietly landing in the wrong slot is caught.
func check(t *testing.T, name string, got Parsed, w want) {
	t.Helper()
	if got.Kind != w.kind {
		t.Errorf("%s: Kind = %v, want %v", name, got.Kind, w.kind)
	}
	if got.Host != w.host {
		t.Errorf("%s: Host = %q, want %q", name, got.Host, w.host)
	}
	if got.Port != w.port {
		t.Errorf("%s: Port = %d, want %d", name, got.Port, w.port)
	}
	if got.Fingerprint != w.fingerprint {
		t.Errorf("%s: Fingerprint = %q, want %q", name, got.Fingerprint, w.fingerprint)
	}
	if got.Secret != w.secret {
		t.Errorf("%s: Secret = %q, want %q", name, got.Secret, w.secret)
	}
	if got.Person != w.person {
		t.Errorf("%s: Person = %q, want %q", name, got.Person, w.person)
	}
}

// TestPairLinePrintedByGatewayParsesVerbatim is the live-run defect of
// 17.09 (SPEC §3.6): the gateway prints a ready command line, the person
// copies what is on the screen, and the field refused it while the
// two-minute pairing window burned.
//
// The inputs are not paraphrases. They are what
// cmd/iamtunnel/gateway.go:866 and cmd/iamtunnel/admin_exec.go:464 write,
// byte for byte:
//
//	fmt.Fprintf(s.out, "On the new admin's machine run:\n  iamtunnel admin pair %s %s\n", ref, pin)
//
// — first the whole two-line block as a terminal hands it to the
// clipboard, then the command line alone with its two-space indent and
// trailing newline, then the RUNBOOK §1.4.1 writing with the reference
// quoted. Every one of them must parse, and to the same thing.
func TestPairLinePrintedByGatewayParsesVerbatim(t *testing.T) {
	printed := fmt.Sprintf("On the new admin's machine run:\n  iamtunnel admin pair %s %s\n", pairRef, pin)
	commandLineOnly := fmt.Sprintf("  iamtunnel admin pair %s %s\n", pairRef, pin)
	runbookQuoted := fmt.Sprintf("iamtunnel admin pair %q %s", pairRef, pin)
	windowsCRLF := strings.ReplaceAll(printed, "\n", "\r\n")

	cases := []struct{ name, in string }{
		{"both lines as printed", printed},
		{"command line alone, indented, newline kept", commandLineOnly},
		{"RUNBOOK writing, reference quoted", runbookQuoted},
		{"the same block copied from a Windows console (CRLF)", windowsCRLF},
	}
	for _, tc := range cases {
		got, err := Parse(tc.in)
		if err != nil {
			t.Errorf("%s: Parse(%q) refused the string the gateway itself printed: %v", tc.name, tc.in, err)
			continue
		}
		check(t, tc.name, got, want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin})
	}
}

// TestParseAcceptedForms is the table of every wrapper SPEC §3.6 promises
// to accept, asserted field by field.
func TestParseAcceptedForms(t *testing.T) {
	cases := []struct {
		name string
		in   string
		w    want
	}{
		// --- the four canonical strings ---------------------------------
		{
			"canonical claim scheme",
			"iamtunnel-claim://" + gwAddr + "#" + fpr43 + ":" + token,
			want{kind: Claim, host: gwHost, port: gwPort, fingerprint: fprCan, secret: token},
		},
		{
			"canonical pair scheme, PIN in the string",
			"iamtunnel-pair://" + pairRef + ":" + pin,
			want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin},
		},
		{
			"canonical enrol scheme",
			"iamtunnel-enrol://" + gwAddr + "#" + fpr43 + ":" + secret,
			want{kind: Enrol, host: gwHost, port: gwPort, fingerprint: fprCan, secret: secret},
		},
		{
			"canonical connection string (SPEC §3.1 order)",
			"iamtunnel://" + gwAddr + "/alice#" + fpr43,
			want{kind: Connect, host: gwHost, port: gwPort, fingerprint: fprCan, person: "alice"},
		},
		{
			"scheme in upper case",
			"IAMTUNNEL-PAIR://" + pairRef + ":" + pin,
			want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin},
		},
		// --- the command lines the gateway prints ------------------------
		{
			"admin pair command line",
			"iamtunnel admin pair " + pairRef + " " + pin,
			want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin},
		},
		{
			"admin pair command line carrying the one-string form",
			"iamtunnel admin pair iamtunnel-pair://" + pairRef + ":" + pin,
			want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin},
		},
		{
			"admin claim command line",
			"iamtunnel admin claim " + gwAddr + "#" + fpr43 + ":" + token,
			want{kind: Claim, host: gwHost, port: gwPort, fingerprint: fprCan, secret: token},
		},
		{
			"admin claim command line with the --key flag §3.3 prints",
			"iamtunnel admin claim " + gwAddr + "#" + fpr43 + ":" + token + " --key C:\\Users\\a\\id.pub",
			want{kind: Claim, host: gwHost, port: gwPort, fingerprint: fprCan, secret: token},
		},
		{
			"enrol command line",
			"iamtunnel enrol iamtunnel-enrol://" + gwAddr + "#" + fpr43 + ":" + secret,
			want{kind: Enrol, host: gwHost, port: gwPort, fingerprint: fprCan, secret: secret},
		},
		{
			"enrol command line, scheme rubbed off the code",
			"iamtunnel enrol " + gwAddr + "#" + fpr43 + ":" + secret,
			want{kind: Enrol, host: gwHost, port: gwPort, fingerprint: fprCan, secret: secret},
		},
		{
			"the Windows binary name",
			"iamtunnel.exe admin pair " + pairRef + " " + pin,
			want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin},
		},
		// --- bare reference plus PIN -------------------------------------
		{
			"bare reference, whitespace, PIN",
			pairRef + " " + pin,
			want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin},
		},
		{
			"bare reference, tab, PIN",
			pairRef + "\t" + pin,
			want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin},
		},
		{
			"bare reference with the legacy SHA256: prefix, plus PIN",
			gwAddr + "#SHA256:" + fpr43 + " " + pin,
			want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin},
		},
		{
			"bare claim reference, token inside, no PIN wanted",
			gwAddr + "#" + fpr43 + ":" + token,
			want{kind: Claim, host: gwHost, port: gwPort, fingerprint: fprCan, secret: token},
		},
		// --- whitespace, quotes, newlines --------------------------------
		{
			"leading and trailing whitespace and a trailing newline",
			"   iamtunnel-pair://" + pairRef + ":" + pin + "  \n",
			want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin},
		},
		{
			"the whole line in double quotes",
			"\"iamtunnel admin pair " + pairRef + " " + pin + "\"",
			want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin},
		},
		{
			"the string in single quotes, as PowerShell keeps it",
			"'iamtunnel-enrol://" + gwAddr + "#" + fpr43 + ":" + secret + "'",
			want{kind: Enrol, host: gwHost, port: gwPort, fingerprint: fprCan, secret: secret},
		},
		{
			"typographic quotes, as a chat client leaves them",
			"\u201ciamtunnel-claim://" + gwAddr + "#" + fpr43 + ":" + token + "\u201d",
			want{kind: Claim, host: gwHost, port: gwPort, fingerprint: fprCan, secret: token},
		},
		{
			"a UTF-8 BOM in front, as some editors paste it",
			"\ufeffiamtunnel-pair://" + pairRef + ":" + pin,
			want{kind: Pair, host: gwHost, port: gwPort, fingerprint: fprCan, secret: pin},
		},
		// --- hosts -------------------------------------------------------
		{
			"a bracketed IPv6 gateway",
			"iamtunnel admin pair [2001:db8::1]:2222#" + fpr43 + " " + pin,
			want{kind: Pair, host: "[2001:db8::1]", port: 2222, fingerprint: fprCan, secret: pin},
		},
		{
			"a DNS name and the default port",
			"gw.example.com:2222#" + fpr43 + " " + pin,
			want{kind: Pair, host: "gw.example.com", port: 2222, fingerprint: fprCan, secret: pin},
		},
	}
	for _, tc := range cases {
		got, err := Parse(tc.in)
		if err != nil {
			t.Errorf("%s: Parse(%q): %v", tc.name, tc.in, err)
			continue
		}
		check(t, tc.name, got, tc.w)
	}
}

// TestParseRefusalsNameTheProblem is the refusal table. Each case asserts
// the words the person reading the field must see — not a code, not a
// class, the thing that was actually wrong with what they pasted.
func TestParseRefusalsNameTheProblem(t *testing.T) {
	cases := []struct {
		name, in string
		wants    []string
	}{
		{
			"a PIN of five digits",
			"iamtunnel admin pair " + pairRef + " 01234",
			[]string{"PIN", "exactly 6 decimal digits", "\"01234\""},
		},
		{
			"a PIN of seven digits",
			"iamtunnel admin pair " + pairRef + " 0123456",
			[]string{"PIN", "exactly 6 decimal digits"},
		},
		{
			"a PIN with a letter in it",
			"iamtunnel admin pair " + pairRef + " 01o345",
			[]string{"PIN", "digits only"},
		},
		{
			"a PIN whose leading zero was dropped on the way",
			"iamtunnel admin pair " + pairRef + " 12345",
			[]string{"leading zeros are part of the PIN"},
		},
		{
			"a fingerprint that is a character short",
			"iamtunnel admin pair " + gwAddr + "#" + fpr43[:42] + " " + pin,
			[]string{"fingerprint", "43 base64 characters"},
		},
		{
			"a fingerprint that is not base64 at all",
			"iamtunnel admin pair " + gwAddr + "#not-a-fingerprint " + pin,
			[]string{"is not a SHA-256 key fingerprint"},
		},
		{
			"a port above the range",
			"iamtunnel admin pair " + gwHost + ":70000#" + fpr43 + " " + pin,
			[]string{"port", "1 to 65535"},
		},
		{
			"a port of zero",
			"iamtunnel-pair://" + gwHost + ":0#" + fpr43 + ":" + pin,
			[]string{"port", "1 to 65535"},
		},
		{
			"a port that is not a number",
			"iamtunnel-pair://" + gwHost + ":ssh#" + fpr43 + ":" + pin,
			[]string{"port", "1 to 65535"},
		},
		{
			"an unknown scheme",
			"ssh://" + gwAddr + "#" + fpr43 + ":" + token,
			[]string{"\"ssh://\"", "is not a scheme this field knows", "iamtunnel-claim://"},
		},
		{
			"a web link pasted into the field",
			"https://gw.example.com/pairing#" + fpr43,
			[]string{"is not a scheme this field knows"},
		},
		{
			"an empty paste",
			"",
			[]string{"nothing was pasted"},
		},
		{
			"whitespace only",
			"   \n\t \n",
			[]string{"nothing was pasted"},
		},
		{
			"the gateway's sentence without the command under it",
			"On the new admin's machine run:",
			[]string{"nothing in the pasted text looks like a gateway string"},
		},
		{
			"a command this field does not perform",
			"iamtunnel admin grants grant alice win01 until 2027-01-31T18:00:00Z",
			[]string{"is not a command this field understands", "iamtunnel admin pair"},
		},
		{
			"a top-level command this field does not perform",
			"iamtunnel gateway install --public-host gw.example.com",
			[]string{"is not a command this field understands"},
		},
		{
			"the program name and nothing else",
			"iamtunnel",
			[]string{"just the program name"},
		},
		{
			"the pair command with no string after it",
			"iamtunnel admin pair",
			[]string{"without its pairing reference"},
		},
		{
			"an enrol code pasted onto an admin pair line",
			"iamtunnel admin pair iamtunnel-enrol://" + gwAddr + "#" + fpr43 + ":" + secret,
			[]string{"the two disagree", "iamtunnel admin pair"},
		},
		{
			"a pairing reference with no PIN next to it",
			pairRef,
			[]string{"pairing reference with no PIN next to it"},
		},
		{
			"two different PINs, one in the string and one after it",
			"iamtunnel admin pair iamtunnel-pair://" + pairRef + ":" + pin + " 999999",
			[]string{"the two disagree", "\"012345\"", "\"999999\""},
		},
		{
			"a stray word next to a claim string",
			"iamtunnel admin claim " + gwAddr + "#" + fpr43 + ":" + token + " " + pin,
			[]string{"already carries its own token", "has no meaning"},
		},
		{
			"a stray word next to a connection string",
			"iamtunnel://" + gwAddr + "/alice#" + fpr43 + " " + pin,
			[]string{"carries everything it needs", "has no meaning"},
		},
		{
			"three values on one line",
			pairRef + " " + pin + " " + pin,
			[]string{"carries 3 values"},
		},
		{
			"a word that is not a reference at all, '#' or no '#'",
			"pair-me-please#",
			[]string{"not <host>:<port>"},
		},
		{
			"a word that merely starts like the program name",
			"iamtunnelish-nonsense",
			[]string{"is not a string this field takes"},
		},
		{
			"an enrol secret too short to be one",
			"iamtunnel-enrol://" + gwAddr + "#" + fpr43 + ":short",
			[]string{"enrol secret has a wrong shape"},
		},
		{
			"a bootstrap token too short to be one",
			"iamtunnel-claim://" + gwAddr + "#" + fpr43 + ":short",
			[]string{"bootstrap token has a wrong shape"},
		},
		{
			"a person name the §4.3 grammar does not allow",
			"iamtunnel://" + gwAddr + "/Alice#" + fpr43,
			[]string{"not a valid name"},
		},
		{
			"a host that is not a host",
			"iamtunnel admin pair gw..example.com:2222#" + fpr43 + " " + pin,
			[]string{"is not a valid hostname"},
		},
		{
			"a reference with no port",
			"gw.example.com#" + fpr43 + " " + pin,
			[]string{"not <host>:<port>"},
		},
	}
	for _, tc := range cases {
		got, err := Parse(tc.in)
		if err == nil {
			t.Errorf("%s: Parse(%q) = %+v, want a refusal", tc.name, tc.in, got)
			continue
		}
		for _, wantText := range tc.wants {
			if !strings.Contains(err.Error(), wantText) {
				t.Errorf("%s: Parse(%q) refused with %q, which does not name %q", tc.name, tc.in, err.Error(), wantText)
			}
		}
	}
}

// TestRefusalsCarryTheUserErrorClass keeps the refusals on the same exit
// code as the same value refused from a command argument: config.ClassUser
// is 2, "the invocation or a value is wrong". A refusal that arrived as a
// plain error would exit 1 and read as a crash.
func TestRefusalsCarryTheUserErrorClass(t *testing.T) {
	inputs := []string{
		"",                                       // our own refusal
		"iamtunnel admin pair " + pairRef + " 1", // our own refusal, PIN
		"ssh://" + gwAddr + "#" + fpr43,          // our own refusal, scheme
		"iamtunnel admin pair " + gwHost + ":0#" + fpr43 + " " + pin, // config's refusal
		"iamtunnel-enrol://" + gwAddr + "#zz:" + secret,              // config's refusal
	}
	for _, in := range inputs {
		_, err := Parse(in)
		if err == nil {
			t.Errorf("Parse(%q) was accepted, want a refusal", in)
			continue
		}
		var cerr *config.Error
		if !errors.As(err, &cerr) {
			t.Errorf("Parse(%q) refused with %T, want a *config.Error so the CLI exit code is the classified one", in, err)
			continue
		}
		if cerr.Class != config.ClassUser {
			t.Errorf("Parse(%q) refused with class %d, want %d (ClassUser)", in, cerr.Class, config.ClassUser)
		}
	}
}

// TestPreviewNamesActionAddressAndFingerprint is SPEC §3.6's "preview is
// mandatory": before the button does anything, one sentence says what is
// about to happen, to which gateway, and with which host key. The
// fingerprint is asserted in full — this is the only place a person
// compares it by eye (§6.2, no TOFU in any role).
func TestPreviewNamesActionAddressAndFingerprint(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		action string
	}{
		{"claim", "iamtunnel-claim://" + gwAddr + "#" + fpr43 + ":" + token, "the first administrator"},
		{"pair", "iamtunnel admin pair " + pairRef + " " + pin, "an administrator"},
		{"enrol", "iamtunnel-enrol://" + gwAddr + "#" + fpr43 + ":" + secret, "register THIS machine"},
		{"connect", "iamtunnel://" + gwAddr + "/alice#" + fpr43, "save the connection"},
	}
	for _, tc := range cases {
		p, err := Parse(tc.in)
		if err != nil {
			t.Errorf("%s: Parse(%q): %v", tc.name, tc.in, err)
			continue
		}
		got := p.Preview()
		for _, wantText := range []string{tc.action, gwAddr, fprCan} {
			if !strings.Contains(got, wantText) {
				t.Errorf("%s: Preview() = %q, which does not name %q", tc.name, got, wantText)
			}
		}
		if !strings.HasSuffix(got, ".") {
			t.Errorf("%s: Preview() = %q, want one finished sentence ending in a full stop", tc.name, got)
		}
		if strings.Contains(got, "\n") {
			t.Errorf("%s: Preview() = %q, want one line under the field, not several", tc.name, got)
		}
	}
	// The connect preview additionally names the person the string is for:
	// pasting somebody else's connection string is exactly what the
	// preview exists to catch.
	p, err := Parse("iamtunnel://" + gwAddr + "/alice#" + fpr43)
	if err != nil {
		t.Fatalf("Parse of the connection string: %v", err)
	}
	if !strings.Contains(p.Preview(), "alice") {
		t.Errorf("connect Preview() = %q, want the person named", p.Preview())
	}
}

// TestPreviewOfNothingIsStillASentence: a caller renders Preview under the
// field from the first keystroke, so the zero value must read as something
// and not as a blank line or a half sentence about port 0.
func TestPreviewOfNothingIsStillASentence(t *testing.T) {
	got := Parsed{}.Preview()
	if got == "" {
		t.Fatalf("Preview() of the zero Parsed is empty — the field would show a blank line")
	}
	if strings.Contains(got, ":0") || strings.Contains(got, "SHA256:") {
		t.Errorf("Preview() of the zero Parsed = %q, want no address and no fingerprint invented out of nothing", got)
	}
	if !strings.Contains(got, "Nothing is pasted yet") {
		t.Errorf("Preview() of the zero Parsed = %q, want it to say that nothing is pasted yet", got)
	}
}

// TestParseAgreesWithTheConfigGrammar is the "one way to spell a thing"
// guard: this package must not grow a second grammar beside
// internal/config. Whatever the wrapper, the result has to be identical to
// what the config parser makes of the bare string.
func TestParseAgreesWithTheConfigGrammar(t *testing.T) {
	claimStr := gwAddr + "#" + fpr43 + ":" + token
	ref, err := config.ParseClaimRef(claimStr)
	if err != nil {
		t.Fatalf("config.ParseClaimRef(%q): %v", claimStr, err)
	}
	got, err := Parse("iamtunnel admin claim " + claimStr)
	if err != nil {
		t.Fatalf("Parse of the claim command line: %v", err)
	}
	check(t, "claim vs config.ParseClaimRef", got,
		want{kind: Claim, host: ref.Host, port: ref.Port, fingerprint: ref.Fingerprint, secret: ref.Token})

	enrolStr := "iamtunnel-enrol://" + gwAddr + "#" + fpr43 + ":" + secret
	code, err := config.ParseEnrolCode(enrolStr)
	if err != nil {
		t.Fatalf("config.ParseEnrolCode(%q): %v", enrolStr, err)
	}
	got, err = Parse("iamtunnel enrol  " + enrolStr + "\n")
	if err != nil {
		t.Fatalf("Parse of the enrol command line: %v", err)
	}
	check(t, "enrol vs config.ParseEnrolCode", got,
		want{kind: Enrol, host: code.Host, port: code.Port, fingerprint: code.Fingerprint, secret: code.Secret})

	connStr := "iamtunnel://" + gwAddr + "/alice#" + fpr43
	cs, err := config.ParseConnString(connStr)
	if err != nil {
		t.Fatalf("config.ParseConnString(%q): %v", connStr, err)
	}
	got, err = Parse("  " + connStr + "  ")
	if err != nil {
		t.Fatalf("Parse of the connection string: %v", err)
	}
	check(t, "connect vs config.ParseConnString", got,
		want{kind: Connect, host: cs.Host, port: cs.Port, fingerprint: cs.Fingerprint, person: cs.Person})

	// The one order there is. §3.6's table first printed the person and
	// the fingerprint the other way round; that was an error in the table,
	// corrected on 17.09.2026 — §3.1 and every printer in the tree have
	// always put the person first. The wrong order must therefore be
	// REFUSED, not quietly accepted: a string nothing prints is a string
	// somebody mistyped, and reading it anyway would hide the mistake.
	if _, err := Parse("iamtunnel://" + gwAddr + "#" + fpr43 + "/alice"); err == nil {
		t.Error("the fingerprint-before-person order parsed — it is not a form this program ever prints, " +
			"and accepting it hides a mistyped string instead of naming it")
	}
}

// TestKindStringNamesEachForm: the refusals interpolate Kind, so a kind
// that stringified as "%!v(PANIC=…)" or as a bare number would land in the
// sentence a person reads.
func TestKindStringNamesEachForm(t *testing.T) {
	cases := []struct {
		k    Kind
		want string
	}{
		{Claim, "bootstrap claim string"},
		{Pair, "pairing reference"},
		{Enrol, "machine enrol code"},
		{Connect, "connection string"},
		{Unknown, "unknown string"},
		{Kind(42), "unknown string"},
	}
	for _, tc := range cases {
		if got := tc.k.String(); got != tc.want {
			t.Errorf("Kind(%d).String() = %q, want %q", int(tc.k), got, tc.want)
		}
	}
}

// TestAddrKeepsIPv6Bracketed: Addr feeds Preview and, in the caller, the
// dial address. An IPv6 gateway whose brackets were dropped would produce
// "2001:db8::1:2022" — an address that is neither wrong-looking nor
// dialable.
func TestAddrKeepsIPv6Bracketed(t *testing.T) {
	p, err := Parse("iamtunnel admin pair [2001:db8::1]:2222#" + fpr43 + " " + pin)
	if err != nil {
		t.Fatalf("Parse of the IPv6 pairing line: %v", err)
	}
	if got, w := p.Addr(), "[2001:db8::1]:2222"; got != w {
		t.Errorf("Addr() = %q, want %q", got, w)
	}
	if !strings.Contains(p.Preview(), "[2001:db8::1]:2222") {
		t.Errorf("Preview() = %q, want the bracketed address", p.Preview())
	}
}
