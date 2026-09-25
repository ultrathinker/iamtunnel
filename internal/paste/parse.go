package paste

import (
	"fmt"
	"strings"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// Kind is what the pasted string turned out to be.
type Kind int

const (
	// Unknown is the zero value: nothing was parsed.
	Unknown Kind = iota
	// Claim is the bootstrap string of SPEC §3.3 — the key that pastes
	// it becomes the key of the FIRST administrator.
	Claim
	// Pair is the pairing reference plus PIN of SPEC §3.3 — the key
	// that pastes it becomes the key of one more administrator.
	Pair
	// Enrol is the machine invitation of SPEC §3.4.
	Enrol
	// Connect is the person's connection string of SPEC §3.1.
	Connect
)

// String names the kind the way the refusals talk about it.
func (k Kind) String() string {
	switch k {
	case Claim:
		return "bootstrap claim string"
	case Pair:
		return "pairing reference"
	case Enrol:
		return "machine enrol code"
	case Connect:
		return "connection string"
	default:
		return "unknown string"
	}
}

// Parsed is what one paste amounts to. Secret carries the bootstrap
// token (Claim), the six-digit PIN (Pair) or the enrol secret (Enrol),
// and is empty for Connect; Person is set only for Connect.
type Parsed struct {
	Kind        Kind
	Host        string
	Port        int
	Fingerprint string // canonical "SHA256:…" form
	Secret      string
	Person      string
}

// pinDigits is the length of a pairing PIN (SPEC §3.3: six decimal
// digits, leading zeros significant — it is a code, not a number).
const pinDigits = 6

// scheme prefixes of the four canonical forms (SPEC §3.6). Matching is
// case-insensitive, as it already is in internal/config.
const (
	schemeClaim   = "iamtunnel-claim://"
	schemePair    = "iamtunnel-pair://"
	schemeEnrol   = "iamtunnel-enrol://"
	schemeConnect = "iamtunnel://"
)

// exampleLine is the shape quoted back at a person who pasted nothing
// usable: the line the gateway actually prints.
const exampleLine = "iamtunnel admin pair gw.example.com:2222#<fingerprint> 012345"

// refusef builds the refusal. It is a config.Error of the user class so
// that a refusal from this field and the same refusal from a command
// argument leave the process with the same exit code (internal/config
// "errors.go": class 2 is "the invocation or a value is wrong").
func refusef(format string, a ...any) error {
	return &config.Error{Class: config.ClassUser, Msg: fmt.Sprintf(format, a...)}
}

// Parse reads one paste and says what it is.
//
// Accepted, all from SPEC §3.6: the four canonical strings; the whole
// command line the gateway prints around them ("iamtunnel admin pair
// <ref> <pin>", "iamtunnel admin claim <ref>", "iamtunnel enrol
// <code>"); a bare "<host>:<port>#<fingerprint>" reference with the PIN
// after it; and any of those wrapped in quotes, indented, followed by a
// newline, or preceded by the sentence the gateway printed above the
// command ("On the new admin's machine run:").
//
// What it never does is guess: a string it cannot place is refused with
// what was wrong and what the wanted shape looks like, never with a
// bare code. The live run of 17.09 is the reason the wrappers are here
// at all — the gateway printed a ready command line, the person copied
// it whole, and the field answered a refusal while the two-minute
// pairing window burned.
func Parse(input string) (Parsed, error) {
	toks, err := tokenize(input)
	if err != nil {
		return Parsed{}, err
	}
	want, args, err := stripCommand(toks)
	if err != nil {
		return Parsed{}, err
	}
	return parseValue(want, args)
}

// tokenize turns the raw paste into the words that carry meaning: the
// interesting line, without quotes, without the trailing flags of a
// command line.
func tokenize(input string) ([]string, error) {
	s := strings.TrimPrefix(input, "\ufeff") // a BOM rides along from some editors
	line, err := interestingLine(s)
	if err != nil {
		return nil, err
	}
	line = unquote(line)
	fields := strings.Fields(line)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		// Everything from the first flag on belongs to the command, not
		// to the string: "admin claim <ref> --key C:\path\id.pub" is a
		// line a person may well copy whole, and this field makes its
		// own key. No value of ours ever starts with '-'.
		if strings.HasPrefix(f, "-") {
			break
		}
		if u := unquote(f); u != "" {
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil, refusef("nothing was pasted — paste the whole line the gateway printed, for example %q.", exampleLine)
	}
	return out, nil
}

// interestingLine picks the one line that carries the string. The
// gateway prints the command under a sentence ("On the new admin's
// machine run:"), and a person copying "the thing that was printed"
// takes both lines; a line that carries neither the program name nor a
// '#' nor a scheme is prose, not a value.
func interestingLine(s string) (string, error) {
	var candidates []string
	sawAny := false
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" {
			continue
		}
		sawAny = true
		if looksLikeValue(line) {
			candidates = append(candidates, line)
		}
	}
	if len(candidates) == 0 {
		if !sawAny {
			return "", refusef("nothing was pasted — paste the whole line the gateway printed, for example %q.", exampleLine)
		}
		return "", refusef("nothing in the pasted text looks like a gateway string — a string this field takes either starts with %q or has the shape %q; copy the line the gateway printed, not the words around it.", "iamtunnel", "<host>:<port>#<fingerprint>")
	}
	return candidates[0], nil
}

// looksLikeValue reports whether a line could carry a value at all.
func looksLikeValue(line string) bool {
	l := strings.ToLower(unquote(line))
	return strings.HasPrefix(l, "iamtunnel") || strings.Contains(l, "#") || strings.Contains(l, "://")
}

// unquote strips matching surrounding quotes. RUNBOOK §1.4.1 prints the
// pairing line with the reference quoted, chat clients turn "…" into the
// typographic pair, and PowerShell keeps the single quote.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 {
		first, last := s[:1], s[len(s)-1:]
		switch {
		case (first == "\"" && last == "\"") ||
			(first == "'" && last == "'") ||
			(first == "`" && last == "`"):
			s = strings.TrimSpace(s[1 : len(s)-1])
		case strings.HasPrefix(s, "\u201c") && strings.HasSuffix(s, "\u201d"):
			s = strings.TrimSpace(s[len("\u201c") : len(s)-len("\u201d")])
		case strings.HasPrefix(s, "\u2018") && strings.HasSuffix(s, "\u2019"):
			s = strings.TrimSpace(s[len("\u2018") : len(s)-len("\u2019")])
		default:
			return s
		}
	}
	return s
}

// stripCommand removes the "iamtunnel …" command wrapper and reports
// which kind that command asked for (Unknown when the paste is the bare
// string). The command is only ever a hint: the string itself decides,
// and a disagreement between the two is a refusal, not a silent pick.
func stripCommand(toks []string) (Kind, []string, error) {
	head := strings.TrimSuffix(strings.ToLower(toks[0]), ".exe")
	if head != "iamtunnel" {
		return Unknown, toks, nil
	}
	rest := toks[1:]
	if len(rest) == 0 {
		return Unknown, nil, refusef("the pasted line is just the program name — paste the whole line, the command and the string it was printed with, for example %q.", exampleLine)
	}
	switch strings.ToLower(rest[0]) {
	case "admin":
		if len(rest) == 1 {
			return Unknown, nil, refusef("%q has no string after it — this field takes %q or %q, or the string on its own.", "iamtunnel admin", "iamtunnel admin pair <reference> <pin>", "iamtunnel admin claim <string>")
		}
		switch strings.ToLower(rest[1]) {
		case "pair":
			return Pair, rest[2:], nil
		case "claim":
			return Claim, rest[2:], nil
		default:
			return Unknown, nil, unknownCommand("iamtunnel admin " + rest[1])
		}
	case "enrol", "enroll":
		return Enrol, rest[1:], nil
	default:
		return Unknown, nil, unknownCommand("iamtunnel " + rest[0])
	}
}

// unknownCommand is the refusal for a command line this field does not
// perform. It names the three it does.
func unknownCommand(got string) error {
	return refusef("%q is not a command this field understands — it takes %q, %q, %q, or the string on its own.", got, "iamtunnel admin pair", "iamtunnel admin claim", "iamtunnel enrol")
}

// parseValue turns the value words into a Parsed, using want (the kind
// the command line asked for, if there was one) only to disambiguate
// and to catch a paste that contradicts its own command.
func parseValue(want Kind, args []string) (Parsed, error) {
	if len(args) == 0 {
		if want != Unknown {
			return Parsed{}, refusef("the command was pasted without its %s — copy the whole line, the command and the string together.", want)
		}
		return Parsed{}, refusef("nothing was pasted — paste the whole line the gateway printed, for example %q.", exampleLine)
	}
	if len(args) > 2 {
		return Parsed{}, refusef("the paste carries %d values (%q) — a line this field takes has the string and, for pairing, the PIN next to it; copy one line, not several.", len(args), strings.Join(args, " "))
	}
	value, extra := args[0], args[1:]

	got, body, err := classify(value)
	if err != nil {
		return Parsed{}, err
	}
	if got == Unknown {
		if got, err = inferBare(value, want, len(extra) == 1); err != nil {
			return Parsed{}, err
		}
	} else if want != Unknown && want != got {
		return Parsed{}, refusef("the pasted line says %q but the string after it is a %s — the two disagree, so nothing was done; paste the line that belongs to the action you meant.", commandOf(want), got)
	}

	switch got {
	case Claim:
		return parseClaim(body, extra)
	case Pair:
		return parsePair(body, extra)
	case Enrol:
		return parseEnrol(value, body, extra)
	case Connect:
		return parseConnect(value, extra)
	default:
		// Unreachable: classify and inferBare between them return one of
		// the four kinds or a refusal. Kept as a refusal rather than a
		// panic — a field must never take the process down.
		return Parsed{}, refusef("the pasted string %q could not be placed — it is none of the four strings this field takes.", value)
	}
}

// commandOf names the command line a kind is printed with.
func commandOf(k Kind) string {
	switch k {
	case Claim:
		return "iamtunnel admin claim"
	case Pair:
		return "iamtunnel admin pair"
	case Enrol:
		return "iamtunnel enrol"
	default:
		return "iamtunnel"
	}
}

// classify reads the scheme. It returns the kind and the body with the
// scheme removed (for Enrol and Connect the body is unused — their
// parsers in internal/config want the whole string, scheme included).
func classify(value string) (Kind, string, error) {
	switch {
	case hasSchemeFold(value, schemeClaim):
		return Claim, value[len(schemeClaim):], nil
	case hasSchemeFold(value, schemePair):
		return Pair, value[len(schemePair):], nil
	case hasSchemeFold(value, schemeEnrol):
		return Enrol, value[len(schemeEnrol):], nil
	case hasSchemeFold(value, schemeConnect):
		return Connect, value[len(schemeConnect):], nil
	case strings.Contains(value, "://"):
		scheme := value[:strings.Index(value, "://")+len("://")]
		return Unknown, "", refusef("%q is not a scheme this field knows — the strings it takes start with %q, %q, %q or %q, or are the bare %q reference.", scheme, schemeClaim, schemePair, schemeEnrol, schemeConnect, "<host>:<port>#<fingerprint>")
	}
	return Unknown, value, nil
}

func hasSchemeFold(s, scheme string) bool {
	return len(s) >= len(scheme) && strings.EqualFold(s[:len(scheme)], scheme)
}

// inferBare decides what a scheme-less "<host>:<port>#…" string is. A
// fingerprint part that carries a ':' carries a token with it, and that
// is the claim shape; a bare reference is a pairing reference, whose
// secret is the PIN standing next to it.
func inferBare(value string, want Kind, havePin bool) (Kind, error) {
	if want != Unknown {
		return want, nil
	}
	i := strings.Index(value, "#")
	if i < 0 {
		return Unknown, refusef("%q is not a string this field takes — there is no %q in it and so no fingerprint; the shapes are %q, %q, and the strings that start with %q.", value, "#", "<host>:<port>#<fingerprint> <pin>", "<host>:<port>#<fingerprint>:<token>", "iamtunnel")
	}
	fp := strings.TrimPrefix(value[i+1:], "SHA256:")
	if strings.Contains(fp, ":") {
		return Claim, nil
	}
	if !havePin {
		// Before saying "the PIN is missing", make sure the thing in
		// hand really is a reference: a word with a '#' in it and no
		// port is a mistyped string, and telling that person about the
		// PIN would send them looking in the wrong place. The shape
		// check is the §3.4 parser's, not a second one written here.
		if _, err := config.ParsePairingRef(value); err != nil {
			return Unknown, err
		}
		return Unknown, refusef("%q is a pairing reference with no PIN next to it — the gateway prints the reference and a %d-digit PIN on the same line; paste the whole line.", value, pinDigits)
	}
	return Pair, nil
}

// parseClaim hands the body to the one §3.3 parser there is.
func parseClaim(body string, extra []string) (Parsed, error) {
	if len(extra) == 1 {
		return Parsed{}, refusef("a bootstrap string already carries its own token, so the extra value %q next to it has no meaning — paste the string alone, or the whole %q line.", extra[0], "iamtunnel admin claim <string>")
	}
	ref, err := config.ParseClaimRef(body)
	if err != nil {
		return Parsed{}, err
	}
	return Parsed{Kind: Claim, Host: ref.Host, Port: ref.Port, Fingerprint: ref.Fingerprint, Secret: ref.Token}, nil
}

// parsePair takes the reference and the PIN, wherever the PIN was: after
// the fingerprint inside the one-string form, or as the word next to the
// reference on the command line the gateway prints.
func parsePair(body string, extra []string) (Parsed, error) {
	refPart, embedded := body, ""
	if i := strings.Index(body, "#"); i >= 0 {
		hostport := body[:i]
		fp := strings.TrimPrefix(body[i+1:], "SHA256:")
		if j := strings.Index(fp, ":"); j >= 0 {
			embedded = fp[j+1:]
			fp = fp[:j]
		}
		refPart = hostport + "#" + fp
	}
	pin := embedded
	if len(extra) == 1 {
		if embedded != "" && embedded != extra[0] {
			return Parsed{}, refusef("the pasted string carries the PIN %q and the line ends with %q — the two disagree, so nothing was done; paste one line, the one the gateway printed.", embedded, extra[0])
		}
		pin = extra[0]
	}
	ref, err := config.ParsePairingRef(refPart)
	if err != nil {
		return Parsed{}, err
	}
	if pin == "" {
		return Parsed{}, refusef("the pairing reference came without a PIN — the gateway prints the reference and a %d-digit PIN on the same line (%q); paste the whole line.", pinDigits, "iamtunnel admin pair <reference> <pin>")
	}
	if err := checkPIN(pin); err != nil {
		return Parsed{}, err
	}
	return Parsed{Kind: Pair, Host: ref.Host, Port: ref.Port, Fingerprint: ref.Fingerprint, Secret: pin}, nil
}

// checkPIN enforces the §3.3 shape: exactly six decimal digits, leading
// zeros significant. It is a code, not a number, so "012345" is a PIN
// and "12345" is not the same PIN with a zero dropped.
func checkPIN(pin string) error {
	if len(pin) != pinDigits {
		return refusef("the pairing PIN must be exactly %d decimal digits and %q is %d — leading zeros are part of the PIN (%q is a PIN, %q is not the same thing), so copy it exactly as the gateway printed it.", pinDigits, pin, len(pin), "012345", "12345")
	}
	for i := 0; i < len(pin); i++ {
		if pin[i] < '0' || pin[i] > '9' {
			return refusef("the pairing PIN must be %d decimal digits and %q is not — copy it exactly as the gateway printed it, digits only.", pinDigits, pin)
		}
	}
	return nil
}

// parseEnrol hands the string to the one §3.4 parser there is. A bare
// "<host>:<port>#<fingerprint>:<secret>" (the scheme rubbed off in a
// chat client, or the operator retyped the parts) gets the scheme put
// back on rather than a second grammar written for it here.
func parseEnrol(value, body string, extra []string) (Parsed, error) {
	if len(extra) == 1 {
		return Parsed{}, refusef("an enrol code already carries its own secret, so the extra value %q next to it has no meaning — paste the code alone, or the whole %q line.", extra[0], "iamtunnel enrol <code>")
	}
	if !hasSchemeFold(value, schemeEnrol) {
		value = schemeEnrol + body
	}
	code, err := config.ParseEnrolCode(value)
	if err != nil {
		return Parsed{}, err
	}
	return Parsed{Kind: Enrol, Host: code.Host, Port: code.Port, Fingerprint: code.Fingerprint, Secret: code.Secret}, nil
}

// parseConnect hands the string to the one §3.1 parser there is.
func parseConnect(value string, extra []string) (Parsed, error) {
	if len(extra) == 1 {
		return Parsed{}, refusef("a connection string carries everything it needs, so the extra value %q next to it has no meaning — paste the string alone.", extra[0])
	}
	cs, err := config.ParseConnString(value)
	if err != nil {
		return Parsed{}, err
	}
	return Parsed{Kind: Connect, Host: cs.Host, Port: cs.Port, Fingerprint: cs.Fingerprint, Person: cs.Person}, nil
}

// Addr is the gateway address the paste points at, "<host>:<port>". An
// IPv6 host arrives already bracketed from internal/config.
func (p Parsed) Addr() string {
	return fmt.Sprintf("%s:%d", p.Host, p.Port)
}

// Preview is the sentence shown under the field before the button does
// anything (SPEC §3.6: "preview is mandatory"). It names the action,
// the gateway address and the fingerprint — the fingerprint in full,
// because this is the one moment a person checks it with their eyes:
// there is no TOFU in any role (§6.2), so an abbreviated fingerprint
// here would be a fingerprint nobody ever compares.
func (p Parsed) Preview() string {
	switch p.Kind {
	case Claim:
		return fmt.Sprintf("This will make THIS machine the first administrator of %s, host key %s.", p.Addr(), p.Fingerprint)
	case Pair:
		return fmt.Sprintf("This will make THIS machine an administrator of %s, host key %s.", p.Addr(), p.Fingerprint)
	case Enrol:
		return fmt.Sprintf("This will register THIS machine with the gateway at %s, host key %s.", p.Addr(), p.Fingerprint)
	case Connect:
		return fmt.Sprintf("This will save the connection to %s as %q, host key %s.", p.Addr(), p.Person, p.Fingerprint)
	default:
		return "Nothing is pasted yet — this field takes the one string the gateway printed."
	}
}
