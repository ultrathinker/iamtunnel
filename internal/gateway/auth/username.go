package auth

import (
	"fmt"
	"regexp"
	"strings"
)

// nameRe is the SPEC 4.3 name rule: [a-z0-9][a-z0-9._-]{0,31}. Holding
// both person and machine names to it is what makes "ambiguous Unicode"
// impossible: anything outside this ASCII class is refused outright.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

// ParsedName is a username split into its parts. Machine is empty when
// the user asked for their own menu (SPEC 5.1: "<person>" for admin and
// client commands, "<person>:<machine>" for a session).
type ParsedName struct {
	Person  string
	Machine string
}

// ParseUsername splits an SSH username into (person, machine) and
// enforces the strict 7-step priority order of refusals from PROTOCOL §1.28
// evaluated on raw bytes before any UTF-8 decoding:
//
//	(1) ASCII control byte (0x00–0x1F, 0x7F) -> E_USERNAME_CONTROL
//	(2) Byte >= 0x80 -> E_USERNAME_NON_ASCII
//	(3) More than one colon -> E_USERNAME_COLON
//	(4) Exactly one colon with empty part, or empty string -> E_USERNAME_EMPTY_PART
//	(5) Part longer than 32 bytes -> E_USERNAME_LENGTH
//	(6) Bare reserved literal ("machine") -> E_NAME_RESERVED
//	(7) Everything else not matching ABNF grammar -> E_USERNAME_GRAMMAR
func ParseUsername(s string) (ParsedName, error) {
	// (1) ASCII control byte 0x00–0x1F or 0x7F -> E_USERNAME_CONTROL
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b <= 0x1f || b == 0x7f {
			return ParsedName{}, &UsernameError{
				Code:    CodeUsernameControl,
				Message: fmt.Sprintf("ASCII control byte 0x%02x is forbidden (PROTOCOL §2.1)", b),
			}
		}
	}

	// (2) Any byte >= 0x80 -> E_USERNAME_NON_ASCII
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 0x80 {
			return ParsedName{}, &UsernameError{
				Code:    CodeUsernameNonASCII,
				Message: fmt.Sprintf("non-ASCII byte 0x%02x is forbidden (PROTOCOL §2.1)", b),
			}
		}
	}

	// (3) More than one colon -> E_USERNAME_COLON
	colonCount := strings.Count(s, ":")
	if colonCount > 1 {
		return ParsedName{}, &UsernameError{
			Code:    CodeUsernameColon,
			Message: fmt.Sprintf("username %q has more than one colon (PROTOCOL §2.1)", s),
		}
	}

	// (4) Exactly one colon with empty part, or empty string -> E_USERNAME_EMPTY_PART
	if s == "" {
		return ParsedName{}, &UsernameError{
			Code:    CodeUsernameEmptyPart,
			Message: "empty username (PROTOCOL §2.1)",
		}
	}
	parts := strings.Split(s, ":")
	for _, p := range parts {
		if p == "" {
			return ParsedName{}, &UsernameError{
				Code:    CodeUsernameEmptyPart,
				Message: fmt.Sprintf("username %q has empty part (PROTOCOL §2.1)", s),
			}
		}
	}

	// (5) Part longer than 32 bytes -> E_USERNAME_LENGTH
	for _, p := range parts {
		if len(p) > 32 {
			return ParsedName{}, &UsernameError{
				Code:    CodeUsernameLength,
				Message: fmt.Sprintf("part %q exceeds 32 bytes limit (PROTOCOL §2.1)", p),
			}
		}
	}

	// (6) Bare reserved literal not enrol/bootstrap -> E_NAME_RESERVED
	if len(parts) == 1 && parts[0] == "machine" {
		return ParsedName{}, &UsernameError{
			Code:    CodeNameReserved,
			Message: fmt.Sprintf("literal %q is reserved by protocol and is not machine-login (PROTOCOL §2.1, §2.2)", parts[0]),
		}
	}

	// (7) Everything else not conforming to ABNF grammar -> E_USERNAME_GRAMMAR
	switch len(parts) {
	case 1:
		if !nameRe.MatchString(parts[0]) {
			return ParsedName{}, &UsernameError{
				Code:    CodeUsernameGrammar,
				Message: fmt.Sprintf("invalid person name %q (want [a-z0-9][a-z0-9._-]{0,31})", parts[0]),
			}
		}
		if parts[0] == "enrol" || parts[0] == "bootstrap" {
			return ParsedName{}, &UsernameError{
				Code:    CodeUsernameGrammar,
				Message: fmt.Sprintf("person name %q is reserved (SPEC §2.1, PROTOCOL §2.1)", parts[0]),
			}
		}
		return ParsedName{Person: parts[0]}, nil
	case 2:
		if !nameRe.MatchString(parts[0]) {
			return ParsedName{}, &UsernameError{
				Code:    CodeUsernameGrammar,
				Message: fmt.Sprintf("invalid person name %q (want [a-z0-9][a-z0-9._-]{0,31})", parts[0]),
			}
		}
		if parts[0] == "machine" || parts[0] == "enrol" || parts[0] == "bootstrap" {
			return ParsedName{}, &UsernameError{
				Code:    CodeUsernameGrammar,
				Message: fmt.Sprintf("person name %q is reserved (SPEC §2.1, PROTOCOL §2.1)", parts[0]),
			}
		}
		if !nameRe.MatchString(parts[1]) {
			return ParsedName{}, &UsernameError{
				Code:    CodeUsernameGrammar,
				Message: fmt.Sprintf("invalid machine name %q (want [a-z0-9][a-z0-9._-]{0,31})", parts[1]),
			}
		}
		return ParsedName{Person: parts[0], Machine: parts[1]}, nil
	default:
		return ParsedName{}, &UsernameError{
			Code:    CodeUsernameGrammar,
			Message: fmt.Sprintf("invalid username grammar %q", s),
		}
	}
}

func validName(s, what string) error {
	if !nameRe.MatchString(s) {
		return fmt.Errorf("auth: invalid %s name %q (want [a-z0-9][a-z0-9._-]{0,31})", what, s)
	}
	if what == "person" && (s == "machine" || s == "enrol" || s == "bootstrap") {
		return fmt.Errorf("auth: person name %q is reserved (SPEC §2.1, PROTOCOL §2.1)", s)
	}
	return nil
}

// MachineUsername is the username a machine uses to open its tunnel
// (SPEC 5.2): "machine:<id>".
func MachineUsername(id string) (string, error) {
	if err := validName(id, "machine"); err != nil {
		return "", err
	}
	return "machine:" + id, nil
}

// ParseMachineUsername accepts exactly "machine:<id>" and nothing else.
func ParseMachineUsername(s string) (string, error) {
	rest, ok := strings.CutPrefix(s, "machine:")
	if !ok {
		return "", fmt.Errorf("auth: username %q is not a machine login", s)
	}
	if err := validName(rest, "machine"); err != nil {
		return "", err
	}
	return rest, nil
}
