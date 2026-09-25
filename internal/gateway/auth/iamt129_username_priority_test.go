package auth

// iamt129_username_priority_test.go — IAMT-129:
//
//   "Gate 14 is one-way: E_NAME_RESERVED is in the dictionary and is
//    produced by no one".
//
// docs/PROTOCOL.md §1.28:
//   "The refusal priority for an arbitrary login is fixed and evaluated
//    on the raw bytes before any UTF-8 decoding:
//    (1) any ASCII control byte 0x00–0x1F or 0x7F — E_USERNAME_CONTROL;
//    (2) any byte ≥ 0x80 — E_USERNAME_NON_ASCII;
//    (3) more than one : — E_USERNAME_COLON;
//    (4) exactly one : with an empty part, or an empty string — E_USERNAME_EMPTY_PART;
//    (5) a part longer than 32 bytes — E_USERNAME_LENGTH;
//    (6) a bare reserved literal that is not an exact enrol/bootstrap name — E_NAME_RESERVED;
//    (7) everything else that does not match the single ABNF form — E_USERNAME_GRAMMAR."

import (
	"strings"
	"testing"
)

// TestParseUsername_MachineReturnsNameReserved tests that bare reserved literal
// "machine" returns E_NAME_RESERVED (PROTOCOL §2.1, §2.2).
//
// Canary 2:
//
//	In internal/gateway/auth/username.go, change CodeNameReserved to CodeUsernameGrammar
//	or remove step 6.
//	The test will fail on line:
//	  t.Fatalf("ParseUsername(\"machine\") returned code %q, want %q", ErrorDenyCode(err), CodeNameReserved)
func TestParseUsername_MachineReturnsNameReserved(t *testing.T) {
	_, err := ParseUsername("machine")
	if err == nil {
		t.Fatalf("ParseUsername(\"machine\") succeeded, want error")
	}
	if got := ErrorDenyCode(err); got != CodeNameReserved {
		t.Fatalf("ParseUsername(\"machine\") returned code %q, want %q", got, CodeNameReserved)
	}
}

// TestUsernamePriority_FollowsProtocolSevenSteps tests that when an input violates
// multiple rules at once, the earlier step in the 7-step priority order always wins.
//
// Canary 1:
//
//	In internal/gateway/auth/username.go, move step 1 (control byte) below step 3 (colons).
//	The test will fail on line:
//	  t.Fatalf("input %q: got code %q, want earlier priority %q", tc.in, got, tc.wantCode)
func TestUsernamePriority_FollowsProtocolSevenSteps(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantCode DenyCode
	}{
		{
			name:     "step 1 beats step 3: control byte + multiple colons",
			in:       "\x01:win:extra",
			wantCode: CodeUsernameControl,
		},
		{
			name:     "step 1 beats step 2: control byte + non-ASCII byte",
			in:       "\x01\x80",
			wantCode: CodeUsernameControl,
		},
		{
			name:     "step 2 beats step 3: non-ASCII + multiple colons",
			in:       "\x80:win:extra",
			wantCode: CodeUsernameNonASCII,
		},
		{
			name:     "step 2 beats step 5: non-ASCII + length > 32",
			in:       "\x80" + strings.Repeat("a", 35),
			wantCode: CodeUsernameNonASCII,
		},
		{
			name:     "step 3 beats step 4: multiple colons + empty part",
			in:       "alice::win",
			wantCode: CodeUsernameColon,
		},
		{
			name:     "step 3 beats step 5: multiple colons + length > 32",
			in:       strings.Repeat("a", 35) + ":win:extra",
			wantCode: CodeUsernameColon,
		},
		{
			name:     "step 4 beats step 5: empty part + length > 32 (real conflict)",
			in:       ":" + strings.Repeat("a", 35),
			wantCode: CodeUsernameEmptyPart,
		},
		{
			name:     "step 4 empty string",
			in:       "",
			wantCode: CodeUsernameEmptyPart,
		},
		{
			name:     "step 5 beats step 7: length > 32 with invalid characters",
			in:       strings.Repeat("A", 35), // uppercase + length > 32
			wantCode: CodeUsernameLength,
		},
		{
			name:     "step 6: bare reserved literal machine",
			in:       "machine",
			wantCode: CodeNameReserved,
		},
		{
			name:     "step 7: enrol with machine suffix",
			in:       "enrol:win01",
			wantCode: CodeUsernameGrammar,
		},
		{
			name:     "step 7: bootstrap with machine suffix",
			in:       "bootstrap:win01",
			wantCode: CodeUsernameGrammar,
		},
		{
			name:     "step 7: uppercase in name",
			in:       "Anna:win01",
			wantCode: CodeUsernameGrammar,
		},
		{
			name:     "step 7: space in name",
			in:       "anna:win 01",
			wantCode: CodeUsernameGrammar,
		},
		{
			name:     "step 7: leading hyphen",
			in:       "-anna:win01",
			wantCode: CodeUsernameGrammar,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseUsername(tc.in)
			if err == nil {
				t.Fatalf("input %q: succeeded, want error %s", tc.in, tc.wantCode)
			}
			got := ErrorDenyCode(err)
			if got != tc.wantCode {
				t.Fatalf("input %q: got code %q, want earlier priority %q", tc.in, got, tc.wantCode)
			}
		})
	}
}
