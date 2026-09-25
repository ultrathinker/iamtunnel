package auth

// iamt328_username_pairing_test.go — IAMT-323/IAMT-328:
//
//   "Every row of the §2.2 table is a separate unit test" (PROTOCOL §2.2).
//
// The pairing window (PROTOCOL §3.4) added two rows to the §2.2 refusal
// table, and both of them make claims about the PARSER that must stay true
// for the surrounding design to hold:
//
//   | `pairing`       | accepted as `pairing-login` (§3.4): the byte-exact match
//                     is intercepted at the SSH layer before the parser |
//   | `pairing:win01` | accepted by the grammar as `human-login`; a person
//                     named `pairing` cannot exist (`E_PERSON_NAME_RESERVED`),
//                     so the login is rejected by key lookup as unknown |
//
// The first row is why these tests assert SUCCESS: gateway.go routes the
// byte-exact username "pairing" to the pairing role before ParseUsername
// ever runs (PROTOCOL §2.1), so the parser itself must keep treating the
// bytes as an ordinary grammar-valid person name. A parser "hardening" that
// rejected "pairing" would not break the pairing role (it never reaches the
// parser) — but it would make §2.2 describe a grammar nobody implements,
// and a person genuinely named "pairing" impossible to even parse while
// auth.go's own ErrNameMismatch messages name that login.

import "testing"

func TestParseUsername_PairingLoginIsGrammarValidAsPerson(t *testing.T) {
	got, err := ParseUsername("pairing")
	if err != nil {
		t.Fatalf("ParseUsername(\"pairing\"): %v — the exact bytes are intercepted on the SSH layer before the parser (§2.1), so the grammar must keep accepting them as a person name", err)
	}
	if got.Person != "pairing" || got.Machine != "" {
		t.Fatalf("ParseUsername(\"pairing\") = %+v, want person=%q machine=%q", got, "pairing", "")
	}
}

func TestParseUsername_PairingColonMachineIsAHumanLogin(t *testing.T) {
	got, err := ParseUsername("pairing:win01")
	if err != nil {
		t.Fatalf("ParseUsername(\"pairing:win01\"): %v — §2.2 promises the grammar accepts it as a human-login; the refusal comes later, from key lookup (the person cannot exist)", err)
	}
	if got.Person != "pairing" || got.Machine != "win01" {
		t.Fatalf("ParseUsername(\"pairing:win01\") = %+v, want person=%q machine=%q", got, "pairing", "win01")
	}
}
