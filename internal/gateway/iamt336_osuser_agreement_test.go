package gateway

// iamt336_osuser_agreement_test.go — the two osUser validators must
// answer the same question the same way.
//
// There are two, and there have to be: state.ValidateOSUser guards what
// may enter state.json, on the gateway, for either platform; and
// config.ValidateOSUser is the per-machine gate that additionally
// decides which of the two shapes the LOCAL operating system accepts.
// The cross-platform half of the second is config.ValidOSUser, and the
// whole of the first is meant to be exactly that — its doc comment has
// said "matching ValidOSUser in internal/config" since it was written.
//
// It did not match. The state-side Windows branch checked one backslash
// and two non-empty halves and nothing else, while the config side
// enforced a character set and 64 bytes per half. The comment described
// the check nobody had written, so nothing ever went red, and the gap
// sat there harmlessly for as long as the value came from an
// administrator typing it into `machines.enrol-code`.
//
// 1.3 moved that field to the enrolling machine's own report (SPEC
// §3.4), and the enrolling machine is whoever holds an invitation. The
// gap stopped being a documentation defect the moment a stranger could
// reach it: a 200 kB "MACHINE\bbbb…" passed the state-side check and
// went into state.json to stay.
//
// The fix was to make the state side do what its comment promised. This
// test is what keeps them from drifting apart again — the thing the
// comment alone failed to do.

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestIAMT336_TheTwoOSUserValidatorsAgree walks the cases that separate
// them. Each row is a value and whether BOTH validators must accept it;
// a row where they disagree is the defect, whichever way round.
//
// Canary: remove the character-set loop from state.ValidateOSUser's
// Windows branch and the "a space" and "a 200 kB half" rows go red,
// naming state as the lenient one.
func TestIAMT336_TheTwoOSUserValidatorsAgree(t *testing.T) {
	long := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = 'b'
		}
		return string(b)
	}

	for _, row := range []struct {
		name  string
		user  string
		valid bool
	}{
		{"the principal from the live run", `DESKTOP-I3FL2S5\Admin`, true},
		{"a service account", `MACHINE\svc`, true},
		{"a domain account with a dot", `corp.example\first.last`, true},
		{"a machine account", `CORP\WIN-SRV01$`, true},
		{"a UPN-ish name", `CORP\alice@corp.example`, true},
		{"a POSIX local name", "iamtunnel", true},
		{"the longest halves the rule allows", long(64) + `\` + long(64), true},

		{"empty", "", false},
		{"two backslashes", `A\B\C`, false},
		{"an empty domain", `\alice`, false},
		{"an empty name", `CORP\`, false},
		{"a space in the name", `CORP\first last`, false},
		{"a comma in the name", `CORP\alice,admin`, false},
		{"a non-ASCII name", "CORP\\\u0430\u043b\u0438\u0441\u0430", false},
		{"a newline in the name", "CORP\\alice\nbob", false},
		{"a half one byte over", `CORP\` + long(65), false},
		{"the flood an invitation holder could send", `MACHINE\` + long(200000), false},
		{"a POSIX name one byte over", long(33), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			stateOK := state.ValidateOSUser(row.user) == nil
			configOK := config.ValidOSUser(row.user)

			if stateOK != configOK {
				lenient, strict := "config", "state"
				if stateOK {
					lenient, strict = "state", "config"
				}
				t.Fatalf("the two validators disagree: %s accepts this osUser and %s refuses it. They guard the same field — one what may enter state.json, the other what a machine may be asked to log in as — and a value only one of them likes is a value that gets written and then cannot be used.", lenient, strict)
			}
			if stateOK != row.valid {
				verb := "accepted"
				if !stateOK {
					verb = "refused"
				}
				t.Errorf("both validators %s it; want valid=%v", verb, row.valid)
			}
		})
	}
}
