package events

// r4_f06_chain_claim_test.go — R4 F-06.
//
// prev_hash is a bare SHA-256 with no key and no anchor outside the file:
// whoever can write events.jsonl can edit a line and recompute every hash
// after it, and VerifyChain says "intact". Against accidental damage and a
// hand edit the chain is real; against someone who can write the file it
// is not. The green "intact" on the Gateway tab and from `gateway
// verify-journal` must say which of the two it is, not leave the reader to
// assume the stronger one.

import (
	"strings"
	"testing"
)

func TestR4F06_AnIntactVerdictNamesWhatTheChainCannotCatch(t *testing.T) {
	for _, rep := range []ChainReport{
		{Files: 1, Lines: 3, Chained: 3},
		{Files: 1, Lines: 5, Chained: 3, Legacy: 2},
	} {
		s := rep.Summary()
		if !strings.HasPrefix(s, "intact") {
			t.Fatalf("fixture is not an intact report: %q", s)
		}
		if !strings.Contains(s, "cannot catch someone who can write the file") {
			t.Fatalf("R4 F-06: the intact verdict reads as tamper-proof but the hashes carry no key: %q", s)
		}
	}
}
