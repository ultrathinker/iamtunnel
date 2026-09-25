//go:build windows || linux || darwin

package ui

import "testing"

// Canary: the row of a stopped command names WHO stopped it.
//
// On 21.09.2026 the maintainer looked at the list and asked: "was it
// the AI or our internal stopper?". The reason was in the row, the
// culprit only in the details window. A hint is not a name, and this
// is the first thing a person wants to know, every time.
//
// Both kinds of initiator are checked, and the degenerate case with
// no rule.
func TestCanary_HeldRowNamesWhoStopped(t *testing.T) {
	cases := []struct{ rule, want string }{
		{"external-classifier", "AI classifier"},
		{"rm-rf-root", "rule rm-rf-root"},
		{"", "the gateway"},
	}
	for _, c := range cases {
		if got := heldDeciderShort(c.rule); got != c.want {
			t.Errorf("rule %q is named as %q, want %q -- a person will not know whether "+
				"to argue with the pattern or with the judgement", c.rule, got, c.want)
		}
	}
}
