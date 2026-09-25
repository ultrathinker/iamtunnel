//go:build windows || linux || darwin

package ui

// IAMT-467: the Gateway tab says whether the journal's hash chain holds,
// and a broken one is the first thing it says.

import (
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

func TestIAMT467_TheGatewayTabSaysTheJournalChainIsBroken(t *testing.T) {
	g := GatewayState{Supported: true, Installed: true, Running: true,
		JournalKnown: true, JournalBroken: true, JournalChain: "BROKEN at events.jsonl line 4: prev_hash is not the hash of the line before"}
	deck, _, key := gatewayHeadline(g)
	if key != design.WarnKey || !strings.Contains(deck, "journal") {
		t.Errorf("the Gateway tab of a gateway whose journal chain is broken says %q (%v)", deck, key)
	}
	g.JournalBroken, g.JournalIntact = false, true
	if _, _, key := gatewayHeadline(g); key != design.GoodKey {
		t.Errorf("an intact journal is not good news any more: %v", key)
	}
}
