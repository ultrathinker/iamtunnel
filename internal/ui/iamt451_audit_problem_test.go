//go:build windows || linux || darwin

package ui

// IAMT-451: while the gateway's audit journal is not being written it
// refuses every change. The window says so where the person looks first -
// the poster of the tab - instead of letting each press fail on its own.

import (
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

func TestIAMT451_TheGatewayTabSaysTheAuditJournalIsNotWritten(t *testing.T) {
	g := GatewayState{Supported: true, Installed: true, Running: true, AuditKnown: true,
		AuditProblem: "the audit journal is NOT being written (since 2026-09-23T18:00:00Z): no space left on device"}
	deck, _, key := gatewayHeadline(g)
	if key != design.WarnKey || !strings.Contains(deck, "audit journal") {
		t.Errorf("the Gateway tab of a running gateway whose journal is not written says %q (%v)", deck, key)
	}
	g.AuditProblem = ""
	if _, _, key := gatewayHeadline(g); key != design.GoodKey {
		t.Errorf("a running gateway whose journal is written is not good news any more: %v", key)
	}
}

func TestIAMT451_TheAdminTabSaysTheAuditJournalIsNotWritten(t *testing.T) {
	deck, _, key := adminPosterDeck(AdminState{AuditProblem: "the audit journal is NOT being written"})
	if key != design.BadKey || !strings.Contains(deck, "audit journal") {
		t.Errorf("the Admin tab of a gateway that refuses every change says %q (%v)", deck, key)
	}
	if deck, _, _ := adminPosterDeck(AdminState{}); strings.Contains(deck, "audit") {
		t.Errorf("the Admin tab talks about the audit journal when nothing is wrong with it: %q", deck)
	}
}
