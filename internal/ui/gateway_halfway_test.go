//go:build windows || linux || darwin

package ui

import (
	"os"
	"strings"
	"testing"
)

// A half-made gateway must get the "finish it" button.
//
// 22.09.2026, a live check by the maintainer. The first click reached
// the very last step -- the service -- and failed there. But by that
// moment the installation had already written the host key, the
// one-time token and the state: it does those BEFORE touching the
// SCM. The screen called this "set up as a gateway" and offered
// exactly one action -- "stop being a gateway". The one thing it did
// not allow was finishing.
//
// Being half-done is the state that needs the button most, not a
// state that has outgrown it. The installation is idempotent and
// continues from where it stopped.
func TestCanary_HalfMadeGatewayCanBeFinished(t *testing.T) {
	src := readScreenSource(t)

	idxRunning := strings.Index(src, "case g.Running:")
	idxDefault := strings.Index(src, "\tdefault:")
	if idxRunning < 0 || idxDefault < 0 {
		t.Fatal("the screen no longer distinguishes a working gateway from a non-working one -- these are different states with different buttons")
	}
	if idxDefault < idxRunning {
		t.Fatal("the \"not working\" branch moved above the \"working\" branch -- the case order decides what a person sees")
	}
	tail := src[idxDefault:]
	if !strings.Contains(tail, "f.layoutGatewayInstallForm") {
		t.Error("the non-working gateway has no install form -- there is nothing to finish with, only to remove")
	}
}

// A first-administrator line that must not be PRINTED must not be
// declared spent.
//
// The same screen told the maintainer "Already claimed" on a gateway
// whose token nobody had touched: the line did not render because the
// gateway did not yet know its address, and the absence was read as
// "spent". Two different facts fused into one, and the screen chose
// the alarming of the two readings.
func TestCanary_UnrenderableClaimIsNotASpentClaim(t *testing.T) {
	pending := GatewayState{Supported: true, Installed: true, ClaimPending: true}
	spent := GatewayState{Supported: true, Installed: true, ClaimPending: false}

	whenPending := gatewayClaimAbsentText(pending)
	whenSpent := gatewayClaimAbsentText(spent)

	if whenPending == whenSpent {
		t.Fatal("an intact token and a spent one are described with the same words -- two different facts fused again")
	}
	if strings.Contains(strings.ToLower(whenPending), "already claimed") {
		t.Errorf("an untouched token is declared spent: %q", whenPending)
	}
	if !strings.Contains(strings.ToLower(whenSpent), "already claimed") {
		t.Errorf("a spent token is not called spent: %q", whenSpent)
	}
	// An intact token must say why it is not visible and what to do.
	if !strings.Contains(whenPending, "address") {
		t.Errorf("the explanation names neither the cause nor the way out: %q", whenPending)
	}
}

func readScreenSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("gateway_screen.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
