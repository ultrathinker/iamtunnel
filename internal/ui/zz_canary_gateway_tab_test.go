//go:build windows || linux || darwin

package ui

import (
	"os"
	"strings"
	"testing"
)

// "Could not read" is never drawn as "not a gateway".
//
// 22.09.2026. This is the third pass at the same class (IAMT-311 and
// two repeats): the unknown, rendered as false -- a screen confidently
// saying "no". The price here is above the usual: a person told "this
// computer is not a gateway" will press "make it a gateway" on a
// machine where a gateway is already installed and running.
func TestCanary_GatewayUnknownIsNotNo(t *testing.T) {
	unknown := GatewayState{Supported: true, Unknown: true}
	notAGateway := GatewayState{Supported: true}

	if gatewayStateWord(unknown) == gatewayStateWord(notAGateway) {
		t.Errorf("\"could not read\" and \"not a gateway\" produce one word %q -- on screen that is one and the same statement",
			gatewayStateWord(unknown))
	}
	if gatewayStateKey(unknown) == gatewayStateKey(notAGateway) {
		t.Error("\"could not read\" and \"not a gateway\" share one colour -- the difference is visible only in the words, and it must be visible out of the corner of the eye")
	}
	deckUnknown, _, _ := gatewayHeadline(unknown)
	deckNo, _, _ := gatewayHeadline(notAGateway)
	if deckUnknown == deckNo {
		t.Errorf("the headline is the same in both cases: %q", deckUnknown)
	}
	// And separately: "installed but not answering" is its own answer,
	// not a variety of running.
	stopped := GatewayState{Supported: true, Installed: true}
	if gatewayStateWord(stopped) == gatewayStateWord(GatewayState{Supported: true, Installed: true, Running: true}) {
		t.Error("a stopped gateway is indistinguishable from a running one")
	}
}

// Canary: the window does NOT keep its own copy of "install gateway".
//
// Installing a gateway is an ACL on the data directory, a service
// under an account able to read the binary, the host key and a
// one-time token. A second implementation of that would be a second
// artefact to keep true, and the half that gets pressed less often
// falls behind first: it is the last to learn about a new privileged
// step and the first to start lying about what it did.
//
// So the window's actions must call the same functions the CLI verb
// does.
func TestCanary_GatewayTabRunsTheRealCommands(t *testing.T) {
	src, err := os.ReadFile("../../cmd/iamtunnel/gui_gateway.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, want := range []string{"runGatewayInstall(", "cmdGatewayStatus(", "cmdGatewayUninstall("} {
		if !strings.Contains(text, want) {
			t.Errorf("the window no longer calls %s -- a second implementation of gateway install has appeared somewhere", want)
		}
	}
	// Signs of an own implementation: the window pokes at services or
	// writes the host key itself.
	for _, bad := range []string{"setupGatewayService(", "teardownGatewayService(", "GenerateKey("} {
		if strings.Contains(text, bad) {
			t.Errorf("gui_gateway.go does %s itself, bypassing the verb -- that is the second implementation", bad)
		}
	}
}

// Canary: what blocks the button sits ABOVE the button.
//
// The first draft put the explanation and the state table higher, and
// the button went below the fold of the 1024x700 window -- on the
// single screen whose entire purpose is one press, on a computer the
// person has just walked up to. Order here is not taste but
// operability: first the reason the press will not work, then the
// press.
func TestCanary_GatewayBlockersComeBeforeTheButton(t *testing.T) {
	src, err := os.ReadFile("gateway_screen.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	warn := strings.Index(text, "f.layoutGatewayWarnings, f.layoutGatewayInstallForm")
	if warn < 0 {
		t.Fatal("the warnings no longer sit right before the install form: " +
			"a person will press the button and receive a refusal the screen already knew about")
	}
	// And the long explanation -- below the action, not above it.
	lede := strings.Index(text, "f.layoutGatewayLede")
	what := strings.LastIndex(text, "sections = append(sections, f.layoutGatewayWhat)")
	if lede < 0 || what < 0 || what < warn {
		t.Error("the long explanation moved back to the top -- it will push the button off the screen again")
	}
}
