//go:build windows || linux || darwin

package ui

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The maintainer's canary for IAMT-400, a finding of 20.09.2026.
//
// The ask mode was added to the gateway and the command line in one
// wave, while the segment switch in the window was made on a separate
// track -- and nobody wrote the button in. The maintainer opened
// Admin -> Safety and saw three buttons instead of four: the one mode
// that makes most sense to keep enabled was unreachable from the
// window.
//
// The statement: the list of modes in the window matches the list the
// gateway declares. It is checked against the gateway's SOURCE, not
// against a second list in the tests: a second list would drift in
// exactly the same way and just as silently.
func TestCanary_IAMT400_WindowOffersEveryModeTheGatewayKnows(t *testing.T) {
	src, err := os.ReadFile("../gateway/config.go")
	if err != nil {
		t.Fatalf("test setup error: reading internal/gateway/config.go: %v", err)
	}
	// RiskActionLog   RiskAction = "log"
	re := regexp.MustCompile(`RiskAction\w+\s+RiskAction\s*=\s*"(\w+)"`)
	found := re.FindAllStringSubmatch(string(src), -1)
	if len(found) < 3 {
		t.Fatalf("test setup error: %d modes found in config.go, expected at least 3 -- "+
			"the declaration changed; fix the canary, do not throw it away", len(found))
	}
	gateway := map[string]bool{}
	for _, m := range found {
		gateway[m[1]] = true
	}

	window := map[string]bool{}
	for _, w := range riskModeWords() {
		window[strings.ToLower(w)] = true
	}

	for mode := range gateway {
		if !window[mode] {
			t.Errorf("CANARY IAMT-400: the gateway knows the mode %q, but the window has no such button. "+
				"This is exactly what the maintainer saw on 20.09: three buttons out of four on Admin -> Safety, "+
				"with ask unreachable from the window. Window: %v", mode, riskModeWords())
		}
	}
	for mode := range window {
		if !gateway[mode] {
			t.Errorf("CANARY IAMT-400: the window offers the mode %q, which the gateway does not know -- "+
				"the press will be refused. Gateway: %v", mode, found)
		}
	}
}
