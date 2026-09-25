//go:build windows

package ui

// Windows-only like its siblings iamt151/iamt327/iamt330: the tests here
// render the frame offscreen (renderFrameOffscreen, shotW/shotH), and
// that path exists only in shot_windows.go — on linux and darwin the
// file did not even compile (R2, 24.09.2026).

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

func TestRiskModeWithoutRuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	f.setRiskMode("block")
	if got := f.saidUnder(ctlAdminRiskMode); got.text != noRuntime || got.key != design.BadKey {
		t.Fatalf("CANARY WINDOW-RISK-1: no-runtime mode action = %+v, want refusal", got)
	}
}

func TestRiskModeSuccessBecomesSelectedState(t *testing.T) {
	f := newBareFrame(t)
	f.cfg.Actions.AdminRiskMode = func(mode string) (RiskModeResult, error) {
		if mode != "block" {
			t.Fatalf("mode action got %q, want block", mode)
		}
		return RiskModeResult{Mode: "block", Source: "live", Changed: true, Previous: "warn"}, nil
	}
	f.setRiskMode("block")
	got := awaitSaid(t, f, ctlAdminRiskMode, design.GoodKey)
	if got.text == "" {
		t.Fatalf("CANARY WINDOW-RISK-2: successful mode action has no response sentence")
	}
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render after mode action: %v", err)
	}
	if f.snap.Admin.RiskMode != (RiskMode{Mode: "block", Source: "live"}) {
		t.Fatalf("CANARY WINDOW-RISK-3: selected mode state = %+v, want block/live", f.snap.Admin.RiskMode)
	}
}
