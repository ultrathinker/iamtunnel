//go:build windows || linux || darwin

package ui

import (
	"strings"
	"testing"
)

// The screen does not let a press find out what it already knows.
//
// 22.09.2026, a live check by the maintainer. They pressed "MAKE THIS
// COMPUTER A GATEWAY" on a program run from its folder on the desktop
// and got back the command's own refusal: "NT SERVICE\iamtunnel-gateway
// cannot read by default (RUNBOOK §1.5) -- copy iamtunnel.exe to
// C:\Program Files\iamtunnel and run "gateway install" from there".
//
// Every word of that refusal is true, and taken together it is the
// very console this tab exists to keep away. Worse: the card above had
// already said the same thing in its own words and offered the button
// that fixes it -- while the main control calmly walked the person
// past it straight into failure.
//
// The test holds both known blockers and demands that the refusal
// sound in the window's voice and point at what to press instead.
func TestGatewayInstallIsRefusedBeforeItCanFail(t *testing.T) {
	t.Run("no administrator rights", func(t *testing.T) {
		f := &Frame{}
		f.snap.Gateway = GatewayState{Supported: true, Platform: "windows", Elevated: false, ExeReachable: true}
		why, blocked := f.gatewayInstallBlocked()
		if !blocked {
			t.Fatal("installation is allowed without administrator rights -- it will fail, and the person will learn of it from the console")
		}
		if !strings.Contains(why, "Restart as administrator") {
			t.Errorf("the refusal does not name the button that fixes it: %q", why)
		}
	})

	t.Run("the program inside the user profile", func(t *testing.T) {
		f := &Frame{}
		f.snap.Gateway = GatewayState{
			Supported: true, Platform: "windows", Elevated: true,
			ExePath: `C:\Users\Admin\Desktop\test\iamtunnel.exe`, ExeReachable: false,
			WantedExeDir: `C:\iamtunnel`,
		}
		why, blocked := f.gatewayInstallBlocked()
		if !blocked {
			t.Fatal("installation is allowed from the user profile -- the service will install and only THEN fail to start")
		}
		if !strings.Contains(why, "Move it there for me") {
			t.Errorf("the refusal does not point at the button that moves the program: %q", why)
		}
		if !strings.Contains(why, `C:\iamtunnel`) {
			t.Errorf("the refusal does not say where exactly: %q", why)
		}
		// And the main thing: these are the window's words, not the console's.
		for _, console := range []string{"NT SERVICE", "RUNBOOK", "gateway install"} {
			if strings.Contains(why, console) {
				t.Errorf("the window's refusal still carries the console wording %q: %q", console, why)
			}
		}
	})

	t.Run("everything is fine", func(t *testing.T) {
		f := &Frame{}
		f.snap.Gateway = GatewayState{Supported: true, Platform: "windows", Elevated: true, ExeReachable: true}
		if why, blocked := f.gatewayInstallBlocked(); blocked {
			t.Fatalf("installation is refused where everything is ready: %q", why)
		}
	})
}

// The label on the button and the outcome of pressing it cannot
// diverge: both sides ask the same function.
func TestGatewayButtonWordMatchesWhatPressingDoes(t *testing.T) {
	f := &Frame{}
	f.snap.Gateway = GatewayState{Supported: true, Platform: "windows", Elevated: false, ExeReachable: true}
	if !f.gatewayInstallBlockedNow() {
		t.Fatal("the button promises installation where a press would refuse it")
	}
	f.snap.Gateway.Elevated = true
	if f.gatewayInstallBlockedNow() {
		t.Fatal("the button talks the person out of installation where a press would work")
	}
}
