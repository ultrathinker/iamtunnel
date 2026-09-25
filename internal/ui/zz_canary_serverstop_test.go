package ui

// The maintainer's canaries: what is running must be stoppable.
//
// Found by the maintainer on 19.09.2026. On a VM the process
// `iamtunnel.exe server start` (pid 1140) was running, while the
// window showed "At rest" and a START button. Pressing it would have
// run into the refusal "a server is already running for this machine
// -- stop it first", issued by a screen offering nothing to stop. A
// deadlock in a circle.
//
// The cause: the window knew exactly two facts -- "the tunnel to the
// gateway is up" (Waiting) and "the door is open". That the PROCESS
// itself was alive was not in the state at all, though the control
// port's answer carried it: the reply.Running field was read and
// thrown away. While the gateway stayed in place the two facts
// coincided and the defect did not show; the gateway was recreated --
// and they diverged.

import (
	"testing"
)

// TestCanary_ARunningAgentCanBeStopped.
//
// Canary: remove `|| s.Running` from the button's condition -- the
// test will say the screen offers START over a running process again.
func TestCanary_ARunningAgentCanBeStopped(t *testing.T) {
	f := newBareFrame(t)
	// Exactly the state the maintainer saw: the process alive, the
	// tunnel down, the door shut, no sessions.
	f.snap.Server = ServerState{Running: true}

	gtx := newTestLayoutContext(900, 700)
	if dims := f.layoutServerScreen(gtx); dims.Size.Y <= 0 {
		t.Fatal("the SERVER screen drew at zero height")
	}

	if !f.lastStopButtonShown {
		t.Fatal("over a running process the screen showed START, not STOP -- exactly the deadlock the maintainer found: START answers \"stop it first\", and there is nothing to stop it with")
	}
	if _, ok := f.btns[ctlServerStop]; !ok {
		t.Error("there is no stop button on the screen at all")
	}
}

// TestCanary_AnIdleMachineStillOffersStart: the other
// side. When nothing is running, the button must be START -- or the
// fix would have eaten the working case.
func TestCanary_AnIdleMachineStillOffersStart(t *testing.T) {
	f := newBareFrame(t)
	f.snap.Server = ServerState{}

	gtx := newTestLayoutContext(900, 700)
	_ = f.layoutServerScreen(gtx)

	if f.lastStopButtonShown {
		t.Error("on a machine with nothing running, STOP was offered")
	}
}

// TestCanary_TheHeadlineDoesNotSayAtRestOverARunningAgent.
//
// "At rest" over a running process is false twice over: something IS
// started, and the machine is NOT reachable.
//
// Canary: remove the s.Running branch from serverHeadline.
func TestCanary_TheHeadlineDoesNotSayAtRestOverARunningAgent(t *testing.T) {
	_, word, _ := serverHeadline(ServerState{Running: true})
	if word == "At rest" {
		t.Error("over a running process with the tunnel down the headline said \"At rest\" -- that is untrue in both directions at once")
	}

	// And a genuinely empty machine is still "At rest".
	if _, word, _ := serverHeadline(ServerState{}); word != "At rest" {
		t.Errorf("on an empty machine the headline = %q, want \"At rest\"", word)
	}

	// Unknown still outranks everything else (IAMT-311).
	if _, word, _ := serverHeadline(ServerState{Unknown: true, Running: true}); word != "Unknown" {
		t.Errorf("with an unverifiable state the headline = %q, want \"Unknown\" -- unknown must not yield to a new fact", word)
	}
}
