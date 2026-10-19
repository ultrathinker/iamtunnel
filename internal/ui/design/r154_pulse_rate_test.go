package design

import (
	"testing"
	"time"
)

// A breathing control must not ask for a frame at the screen's refresh
// rate: a window whose only moving part was the "Restart as administrator"
// button used 10-20% of a processor on a server without a graphics card
// (19.10.2026). The breath is still smooth: the opacity changes
// by only a few percent between two frames.
func TestR154_APulseDoesNotRedrawAtTheRefreshRate(t *testing.T) {
	now := time.Now()
	if got := pulseNextFrame(now).Sub(now); got < 50*time.Millisecond {
		t.Fatalf("the next frame of a breathing control is asked for after %s; that is the refresh rate, not a breath", got)
	}
	if PulseFrameInterval > 250*time.Millisecond {
		t.Fatalf("the interval %s is so long that the breath is no longer smooth", PulseFrameInterval)
	}
	var step float32
	for at := time.Duration(0); at < SoftPulseDuration; at += PulseFrameInterval {
		d := SoftPulseOpacity(at+PulseFrameInterval) - SoftPulseOpacity(at)
		if d < 0 {
			d = -d
		}
		if d > step {
			step = d
		}
	}
	if step > 0.08 {
		t.Fatalf("the opacity jumps by %.2f between two frames: the breath would flicker", step)
	}
}
