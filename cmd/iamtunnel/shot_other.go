//go:build !windows || nogui

package main

import "runtime"

// shotScreen refuses honestly on non-Windows: the offscreen renderer is
// Windows-only (SPEC §9) — it lives in internal/ui/shot_windows.go and
// its example data is a Windows machine — so there is nothing to draw
// here, even though the window itself now opens on Linux and macOS
// (IAMT-252, IAMT-262). The command still parses and validates the same
// way on every platform; only the drawing is refused, and the refusal is
// the environment class, not the shared stub.
func finishShot(s *streams, screen, subTab string, dark bool, outPath, theme string) int {
	return fail(s, envErrf("iamtunnel shot: screen %q cannot be drawn on %s: the offscreen shot renders the Windows GUI and is Windows-only (SPEC §9)", screen, runtime.GOOS))
}
