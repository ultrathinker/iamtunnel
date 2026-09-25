//go:build (!windows && !linux && !darwin) || nogui

package main

import "fmt"

// runGUI is never reached with a window on this platform: main.go's
// no-arguments branch reaches it everywhere, but only Windows, Linux and
// macOS have a live window behind it (IAMT-252, IAMT-262) — here the
// printed usage text is what a no-argument invocation actually gets.
// This stub exists only so the package compiles for every platform the
// gates check, the same split shot_other.go/shot_windows.go already uses
// for the offscreen renderer.
func runGUI(s *streams) int {
	fmt.Fprint(s.errs, usageText)
	return exitUser
}
