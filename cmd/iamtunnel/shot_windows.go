//go:build windows && !nogui

package main

import (
	"errors"
	"fmt"
	iofs "io/fs"
	"os"

	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// shotScreen renders the named screen offscreen — no window opens — and
// writes the picture to outPath as a PNG of the standard resolution.
// The drawing is the phase-0 spike method (gioui.org/gpu/headless on
// Direct3D, SPEC §7.2) kept in internal/ui; this file is the only place
// cmd/iamtunnel touches the window library, so a Linux build of the
// command never sees Gio (SPEC §9).
func finishShot(s *streams, screen, subTab string, dark bool, outPath, theme string) int {
	if _, err := ui.ShotSub(screen, subTab, dark, ui.DefaultShotWidth, ui.DefaultShotHeight, outPath); err != nil {
		if errors.Is(err, iofs.ErrPermission) {
			return fail(s, deniedErrf("iamtunnel shot: the OS refuses to write %s: %v", outPath, err))
		}
		return fail(s, envErrf("iamtunnel shot: %v", err))
	}
	info, err := os.Stat(outPath)
	if err != nil {
		return fail(s, envErrf("iamtunnel shot: wrote %s but cannot stat it: %v", outPath, err))
	}
	fmt.Fprintf(s.out, "iamtunnel shot: wrote %s (%d bytes, %s theme)\n", outPath, info.Size(), theme)
	return exitOK
}
