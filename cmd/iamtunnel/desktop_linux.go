//go:build linux

package main

// desktop_linux.go — the Linux half of \`iamtunnel desktop
// install|uninstall\` (IAMT-255). Writes a .desktop entry and 48 +
// 256-pixel PNG icons under $XDG_DATA_HOME/applications/ and
// $XDG_DATA_HOME/icons/hicolor/<size>/apps/, the two
// freedesktop.org-standard locations every application launcher
// looks at. uninstall removes the same paths.
//
// Every path goes through desktopControl — there is no string
// constant naming /usr/share/applications or /usr/share/icons
// here, because install MUST NOT touch system locations. A user
// who happens to run the command as root still gets a per-user
// shortcut; the seamed \`xdgDataHome\` never returns a system path.
//
// The icons come from assets/icon/iamtunnel-<size>.png, the
// canonical source assets extracted once via
// \`go run ./tools/extract_windows_icon\` from the Windows
// .syso (IAMT-255 step 0).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// desktopControl is the seam every desktop install / uninstall path
// goes through. The Linux init wires it with the production os
// helpers; the !linux init in desktop_other.go populates it with
// the zero value (cmdDesktop reaches install/uninstall through the
// installFn / uninstallFn function pointers it initialises, and
// those refuse with desktopUnsupportedErr before touching the
// seam). The struct lives here on purpose: its fields (func types)
// are only assigned and read on Linux, and staticcheck flags them
// as U1000 on darwin/windows if the declaration stays in the
// untagged file.
type desktopControl struct {
	// xdgDataHome is the base directory under which
	// applications/<basename>.desktop and
	// icons/hicolor/<size>/apps/<basename>.png live. install
	// appends the relative suffix; uninstall looks up the absolute
	// files and deletes them.
	xdgDataHome func() string
	// openForWrite is used by install; tests inject a recording
	// fake instead of writing real files.
	openForWrite func(path string, data []byte) error
	// remove is used by uninstall; tests inject a recording fake.
	// The second return is the "did this path exist and was it
	// removed" signal: a second uninstall against the same path
	// reports "not removed" (existed=false), the idempotent path.
	// ENOENT is not a removal — the contract is "report only paths
	// that existed and were deleted", so a stale state from a
	// half-finished previous install does not double-count.
	remove func(path string) (existed bool, err error)
	// exePath returns the absolute path of the binary the
	// .desktop file's Exec=... should point at. install resolves
	// it via os.Executable(); tests inject a stable path.
	exePath func() (string, error)
	// iconOpen is the function the install path uses to read the
	// bundled icon assets/icon/iamtunnel-<size>.png file. Tests
	// inject their own asset directory.
	iconOpen func(size int) ([]byte, error)
}

// defaultDesktopControl is the seam the platform populates in its
// own init(). The Linux init wires it with the production os
// helpers; on !linux cmdDesktop's installFn / uninstallFn refuse
// with desktopUnsupportedErr before the seam is ever read.
var defaultDesktopControl desktopControl

// xdgDataHome returns $XDG_DATA_HOME when set, falling back to
// ~/.local/share per the freedesktop base-directory specification.
// This is the same fallback the freedesktop implementations use
// when XDG_DATA_HOME is unset, so install produces the same path
// the user's environment expects. Indirected through osGetenv so
// a future test could override the environment by overriding
// osGetenvFn; today the production wiring reads os.Getenv directly.
func xdgDataHome() string {
	if v := osGetenv("XDG_DATA_HOME"); v != "" {
		return v
	}
	home := osGetenv("HOME")
	if home == "" {
		return ""
	}
	return home + "/.local/share"
}

// osGetenv is the seam every platform's env-reads go through. The
// production definition lives here (desktop_linux.go); the seam
// exists so a future test could override osGetenvFn to drive
// xdgDataHome against a different environment without touching
// the seam struct.
func osGetenv(k string) string { return osGetenvFn(k) }

// osGetenvFn is the indirect call — overridden in tests.
var osGetenvFn = func(k string) string { return os.Getenv(k) }

// desktopFileTemplate is the .desktop file install writes —
// Name=iamtunnel, Exec=<absolute path>, Icon=iamtunnel,
// Terminal=false, Categories=Network;. The rest is freedesktop
// standard (Type=Application, the version fields). Every literal
// here is verified by TestIAMT255_DesktopFileLivesUpToFreedesktopSpec:
// Name, Exec=, Icon=iamtunnel, Terminal=false, and
// Categories=Network; MUST appear, otherwise the entry becomes
// invisible to the application launcher per freedesktop §1.1.
const desktopFileTemplate = `[Desktop Entry]
Type=Application
Version=1.0
Name=iamtunnel
GenericName=Remote Access Client
Comment=Recorded SSH access to your machines
Exec=%s
Icon=iamtunnel
Terminal=false
Categories=Network;
StartupNotify=true
`

// requiredDesktopKeywords is the list of substrings the canary
// test greps for. Anything missing makes the file invisible to the
// launcher. Keep the list and the template in lock-step.
var requiredDesktopKeywords = []string{
	"Name=iamtunnel",
	"Exec=",
	"Icon=iamtunnel",
	"Terminal=false",
	"Categories=Network;",
}

// iconSizes is the list of PNG sizes install writes: 48 and 256, the
// two standard freedesktop hicolor sizes (every other launcher renders
// one of those). The list is part of the canary test so a future
// change of size is gated.
var iconSizes = []int{48, 256}

// installDesktopFiles writes the .desktop entry plus the two PNG
// icons under ctrl.xdgDataHome(). Returns the list of absolute paths
// it wrote so the canary test can observe the install. Every
// failure returns the exact reason the next test's canary string
// names.
func installDesktopFiles(ctrl desktopControl) ([]string, error) {
	base := ctrl.xdgDataHome()
	if base == "" {
		return nil, errors.New("desktop install: cannot determine XDG_DATA_HOME: neither $XDG_DATA_HOME nor $HOME is set")
	}
	exe, err := ctrl.exePath()
	if err != nil {
		return nil, fmt.Errorf("desktop install: locate this binary: %w", err)
	}
	desktopAbs := filepath.Join(base, "applications", "iamtunnel.desktop")
	content := fmt.Sprintf(desktopFileTemplate, exe)
	if err := ctrl.openForWrite(desktopAbs, []byte(content)); err != nil {
		return nil, fmt.Errorf("desktop install: write %s: %w", desktopAbs, err)
	}
	written := []string{desktopAbs}
	for _, size := range iconSizes {
		iconAbs := filepath.Join(base, "icons", "hicolor", strconv.Itoa(size), "apps", "iamtunnel.png")
		raw, err := ctrl.iconOpen(size)
		if err != nil {
			return nil, fmt.Errorf("desktop install: open the %d-pixel icon: %w", size, err)
		}
		if err := ctrl.openForWrite(iconAbs, raw); err != nil {
			return nil, fmt.Errorf("desktop install: write %s: %w", iconAbs, err)
		}
		written = append(written, iconAbs)
	}
	return written, nil
}

// uninstallDesktopFiles deletes the same paths install wrote. The
// install-time paths are computed here too — keeping the symmetry
// inside this file (and the seam) means install and uninstall can
// never drift apart: a future size added to iconSizes appears in
// uninstall the moment install produces it. The returned list
// names ONLY paths that existed and were deleted; an idempotent
// second call against the same targets returns an empty list
// (ENOENT means "not removed, do not report").
func uninstallDesktopFiles(ctrl desktopControl) ([]string, error) {
	base := ctrl.xdgDataHome()
	if base == "" {
		return nil, errors.New("desktop uninstall: cannot determine XDG_DATA_HOME: neither $XDG_DATA_HOME nor $HOME is set")
	}
	removed := []string{}
	targets := []string{filepath.Join(base, "applications", "iamtunnel.desktop")}
	for _, size := range iconSizes {
		targets = append(targets, filepath.Join(base, "icons", "hicolor", strconv.Itoa(size), "apps", "iamtunnel.png"))
	}
	for _, p := range targets {
		existed, err := ctrl.remove(p)
		if err != nil {
			return removed, fmt.Errorf("desktop uninstall: remove %s: %w", p, err)
		}
		if existed {
			removed = append(removed, p)
		}
	}
	return removed, nil
}

// init populates defaultDesktopControl with the production os
// helpers AND wires installFn / uninstallFn to call the bodies
// against it. The canary test swaps defaultDesktopControl with a
// recording fake and replaces the function pointers so the CLI
// dispatch canary exercises the fake end-to-end.
func init() {
	defaultDesktopControl = desktopControl{
		xdgDataHome: xdgDataHome,
		openForWrite: func(path string, data []byte) error {
			return defaultWriteFile(path, data, 0o644)
		},
		remove:   defaultRemove,
		exePath:  defaultExePath,
		iconOpen: openBundledIcon,
	}
	installFn = func() ([]string, error) {
		return installDesktopFiles(defaultDesktopControl)
	}
	uninstallFn = func() ([]string, error) {
		return uninstallDesktopFiles(defaultDesktopControl)
	}
}

// openBundledIcon reads assets/icon/iamtunnel-<size>.png. The path
// resolution walks up from the test binary the same way
// extract_windows_icon does, so the production binary and a test
// running from anywhere in the module both find the assets.
func openBundledIcon(size int) ([]byte, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(exe)
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "assets", "icon", fmt.Sprintf("iamtunnel-%d.png", size))
		if data, err := os.ReadFile(candidate); err == nil {
			return data, nil
		}
		dir = filepath.Dir(dir)
	}
	return nil, fmt.Errorf("bundled icon assets/icon/iamtunnel-%d.png not found in the repo tree", size)
}

// defaultWriteFile and defaultRemove are the production seams for
// the desktopControl — test-only helpers substitute recording fakes
// so install/uninstall can run in t.TempDir() without touching the
// real $XDG_DATA_HOME tree.
func defaultWriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// WriteFileAtomic, not the flat os.WriteFile this was (IAMT-332
	// round nine): the desktop entries are written into $XDG_DATA_HOME,
	// which an attacker-controlled XDG_DATA_HOME environment (the
	// documented GUI reachability, SPEC §3.1) can aim anywhere — a
	// symlink planted at the entry's name used to be truncated through
	// and a FIFO wedged the install. The replace acts on the entry,
	// never through it, and the mode lands on the temporary before the
	// rename.
	return datafile.WriteFileAtomic(path, data, datafile.WithMode(mode))
}

// defaultRemove deletes the file at path. The second return
// reflects the "existed and was removed" contract: true means the
// file existed before this call and was successfully deleted;
// false means the file did not exist (ENOENT) and nothing
// happened. Other errors (permission denied, EIO, ...) are
// returned as-is. This is what makes uninstall idempotent:
// a second call against the same targets reports zero removals
// rather than counting ENOENT as a removal.
func defaultRemove(path string) (bool, error) {
	err := os.Remove(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func defaultExePath() (string, error) {
	return os.Executable()
}
