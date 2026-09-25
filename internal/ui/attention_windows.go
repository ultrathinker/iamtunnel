//go:build windows

package ui

// Asking to be noticed: the taskbar button flashes and the system plays
// its notification sound.
//
// This file used to also centre windows by hand. That is gone: gio has
// system.ActionCenter and applies it before the window is shown, while
// anything done from the view event necessarily moves a window that is
// already on screen. What is left here has no equivalent in gio.

import (
	"syscall"
	"unsafe"
)

var (
	user32 = syscall.NewLazyDLL("user32.dll")
)

// --- attention ------------------------------------------------------

var (
	procFlashWindowEx = user32.NewProc("FlashWindowEx")
	procMessageBeep   = user32.NewProc("MessageBeep")
)

type flashwinfo struct {
	cbSize    uint32
	hwnd      uintptr
	dwFlags   uint32
	uCount    uint32
	dwTimeout uint32
}

const (
	flashwStop = 0x00000000
	// FLASHW_ALL: the caption AND the taskbar button. Tray alone was too
	// quiet -- on a window that is merely behind another, the taskbar
	// button is the only thing flashing and it was missed.
	flashwAll = 0x00000003
	// FLASHW_TIMERNOFG: keep flashing until the window comes to the
	// FOREGROUND. This is the one flag that makes the signal self-ending
	// and honest. The previous FLASHW_TIMER kept going until told to stop
	// explicitly, which meant it also kept going after the person had
	// already looked.
	flashwTimerNoFG = 0x0000000C
	mbIconAsterisk  = 0x00000040
)

// callForAttention flashes the taskbar button and plays the system's own
// notification sound (21.09.2026).
//
// Asked for by the maintainer once a held command could be settled from
// the window: some short sound would be nice, and a bit of blinking in
// the taskbar, so that it is visible that something is happening. That is
// right -- without it the feature is half-built -- a
// question nobody hears is a question nobody answers, and the whole point
// is that an agent is waiting RIGHT NOW, for five minutes.
//
// The sound is MessageBeep with the system's asterisk, not a file of our
// own: it follows whatever the person has chosen for notifications,
// including silence, and a program that insists on being heard by someone
// who muted notifications is a program that gets muted entirely.
//
// FLASHW_ALL|FLASHW_TIMERNOFG: the caption and the taskbar button flash
// until the window comes to the FOREGROUND, which is exactly what "there
// is something waiting" means and exactly when it stops being true.
//
// The first attempt used FLASHW_TRAY|FLASHW_TIMER and the maintainer saw
// nothing at all. Two reasons, and both are fixed here: TRAY alone leaves
// a window that is merely behind another with nothing but a taskbar
// button blinking, and TIMER does not stop on its own, so the flag that
// looks more persistent is the one that gets missed and then lingers.
func callForAttention(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	go func() {
		fi := flashwinfo{hwnd: hwnd, dwFlags: flashwAll | flashwTimerNoFG, uCount: 0, dwTimeout: 0}
		fi.cbSize = uint32(unsafe.Sizeof(fi))
		procFlashWindowEx.Call(uintptr(unsafe.Pointer(&fi)))
		procMessageBeep.Call(uintptr(mbIconAsterisk))
	}()
}

// stopCallingForAttention ends the flashing once the question has been
// looked at. Leaving it to Windows' own "stop on activate" is not enough:
// a person may settle the command from a window that was already in
// front, and a button still blinking then says something is waiting when
// nothing is.
func stopCallingForAttention(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	go func() {
		fi := flashwinfo{hwnd: hwnd, dwFlags: flashwStop}
		fi.cbSize = uint32(unsafe.Sizeof(fi))
		procFlashWindowEx.Call(uintptr(unsafe.Pointer(&fi)))
	}()
}
