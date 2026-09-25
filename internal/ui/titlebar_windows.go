//go:build windows

package ui

// The title bar follows the theme (IAMT-362).
//
// Windows draws the caption -- the strip with the icon, the program's
// name and the three buttons -- itself, and it draws it light unless the
// program says otherwise. The maintainer put it plainly on 19.09.2026:
// the light header on the form does not look right -- even Chrome's is
// dark, while this one was white. A dark window under a white caption does not read as a
// dark window; it reads as a window that has not finished loading.
//
// The lever is one DWM attribute, set on the window handle. Gio hands
// the handle over in a Win32ViewEvent, which arrives once when the
// window is created and again as an empty one when it goes away, so the
// call has a natural place to live and nothing has to go looking for an
// HWND behind gio's back.

import (
	"syscall"
	"unsafe"
)

var (
	dwmapi                  = syscall.NewLazyDLL("dwmapi.dll")
	procDwmSetWindowAttrib  = dwmapi.NewProc("DwmSetWindowAttribute")
	dwmaUseImmersiveDark    = uint32(20)
	dwmaUseImmersiveDarkOld = uint32(19)
)

// applyTitleBarTheme paints the caption dark or light to match the rest
// of the window.
//
// Both attribute numbers are tried. 20 is the documented one; 19 is what
// the first Windows 10 builds that had this feature used, and on those
// the documented number is simply ignored. Trying both costs one failed
// call on every version and works on all of them -- the alternative is
// reading the build number and deciding, which is a second copy of
// Microsoft's own compatibility table living in this file.
//
// A failure is silent by design. The caption colour is not worth a line
// of error output, let alone a refusal to open the window: the product
// works identically with a light strip at the top.
func applyTitleBarTheme(hwnd uintptr, dark bool) {
	if hwnd == 0 {
		return
	}
	var on int32
	if dark {
		on = 1
	}
	for _, attr := range []uint32{dwmaUseImmersiveDark, dwmaUseImmersiveDarkOld} {
		_, _, _ = procDwmSetWindowAttrib.Call(
			hwnd,
			uintptr(attr),
			uintptr(unsafe.Pointer(&on)),
			unsafe.Sizeof(on),
		)
	}
}
