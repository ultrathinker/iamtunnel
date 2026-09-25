//go:build windows

package ui

import "gioui.org/app"

// viewHandle digs the window handle out of the platform's view event.
// An empty event (the window going away) yields zero, which every caller
// already treats as "nothing to do".
func viewHandle(e app.ViewEvent) uintptr {
	if v, ok := e.(app.Win32ViewEvent); ok {
		return v.HWND
	}
	return 0
}
