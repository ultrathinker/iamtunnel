//go:build linux || darwin

package ui

import "gioui.org/app"

// viewHandle has nothing to hand back off Windows: no caption here
// belongs to this program (IAMT-362).
func viewHandle(app.ViewEvent) uintptr { return 0 }
