//go:build linux || darwin

package ui

// Only Windows draws a caption this program can repaint (IAMT-362). On
// Linux the window manager owns the decoration and follows the desktop's
// own theme; on macOS the system does the same. A no-op here keeps the
// window loop identical on all three rather than fencing the call site
// with build tags.
func applyTitleBarTheme(hwnd uintptr, dark bool) {}
