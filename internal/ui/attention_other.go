//go:build linux || darwin

package ui

// callForAttention and stopCallingForAttention are Windows levers. On
// Linux and macOS the desktop decides how a window asks to be noticed,
// and gio offers no portable way to ask; a no-op keeps the call sites
// identical on all three.

func callForAttention(uintptr)        {}
func stopCallingForAttention(uintptr) {}
