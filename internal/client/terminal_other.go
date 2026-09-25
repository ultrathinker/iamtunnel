//go:build !windows && !linux && !darwin

package client

import "io"

// No local terminal mode is changed outside the platforms the
// terminal_unix.go / terminal_windows.go / terminal_ioctl_*.go files
// cover. In particular, this keeps the Windows-specific console API
// out of Linux builds and the x/sys/unix ioctl helpers out of every
// non-Unix-or-non-Windows build. Other Unix (FreeBSD, OpenBSD, …)
// stays on this inert path for now; the CLI refuses to change mode
// on them, and "client connect" still works through it.
func openTerminal(io.Reader, io.Writer) (localTerminal, error) { return inertTerminal{}, nil }
