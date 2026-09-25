//go:build linux || darwin

package client

import "golang.org/x/sys/unix"

// ioctlGetTermios reads the termios struct from fd. The result is a
// copy of the kernel's struct, not a pointer to live memory — we keep
// only the fields we care about (see termiosSnapshot) so a future
// x/sys/unix layout change cannot break the snapshot/restore logic.
func ioctlGetTermios(fd int) (termiosSnapshot, error) {
	t, err := unix.IoctlGetTermios(fd, getTermiosReq)
	if err != nil {
		return termiosSnapshot{}, err
	}
	return fromUnixTermios(t), nil
}

// ioctlSetTermios writes the termios struct back. The unix package
// takes the live struct by pointer, so we build it on the stack from
// the snapshot's named fields and let unix.IoctlSetTermios pass it on.
// ioctlSetTermios is the bridge between our snapshot (which is
// platform-agnostic in shape) and unix.Termios (whose exact struct
// layout differs between Linux and Darwin).
func ioctlSetTermios(fd int, iflag, oflag, cflag, lflag, ispeed, ospeed uint64, cc [20]uint8) error {
	t := toUnixTermios(iflag, oflag, cflag, lflag, ispeed, ospeed, cc)
	return unix.IoctlSetTermios(fd, setTermiosReq, t)
}

// ioctlGetWinsize reads the terminal window size from fd. It returns
// (size, true) on success, (zero, false) on a non-tty fd or a tty
// that does not have a current size.
func ioctlGetWinsize(fd int) (*unix.Winsize, error) {
	return unix.IoctlGetWinsize(fd, getWinSizeReq)
}
