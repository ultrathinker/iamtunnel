//go:build darwin

package client

import "golang.org/x/sys/unix"

// Darwin uses the BSD-derived ioctl numbering for termios: TIOCGETA /
// TIOCSETA / TIOCGWINSZ. Requests and flags come from the x/sys/unix
// tables by name (see terminal_ioctl_linux.go for why hand-typed numbers
// are not allowed here); darwin/amd64 and darwin/arm64 share the values.
const (
	getTermiosReq = unix.TIOCGETA
	setTermiosReq = unix.TIOCSETA
	getWinSizeReq = unix.TIOCGWINSZ
)

const (
	iflagClearRaw uint64 = unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	oflagClearRaw uint64 = unix.OPOST
	lflagClearRaw uint64 = unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	cflagClearRaw uint64 = unix.CSIZE | unix.PARENB
	cflagSetRaw   uint64 = unix.CS8

	// Indexes into Termios.Cc (VMIN=16, VTIME=17 on Darwin).
	ccVMin  = unix.VMIN
	ccVTime = unix.VTIME
)
