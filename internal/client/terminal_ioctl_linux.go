//go:build linux

package client

import "golang.org/x/sys/unix"

// Linux ioctl request numbers and termios flags come straight from the
// x/sys/unix tables, never as hand-typed numbers: IAMT-244 found ICANON
// written as 0x0100 (its Darwin value; on Linux 0x0100 is TOSTOP), which
// left the live terminal line-buffered while every fake-API test passed.
// The values are the same on every Linux arch the project builds.
const (
	getTermiosReq = unix.TCGETS
	setTermiosReq = unix.TCSETS
	getWinSizeReq = unix.TIOCGWINSZ
)

// The flag sets cfmakeraw clears and sets, by name.
const (
	iflagClearRaw uint64 = unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	oflagClearRaw uint64 = unix.OPOST
	lflagClearRaw uint64 = unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	cflagClearRaw uint64 = unix.CSIZE | unix.PARENB
	cflagSetRaw   uint64 = unix.CS8

	// Indexes into Termios.Cc. VMIN=1, VTIME=0 is the canonical raw mode.
	ccVMin  = unix.VMIN
	ccVTime = unix.VTIME
)
