//go:build linux

package client

import "golang.org/x/sys/unix"

// Linux termios has 19 Cc entries (NCCS=19). The snapshot's Cc[20]
// array pads the unused slot, which makeRaw never writes to and
// fromUnixTermios leaves zero. Linux's flag fields are uint32; the
// snapshot's uint64 keeps the value losslessly.
//
// Linux has no Ispeed/Ospeed on Termios: baud-rate setters live in
// the separate cfsetispeed/cfsetospeed wrapper, not in the ioctl
// payload. fromUnixTermios therefore leaves the snapshot's ispeed/
// ospeed at zero, and toUnixTermios ignores them on the way out —
// which is the correct round-trip, because the kernel never sees
// them on Linux in the first place.
const linuxCcLen = 19

func fromUnixTermios(t *unix.Termios) termiosSnapshot {
	var cc [20]uint8
	for i := 0; i < linuxCcLen && i < len(cc); i++ {
		cc[i] = t.Cc[i]
	}
	return termiosSnapshot{
		iflag: uint64(t.Iflag),
		oflag: uint64(t.Oflag),
		cflag: uint64(t.Cflag),
		lflag: uint64(t.Lflag),
		cc:    cc,
	}
}

func toUnixTermios(iflag, oflag, cflag, lflag, ispeed, ospeed uint64, cc [20]uint8) *unix.Termios {
	t := &unix.Termios{
		Iflag: uint32(iflag),
		Oflag: uint32(oflag),
		Cflag: uint32(cflag),
		Lflag: uint32(lflag),
	}
	for i := 0; i < linuxCcLen && i < len(t.Cc); i++ {
		t.Cc[i] = cc[i]
	}
	return t
}
