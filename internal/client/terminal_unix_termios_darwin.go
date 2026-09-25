//go:build darwin

package client

import "golang.org/x/sys/unix"

// macOS termios has 20 Cc entries (NCCS=20). The snapshot's Cc[20]
// array fits exactly; Darwin's flag fields are already uint64,
// matching the snapshot.
//
// Ispeed and Ospeed are part of the TIOCSETA payload on Darwin: a
// raw-mode install that zeroes them changes the baud rate that the
// kernel will drive the line at, and a subsequent restore that
// re-zeros them leaves the user at the wrong speed. fromUnixTermios
// copies both fields into the snapshot; toUnixTermios writes them
// back into the struct the unix package hands to the kernel.
const darwinCcLen = 20

func fromUnixTermios(t *unix.Termios) termiosSnapshot {
	var cc [20]uint8
	for i := 0; i < darwinCcLen && i < len(cc); i++ {
		cc[i] = t.Cc[i]
	}
	return termiosSnapshot{
		iflag:  t.Iflag,
		oflag:  t.Oflag,
		cflag:  t.Cflag,
		lflag:  t.Lflag,
		ispeed: t.Ispeed,
		ospeed: t.Ospeed,
		cc:     cc,
	}
}

func toUnixTermios(iflag, oflag, cflag, lflag, ispeed, ospeed uint64, cc [20]uint8) *unix.Termios {
	t := &unix.Termios{
		Iflag:  iflag,
		Oflag:  oflag,
		Cflag:  cflag,
		Lflag:  lflag,
		Ispeed: ispeed,
		Ospeed: ospeed,
	}
	for i := 0; i < darwinCcLen && i < len(t.Cc); i++ {
		t.Cc[i] = cc[i]
	}
	return t
}
