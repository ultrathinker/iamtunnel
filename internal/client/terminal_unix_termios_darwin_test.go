//go:build darwin

package client

import "testing"

// TestUnixTerminalDarwinPreservesIspeedOspeed is the canary for
// fix #2: on macOS, TIOCSETA carries Ispeed and Ospeed in its
// payload. A raw-mode install that does not preserve them changes
// the line's baud rate on the way out, and a subsequent restore
// that re-zeros them leaves the user at the wrong speed. The
// snapshot must round-trip both fields byte-for-byte.
//
// This test lives in a Darwin-only file because the canonicalCooked
// helper on Linux produces ispeed=ospeed=0, and round-tripping zeros
// is not a useful assertion. On Darwin we preload the snapshot with
// non-zero values (B19200 and B38400 — common modem speeds in the
// canonical <termios.h> baud-rate encoding) and assert the same
// numbers come back after raw install + restore.
func TestUnixTerminalDarwinPreservesIspeedOspeed(t *testing.T) {
	const b19200 = 0x0e // B19200 on Darwin, per <termios.h>
	const b38400 = 0x0f // B38400 on Darwin, per <termios.h>
	saved := termiosSnapshot{
		iflag:  0x0100,                            // ICRNL
		oflag:  0x0001,                            // OPOST
		cflag:  0x0030 | 0x0100,                   // CS8 | PARENB
		lflag:  0x0008 | 0x0100 | 0x0001 | 0x8000, // ECHO | ICANON | ISIG | IEXTEN
		ispeed: b19200,
		ospeed: b38400,
	}
	api := &fakeTermAPI{current: saved}
	withSignalSeam(t, nil, nil, func(int) { t.Fatal("fatalExit called in unit test") })

	const in, out uintptr = 11, 12
	terminal, err := openUnixTerminal(in, out, api)
	if err != nil {
		t.Fatalf("openUnixTerminal: %v", err)
	}

	// Raw install must keep ispeed and ospeed — the snapshot only
	// changes the lflag/oflag/cflag bits and VMIN/VTIME, never the
	// baud rate.
	raw := api.lastSet(t)
	if raw.ispeed != b19200 {
		t.Errorf("raw.ispeed = %#x, want %#x (raw install must preserve Ispeed)", raw.ispeed, b19200)
	}
	if raw.ospeed != b38400 {
		t.Errorf("raw.ospeed = %#x, want %#x (raw install must preserve Ospeed)", raw.ospeed, b38400)
	}

	// Restore must put both back exactly as they were.
	if err := terminal.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := api.lastSet(t)
	if got.ispeed != b19200 || got.ospeed != b38400 {
		t.Errorf("restored snapshot speeds = (ispeed=%#x, ospeed=%#x), want (ispeed=%#x, ospeed=%#x)",
			got.ispeed, got.ospeed, b19200, b38400)
	}
	if got.lflag != saved.lflag || got.iflag != saved.iflag ||
		got.oflag != saved.oflag || got.cflag != saved.cflag {
		t.Errorf("restored snapshot flags differ from the original: got %+v, want %+v", got, saved)
	}
}
