//go:build linux

package client

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// openTestPty allocates a fresh pseudo-terminal pair owned by the test
// process. Nothing on disk is created or changed: /dev/pts entries live
// only as long as the descriptors do.
func openTestPty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx in this environment (%v): the real-pty raw-mode check needs a pty", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		t.Fatalf("unlock pty: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		t.Fatalf("pty number: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		t.Fatalf("open pty slave: %v", err)
	}
	t.Cleanup(func() { s.Close(); m.Close() })
	return m, s
}

// TestUnixTerminalRealPtyIsRawAndRestored is the IAMT-244 regression:
// the fake-API tests passed while the live Linux terminal stayed in
// canonical mode, because ICANON was a hand-typed Darwin value. This
// test installs raw mode through the production ioctl path on a real
// pty and reads the kernel's termios back, so a wrong constant turns
// it red no matter what the fake says.
func TestUnixTerminalRealPtyIsRawAndRestored(t *testing.T) {
	_, slave := openTestPty(t)
	fd := int(slave.Fd())
	withSignalSeam(t, nil, nil, func(int) { t.Fatal("fatalExit called in unit test") })

	before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		t.Fatalf("read termios before: %v", err)
	}
	if before.Lflag&unix.ICANON == 0 {
		t.Fatalf("a fresh pty should start in canonical mode, lflag=%#x", before.Lflag)
	}

	terminal, err := openUnixTerminal(uintptr(fd), uintptr(fd), xSysTermiosAPI{})
	if err != nil {
		t.Fatalf("openUnixTerminal on a real pty: %v", err)
	}
	if _, inert := terminal.(inertTerminal); inert {
		t.Fatal("openUnixTerminal returned inertTerminal for a real pty")
	}

	raw, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		t.Fatalf("read termios in raw mode: %v", err)
	}
	if bits := raw.Lflag & (unix.ICANON | unix.ECHO | unix.ISIG | unix.IEXTEN); bits != 0 {
		t.Errorf("raw mode left lflag bits %#x set (ICANON|ECHO|ISIG|IEXTEN must be clear): input stays line-buffered", bits)
	}
	if raw.Iflag&(unix.ICRNL|unix.IXON) != 0 {
		t.Errorf("raw mode left iflag ICRNL/IXON set: %#x", raw.Iflag)
	}
	if raw.Oflag&unix.OPOST != 0 {
		t.Errorf("raw mode left oflag OPOST set: %#x", raw.Oflag)
	}
	if raw.Cc[unix.VMIN] != 1 || raw.Cc[unix.VTIME] != 0 {
		t.Errorf("raw mode VMIN/VTIME = %d/%d, want 1/0", raw.Cc[unix.VMIN], raw.Cc[unix.VTIME])
	}

	if err := terminal.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	after, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		t.Fatalf("read termios after restore: %v", err)
	}
	if after.Iflag != before.Iflag || after.Oflag != before.Oflag || after.Cflag != before.Cflag ||
		after.Lflag != before.Lflag || after.Cc != before.Cc {
		t.Errorf("restore did not put the kernel termios back: before %+v, after %+v", *before, *after)
	}
}
