package client

import (
	"fmt"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

type fakeConsoleAPI struct {
	mu    sync.Mutex
	modes map[uintptr]uint32
	sizes map[uintptr]terminalSize
}

func (f *fakeConsoleAPI) getMode(fd uintptr) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mode, ok := f.modes[fd]
	if !ok {
		return 0, fmt.Errorf("unknown fake handle %d", fd)
	}
	return mode, nil
}
func (f *fakeConsoleAPI) setMode(fd uintptr, mode uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.modes[fd]; !ok {
		return fmt.Errorf("unknown fake handle %d", fd)
	}
	f.modes[fd] = mode
	return nil
}
func (f *fakeConsoleAPI) size(fd uintptr) (terminalSize, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	size, ok := f.sizes[fd]
	if !ok {
		return terminalSize{}, fmt.Errorf("unknown fake handle %d", fd)
	}
	return size, nil
}
func (f *fakeConsoleAPI) mode(fd uintptr) uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.modes[fd]
}

// TestWindowsTerminalRawModeAndExactRestore proves the two essential console
// facts without ever touching the owner's real console: raw input and VT
// output are installed on a fake console, then both original bit patterns are
// restored exactly rather than replaced by guessed defaults.
func TestWindowsTerminalRawModeAndExactRestore(t *testing.T) {
	const in, out uintptr = 11, 12
	initialIn := uint32(windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT | 0x40)
	initialOut := uint32(windows.ENABLE_PROCESSED_OUTPUT | 0x80)
	fake := &fakeConsoleAPI{
		modes: map[uintptr]uint32{in: initialIn, out: initialOut},
		sizes: map[uintptr]terminalSize{out: {cols: 80, rows: 24}},
	}
	terminal, err := openWindowsTerminal(in, out, fake)
	if err != nil {
		t.Fatalf("openWindowsTerminal: %v", err)
	}

	wantIn := (initialIn &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT)) | windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	wantOut := initialOut | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	if got := fake.mode(in); got != wantIn {
		t.Fatalf("input raw mode = %#x, want %#x", got, wantIn)
	}
	if got := fake.mode(out); got != wantOut {
		t.Fatalf("output VT mode = %#x, want %#x", got, wantOut)
	}
	if err := terminal.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := fake.mode(in); got != initialIn {
		t.Fatalf("restored input mode = %#x, want original %#x", got, initialIn)
	}
	if got := fake.mode(out); got != initialOut {
		t.Fatalf("restored output mode = %#x, want original %#x", got, initialOut)
	}
}
