package client

import (
	"fmt"
	"io"

	"golang.org/x/sys/windows"
)

// consoleAPI isolates the small, stateful Win32 surface so the mode
// transition itself is testable against a fake console. It is package-local:
// production callers cannot replace it or disable the invariant.
type consoleAPI interface {
	getMode(uintptr) (uint32, error)
	setMode(uintptr, uint32) error
	size(uintptr) (terminalSize, error)
}

type winConsoleAPI struct{}

func (winConsoleAPI) getMode(fd uintptr) (uint32, error) {
	var mode uint32
	err := windows.GetConsoleMode(windows.Handle(fd), &mode)
	return mode, err
}

func (winConsoleAPI) setMode(fd uintptr, mode uint32) error {
	return windows.SetConsoleMode(windows.Handle(fd), mode)
}

func (winConsoleAPI) size(fd uintptr) (terminalSize, error) {
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(fd), &info); err != nil {
		return terminalSize{}, err
	}
	return terminalSize{
		cols: uint32(info.Window.Right - info.Window.Left + 1),
		rows: uint32(info.Window.Bottom - info.Window.Top + 1),
	}, nil
}

type fdReader interface {
	io.Reader
	Fd() uintptr
}

type fdWriter interface {
	io.Writer
	Fd() uintptr
}

type windowsTerminal struct {
	cleanup *closeOnceTerminal
	api     consoleAPI
	out     uintptr
}

func (t *windowsTerminal) restore() error { return t.cleanup.restore() }

func (t *windowsTerminal) size() (terminalSize, bool) {
	size, err := t.api.size(t.out)
	return size, err == nil && size.cols != 0 && size.rows != 0
}

func openTerminal(in io.Reader, out io.Writer) (localTerminal, error) {
	input, inputOK := in.(fdReader)
	output, outputOK := out.(fdWriter)
	if !inputOK || !outputOK {
		return inertTerminal{}, nil
	}
	return openWindowsTerminal(input.Fd(), output.Fd(), winConsoleAPI{})
}

// openWindowsTerminal takes snapshots before changing either handle. The
// exact snapshots, rather than a guessed "normal" mode, are put back during
// cleanup. That is essential when Connect is called from an already configured
// terminal host.
func openWindowsTerminal(in, out uintptr, api consoleAPI) (localTerminal, error) {
	inMode, err := api.getMode(in)
	if err != nil {
		// Redirected streams are a supported non-interactive use of Connect.
		return inertTerminal{}, nil
	}
	outMode, err := api.getMode(out)
	if err != nil {
		return inertTerminal{}, nil
	}

	rawInput := (inMode &^ (windows.ENABLE_LINE_INPUT | windows.ENABLE_ECHO_INPUT)) | windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	rawOutput := outMode | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	if err := api.setMode(in, rawInput); err != nil {
		return nil, fmt.Errorf("set console input raw mode: %w", err)
	}
	if err := api.setMode(out, rawOutput); err != nil {
		if restoreErr := api.setMode(in, inMode); restoreErr != nil {
			return nil, fmt.Errorf("set console output VT mode: %w (also restoring input mode: %v)", err, restoreErr)
		}
		return nil, fmt.Errorf("set console output VT mode: %w", err)
	}

	return &windowsTerminal{
		api: api,
		out: out,
		cleanup: &closeOnceTerminal{fn: func() error {
			// Output first prevents a restored input mode from accepting a key
			// before the screen understands the matching terminal sequences.
			if err := api.setMode(out, outMode); err != nil {
				return fmt.Errorf("restore console output mode: %w", err)
			}
			if err := api.setMode(in, inMode); err != nil {
				return fmt.Errorf("restore console input mode: %w", err)
			}
			return nil
		}},
	}, nil
}
