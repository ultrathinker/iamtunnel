//go:build windows

package main

// console_windows.go: iamtunnel.exe is one console-subsystem binary for
// both the CLI and the window (IAMT-222). Started by a double click,
// Windows gives the process a console of its own, and that black window
// sat behind the form for the whole life of the GUI. hideOwnConsole
// detaches that console, but only when no other process shares it — a
// user who types "iamtunnel" in an already open cmd or PowerShell keeps
// their terminal.

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procGetConsoleProcessList = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	procGetConsoleWindow      = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow")
	procFreeConsole           = windows.NewLazySystemDLL("kernel32.dll").NewProc("FreeConsole")
	procShowWindow            = windows.NewLazySystemDLL("user32.dll").NewProc("ShowWindow")
	procAttachConsole         = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")
)

const attachParentProcess = ^uintptr(0) // (DWORD)-1

const swHide = 0

var procMessageBox = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW")

// attachParentConsole takes back the caller's console, and is the other
// half of linking this binary for the GUI subsystem (21.09.2026).
//
// hideOwnConsole below has freed the process's own console since
// IAMT-222, but only AFTER Windows had created and shown it. The
// maintainer finally pinned down the symptom that had been appearing
// for days: not the program's window sliding, a console flashing into
// existence and out again beside it.
//
// A console appears because a Go program on Windows is linked for the
// CONSOLE subsystem unless told otherwise, and Windows hands a console
// program a console. Linked with -H windowsgui it is never created, so
// there is nothing to flash and nothing to hide.
//
// That alone would break the other half of this binary: the same exe is
// a command-line tool, and a GUI-subsystem process starts with no
// standard handles, so every printed line would go nowhere.
// ATTACH_PARENT_PROCESS joins the console of whoever launched us. From a
// terminal, output appears there as before; from Explorer there is no
// parent console, the call fails, and the program stays silent and
// windowless -- which is right for a program whose interface is a window.
//
// Redirection is left alone: if stdout already stats, the shell arranged
// it (a pipe, a file) and re-pointing it at CONOUT$ would throw the
// output onto the screen the person was capturing it away from.
func attachParentConsole() {
	if _, err := os.Stdout.Stat(); err == nil {
		return
	}
	if r, _, _ := procAttachConsole.Call(attachParentProcess); r == 0 {
		return
	}
	// The runtime captured its (invalid) handles at start, so the files
	// have to be reopened against the console just joined. A failure is
	// silent: the program's job is the window, and refusing to start
	// because a log line has nowhere to go would be the tail wagging the
	// dog.
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = f
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stderr = f
	}
	if f, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = f
	}
}

// consoleIsOwn reports whether this process is the only user of its console
// — started by a double click, not from an open cmd or PowerShell.
func consoleIsOwn() bool {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// showErrorBox shows a start-up error of the window in a message box
// (IAMT-228): once the console is gone — or about to close with the process
// — stderr is not something anybody can read.
func showErrorBox(text string) {
	msg, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	title, _ := windows.UTF16PtrFromString("iamtunnel")
	const mbIconError = 0x10
	_, _, _ = procMessageBox.Call(0, uintptr(unsafe.Pointer(msg)), uintptr(unsafe.Pointer(title)), mbIconError)
}

// hideOwnConsole hides and frees the console when this process is its only
// user (GetConsoleProcessList == 1). Any failure leaves the console as it
// was: the window opens either way.
func hideOwnConsole() {
	if !consoleIsOwn() {
		return
	}
	if hwnd, _, _ := procGetConsoleWindow.Call(); hwnd != 0 {
		_, _, _ = procShowWindow.Call(hwnd, swHide)
	}
	_, _, _ = procFreeConsole.Call()
}
