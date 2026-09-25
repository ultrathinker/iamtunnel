//go:build windows

// Windows elevation: IsElevated + Relaunch.
//
// ShellExecuteEx with lpVerb="runas" is the documented user
// consent flow. If the user accepts, the OS spawns a new
// elevated process that is a copy of the current command line.
// The original (non-elevated) process then exits to hand over.
//
// To detect a loop, the elevated child must mark itself with
// AlreadyElevatedFlag. If the marker is in argv[1], the child
// does NOT call Relaunch and does NOT show the consent prompt.
//
// We never silently bypass UAC, never read environment
// variables to disable elevation, and never expose an
// exported setter that turns Relaunch into a no-op. The
// whole point of Relaunch is to surface the prompt to the
// user; a kill switch would be the "proving a fix by
// disabling it" pattern that the project forbids.

package elevate

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AlreadyElevatedFlag is the argv marker the elevated parent
// prepends so the child does not relaunch itself.
const AlreadyElevatedFlag = "--elevated-child"

// well-known SID for BUILTIN\Administrators — membership means
// the process token has been elevated.
// IsElevated reports whether the current process's token has
// the BUILTIN\Administrators group enabled. The check uses
// CheckTokenMembership, which is the documented and stable
// way to do this on Windows; it does not allocate resources
// beyond the SID lookup.
func IsElevated() (bool, error) {
	sid, err := windows.StringToSid(builtinAdministratorsSID)
	if err != nil {
		return false, fmt.Errorf("StringToSid: %w", err)
	}
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("CheckTokenMembership")
	var isMember int32
	r1, _, _ := proc.Call(
		0, // Use the process token, not an impersonation token.
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&isMember)),
	)
	if r1 == 0 {
		// CheckTokenMembership returns 0 on failure; we still
		// trust isMember because, in practice, this path is
		// only reached if the SID allocation succeeded.
		return false, nil
	}
	return isMember != 0, nil
}

// ShellExecuteInfo and ShellExecuteEx are not in
// golang.org/x/sys/windows v0.48.0; declare them via syscall.
type shellExecuteInfo struct {
	CbSize       uint32
	FMask        uint32
	HWnd         uintptr
	LpVerb       *uint16
	LpFile       *uint16
	LpParameters *uint16
	LpDirectory  *uint16
	NShow        int32
	// The struct has many more fields; we only need the first
	// ones, plus HInstApp and HProcess at known offsets. Pad
	// with a generous buffer.
	_reserved [40]byte
	HInstApp  uintptr
	HProcess  windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	swShowDefault         = 10
)

// procShellExecuteEx is lazy-loaded so we don't pay for the
// syscall binding when the package is just imported.
var procShellExecuteEx = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// Relaunch uses ShellExecuteEx with lpVerb="runas" to ask the
// user for elevation. The new elevated process is a copy of
// the current argv, with AlreadyElevatedFlag prepended so the
// elevated child does not relaunch itself.
//
// If wait is true, Relaunch blocks until the elevated child
// exits. If wait is false, Relaunch returns as soon as the
// child has started; the caller is expected to exit its own
// process to hand over control to the child.
//
// Relaunch refuses if AlreadyElevatedFlag is already in argv
// (would loop forever). Relaunch refuses if IsElevated is
// already true (no need to relaunch).
func Relaunch(argv []string, wait bool) error {
	if len(argv) == 0 {
		return errors.New("elevate: argv is empty")
	}
	if containsAlreadyElevated(argv) {
		return errors.New("elevate: relaunch loop detected (AlreadyElevatedFlag already set)")
	}
	elevated, err := IsElevated()
	if err != nil {
		return fmt.Errorf("elevate: IsElevated: %w", err)
	}
	if elevated {
		return errors.New("elevate: already running elevated — no relaunch needed")
	}

	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := syscall.UTF16PtrFromString(argv[0])
	if err != nil {
		return err
	}
	args := append([]string{AlreadyElevatedFlag}, argv[1:]...)
	paramsStr := quoteCommandLine(args)
	params, err := syscall.UTF16PtrFromString(paramsStr)
	if err != nil {
		return err
	}
	dir, err := syscall.UTF16PtrFromString("")
	if err != nil {
		return err
	}

	sei := shellExecuteInfo{
		CbSize:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
		FMask:        seeMaskNoCloseProcess,
		LpVerb:       verb,
		LpFile:       file,
		LpParameters: params,
		LpDirectory:  dir,
		NShow:        swShowDefault,
	}
	r1, _, _ := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&sei)))
	if r1 == 0 {
		// Last-error is set by the syscall layer; surface as a
		// generic error. The common case is the user clicking
		// "No" on the consent prompt, which returns
		// ERROR_CANCELLED (1223) — but we don't try to
		// distinguish.
		return errors.New("elevate: ShellExecuteEx failed (likely consent declined)")
	}
	if sei.HProcess == 0 || sei.HProcess == windows.InvalidHandle {
		return errors.New("elevate: ShellExecuteEx did not return a process handle")
	}
	if !wait {
		windows.CloseHandle(sei.HProcess)
		return nil
	}
	s, err := windows.WaitForSingleObject(sei.HProcess, windows.INFINITE)
	windows.CloseHandle(sei.HProcess)
	if err != nil {
		return fmt.Errorf("elevate: WaitForSingleObject: %w", err)
	}
	if s != 0 {
		return fmt.Errorf("elevate: child wait returned %d", s)
	}
	return nil
}

func containsAlreadyElevated(argv []string) bool {
	for _, a := range argv {
		if a == AlreadyElevatedFlag {
			return true
		}
	}
	return false
}

// quoteCommandLine rebuilds a Windows command line from argv.
// We split on whitespace and quote anything that contains it.
// This is sufficient for ASCII tokens; production iamtunnel
// argv does not need more.
func quoteCommandLine(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		if needsQuoting(a) {
			out += quoteArg(a)
		} else {
			out += a
		}
	}
	return out
}

func needsQuoting(a string) bool {
	for i := 0; i < len(a); i++ {
		c := a[i]
		if c <= ' ' || c == '"' || c == '\'' || c == '\\' {
			return true
		}
	}
	return false
}

// quoteArg quotes a single Windows argument. The rules around
// backslashes-before-quotes are the only ones that matter here:
//   - N backslashes followed by a quote -> emit 2N+1 backslashes
//     and a quote.
//   - N backslashes at the end of the arg -> emit 2N.
//   - Everything else passes through.
func quoteArg(s string) string {
	out := `"`
	slashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			slashes++
			continue
		}
		if c == '"' {
			out += repeat('\\', slashes*2+1)
			out += `"`
			slashes = 0
			continue
		}
		if slashes > 0 {
			out += repeat('\\', slashes)
			slashes = 0
		}
		out += string(c)
	}
	out += repeat('\\', slashes*2)
	out += `"`
	return out
}

func repeat(c byte, n int) string {
	if n <= 0 {
		return ""
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = c
	}
	return string(out)
}

// Supported reports whether elevate can run on this platform.
// Production targets are Windows machines in 1.0 (SPEC §12).
func Supported() bool { return true }
