//go:build windows

package server

import (
	"fmt"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// pinTesting keeps the testing import live on every Windows
// build where the symbol is otherwise unreferenced; Go trips
// an "imported and not used" error otherwise.
var _ = testing.Testing

// sshdStartHint is the "how do I switch the daemon on" sentence
// CheckSSHD puts in its dial-failure text when 127.0.0.1:22 does not
// answer (run.go). On Windows the daemon is the OpenSSH Server SCM
// service, so the sentence is the one this message has always carried.
const sshdStartHint = "start OpenSSH Server and retry"

// checkSSHDConfigPlatform is the Windows half of the dispatcher.
// Windows does not need sshd -T — sshd reads the well-known
// %ProgramData%\ssh\administrators_authorized_keys file the
// machine controls directly, so the "is the path configured
// correctly" question is moot. The function returns nil so
// cmd/iamtunnel's "server start" can call it unconditionally
// without having to branch on runtime.GOOS.
func checkSSHDConfigPlatform(_ string, _ func(string) error) error {
	return nil
}

// defaultCheckSSHDService queries the Windows Service Control Manager to verify
// that the "sshd" service is running (SPEC §3.2: QueryServiceStatusEx).
func defaultCheckSSHDService() error {
	if testing.Testing() {
		panic("server: defaultCheckSSHDService invoked in test binary; tests must never access real Windows SCM")
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("open service control manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	svcName, err := windows.UTF16PtrFromString("sshd")
	if err != nil {
		return fmt.Errorf("encode service name: %w", err)
	}

	svc, err := windows.OpenService(scm, svcName, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return fmt.Errorf("sshd service not found or cannot be queried: %w", err)
	}
	defer windows.CloseServiceHandle(svc)

	var ssp windows.SERVICE_STATUS_PROCESS
	var bytesNeeded uint32
	err = windows.QueryServiceStatusEx(
		svc,
		windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&ssp)),
		uint32(unsafe.Sizeof(ssp)),
		&bytesNeeded,
	)
	if err != nil {
		return fmt.Errorf("QueryServiceStatusEx: %w", err)
	}
	if ssp.CurrentState != windows.SERVICE_RUNNING {
		return fmt.Errorf("sshd service is not running (state=%d)", ssp.CurrentState)
	}
	return nil
}
