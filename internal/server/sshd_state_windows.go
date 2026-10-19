//go:build windows

package server

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SSHDServiceState reports the local OpenSSH Server service as the window
// shows it: "missing" when Windows has no sshd service at all, "stopped"
// when it is installed and not running, "running", or "" when the answer
// could not be had. Querying a service's status needs no administrator
// rights, so an ordinary window can say this before START is pressed
// (1.52: a server without OpenSSH was only told so by START's failure).
func SSHDServiceState() string {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return ""
	}
	defer windows.CloseServiceHandle(scm)
	name, err := windows.UTF16PtrFromString("sshd")
	if err != nil {
		return ""
	}
	svc, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return "missing"
		}
		return ""
	}
	defer windows.CloseServiceHandle(svc)
	var ssp windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if err := windows.QueryServiceStatusEx(svc, windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&ssp)), uint32(unsafe.Sizeof(ssp)), &needed); err != nil {
		return ""
	}
	if ssp.CurrentState == windows.SERVICE_RUNNING {
		return "running"
	}
	return "stopped"
}
