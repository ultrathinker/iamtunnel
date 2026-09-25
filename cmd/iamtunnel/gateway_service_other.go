//go:build !windows

// gateway_service_other.go — service seam stubs for non-Windows builds
// (SPEC §3.5.1 — the Windows half of install/uninstall). The routing in
// runGatewayInstall/cmdGatewayUninstall switches on runtime.GOOS and
// never reaches here; the stubs return an error so a routing mistake is
// visible instead of passing silently. The exception is
// runGatewayServiceIfSCM: a non-Windows process is never under SCM, so
// "gateway run" always takes the signal path.

package main

import (
	"errors"
	"io"
	"path/filepath"
	"runtime"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// errNotWindows is every stub's answer: the stubs are reachable only
// through a GOOS routing mistake.
var errNotWindows = errors.New("the Windows service seam is wired only on windows builds")

var windowsService = windowsServiceSetup{
	serviceExists:  func(string) (bool, error) { return false, errNotWindows },
	createService:  func(gatewayServiceSpec) error { return errNotWindows },
	changeService:  func(gatewayServiceSpec) error { return errNotWindows },
	startService:   func(string) error { return errNotWindows },
	serviceRunning: func(string) (bool, error) { return false, errNotWindows },
	waitRunning:    func(string) (bool, error) { return false, errNotWindows },
	stopService:    func(string) error { return errNotWindows },
	deleteService:  func(string) error { return errNotWindows },
	hardenDir:      func(string, bool, io.Writer) (func(), error) { return nil, errNotWindows },
	hardenExeDir:   func(string, string, bool, io.Writer) error { return errNotWindows },
}

func runGatewayServiceIfSCM(dir string, settings config.Settings) (bool, error) {
	return false, nil
}

func runningGatewayServicePort() (int, error) {
	switch runtime.GOOS {
	case "linux":
		data, err := datafile.ReadFile(filepath.Join(systemdUnitDir, gatewayUnitName))
		if err != nil {
			return 0, err
		}
		return parseGatewayServicePort(string(data))
	case "darwin":
		data, err := datafile.ReadFile(darwinPlistPath)
		if err != nil {
			return 0, err
		}
		return parseGatewayPlistPort(string(data))
	default:
		return 0, errors.New("gateway service port is unavailable on this operating system")
	}
}
