//go:build !darwin

package main

// gateway_launchd_stub.go — macOS seam stubs for non-darwin builds:
// the darwin branch is selected only on darwin, so the stubs are
// reachable only through a GOOS routing mistake.

import (
	"errors"
	"os"
)

// errNotDarwin is every stub's answer: the stubs are reachable only
// through a GOOS routing mistake. It is declared here, in the only file
// that uses it: on darwin the stub is switched off by the build tag, and
// a declaration in the platform-neutral gateway_launchd.go would sit
// unused (IAMT-259,
// staticcheck U1000 would flag it).
var errNotDarwin = errors.New("the macOS launchd seam is wired only on darwin builds")

var darwinLaunchd = darwinLaunchdSetup{
	currentUserIsRoot: func() (bool, error) { return false, errNotDarwin },
	makeLogDir:        func(path string) error { return errNotDarwin },
	lookupUser:        func(name string) (int, bool, error) { return 0, false, errNotDarwin },
	systemUIDsTaken:   func() (map[int]bool, error) { return nil, errNotDarwin },
	createUser:        func(spec darwinServiceUserSpec) error { return errNotDarwin },
	chownDir:          func(path string, uid, gid int) error { return errNotDarwin },
	writePlist:        func(path string, content []byte, mode os.FileMode, uid, gid int) error { return errNotDarwin },
	plistExists:       func(path string) (bool, error) { return false, errNotDarwin },
	removePlist:       func(path string) error { return errNotDarwin },
	exeWriters:        func(bin string) ([]string, error) { return nil, errNotDarwin },
	serviceLoaded:     func(label string) (bool, error) { return false, errNotDarwin },
	bootout:           func(label string) (bool, error) { return false, errNotDarwin },
	bootstrap:         func(plistPath string) error { return errNotDarwin },
	serviceRunning:    func(label string) (bool, error) { return false, errNotDarwin },
	parentTraversable: func(dataDir string, uid, gid int) error { return errNotDarwin },
	ancestorsAreSafe:  func(dataDir string) error { return errNotDarwin },
	leafIsSafe:        func(dataDir string, serviceUID int) error { return errNotDarwin },
}
