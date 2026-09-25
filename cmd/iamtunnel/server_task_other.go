//go:build !windows

// server_task_other.go — refusing stubs of the logon-task seam for
// non-Windows builds (IAMT-337). runServerInstall/cmdServerUninstall
// switch on runtime.GOOS and never route here; the stubs answer with an
// error so a routing mistake is visible instead of passing silently —
// the same arrangement as gateway_service_other.go.

package main

import "errors"

// errNoTaskScheduler is what every stub answers: only a routing error can
// reach them.
var errNoTaskScheduler = errors.New("the Windows logon-task seam is wired only on windows builds")

var windowsTasks = logonTaskSetup{
	createTask: func(string, string) error { return errNoTaskScheduler },
	taskExists: func(string) (bool, error) { return false, errNoTaskScheduler },
	deleteTask: func(string) error { return errNoTaskScheduler },
	runTask:    func(string) error { return errNoTaskScheduler },
}
