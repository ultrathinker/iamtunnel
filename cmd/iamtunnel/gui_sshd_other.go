//go:build (linux || darwin) && !nogui

package main

import "errors"

// guiPrepareSSHD exists on Windows only (gui_sshd_windows.go): there the
// window can tell OpenSSH Server is missing and install it. Elsewhere the
// window never learns that (server.SSHDServiceState answers ""), so the
// prompt that calls this never opens; the hook is wired for completeness.
func guiPrepareSSHD() (string, error) {
	return "", errors.New("OpenSSH Server comes with this system: install openssh-server with the package manager (Linux), or turn on Remote Login in System Settings → General → Sharing (macOS)")
}
