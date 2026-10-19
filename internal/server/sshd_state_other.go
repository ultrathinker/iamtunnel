//go:build !windows

package server

// SSHDServiceState is Windows-only (sshd_state_windows.go): elsewhere
// the window has nothing to add to what the running agent reports.
func SSHDServiceState() string { return "" }
