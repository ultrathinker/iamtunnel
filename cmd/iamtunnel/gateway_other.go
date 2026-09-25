//go:build !windows

// gateway_other.go — non-Windows stubs for gateway-install helpers
// defined in gateway_windows.go. The gateway install path on non-Windows
// hosts goes through a different seam (Linux: setupSystemd / systemdSetup;
// macOS: setupLaunchdDaemon / darwinLaunchd) and has no ACL concept,
// so the IAMT-315 preflight is a no-op on those platforms: there is no
// "foreign ACCESS_DENIED ACE" to refuse on, and the DACL hardening
// path does not run.
//
// The runGatewayInstall call site in gateway.go is wrapped in a
// `runtime.GOOS == "windows"` guard, so this no-op stub is what the
// unix build sees if any future caller (test, future flag path, etc.)
// ends up referencing the symbol — keeping the symbol defined on
// every platform matches the winkeys.LockDownFileACL pattern, where
// the unix stub accepts the same replaceACL parameter and ignores it.

package main

import "io"

// preflightGatewayACL is the non-Windows stub of the IAMT-315 ACL
// preflight. There is no DACL on Unix, no ACCESS_DENIED ACE to refuse
// on, and the unix install paths do not call hardenGatewayDirACL or
// hardenGatewayExeACL — the install just chmods the data dir and
// writes a unit file (Linux) or a plist (macOS). Always returns nil
// so the symbol resolves on every platform; the platform-specific
// implementation lives in gateway_windows.go (//go:build windows)
// and is what runGatewayInstall's `runtime.GOOS == "windows"` branch
// actually calls on Windows. report is ignored on non-Windows
// builds; see the Windows implementation for why every call carries
// one.
func preflightGatewayACL(_, _ string, _ bool, _ io.Writer) error {
	return nil
}
