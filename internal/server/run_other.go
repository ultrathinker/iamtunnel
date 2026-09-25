//go:build !windows && !linux && !darwin

// Stub for the Unixes this product does not implement the sshd
// pre-flight for (FreeBSD, OpenBSD, NetBSD, illumos, …). Linux has its
// implementation in run_linux.go (systemctl + sshd -T); macOS has its
// own in run_darwin.go (launchctl + sshd -T, IAMT-263); Windows has
// run_windows.go (SCM). This file is what is left: the explicit
// "not this platform" answer, so a launch on an unimplemented Unix
// refuses loudly instead of silently skipping the pre-flight.
//
// ErrServiceCheckNotApplicable is returned rather than a hard
// refusal, because the TCP dial in CheckSSHD still runs afterwards and
// is the real gate: a build that ends up on an unimplemented Unix gets
// the dial's verdict, not a "we do not know how to ask your init
// system" dead end. ErrServiceCheckNotApplicable keeps that visible to
// the caller.
package server

import "testing"

// sshdStartHint is the "how do I switch the daemon on" sentence
// CheckSSHD puts in its dial-failure text when 127.0.0.1:22 does not
// answer (run.go). This platform has no implementation to name a
// mechanism after, so it carries the neutral sentence the message has
// always used.
const sshdStartHint = "start OpenSSH Server and retry"

// defaultCheckSSHDService is the unimplemented-Unix stub.
func defaultCheckSSHDService() error {
	if testing.Testing() {
		panic("server: defaultCheckSSHDService invoked in test binary on unsupported Unix")
	}
	return ErrServiceCheckNotApplicable
}

// checkSSHDConfigPlatform is the unimplemented-Unix half of the
// dispatcher: there is no sshd -T pre-flight here, so the question is
// not applicable and the answer is nil — cmd/iamtunnel's production
// path can call it without runtime.GOOS branching, exactly as it does
// on Windows (run_windows.go), and the dial in CheckSSHD remains the
// gate.
func checkSSHDConfigPlatform(_ string, _ func(string) error) error {
	return nil
}
