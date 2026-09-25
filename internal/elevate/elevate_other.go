//go:build !windows && !darwin && !linux

// Stub for Unixes that are not Linux or Darwin (FreeBSD,
// OpenBSD, …). The platform layer there is not in scope for
// SPEC §3.2.1, which names linux and darwin explicitly; a
// build that ends up on any other Unix gets an explicit
// refusal rather than a silent "always false" answer that
// could let `server start` claim it is running with rights it
// does not actually have.
package elevate

import "errors"

// IsElevated is a stub: returns false so production code that
// is mistakenly run on an unsupported Unix refuses to do
// anything privileged. SPEC §3.2.1 names Linux and Darwin only.
func IsElevated() (bool, error) { return false, nil }

// Relaunch returns an error. There is no elevation primitive on
// FreeBSD / OpenBSD that iamtunnel knows how to drive.
func Relaunch(argv []string, wait bool) error {
	return errors.New("elevate: supported only on linux, darwin and windows")
}

// Supported reports whether elevate can run on this platform.
func Supported() bool { return false }

// AlreadyElevatedFlag is the argv marker the elevated parent
// prepends so the child does not relaunch itself.
const AlreadyElevatedFlag = "--elevated-child"

// VerifyOSUser refuses. The Linux/Darwin equivalent in
// elevate_unix.go looks the user up via os/user.Lookup (under
// a seam so tests do not touch the real database); on
// unsupported Unixes the lookup primitive would not be
// portable anyway, so the gate refuses explicitly.
func VerifyOSUser(_ string) error {
	return errors.New("elevate: VerifyOSUser is supported only on linux and darwin")
}
