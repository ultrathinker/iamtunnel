//go:build !windows && !linux && !darwin

// Stub for Unixes that are not Linux or Darwin. VerifyOSUser is
// defined for Linux/Darwin in elevate_unix.go; VerifyAdministrator
// has no portable equivalent off Windows — only a Linux analogue,
// the user-exists check, is needed, not a generic Unix analogue that
// would need a build tag for every flavour.

package elevate

import "errors"

// VerifyAdministrator is unavailable off Windows because Windows local group
// membership has no portable equivalent. Production server startup is already
// refused on non-Windows; keeping the explicit error makes accidental use
// visible to callers and preserves cross-platform builds.
func VerifyAdministrator(string) error {
	return errors.New("windows account administrator verification is supported only on Windows")
}
