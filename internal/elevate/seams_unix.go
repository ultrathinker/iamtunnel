//go:build linux || darwin

// Seams for the Linux/Darwin elevation layer.
//
// userLookupFn is the package-level seam VerifyOSUser reaches
// for. Production default is os/user.Lookup; tests install a
// fake via init() in elevate_unix_test.go. There is no
// exported setter and the production lookup is reached only
// after the fake has had a chance to substitute itself; the
// gate mirrors the discipline winkeys/doors_unix.go applies
// to chmodFn / chownFn.

package elevate

import "os/user"

// userLookupFn is the seam for os/user.Lookup. The production
// default delegates straight through; tests install a fake in
// init() so the test binary never touches /etc/passwd,
// libnss-mysql, LDAP or sssd.
var userLookupFn = func(name string) (*user.User, error) {
	return user.Lookup(name)
}
