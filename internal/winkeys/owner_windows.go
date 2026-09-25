//go:build windows

package winkeys

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// trustedOwnerSIDs may own an object before a lockdown hands it to
// Administrators (R2-CX F-07, F-13): Administrators, SYSTEM and
// TrustedInstaller, besides the account running this process and the
// caller's own extra (the gateway's service account, whose files its data
// directory holds).
var trustedOwnerSIDs = []string{
	"S-1-5-32-544", // BUILTIN\Administrators
	"S-1-5-18",     // NT AUTHORITY\SYSTEM
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // NT SERVICE\TrustedInstaller
}

// OwnerTrusted reports whether owner may own an object that is about to
// be locked down: one of trustedOwnerSIDs, the account running this
// process, or one of extra.
func OwnerTrusted(owner *windows.SID, extra ...*windows.SID) bool {
	if owner == nil {
		return false
	}
	for _, s := range trustedOwnerSIDs {
		if sid, err := windows.StringToSid(s); err == nil && owner.Equals(sid) {
			return true
		}
	}
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && owner.Equals(u.User.Sid) {
		return true
	}
	for _, sid := range extra {
		if sid != nil && owner.Equals(sid) {
			return true
		}
	}
	return false
}

// refuseForeignOwnerIn refuses with *ForeignOwnerRefusalError when the
// owner in sd, the descriptor of path read through the handle about to
// lock it, is one OwnerTrusted says no to (R2-CX F-07, F-13). A lockdown
// that replaced the DACL and kept such an owner left the object theirs:
// an owner can always rewrite the DACL. A read that fails is an error,
// never a pass.
func refuseForeignOwnerIn(path string, sd *windows.SECURITY_DESCRIPTOR, extra []*windows.SID) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read the owner of %s: %w", path, err)
	}
	if OwnerTrusted(owner, extra...) {
		return nil
	}
	return &ForeignOwnerRefusalError{Path: path, Owner: describeSID(owner)}
}

// describeSID is "DOMAIN\name (SID)", or the SID alone.
func describeSID(sid *windows.SID) string {
	if sid == nil {
		return "nobody"
	}
	if name := resolveSIDName(sid); name != "" {
		return name + " (" + sid.String() + ")"
	}
	return sid.String()
}

// AdministratorsSID is BUILTIN\Administrators, the owner every locked-down
// object gets.
func AdministratorsSID() *windows.SID {
	return mustSID("S-1-5-32-544")
}
