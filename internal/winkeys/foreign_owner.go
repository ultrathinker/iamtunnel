package winkeys

import "fmt"

// ForeignOwnerRefusalError is the refusal to lock down an object whose
// owner is not trusted (R2-CX F-07, F-13): an owner can always rewrite an
// object's DACL, so whatever DACL a lockdown sets, the owner could open
// it again. Platform-neutral, like ForeignDenyRefusalError, so callers
// can recognise it with errors.As on every build.
type ForeignOwnerRefusalError struct {
	Path string
	// Owner names the owner: "DOMAIN\name (SID)", or the SID alone when
	// the account cannot be named.
	Owner string
}

func (e *ForeignOwnerRefusalError) Error() string {
	return fmt.Sprintf("%s is owned by %s, which is neither Administrators, SYSTEM nor the account running this - "+
		"and an owner can always rewrite the permissions, so it would stay theirs to reopen however they are locked. "+
		"Create it from an elevated console, or take it over first (takeown /f \"%s\" /r /a), and repeat",
		e.Path, e.Owner, e.Path)
}
