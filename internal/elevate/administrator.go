package elevate

import (
	"fmt"
	"strings"
)

// builtinAdministratorsSID identifies the local Administrators group even
// when its display name is localised or has been renamed by an administrator.
const builtinAdministratorsSID = "S-1-5-32-544"

// AccountNotFoundError tells an owner that the named Windows account cannot
// be found. It is deliberately distinct from NotAdministratorError: one is a
// spelling or identity problem, the other is a permissions problem.
type AccountNotFoundError struct{ Account string }

func (e *AccountNotFoundError) Error() string {
	return fmt.Sprintf("Windows account %q does not exist; check the DOMAIN\\name or MACHINE\\name spelling", e.Account)
}

// NotAdministratorError tells an owner that an existing Windows account is
// not a member of the local Administrators group. The caller must not try to
// repair that by changing the account or group; granting rights is outside
// this read-only check.
type NotAdministratorError struct{ Account string }

func (e *NotAdministratorError) Error() string {
	return fmt.Sprintf("Windows account %q is not a local administrator; add the intended account to Administrators before opening access", e.Account)
}

// administratorVerifier owns the decision over one membership query. The
// source is supplied at construction so tests can use fixed observations;
// there is no package variable, environment switch, or exported setter that
// could disable the check in production.
type administratorVerifier struct {
	groupsForAccount func(string) ([]string, error)
}

func newAdministratorVerifier(groupsForAccount func(string) ([]string, error)) administratorVerifier {
	return administratorVerifier{groupsForAccount: groupsForAccount}
}

func (v administratorVerifier) verify(account string) error {
	if !validAccountName(account) {
		return fmt.Errorf("windows account %q must be exactly DOMAIN\\name or MACHINE\\name; bare names, .\\name, UPNs, and SID strings are rejected to avoid ambiguity", account)
	}
	groups, err := v.groupsForAccount(account)
	if err != nil {
		return err
	}
	for _, sid := range groups {
		if strings.EqualFold(sid, builtinAdministratorsSID) {
			return nil
		}
	}
	return &NotAdministratorError{Account: account}
}

// validAccountName is intentionally the same narrow, unambiguous grammar as
// the machine's persisted osUser value: DOMAIN\\name or MACHINE\\name. A
// bare name depends on the local/domain lookup order, .\\name changes its
// meaning with the host, UPN is a different naming authority, and an SID is
// not an account name accepted by the protocol.
func validAccountName(account string) bool {
	domain, name, ok := strings.Cut(account, `\`)
	if !ok || domain == "" || name == "" || strings.Contains(name, `\`) {
		return false
	}
	return validAccountPart(domain) && validAccountPart(name)
}

func validAccountPart(part string) bool {
	if len(part) == 0 || len(part) > 64 {
		return false
	}
	for i := 0; i < len(part); i++ {
		c := part[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == '@', c == '$':
		default:
			return false
		}
	}
	return true
}
