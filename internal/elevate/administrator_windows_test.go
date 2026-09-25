//go:build windows

package elevate

import (
	"errors"
	"os/user"
	"strings"
	"testing"
)

// TestVerifyAdministratorReadsExistingAndMissingAccounts exercises the real
// read-only Windows API without creating an account or editing a group.
func TestVerifyAdministratorReadsExistingAndMissingAccounts(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("current Windows account: %v", err)
	}
	if !validAccountName(current.Username) {
		t.Skipf("Windows user.Current returned %q, not the protocol's DOMAIN\\name form", current.Username)
	}
	if err := VerifyAdministrator(current.Username); err != nil {
		var missing *AccountNotFoundError
		if errors.As(err, &missing) {
			t.Fatalf("existing current account %q was reported missing", current.Username)
		}
		var notAdmin *NotAdministratorError
		if !errors.As(err, &notAdmin) {
			t.Fatalf("read current account %q: %v", current.Username, err)
		}
	}

	parts := strings.SplitN(current.Username, `\`, 2)
	missingName := parts[0] + `\iamtunnel-account-that-does-not-exist-96`
	err = VerifyAdministrator(missingName)
	var missing *AccountNotFoundError
	if !errors.As(err, &missing) {
		t.Fatalf("missing account %q error = %v, want AccountNotFoundError", missingName, err)
	}
}
