package elevate

import (
	"errors"
	"strings"
	"testing"
)

func TestAdministratorVerifierAcceptsAdministratorsBySID(t *testing.T) {
	called := ""
	v := newAdministratorVerifier(func(account string) ([]string, error) {
		called = account
		// The display name intentionally is absent: the decision must rest
		// on the well-known SID, which survives renaming and localisation.
		return []string{"S-1-5-21-123-456-789-1001", "s-1-5-32-544"}, nil
	})
	if err := v.verify(`CORP\alice`); err != nil {
		t.Fatalf("administrator was refused: %v", err)
	}
	if called != `CORP\alice` {
		t.Fatalf("query received %q, want exact account", called)
	}
}

func TestAdministratorVerifierRefusesNonAdministrator(t *testing.T) {
	v := newAdministratorVerifier(func(string) ([]string, error) {
		return []string{"S-1-5-32-545"}, nil
	})
	err := v.verify(`MACHINE\operator`)
	var notAdmin *NotAdministratorError
	if !errors.As(err, &notAdmin) {
		t.Fatalf("non-administrator error = %v, want NotAdministratorError", err)
	}
	if notAdmin.Account != `MACHINE\operator` || !strings.Contains(err.Error(), "not a local administrator") {
		t.Fatalf("refusal is not actionable: %+v", notAdmin)
	}
}

func TestAdministratorVerifierDistinguishesMissingAccount(t *testing.T) {
	v := newAdministratorVerifier(func(account string) ([]string, error) {
		return nil, &AccountNotFoundError{Account: account}
	})
	err := v.verify(`MACHINE\does-not-exist`)
	var missing *AccountNotFoundError
	if !errors.As(err, &missing) {
		t.Fatalf("missing account error = %v, want AccountNotFoundError", err)
	}
	if strings.Contains(err.Error(), "not a local administrator") {
		t.Fatalf("missing account was misreported as a permissions problem: %v", err)
	}
}

func TestAdministratorVerifierRejectsAmbiguousAccountForms(t *testing.T) {
	v := newAdministratorVerifier(func(string) ([]string, error) {
		t.Fatal("membership lookup must not run for an ambiguous account form")
		return nil, nil
	})
	for _, account := range []string{
		"user", `\.\user`, `DOMAIN\user\extra`, "user@example.test", "S-1-5-21-1-2-3-4", "", `DOMAIN\`, `\user`,
	} {
		if err := v.verify(account); err == nil {
			t.Errorf("verify(%q) accepted an ambiguous account form", account)
		}
	}
}
