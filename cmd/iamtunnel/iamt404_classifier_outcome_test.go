//go:build (windows || linux || darwin) && !nogui

package main

// IAMT-404 canary: the window reads the risk.key refusal's category
// FIELD when the gateway names one, and falls back to the prose only
// for a gateway that predates the field. While the decision reads the
// sentence first, a gateway that says "unavailable" in the field but
// uses the word "rejected" in its prose would flip the outcome — the
// exact fragility this card exists to retire, kept alive in miniature.

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/admin"
)

func TestIAMT404_TheWindowTrustsTheCategoryFieldOverThePhrase(t *testing.T) {
	cases := []struct {
		name string
		ce   *admin.CommandError
		want string
	}{
		{
			"the field says refused without the phrase",
			&admin.CommandError{Code: "E_RISK_KEY_REJECTED", Message: "the service declined this key", Category: "rejected"},
			"refused",
		},
		{
			"the field wins over a prose that happens to say rejected",
			&admin.CommandError{Code: "E_RISK_KEY_REJECTED", Message: "new key rejected by the classifier service (HTTP 503)", Category: "unavailable"},
			"unavailable",
		},
		{
			"a gateway before the field: the phrase still reads refused",
			&admin.CommandError{Code: "E_RISK_KEY_REJECTED", Message: "new key rejected by the classifier service (HTTP 401; key invalid or expired)"},
			"refused",
		},
		{
			"a gateway before the field: other prose reads unavailable",
			&admin.CommandError{Code: "E_RISK_KEY_REJECTED", Message: "classifier service unavailable while probing the new key (HTTP 503)"},
			"unavailable",
		},
		{
			"the field says refused with no prose at all",
			&admin.CommandError{Code: "E_RISK_KEY_REJECTED", Category: "rejected"},
			"refused",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifierKeyOutcome(tc.ce); got != tc.want {
				t.Fatalf("classifierKeyOutcome(category=%q, message=%q) = %q, want %q (IAMT-404)", tc.ce.Category, tc.ce.Message, got, tc.want)
			}
		})
	}
}
