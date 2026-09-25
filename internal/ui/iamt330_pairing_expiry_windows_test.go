//go:build windows

package ui

// iamt330_pairing_expiry_windows_test.go — the render half of the expired
// pairing-window fix (IAMT-330): a card whose stored window has lapsed
// must lay out with the PIN hidden — the smoke render pins that the
// expired card draws without complaint in both themes, while
// iamt330_pairing_expiry_test.go pins the fact arithmetic itself.

import (
	"strings"
	"testing"
	"time"
)

func TestAdminScreenRendersAnExpiredPairingWindow(t *testing.T) {
	lapsed := exampleSnapshot()
	lapsed.Admin.Pairing = &PairingWindow{
		Pin:     "012345",
		Ref:     "gw.example.net:2022#" + strings.Repeat("A", 43),
		Expires: time.Now().Add(-time.Minute),
	}
	for _, dark := range []bool{false, true} {
		renderFrame(t, renderCfg{screen: "admin", dark: dark, rights: true, snap: lapsed})
	}
}
