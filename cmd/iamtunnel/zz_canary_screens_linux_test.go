//go:build linux && !nogui

package main

// The canary: the window has ONE dictionary of screens, not three.
//
// On 21.09.2026 the maintainer asked for snapshots of ALL screens. It
// turned out they could not be taken: "shot" knew five names (setup,
// client, server, admin, settings), --tab knew six (the same plus
// session), and the window had eight. Guide — the first screen a new
// person sees — and History, added the same day, could not be opened by
// any of the doors.
//
// The hole appeared quietly and lived long: the lists were maintained by
// hand, tabs were added later, and nothing crashed over a name that was
// never entered. It starts crashing here.

import (
	"sort"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/ui"
)

func TestCanary_EveryTabIsReachableByName(t *testing.T) {
	// All of the window's tabs, as internal/ui itself declares them.
	tabs := []string{
		ui.TabGuide, ui.TabSetUp, ui.TabClient, ui.TabServer,
		ui.TabGateway, ui.TabSession, ui.TabAdmin, ui.TabHistory,
		ui.TabSettings,
	}

	// 1. Every tab is reachable through --tab.
	covered := map[string]bool{}
	for _, header := range guiTabNames {
		covered[header] = true
	}
	for _, tab := range tabs {
		if !covered[tab] {
			t.Errorf("tab %q is unreachable through --tab: it is not in guiTabNames. "+
				"That is exactly how Guide and History ended up without a door", tab)
		}
	}
	if len(guiTabNames) != len(tabs) {
		t.Errorf("guiTabNames knows %d names but there are %d tabs — a list maintained by "+
			"hand falls behind silently", len(guiTabNames), len(tabs))
	}

	// 2. And through shot — with the very same set of names. Two
	// different dictionaries mean the same window is called differently
	// depending on which door you enter it by.
	shot := config.ScreenNames()
	sort.Strings(shot)
	flags := make([]string, 0, len(guiTabNames))
	for name := range guiTabNames {
		flags = append(flags, name)
	}
	sort.Strings(flags)
	if len(shot) != len(flags) {
		t.Fatalf("shot accepts %v but --tab %v — the dictionaries have drifted apart", shot, flags)
	}
	for i := range shot {
		if shot[i] != flags[i] {
			t.Errorf("shot accepts %q where --tab accepts %q — "+
				"the window must have ONE dictionary of names", shot[i], flags[i])
		}
	}

	// 3. And every name really is parsed by both sides.
	for name := range guiTabNames {
		if _, err := config.ParseScreen(name); err != nil {
			t.Errorf("shot does not accept %q although --tab does: %v", name, err)
		}
	}
}
