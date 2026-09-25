//go:build (windows || linux || darwin) && !nogui

package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// exemptFromUIActionsWiring lists the ui.Actions fields that are
// legitimately never assigned by a gui_<os>.go literal:
//
//   - Repaint is wired by ui.Run itself (it passes the window's own
//     Invalidate), not by any gui_<os>.go literal.
//   - AdminGrant is superseded by AdminGrantWithCaps, which every
//     gui_<os>.go assigns instead; the field stays on ui.Actions only for
//     embedders that predate capability selection.
//
// Nothing else belongs on this list. review19 finding 2 is exactly what
// happens when a hook is added to ui.Actions (internal/ui/live.go) and
// nobody threads it through the three gui_<os>.go files: internal/ui's own
// tests stay green because they inject their own Actions, and the gap is
// invisible until a real build's button prints "this build has no runtime
// wired". This test reads the three OS-specific literals as plain text
// (not via a build-tagged import, so it runs and catches the gap
// regardless of which OS built the test binary) and fails for any
// exported ui.Actions field whose name never appears there.
var exemptFromUIActionsWiring = map[string]bool{
	"Repaint":    true,
	"AdminGrant": true,
}

func TestEveryUIActionIsWired(t *testing.T) {
	typ := reflect.TypeOf(ui.Actions{})

	// EACH file, not the three concatenated.
	//
	// Concatenating them asks "is this hook wired ANYWHERE", and that is
	// not the question. The gap that review19 finding 2 describes — a hook
	// added to ui.Actions and threaded nowhere — is caught either way, but
	// it is not the gap most likely to happen NEXT. That one is a hook
	// wired in gui_windows.go, where it was developed and tried, and
	// forgotten in the other two: Linux and macOS then ship a button that
	// silently performs nothing, and only an owner on that platform finds
	// out. A union check is blind to exactly that, and this test was: it
	// stayed green with AdminSetClassifierKey deleted from gui_windows.go.
	for _, name := range []string{"gui_windows.go", "gui_linux.go", "gui_darwin.go"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(raw)

		var missing []string
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() || exemptFromUIActionsWiring[field.Name] {
				continue
			}
			// ":" excludes a field merely mentioned in a comment or another
			// identifier's prefix (e.g. AdminGrant is a prefix of
			// AdminGrantGoal) from counting as wired.
			if !strings.Contains(src, field.Name+":") {
				missing = append(missing, field.Name)
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s assigns no runtime for these ui.Actions hooks: %v — "+
				"on that platform every one of their buttons answers "+
				"\"this build has no runtime wired\" and does nothing", name, missing)
		}
	}
}
