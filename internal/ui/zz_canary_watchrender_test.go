package ui

// The maintainer's canaries: the transcript is text, and the Admin tab
// asks the gateway every time it is entered.
//
// Both found by the maintainer on 19.09.2026, in one message.
//
// 1. They pressed Watch and got a base64 screen. The gateway hands
//    out base64, and inside it is an asciicast: a header line and a
//    JSON array per screen write. Neither of those is text. The panel
//    decoded neither the base64 nor ran the record through a terminal
//    emulator, though the Session tab does exactly that.
//
// 2. "If I switch to the tab, that means I want to see the current
//    state." The list request was one-shot for the window's whole
//    lifetime.

import (
	"context"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// TestCanary_TheTranscriptIsRenderedNotDumped.
//
// Canary: feed the panel a raw asciicast without an emulator -- the
// text will contain `{"version"` or `[0.0`, that is, JSON instead of
// a screen.
func TestCanary_TheTranscriptIsRenderedNotDumped(t *testing.T) {
	f := newBareFrame(t)
	f.watchSession("session:1", "admin", "win-test-vm")
	if f.watch == nil || f.watch.vt == nil {
		t.Fatal("the watched session has no terminal emulator -- the record will be shown as is, that is, as JSON")
	}

	cast := []byte(`{"version":2,"width":80,"height":24}` + "\n" +
		`[0.1,"o","hello from the machine\r\n"]` + "\n")
	f.watch.remainder = record.ParseCast(cast, nil, f.watch.vt)

	got := f.watch.vt.Transcript()
	if got == "" {
		t.Fatal("the emulator rendered nothing from a well-formed record")
	}
	for _, leak := range []string{`{"version"`, `[0.1,`, `"o"`} {
		if strings.Contains(got, leak) {
			t.Errorf("asciicast markup is visible in the transcript (%q) -- it is being printed as is:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "hello from the machine") {
		t.Errorf("the transcript = %q, want the machine's output", got)
	}
}

// TestCanary_TheAdminTabAsksEveryTimeItIsEntered.
//
// Canary: restore the one-shot flag -- the test will catch the second
// entry, which asked nothing.
func TestCanary_TheAdminTabAsksEveryTimeItIsEntered(t *testing.T) {
	f := newBareFrame(t)
	asked := 0
	f.cfg.Actions.AdminList = func(ctx context.Context) (AdminLists, error) {
		asked++
		return AdminLists{}, nil
	}

	machinesAsked := 0
	f.cfg.Actions.Machines = func(ctx context.Context) ([]MachineAccess, error) {
		machinesAsked++
		return nil, nil
	}

	gtx := newTestLayoutContext(900, 600)
	admin := f.makeTabBody(TabAdmin)
	client := f.makeTabBody(TabClient)

	_ = admin(gtx)
	first := asked
	if first == 0 {
		t.Fatal("entering the Admin tab asked nothing")
	}
	_ = admin(gtx)
	if asked != first {
		t.Errorf("redrawing the same tab asked the gateway again -- that is a network call per frame (%d instead of %d)", asked, first)
	}

	// Away, and back.
	_ = client(gtx)
	if machinesAsked == 0 {
		t.Error("entering the Client tab did not refresh the machine list -- exactly what the maintainer found: the fix covered only Admin")
	}
	_ = admin(gtx)
	if asked <= first {
		t.Error("returning to the Admin tab did not ask the gateway -- the lists would show the state as of the window's first opening")
	}
}

// TestCanary_TheExcerptCannotSwallowThePage.
//
// Found by the maintainer on 19.09.2026: "there is no scroll, not a
// thing". The transcript was drawn in an unbounded box, and a session
// of any real length pushed everything below it off the bottom of the
// page -- including the buttons that stop this session. There was no
// scrollbar at all: the page simply ended.
//
// Canary: remove the height cap in the panel -- the section will grow
// with the transcript's length, and the test will see it.
func TestCanary_TheExcerptCannotSwallowThePage(t *testing.T) {
	f := newBareFrame(t)
	f.watchSession("session:1", "admin", "win-test-vm")

	short := []byte(`{"version":2,"width":80,"height":24}` + "\n" +
		`[0.1,"o","one line\r\n"]` + "\n")
	f.watch.remainder = record.ParseCast(short, nil, f.watch.vt)
	gtx := newTestLayoutContext(900, 4000)
	small := f.layoutLiveSection(gtx).Size.Y

	// Two hundred more lines must not make the section two hundred
	// lines taller.
	var long []byte
	for i := 0; i < 200; i++ {
		long = append(long, []byte(`[0.2,"o","a line of output\r\n"]`+"\n")...)
	}
	f.watch.remainder = record.ParseCast(long, f.watch.remainder, f.watch.vt)
	big := f.layoutLiveSection(gtx).Size.Y

	if big > small*2 {
		t.Errorf("the panel grew from %d to %d with a long transcript -- it will push off the bottom of the page the buttons that stop the session", small, big)
	}
}
