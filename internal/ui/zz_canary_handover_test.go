package ui

// The maintainer's canaries: a string the window HANDS to a person
// must be takeable.
//
// Found by the maintainer on 19.09.2026 at the second step of the
// live setup from scratch. They pressed "Invite a machine", the
// invitation code appeared under the button -- and there was no way
// to take it from there. The line printed as a status line, and in
// gio an ordinary label has no selection state: no way to drag the
// mouse across it, nothing for Ctrl+C to copy. There was no "copy"
// button next to it either, though elsewhere in the window there is.
//
// Worse: the code arrived glued to an explanation -- "<code>
// (expires ...)". Even if selecting had worked, the buffer would
// have carried extra words, and the paste on the other machine would
// have broken not at once but at parse time.
//
// None of the existing tests caught this: they checked that the
// action is called with the right name and that an empty name is
// refused. Nobody checked what happened to the string AFTER it came
// back.

import (
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

const handoverCode = "iamtunnel-enrol://203.0.113.10:2022#SHA256:VHcYlXQPy+pny9JSYsyO0OoExJyZfiiWy11VbnWLpLg:s3cr3t"

// mintedCode drives the Invite card's action with a stub gateway and
// returns the card's status line once the work has finished.
func mintedCode(t *testing.T, f *Frame) saying {
	t.Helper()
	f.cfg.Actions.AdminMachinesEnrolCode = func(name string) (string, string, error) {
		return handoverCode, "in 24 hours", nil
	}
	f.editor(ctlAdminEnrolCode + "/name").SetText("win-test-vm")
	f.mintEnrolCode()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s := f.saidUnder(ctlAdminEnrolCode); !f.busy(ctlAdminEnrolCode) && s.text != "" {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the \"Invite a machine\" card said nothing for two seconds")
	return saying{}
}

// TestCanary_TheEnrolCodeArrivesWholeAndAlone.
//
// The code and the explanation arrive SEPARATELY. The explanation is
// read and forgotten, the code is pasted into another window
// character by character -- everything glued to it travels along.
//
// Canary: restore the concatenation in guiAdminMachineEnrolCode,
// `code + " (expires " + expires + ")"`, with a single return value
// -- the test names exactly what arrived as the extra.
func TestCanary_TheEnrolCodeArrivesWholeAndAlone(t *testing.T) {
	f := newBareFrame(t)
	said := mintedCode(t, f)

	if said.give != handoverCode {
		t.Errorf("handed out %q, want exactly the code %q -- the buffer will carry whatever sits here, and the extra words will travel with it",
			said.give, handoverCode)
	}
	if strings.Contains(said.text, handoverCode) {
		t.Errorf("the code landed in the status sentence (%q) -- that is exactly how it became unselectable on 19.09.2026: a status line is drawn as a label, and a label cannot be selected",
			said.text)
	}
	if said.text == "" {
		t.Error("no explanation at all -- a person must see the invitation's expiry, just not inside the code itself")
	}
}

// TestCanary_AHandedOverStringCanBeSelected.
//
// What is checked is not "the function was called" but that the label
// REALLY carries the selection state: material.Label feeds its text
// into the State only while drawing and only if State is not nil. If
// the state is not wired up, Text() stays empty.
//
// Canary: remove `lbl.State = sel` in design.CopyableBox -- it goes
// red here, with the message about the mouse.
func TestCanary_AHandedOverStringCanBeSelected(t *testing.T) {
	f := newBareFrame(t)
	f.tabs.Show(TabAdmin)
	f.selectSubTab("Machines")
	_ = mintedCode(t, f)

	gtx := newTestLayoutContext(900, 600)
	if dims := f.layoutAdminScreen(gtx); dims.Size.Y <= 0 {
		t.Fatal("the \"Invite a machine\" card drew at zero height")
	}

	sel, ok := f.sels[ctlAdminEnrolCode]
	if !ok {
		t.Fatal("the handed-out code has no selection state -- no way to drag the mouse across it, nothing for Ctrl+C to copy")
	}
	if got := sel.Text(); got != handoverCode {
		t.Errorf("the selection state holds %q, want the code whole -- exactly what sits inside it is what gets selected", got)
	}
	if _, ok := f.btns[ctlAdminEnrolCode+"/copy"]; !ok {
		t.Error("there is no copy button next to the code -- mouse selection and the button serve different people, and the agreement covered both")
	}
}

// TestCanary_NothingIsOfferedWhenNothingWasGiven: before
// the button is pressed there is nothing to take, and there must be
// no empty frame with a "Copy" button -- it would offer to copy
// emptiness.
func TestCanary_NothingIsOfferedWhenNothingWasGiven(t *testing.T) {
	f := newBareFrame(t)
	f.tabs.Show(TabAdmin)
	f.selectSubTab("Machines")

	gtx := newTestLayoutContext(900, 600)
	_ = f.layoutAdminScreen(gtx)

	if _, ok := f.btns[ctlAdminEnrolCode+"/copy"]; ok {
		t.Error("the copy button is drawn before the invitation is issued -- there is nothing to copy")
	}
}

// TestCanary_ThePairingLineIsTakeableToo.
//
// The maintainer said "we agreed you put copy buttons everywhere".
// The pair line is the second place in the window that hands a string
// over, and before this edit it had a frame without a button.
//
// Canary: restore a bare design.CopyableBox in the Pairing card
// instead of layoutHandOver.
func TestCanary_ThePairingLineIsTakeableToo(t *testing.T) {
	f := newBareFrame(t)
	f.snap.Admin.Pairing = &PairingWindow{
		Pin:     "123456",
		Ref:     "203.0.113.10:2022#SHA256:VHcYlXQPy+pny9JSYsyO0OoExJyZfiiWy11VbnWLpLg",
		Expires: f.now().Add(10 * time.Minute),
	}

	gtx := newTestLayoutContext(900, 600)
	if dims := f.layoutPairingCard(gtx); dims.Size.Y <= 0 {
		t.Fatal("the Pairing card drew at zero height")
	}

	sel, ok := f.sels[ctlAdminPairingStart]
	if !ok || sel.Text() == "" {
		t.Fatal("the pair line cannot be selected -- it is handed over exactly like the invitation code")
	}
	if _, ok := f.btns[ctlAdminPairingStart+"/copy"]; !ok {
		t.Error("the pair line has no copy button")
	}
}

// TestCanary_AStatusLineCanBeSelected.
//
// The lines under buttons carry the only thing a person needs to pass
// on when something went wrong -- the refusal in the program's own
// words. Until 19.09.2026 they could only be photographed: the
// maintainer received a refusal with a path they could not retype.
//
// Canary: remove the State wiring in design.Said -- the label becomes
// unselectable again and the text never reaches the selection state.
func TestCanary_AStatusLineCanBeSelected(t *testing.T) {
	const refusal = "the gateway at 203.0.113.10:2022 refused this claim line"

	f := newBareFrame(t)
	f.say(ctlSetupRegister, refusal, design.BadKey)

	gtx := newTestLayoutContext(900, 600)
	_ = f.layoutSetupScreen(gtx)

	sel, ok := f.sels[ctlSetupRegister+"/said"]
	if !ok {
		t.Fatal("the status line has no selection state -- the error can only be photographed")
	}
	if got := sel.Text(); got != refusal {
		t.Errorf("%q is selected, want the whole refusal text", got)
	}
}
