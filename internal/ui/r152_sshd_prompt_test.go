package ui

import (
	"errors"
	"image"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// START on a machine without a running OpenSSH Server opens the prompt
// instead of failing later with one line of small text (1.52); with the
// service running, or unknown, START goes ahead as before.
func TestR152_StartAsksForOpenSSHWhenItIsMissingOrStopped(t *testing.T) {
	var mu sync.Mutex
	var asked []string
	old := openSSHDPrompt
	openSSHDPrompt = func(_ *Frame, _ *design.Theme, state string) {
		mu.Lock()
		asked = append(asked, state)
		mu.Unlock()
	}
	defer func() { openSSHDPrompt = old }()

	for _, tc := range []struct {
		state string
		ready bool
	}{
		{SshdMissing, false},
		{SshdStopped, false},
		{SshdRunning, true},
		{"", true},
	} {
		f := newBareFrame(t)
		f.snap.Server.SshdState = tc.state
		if got := f.sshdReady(); got != tc.ready {
			t.Errorf("sshdReady with SshdState %q = %v, want %v", tc.state, got, tc.ready)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(asked)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 2 {
		t.Fatalf("the prompt was asked for %v, want exactly once for missing and once for stopped", asked)
	}
}

// "Install and start" runs the install and then the start the person
// asked for in the first place, without a second press.
func TestR152_PrepareSSHDThenStartsTheAgent(t *testing.T) {
	f := newBareFrame(t)
	f.cfg.HasAdminRights = true
	var prepared, started atomic.Int32
	f.cfg.Actions.ServerPrepareSSHD = func() (string, error) {
		prepared.Add(1)
		return "installed", nil
	}
	f.cfg.Actions.ServerStart = func() (string, error) {
		started.Add(1)
		return "started", nil
	}
	f.prepareSSHD(SshdMissing)
	deadline := time.Now().Add(5 * time.Second)
	for started.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if prepared.Load() != 1 || started.Load() != 1 {
		t.Fatalf("prepared %d times, started %d times; want one install followed by one start", prepared.Load(), started.Load())
	}
}

// The prompt is drawn in a window of a fixed size and has no scrollbar: the
// buttons must be inside it, for both wordings and for the longest note the
// prompt itself can show. (A first version put the big words, seven lines
// of explanation and the buttons into 600x340 dp on the strength of a
// sum done in the head.)
func TestR152_SSHDPromptFitsItsWindow(t *testing.T) {
	f := newBareFrame(t)
	var yes, no widget.Clickable
	var sel widget.Selectable
	for _, tc := range []struct{ name, heading, body, yes string }{
		{"missing", "Not installed", sshdPromptBody(SshdMissing), "Install and start OpenSSH Server"},
		{"stopped", "Not running", sshdPromptBody(SshdStopped), "Start OpenSSH Server"},
	} {
		var ops op.Ops
		gtx := layout.Context{
			Ops:         &ops,
			Constraints: layout.Constraints{Max: image.Pt(sshdPromptWidth, 10000)},
			Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
		}
		dims := layoutSSHDPrompt(gtx, f.theme, sshdPromptView{
			lead: "OpenSSH Server", heading: tc.heading, body: tc.body, yesWord: tc.yes,
			note: noRuntime, noteKey: design.BadKey, sel: &sel, yes: &yes, no: &no,
		})
		t.Logf("%s: the prompt needs %d dp of height, its window has %d", tc.name, dims.Size.Y, sshdPromptHeight)
		if dims.Size.Y > sshdPromptHeight {
			t.Errorf("%s: the prompt needs %d dp of height, its window has %d - the buttons would be cut off", tc.name, dims.Size.Y, sshdPromptHeight)
		}
	}
}

// A claim line is spent only by a success. When the gateway cannot be
// reached (a firewall, a security group) the line must still be in the box,
// or the person has to fetch it again for nothing.
func TestR152_ClientBoxKeepsTheClaimLineWhenTheJoinFails(t *testing.T) {
	f := newBareFrame(t)
	f.cfg.Actions.AdminClaim = func(ref, token string) (string, *AdminIdentity, error) {
		return "", nil, errors.New("could not reach the gateway at 203.0.113.10:2022: i/o timeout")
	}
	line := "iamtunnel-claim://203.0.113.10:2022#" + claimRouteFingerprint + ":" + claimRouteToken
	f.editor(ctlClientSave).SetText(line)
	f.saveConnectionString(false)

	deadline := time.Now().Add(3 * time.Second)
	for f.busy(ctlClientSave) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := f.saidUnder(ctlClientSave).text; !strings.Contains(got, "i/o timeout") {
		t.Fatalf("the failure was not reported under the box: %q", got)
	}
	if got := f.editor(ctlClientSave).Text(); got != line {
		t.Fatalf("the claim line left the box although nothing was spent: %q", got)
	}
}
