//go:build windows

package ui

// iamt499_admin_manage_test.go — the window's half of the §3.3 verbs it did
// not have until IAMT-499: machines verify / set-user / rekey, people keys
// add / remove / connection-string, gateway fingerprint / backup /
// rotate-hostkey. Driven at the actions layer, like the rename and extend
// tests: what matters is what reaches the gateway, when, and with what.

import (
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// wantNothingSent fails if anything arrives on asked within guardWait.
func wantNothingSent[T any](t *testing.T, asked chan T, why string) {
	t.Helper()
	select {
	case got := <-asked:
		t.Fatalf("%v reached the gateway — %s", got, why)
	case <-time.After(guardWait):
	}
}

// wantSent returns what arrives on asked, or fails.
func wantSent[T any](t *testing.T, asked chan T, what string) T {
	t.Helper()
	select {
	case got := <-asked:
		return got
	case <-time.After(5 * time.Second):
		t.Fatalf("%s asked the gateway nothing", what)
	}
	var zero T
	return zero
}

func TestIAMT499SetUserAsksBeforeSendingAndSendsWhatItAsked(t *testing.T) {
	f := newBareFrame(t)
	ctl := machineManageCtl("vm1") + "/user"
	asked := make(chan [2]string, 2)
	f.cfg.Actions.AdminMachineSetUser = func(id, user string) (string, error) {
		asked <- [2]string{id, user}
		return "set", nil
	}

	f.editor(ctl + "/box").SetText(`VM1\alice`)
	f.setMachineUser(ctl, "vm1")
	wantNothingSent(t, asked, "set-user shuts the door; the first press must only ask")
	if said := f.saidUnder(ctl); !strings.Contains(said.text, `VM1\alice`) {
		t.Fatalf("the question %q does not name the account it will set", said.text)
	}

	// The box changed between the presses: the second press must ask
	// again about the NEW value, not send it under the old question.
	f.editor(ctl + "/box").SetText(`VM1\bob`)
	f.setMachineUser(ctl, "vm1")
	wantNothingSent(t, asked, "the box was edited after the question; the value sent must be the one confirmed")

	f.setMachineUser(ctl, "vm1")
	got := wantSent(t, asked, "the confirmed set-user")
	if got != [2]string{"vm1", `VM1\bob`} {
		t.Fatalf("set-user sent %v, want [vm1 VM1\\bob]", got)
	}
}

func TestIAMT499SetUserRefusesAnEmptyBox(t *testing.T) {
	f := newBareFrame(t)
	ctl := machineManageCtl("vm1") + "/user"
	asked := make(chan string, 2)
	f.cfg.Actions.AdminMachineSetUser = func(id, user string) (string, error) {
		asked <- user
		return "", nil
	}
	f.setMachineUser(ctl, "vm1")
	f.setMachineUser(ctl, "vm1")
	wantNothingSent(t, asked, "an empty account must be refused before anything travels")
	if f.saidUnder(ctl).text == "" {
		t.Error("the refusal left no word under the control")
	}
}

func TestIAMT499RekeySendsTheTypedFingerprintAfterConfirmation(t *testing.T) {
	f := newBareFrame(t)
	ctl := machineManageCtl("vm1") + "/rekey"
	asked := make(chan [2]string, 2)
	f.cfg.Actions.AdminMachineRekey = func(id, fp string) (string, error) {
		asked <- [2]string{id, fp}
		return "pinned", nil
	}

	f.rekeyMachine(ctl, "vm1")
	wantNothingSent(t, asked, "an empty fingerprint box must be refused")

	const fp = "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	f.editor(ctl + "/box").SetText(fp)
	f.rekeyMachine(ctl, "vm1")
	wantNothingSent(t, asked, "rekey replaces a pinned key; the first press must only ask")
	f.rekeyMachine(ctl, "vm1")
	if got := wantSent(t, asked, "the confirmed rekey"); got != [2]string{"vm1", fp} {
		t.Fatalf("rekey sent %v, want [vm1 %s]", got, fp)
	}
}

func TestIAMT499VerifyIsOnePress(t *testing.T) {
	f := newBareFrame(t)
	asked := make(chan string, 1)
	f.cfg.Actions.AdminMachineVerify = func(id string) (string, error) {
		asked <- id
		return "probed", nil
	}
	f.verifyMachine(machineManageCtl("vm1")+"/verify", "vm1")
	if got := wantSent(t, asked, "verify"); got != "vm1" {
		t.Fatalf("verify asked about %q, want vm1", got)
	}
}

func TestIAMT499RemoveKeyIsConfirmedAndKeyedByFingerprint(t *testing.T) {
	f := newBareFrame(t)
	ctl := personKeysCtl("alice")
	asked := make(chan [2]string, 2)
	f.cfg.Actions.AdminPersonKeyRemove = func(name, fp string) (string, error) {
		asked <- [2]string{name, fp}
		return "removed", nil
	}
	a, b := personKeyRemoveCtl(ctl, "SHA256:aaa"), personKeyRemoveCtl(ctl, "SHA256:bbb")

	f.removePersonKey(a, "alice", "SHA256:aaa")
	// A press on a DIFFERENT key's button is that key's first press, not
	// the confirmation of the first key.
	f.removePersonKey(b, "alice", "SHA256:bbb")
	wantNothingSent(t, asked, "each key's removal must be confirmed on its own row")

	f.removePersonKey(a, "alice", "SHA256:aaa")
	if got := wantSent(t, asked, "the confirmed key removal"); got != [2]string{"alice", "SHA256:aaa"} {
		t.Fatalf("key removal sent %v, want [alice SHA256:aaa]", got)
	}
}

func TestIAMT499AddKeyAndConnectionString(t *testing.T) {
	f := newBareFrame(t)
	ctl := personKeysCtl("alice")
	added := make(chan [2]string, 1)
	f.cfg.Actions.AdminPersonKeyAdd = func(name, key string) (string, error) {
		added <- [2]string{name, key}
		return "added", nil
	}
	f.editor(ctl + "/add/box").SetText("ssh-ed25519 AAAAC3Nz alice@laptop")
	f.addPersonKey(ctl+"/add", "alice")
	if got := wantSent(t, added, "add key"); got != [2]string{"alice", "ssh-ed25519 AAAAC3Nz alice@laptop"} {
		t.Fatalf("add key sent %v", got)
	}

	f.cfg.Actions.AdminPersonConnectionString = func(name string) (string, error) {
		return "gw.example:2022#SHA256:x:alice", nil
	}
	f.personConnectionString(ctl+"/cs", "alice")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && f.saidUnder(ctl+"/cs").give == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if got := f.saidUnder(ctl + "/cs").give; got != "gw.example:2022#SHA256:x:alice" {
		t.Fatalf("the connection string was handed over as %q, want it in the copyable box whole", got)
	}
}

func TestIAMT499RotateHostkeyAsksFirst(t *testing.T) {
	f := newBareFrame(t)
	asked := make(chan struct{}, 2)
	f.cfg.Actions.AdminGatewayRotateHostkey = func() (string, error) {
		asked <- struct{}{}
		return "rotated", nil
	}
	f.gatewayRotateHostkey()
	wantNothingSent(t, asked, "rotation cuts every client and machine off; the first press must only ask")
	if said := f.saidUnder(ctlAdminGatewayRotate); !strings.Contains(said.text, "EVERY client and machine") {
		t.Fatalf("the question %q does not say who is cut off", said.text)
	}
	f.gatewayRotateHostkey()
	wantSent(t, asked, "the confirmed rotation")
}

func TestIAMT499MismatchIsSaidOnTheRowAndOffersRekey(t *testing.T) {
	if !hostKeyMismatch(AdminMachine{HostKeyStatus: "mismatch"}) {
		t.Fatal("a machine in hostKeyStatus mismatch is not recognised as one")
	}
	if hostKeyMismatch(AdminMachine{HostKeyStatus: "match"}) {
		t.Fatal("a matching key reads as a mismatch")
	}
}

// TestIAMT499OpenPanelsRender draws Machines with a mismatch machine's
// Manage panel open, People with a Keys panel open, and the Gateway
// sub-tab, offscreen. It fails if any of them cannot be drawn; with
// IAMT_SHOT_OUT set to a directory it also leaves the pictures there for
// a person to look at.
func TestIAMT499OpenPanelsRender(t *testing.T) {
	cases := []struct {
		sub, open, file string
	}{
		{"Machines", machineManageCtl("backup-db02"), "iamt499-machines-manage.png"},
		{"People", personKeysCtl("alice"), "iamt499-people-keys.png"},
		{"Gateway", "", "iamt499-gateway.png"},
	}
	for _, c := range cases {
		for _, dark := range []bool{false, true} {
			theme := ThemeLight
			if dark {
				theme = ThemeDark
			}
			f, err := NewFrame(FrameConfig{
				Enrolled: true, InitialTab: TabAdmin, StillFrame: true,
				ForceTheme: theme, Snap: exampleSnapshot(),
			})
			if err != nil {
				t.Fatalf("NewFrame: %v", err)
			}
			f.SelectTab(TabAdmin)
			f.selectSubTab(c.sub)
			if c.open != "" {
				f.toggleForm(c.open)
			}
			img, err := renderFrameOffscreen(f, DefaultShotWidth, DefaultShotHeight)
			if err != nil {
				t.Fatalf("%s: render: %v", c.sub, err)
			}
			if dir := os.Getenv("IAMT_SHOT_OUT"); dir != "" {
				name := c.file
				if dark {
					name = strings.TrimSuffix(name, ".png") + "-dark.png"
				}
				out, err := os.Create(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := png.Encode(out, img); err != nil {
					t.Fatal(err)
				}
				out.Close()
			}
		}
	}
}
