//go:build windows || linux || darwin

package ui

// What the Gateway tab's buttons do (IAMT-434).

import (
	"errors"
	"strconv"
	"strings"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// errPortNotANumber is what a port box with words in it answers.
var errPortNotANumber = errors.New("the port must be a number, like 2222")

// refreshGatewayState asks what this computer currently is.
//
// Pressed, and also on arriving at the tab: the answer changes from
// outside this window -- somebody stops the service, a colleague claims
// the one-time string -- and a card that only refreshed on a button
// would be showing whatever was true when the window opened.
func (f *Frame) refreshGatewayState() {
	ask := f.cfg.Actions.GatewayStatus
	if ask == nil {
		f.say(ctlGateway, noRuntime, design.BadKey)
		return
	}
	// The port box opens on the default rather than on a watermark: a
	// person who does not care about ports should be able to fill the
	// one field they do care about and press the button.
	if strings.TrimSpace(f.editor(ctlGatewayPort).Text()) == "" && f.snap.Settings.Port > 0 {
		f.editor(ctlGatewayPort).SetText(strconv.Itoa(f.snap.Settings.Port))
	}
	f.begin(ctlGateway, "Reading.", func() (string, design.ColorKey) {
		st, err := ask()
		if err != nil {
			return err.Error(), design.BadKey
		}
		f.reviseSnapshot(func(s *Snapshot) { s.Gateway = st })
		return "", design.MutedKey
	})
}

// installGateway is the button the maintainer asked for.
func (f *Frame) installGateway() {
	do := f.cfg.Actions.GatewayInstall
	if do == nil {
		f.say(ctlGatewayInstall, noRuntime, design.BadKey)
		return
	}
	// WHAT THE SCREEN ALREADY KNOWS, it does not let a person discover
	// by pressing.
	//
	// 22.09.2026, live check: the maintainer pressed this on a program run
	// from the Desktop and got the command's own refusal back --
	// "NT SERVICE\\iamtunnel-gateway cannot read by default (RUNBOOK
	// §1.5) -- copy iamtunnel.exe to C:\\Program Files\\iamtunnel and run
	// \"gateway install\" from there". Every word of that is true, and
	// all of it is the console this tab exists to replace. The state
	// card above had been saying the same thing in its own words, with
	// a button that fixes it, and the primary control let him walk
	// straight past into the failure anyway.
	//
	// So the two known blockers are refused HERE, in the window's own
	// voice, pointing at the control that solves them. Nothing is
	// guessed: both come from the status this screen already holds.
	if why, blocked := f.gatewayInstallBlocked(); blocked {
		f.say(ctlGatewayInstall, why, design.BadKey)
		return
	}

	host := strings.TrimSpace(f.editor(ctlGatewayHost).Text())
	port, perr := gatewayPortFrom(f.editor(ctlGatewayPort).Text(), f.snap.Settings.Port)
	if perr != nil {
		f.say(ctlGatewayInstall, perr.Error(), design.BadKey)
		return
	}
	f.begin(ctlGatewayInstall, "Setting up the gateway — a few seconds.", func() (string, design.ColorKey) {
		what, err := do(host, port)
		if err != nil {
			return err.Error(), design.BadKey
		}
		// The new state FIRST, then the good news: the card below this
		// one has to be showing the claim string by the time a person
		// reads the sentence telling them to take it somewhere.
		f.refreshGatewayStateNow()
		return what, design.GoodKey
	})
}

// uninstallGateway stops and removes the service, keeping the data.
func (f *Frame) uninstallGateway() {
	do := f.cfg.Actions.GatewayUninstall
	if do == nil {
		f.say(ctlGatewayUninstall, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlGatewayUninstall, "Removing the service.", func() (string, design.ColorKey) {
		what, err := do()
		if err != nil {
			return err.Error(), design.BadKey
		}
		f.refreshGatewayStateNow()
		return what, design.GoodKey
	})
}

// copyGatewayExe moves this program somewhere a service account can
// read it, on the Windows path where that matters.
func (f *Frame) copyGatewayExe() {
	do := f.cfg.Actions.GatewayCopyExe
	if do == nil {
		f.say(ctlGatewayCopyExe, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlGatewayCopyExe, "Copying.", func() (string, design.ColorKey) {
		where, err := do()
		if err != nil {
			return err.Error(), design.BadKey
		}
		f.refreshGatewayStateNow()
		return "Copied to " + where + ". Close this window and start the program from there — " +
			"the copy you are looking at now is still the one in the old place.", design.GoodKey
	})
}

// refreshGatewayStateNow re-reads the state on the goroutine that is
// already working, without a second "Reading." line under the button
// somebody just pressed.
func (f *Frame) refreshGatewayStateNow() {
	ask := f.cfg.Actions.GatewayStatus
	if ask == nil {
		return
	}
	st, err := ask()
	if err != nil {
		return
	}
	f.reviseSnapshot(func(s *Snapshot) { s.Gateway = st })
}

// gatewayInstallBlocked reports what would stop an install right now.
//
// Both answers are facts the tab already read, not predictions: whether
// this copy is elevated, and whether it sits where a service account
// can read it. Saying them before the press is the whole difference
// between a screen that knows what it needs and one that finds out at
// the same moment the person does.
func (f *Frame) gatewayInstallBlocked() (string, bool) {
	g := f.snap.Gateway
	if !g.Elevated {
		return "This needs administrator rights — press “Restart as administrator” at the top of " +
			"this window, then come back here.", true
	}
	if g.Platform == "windows" && g.ExePath != "" && !g.ExeReachable {
		// The one home this program has on Windows. The fallback names
		// it literally rather than naming some other folder: a sentence
		// that sends a person to a second place is how this program came
		// to have three of them.
		where := g.WantedExeDir
		if where == "" {
			where = `C:\iamtunnel`
		}
		return "This program is running from a user profile, and the account the gateway service runs " +
			"under cannot read it there — the service would install and then fail to start. Press " +
			"“Move it there for me” above to copy it into " + where + ", then start the program from there.", true
	}
	return "", false
}
