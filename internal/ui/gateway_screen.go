//go:build windows || linux || darwin

package ui

// Making this computer a gateway, from the window (IAMT-434).
//
// The maintainer, 22.09.2026: the plan is to copy the exe over, run it,
// press the "make gateway" button on some tab, then connect the client
// to that gateway, then go to the Windows server and, in the same
// application, open the Server tab and start it.
//
// Every piece of that worked already and none of it had a screen. The
// gateway installed itself as a Windows service, wrote the ACL on its
// data directory and printed the one string that makes somebody the
// first administrator -- from a console, by somebody who knew the verb.
// The hole was the same one this product keeps growing: a capability
// that works, is reachable from a terminal, and is invisible to the
// person it is for.
//
// A TAB, NOT A CARD SOMEWHERE. Being a gateway is a ROLE this computer
// holds, exactly like being a machine people enter -- and that role has
// had the Server tab since 1.0. The two are symmetric, they are the two
// halves of what one binary can be, and burying one of them inside
// Settings would have said they are not.
//
// It is shown on every computer, including the laptops that will never
// be a gateway. The screen exists to be FOUND by somebody standing in
// front of a fresh server who does not yet know what this program can
// do; a tab that appears only once you have already done the thing is a
// tab for people who did not need it.

import (
	"strconv"
	"strings"

	"gioui.org/layout"
	"gioui.org/unit"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

const (
	ctlGateway          = "gateway"
	ctlGatewayHost      = ctlGateway + "/host"
	ctlGatewayPort      = ctlGateway + "/port"
	ctlGatewayInstall   = ctlGateway + "/install"
	ctlGatewayRefresh   = ctlGateway + "/refresh"
	ctlGatewayUninstall = ctlGateway + "/uninstall"
	ctlGatewayCopyExe   = ctlGateway + "/copy-exe"
	ctlGatewayCopyClaim = ctlGateway + "/copy-claim"
)

// gatewayHeadline is the poster: what this computer is, in three words.
func gatewayHeadline(g GatewayState) (deck, title string, key design.ColorKey) {
	switch {
	case !g.Supported:
		return "This system has no service integration for a gateway", "Gateway", design.MutedKey
	case g.Unknown:
		return "Could not read whether this computer is a gateway", "Gateway", design.WarnKey
	case g.Running && g.AuditProblem != "":
		// IAMT-451: answering, and refusing every change - the journal
		// that records them is not being written.
		return "This computer IS the gateway, but its audit journal is NOT being written", "Gateway", design.WarnKey
	case g.JournalBroken:
		// IAMT-467: the journal is not what was written, or not all of it
		// is vouched for - whatever else is true, that comes first.
		return "The gateway's journal does NOT hold together: a line in it is not what was written", "Gateway", design.WarnKey
	case g.Running:
		return "This computer IS the gateway, and it is answering now", "Gateway", design.GoodKey
	case g.Installed:
		return "This computer is set up as a gateway, but it is not answering", "Gateway", design.WarnKey
	default:
		return "This computer is not a gateway — it can become one", "Gateway", design.InkKey
	}
}

// layoutGatewayScreen is the whole tab.
func (f *Frame) layoutGatewayScreen(gtx layout.Context) layout.Dimensions {
	g := f.snap.Gateway
	deck, title, key := gatewayHeadline(g)

	// ORDER IS THE POINT HERE. The first draft put the explanation and
	// the status table above the button, and the button landed below the
	// fold of a 1024x700 window -- on the one screen whose entire
	// purpose is a single press, on a computer somebody has just walked
	// up to. So: what this is in one line, then anything that would
	// make the press fail, then the press. The longer explanation and
	// the details go under it, where somebody who wants them will look.
	sections := []layout.Widget{
		posterOf(f.theme, deck, title, key),
		f.layoutGatewayLede,
	}
	switch {
	case !g.Supported:
		sections = append(sections, f.layoutGatewayState)
	case g.Running:
		sections = append(sections, f.layoutGatewayClaim, f.layoutGatewayState, f.layoutGatewayRemove)
	default:
		// NOT RUNNING, whether or not a host key is already here.
		//
		// 22.09.2026: the maintainer's first press failed at the very last
		// step -- the service -- but the install had already written
		// the host key, the token and the state before reaching it. The
		// screen then called that "set up" and offered only "stop being
		// a gateway": the one thing it would not let him do was finish.
		// Being half-made is the state that most needs the button, not
		// the state that has outgrown it.
		sections = append(sections, f.layoutGatewayWarnings, f.layoutGatewayInstallForm)
		if g.Installed {
			sections = append(sections, f.layoutGatewayClaim)
		}
		sections = append(sections, f.layoutGatewayState)
		if g.Installed {
			sections = append(sections, f.layoutGatewayRemove)
		}
	}
	sections = append(sections, f.layoutGatewayWhat)
	return design.Page(gtx, f.theme, f.pageList(), sections...)
}

// layoutGatewayLede is the one sentence above the button: enough to
// press it, short enough not to push it off the screen.
func (f *Frame) layoutGatewayLede(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Text(gtx, f.theme,
				"A gateway is the meeting point: nobody opens a port, both ends dial OUT to it and it "+
					"joins them. It is the one computer here that needs an address others can reach.")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
	)
}

// layoutGatewayWhat is the rest of the explanation, under the action.
func (f *Frame) layoutGatewayWhat(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme, "worth knowing")
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Text(gtx, f.theme,
				"A rented server is the usual home for it, but any computer with a fixed address and "+
					"one port open through the firewall will do.")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Text(gtx, f.theme,
				"This same computer can also be a machine people enter: set it up here, then open the "+
					"Server tab. One thing to weigh before you do — the recordings would then live on the "+
					"very computer being recorded, so whoever administers it could alter them. On your own "+
					"server that is usually fine; where the recordings are evidence about somebody, it is not.")
		}),
	)
}

// layoutGatewayState is what is true right now.
func (f *Frame) layoutGatewayState(gtx layout.Context) layout.Dimensions {
	g := f.snap.Gateway

	if !g.Supported {
		return design.Empty(gtx, f.theme,
			"A gateway installs itself as a service, and this build has no service integration for "+
				runtimeWord(g.Platform)+". Use a computer running Windows, Linux or macOS.")
	}

	rows := []design.FactRow{
		{Label: "state", Widget: func(gtx layout.Context) layout.Dimensions {
			// A Widget rather than a plain value: the four states are
			// not equally good news, and the one that matters most --
			// "could not be read" -- must not look like the others.
			return design.Said(gtx, f.theme, f.sel(ctlGateway+"/state"),
				gatewayStateWord(g), gatewayStateKey(g))
		}},
		{Label: "data", Value: orDash(g.DataDir)},
	}
	if g.Fingerprint != "" {
		rows = append(rows, design.FactRow{Label: "host key", Value: g.Fingerprint})
	}
	if g.Running && g.AuditKnown {
		rows = append(rows, design.FactRow{Label: "audit", Widget: func(gtx layout.Context) layout.Dimensions {
			if g.AuditProblem != "" {
				return design.Said(gtx, f.theme, f.sel(ctlGateway+"/audit"), g.AuditProblem, design.BadKey)
			}
			return design.Said(gtx, f.theme, f.sel(ctlGateway+"/audit"), "the journal is being written", design.GoodKey)
		}})
	}
	if g.JournalKnown {
		rows = append(rows, design.FactRow{Label: "journal", Widget: func(gtx layout.Context) layout.Dimensions {
			key := design.BadKey
			if g.JournalIntact {
				key = design.GoodKey
			}
			return design.Said(gtx, f.theme, f.sel(ctlGateway+"/journal"), clipStr(g.JournalChain, 240), key)
		}})
	}
	rows = append(rows, design.FactRow{Label: "this program", Value: orDash(g.ExePath)})

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Facts(gtx, f.theme, rows)
		}),
		layout.Rigid(f.layoutGatewayWarnings),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if f.btn(ctlGatewayRefresh).Clicked(gtx) {
				f.refreshGatewayState()
			}
			word := "Refresh"
			if f.busy(ctlGateway) {
				word = "Reading…"
			}
			said := f.saidUnder(ctlGateway)
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return design.Said(gtx, f.theme, f.sel(ctlGateway+"/said"), clipStr(said.text, 600), said.key)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.SecondaryButton(gtx, f.theme, f.btn(ctlGatewayRefresh), word)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
	)
}

// layoutGatewayWarnings are the two things that would otherwise fail
// later, said before the press.
//
// Both are real refusals of the install command. Meeting them as a red
// line AFTER pressing a button is the difference between a program that
// knows what it needs and one that finds out at the same time you do.
func (f *Frame) layoutGatewayWarnings(gtx layout.Context) layout.Dimensions {
	g := f.snap.Gateway
	var children []layout.FlexChild

	if !g.Elevated {
		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, f.theme, f.sel(ctlGateway+"/elev"),
				"Setting up a gateway installs a service, which needs administrator rights. "+
					"Use \"Restart as administrator\" at the top of this window first.", design.WarnKey)
		}))
	}
	// Not gated on "no gateway here yet": this is a fact about the copy
	// of the program a person is looking at, and it matters just as
	// much when they came to re-install or to remove one.
	if g.Platform == "windows" && g.ExePath != "" && !g.ExeReachable {
		children = append(children,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Said(gtx, f.theme, f.sel(ctlGateway+"/exe"),
					"This program is sitting inside a user profile, which the service account cannot read — "+
						"the service would install and then fail to start. It belongs in "+
						orDash(g.WantedExeDir)+", and that is where it lives on every machine.", design.WarnKey)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if f.btn(ctlGatewayCopyExe).Clicked(gtx) {
					f.copyGatewayExe()
				}
				word := "Move it there for me"
				if f.busy(ctlGatewayCopyExe) {
					word = "Copying…"
				}
				said := f.saidUnder(ctlGatewayCopyExe)
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.SecondaryButton(gtx, f.theme, f.btn(ctlGatewayCopyExe), word)
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return layout.Dimensions{}
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Said(gtx, f.theme, f.sel(ctlGatewayCopyExe+"/said"),
							clipStr(said.text, 400), said.key)
					}),
				)
			}),
		)
	}
	if len(children) == 0 {
		return layout.Dimensions{}
	}
	children = append([]layout.FlexChild{
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
	}, children...)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// layoutGatewayInstallForm is the button the maintainer asked for, and the
// two things it cannot invent.
func (f *Frame) layoutGatewayInstallForm(gtx layout.Context) layout.Dimensions {
	if f.btn(ctlGatewayInstall).Clicked(gtx) {
		f.installGateway()
	}
	half := f.snap.Gateway.Installed && !f.snap.Gateway.Running
	word := "MAKE THIS COMPUTER A GATEWAY"
	if half {
		word = "FINISH SETTING IT UP"
	}
	switch {
	case f.busy(ctlGatewayInstall):
		word = "SETTING IT UP…"
	case f.gatewayInstallBlockedNow():
		// Still a button, and still pressable: pressing it says exactly
		// what to do, which is more use than a dead grey rectangle that
		// says nothing. But it stops promising.
		word = "FIRST FIX THE LINES ABOVE"
	}
	said := f.saidUnder(ctlGatewayInstall)

	title := "Make this computer a gateway"
	if half {
		title = "Finish setting up this gateway"
	}
	return cardOf(f.theme, title,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if !half {
						return layout.Dimensions{}
					}
					return design.Said(gtx, f.theme, f.sel(ctlGatewayInstall+"/half"),
						"A previous attempt got as far as this computer's own keys and stopped before the "+
							"service. Nothing is lost and nothing needs undoing: say the address and port "+
							"again and it carries on from where it stopped.", design.MutedKey)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Field(gtx, f.theme, "address",
						func(gtx layout.Context) layout.Dimensions {
							return design.TextBox(gtx, f.theme, f.editor(ctlGatewayHost), "gw.example.com")
						},
						"what OTHER computers type to reach this one — a DNS name or an IP, never \"localhost\"")
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Field(gtx, f.theme, "port",
						func(gtx layout.Context) layout.Dimensions {
							return design.TextBox(gtx, f.theme, f.editor(ctlGatewayPort), "2222")
						},
						"the one port open through the firewall; 1024 or above")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.PrimaryButton(gtx, f.theme, f.btn(ctlGatewayInstall), word)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Said(gtx, f.theme, f.sel(ctlGatewayInstall+"/said"), clipStr(said.text, 900), said.key)
				}),
			)
		},
	)(gtx)
}

// layoutGatewayClaim is the one string that has to travel to another
// computer, and the sentence saying where it goes.
//
// It is the whole reason this screen matters right after the install.
// Everything else here can be looked at again later; this is used once,
// expires in a day, and there is no second copy of it anywhere.
func (f *Frame) layoutGatewayClaim(gtx layout.Context) layout.Dimensions {
	g := f.snap.Gateway
	if g.Claim == "" {
		return cardOf(f.theme, "The first administrator",
			func(gtx layout.Context) layout.Dimensions {
				return design.Text(gtx, f.theme, gatewayClaimAbsentText(g))
			},
		)(gtx)
	}

	if f.btn(ctlGatewayCopyClaim).Clicked(gtx) {
		copyToClipboard(gtx, g.Claim)
		f.say(ctlGatewayCopyClaim, "The claim string is on the clipboard.", design.GoodKey)
	}
	said := f.saidUnder(ctlGatewayCopyClaim)

	return cardOf(f.theme, "Take this to the computer you work from",
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Text(gtx, f.theme,
						"Paste this one string into the Admin tab of the computer you work from, and you "+
							"become this gateway's first administrator. It works once, within 24 hours, and "+
							"nothing else here can be done until somebody has.")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.CopyableBox(gtx, f.theme, f.sel(ctlGatewayCopyClaim+"/box"), g.Claim)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.SecondaryButton(gtx, f.theme, f.btn(ctlGatewayCopyClaim), "Copy")
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return design.Said(gtx, f.theme, f.sel(ctlGatewayCopyClaim+"/said"),
								clipStr(said.text, 200), said.key)
						}),
					)
				}),
			)
		},
	)(gtx)
}

// layoutGatewayRemove is the way back out, and what it does not take.
func (f *Frame) layoutGatewayRemove(gtx layout.Context) layout.Dimensions {
	if f.btn(ctlGatewayUninstall).Clicked(gtx) {
		f.uninstallGateway()
	}
	word := "Stop being a gateway"
	if f.busy(ctlGatewayUninstall) {
		word = "Removing…"
	}
	said := f.saidUnder(ctlGatewayUninstall)

	return cardOf(f.theme, "Stop being a gateway",
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Text(gtx, f.theme,
						"The service is stopped and removed. Nothing in the data directory is touched — "+
							"the host key, the people and machines it knows, and every recording stay where "+
							"they are, and setting it up again here finds them. Delete that folder by hand "+
							"if you really want them gone.")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.SecondaryButton(gtx, f.theme, f.btn(ctlGatewayUninstall), word)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Said(gtx, f.theme, f.sel(ctlGatewayUninstall+"/said"), clipStr(said.text, 600), said.key)
				}),
			)
		},
	)(gtx)
}

// gatewayStateWord and gatewayStateKey put the four states into words
// and a colour. "Unknown" is its own answer and never renders as "no".
func gatewayStateWord(g GatewayState) string {
	switch {
	case g.Unknown:
		return "could not be read"
	case g.Running:
		return "running"
	case g.Installed:
		return "set up, not running"
	default:
		return "not a gateway"
	}
}

func gatewayStateKey(g GatewayState) design.ColorKey {
	switch {
	case g.Unknown:
		return design.WarnKey
	case g.Running:
		return design.GoodKey
	case g.Installed:
		return design.WarnKey
	default:
		return design.MutedKey
	}
}

// runtimeWord names the platform in a sentence.
func runtimeWord(goos string) string {
	if goos == "" {
		return "this system"
	}
	return goos
}

// gatewayPortFrom reads the port box, falling back to the default the
// box opens on.
func gatewayPortFrom(text string, fallback int) (int, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(text)
	if err != nil {
		return 0, errPortNotANumber
	}
	return n, nil
}

// gatewayInstallBlockedNow is the button's own peek at the check the
// press makes, so the word on it and the outcome of pressing it can
// never disagree.
func (f *Frame) gatewayInstallBlockedNow() bool {
	_, blocked := f.gatewayInstallBlocked()
	return blocked
}

// gatewayClaimAbsentText says why there is no string to copy.
//
// TWO DIFFERENT SILENCES, and merging them is how this card told the
// maintainer that an untouched gateway was already claimed on 22.09.2026. A
// string that has been USED is gone for good and needs a re-issue; a
// string that merely cannot be WRITTEN OUT yet -- because the gateway
// does not know its own address until the install finishes -- is sitting
// there intact. The screen had no way to tell them apart and chose the
// alarming reading of the two.
func gatewayClaimAbsentText(g GatewayState) string {
	if g.ClaimPending {
		return "The one-time string is still here and still unused — it just cannot be written out yet, " +
			"because this gateway does not know its own address. Finish setting it up above, with the " +
			"address other computers will dial, and the string appears here."
	}
	if g.ClaimExpired {
		// OUT OF DATE IS NOT SPENT, and saying the wrong one of the two
		// sends a person looking for a colleague who does not exist.
		// Nobody took this gateway: the string simply has a deadline and
		// it passed. Re-issuing it is a local act, here, and it is
		// allowed precisely because no administrator exists yet.
		return "The one-time string has run out of time — it was never used, and nobody is this gateway's " +
			"administrator yet. Issue a fresh one by running \"gateway install --rebootstrap\" here, then " +
			"take it to the computer that should be the administrator."
	}
	return "Already claimed. The one-time string this gateway printed when it was set up has been " +
		"used, so somebody is its administrator now. If nobody is — because the string was lost " +
		"before anyone took it — a new one is issued by running \"gateway install --rebootstrap\" here."
}
