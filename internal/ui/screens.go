//go:build windows || linux || darwin

package ui

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gioui.org/io/clipboard"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// The five screens of SPEC §7.1, drawn from one Snapshot. Every screen is
// a Telescope page: a Poster (the state), then Cards over hairlines. Two
// things are structural, not configurable: the recording notice stands on
// the client screen in every state, and the door-cutting control stands
// at the top of the server screen whenever the machine is reachable.
// There is deliberately no switch that hides either.

// layoutServerScreen is the machine owner's main screen: what is
// happening on this machine right now, who is in, until when, whether
// the session is recorded — and the control that cuts it all off,
// standing on the first screenful, right of the state headline.
func (f *Frame) layoutServerScreen(gtx layout.Context) layout.Dimensions {
	s := f.snap.Server
	f.lastServerFactsUnknown = s.Unknown

	lead, word, key := serverHeadline(s)

	if f.btn(ctlServerStop).Clicked(gtx) {
		f.stopServer()
	}
	if f.btn(ctlServerStart).Clicked(gtx) {
		f.startServer()
	}

	// Structural invariant (IAMT-255, off-Windows layout-level test
	// pins on this): the cutting control is drawn exactly when the
	// server is running AND the stop button is the visible control.
	// The pixel-level invariant (verify_iamt66_test.go) checks the
	// same thing via the STOP colour stripe above the tab rule; the
	// off-screen Windows tests already guarantee the layout produces
	// the right pixels, so the flag below is the cheapest faithful
	// statement of "the button was laid out", not "the user clicked
	// it". F-GUI-2: gated on MaybeBusy, not Busy — an Unknown status
	// must never present START as a fact.
	// Offered whenever there is something to stop: a reachable machine
	// (MaybeBusy) or a server process that is merely up (IAMT-358). The
	// second case is the one the maintainer hit -- a process running with its
	// tunnel down, and a screen that showed START.
	f.lastStopButtonShown = s.MaybeBusy() || s.Running

	// The first section (headline and the cutting control) is pinned: it
	// never scrolls away (IAMT-229).
	return design.PinnedPage(gtx, f.theme, f.pageList(), 1,
		// Headline on the left, the cutting control on the right: both on
		// the first screenful, neither behind a scroll or another tab.
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{
				Axis:      layout.Horizontal,
				Alignment: layout.Start,
			}.Layout(gtx,
				// The headline takes the flexible share: a long lead wraps
				// instead of pushing the control off the edge.
				layout.Flexed(1, posterOf(f.theme, lead, word, key)),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Left: unit.Dp(design.Gap)}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							if s.MaybeBusy() || s.Running {
								// The words differ because the
								// consequence differs: cutting a live
								// session is not the same act as
								// stopping an idle agent, and a button
								// that said "cut access now" over an
								// idle machine would teach everyone to
								// ignore the warning on the day it
								// counts.
								word := "STOP — cut access now"
								if !s.MaybeBusy() {
									word = "STOP the machine agent"
								}
								if f.busy(ctlServerStop) {
									word = "STOPPING…"
								}
								return design.DangerButton(gtx, f.theme, f.btn(ctlServerStop), word)
							}
							word := "START — wait for a specialist"
							if f.busy(ctlServerStart) {
								word = "STARTING…"
							}
							return design.PrimaryButton(gtx, f.theme, f.btn(ctlServerStart), word)
						})
				}),
			)
		},
		// What the last Start/Stop press said, if anything.
		func(gtx layout.Context) layout.Dimensions {
			said := f.saidUnder(ctlServerStop)
			if said.text == "" {
				said = f.saidUnder(ctlServerStart)
			}
			return design.Said(gtx, f.theme, f.sel("server/said"), clipStr(said.text, 400), said.key)
		},
		// The reason the gateway currently refuses this machine, verbatim
		// from the runtime (IAMT-69): a machine the gateway has cut off
		// must not look like an ordinary idle one. The block exists only
		// when the snapshot carries a notice; an empty one draws nothing.
		f.layoutServerNotice,
		// The machine's own facts.
		func(gtx layout.Context) layout.Dimensions {
			rows := []design.FactRow{
				f.tristateFact("sshd service", s, s.SshdRunning,
					"running — the machine can be entered",
					"not running — the door cannot open"),
				f.tristateFact("gateway tunnel", s, s.Waiting,
					"online — the machine is reachable",
					"offline — the machine is invisible"),
				design.Fact("machine / recording", machineNameText(f.snap.Setup)+" · "+recordingFact(s)+" · The machine agent keeps running after this window is closed"),
			}
			return design.Facts(gtx, f.theme, rows)
		},
		// WHO THIS DOOR IS OPEN FOR, and not who walked through it
		// (22.09.2026). The card was headed "Who is in right now" over a
		// list this screen cannot build: what the control port answers is
		// doorOpen, and the window turns that single boolean into one
		// nameless, deadline-less session. On a live machine the card
		// therefore drew one row of dashes under a heading that promised
		// a name.
		//
		// Who is ATTACHED is a different question with a different
		// source -- the gateway, asked on the Session tab and on Admin ->
		// Live -- and those two are the only screens that can answer it.
		// This one says what it checked and points at them.
		cardOf(f.theme, "Who the door is open for",
			func(gtx layout.Context) layout.Dimensions {
				if s.Unknown {
					return design.Fixed(gtx, f.theme, s.unknownText())
				}
				if len(s.Sessions) == 0 {
					return design.Fixed(gtx, f.theme, "nobody — the door is shut")
				}
				rows := make([]design.FactRow, 0, len(s.Sessions))
				named := 0
				for _, sess := range s.Sessions {
					who := strings.TrimSpace(clipStr(sess.Person, 24))
					if who == "" {
						// The ordinary live case: the door is up and this
						// machine was not told for whom. Saying so is
						// shorter than a row of dashes and true.
						continue
					}
					named++
					when := "no deadline"
					if !sess.Until.IsZero() {
						when = "until " + untilText(sess.Until) + " (" + leftText(sess.Until, f.now()) + ")"
					}
					if !sess.Started.IsZero() {
						when = "since " + untilText(sess.Started) + " · " + when
					}
					rows = append(rows, design.Fact(who, when))
				}
				if named == 0 {
					return design.Fixed(gtx, f.theme,
						"open — this machine was not told who for. "+
							"The Session tab and Admin → Live ask the gateway who is actually attached.")
				}
				return design.Facts(gtx, f.theme, rows)
			}),
		// The door, with its deadlines.
		cardOf(f.theme, "The door",
			func(gtx layout.Context) layout.Dimensions {
				return design.Facts(gtx, f.theme, []design.FactRow{
					design.Fact("state", doorStateText(s)),
					design.Fact("opened", untilText(s.Door.Opened)),
					design.Fact("idle limit", untilText(s.Door.IdleDeadline)),
					design.Fact("hard limit", untilText(s.Door.HardDeadline)),
				})
			}),
		// What to do when the prerequisite is missing (docs/USER.md §6.1).
		// Unknown must not draw a fix-it hint that assumes the negative
		// fact it names — the fix here is rights, not sshd (IAMT-311),
		// and that fix is already named in the fact row above.
		func(gtx layout.Context) layout.Dimensions {
			if s.Unknown || s.SshdRunning {
				return layout.Dimensions{}
			}
			return design.Hint(gtx, f.theme, sshdServiceNotice)
		},
	)
}

// serverHeadline is the state word of the server screen, and nothing else.
func serverHeadline(s ServerState) (lead, word string, key design.ColorKey) {
	if s.Unknown {
		// Every other case below reads Waiting/Door/Recording — all bare
		// zero values while Unknown is true — so this must be checked
		// first: falling through would draw "At rest", a confident claim
		// this state has no grounds to make (IAMT-311).
		return "This machine's own status could not be checked", "Unknown", design.WarnKey
	}
	switch {
	case s.AccessOpen():
		// THE SAME CLAIM THE STRIP USED TO MAKE, AND THE SAME CORRECTION
		// (21.09.2026). What AccessOpen reports is that the door is up,
		// not that anybody walked through it -- and this window says
		// "nobody is inside any machine at this moment" two tabs away,
		// on Session and Admin -> Live, which are the screens that
		// actually ask the gateway about attached terminals.
		//
		// The big word stays honest about the OTHER half, the half this
		// product is for: from the moment the door opens, whatever
		// happens behind it is recorded. "Open" is the state; "recorded
		// from the first keystroke" is the promise.
		return "The way in is open — anything done here is recorded", "Open", design.SpotKey
	case s.Door.IsOpen():
		return "A booked specialist is entering", "Door open", design.SpotKey
	case s.Waiting:
		return "Waiting for a specialist to connect", "Waiting", design.GoodKey
	case s.Running:
		// Up, but not reachable: the agent is running and its tunnel to
		// the gateway is not. "At rest" here would be false twice over
		// -- something IS running, and the machine is NOT reachable
		// (IAMT-358).
		return "The machine agent is running, but the gateway cannot be reached", "Disconnected", design.WarnKey
	default:
		return "The door is shut — nobody can get in", "At rest", design.InkKey
	}
}

// layoutServerNotice draws the gateway's reason for refusing this machine
// in Warn, directly under the state headline. It exists exactly when the
// snapshot carries a notice: there is no switch that hides a non-empty
// one, and an empty one draws nothing at all (the zero snapshot stays an
// honest idle machine).
func (f *Frame) layoutServerNotice(gtx layout.Context) layout.Dimensions {
	if strings.TrimSpace(f.snap.Server.Notice) == "" {
		return layout.Dimensions{}
	}
	return widget.Border{
		Color:        f.theme.Color(design.WarnKey),
		Width:        unit.Dp(1),
		CornerRadius: unit.Dp(design.Radius),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top: unit.Dp(design.Pad), Bottom: unit.Dp(design.Pad),
			Left: unit.Dp(design.Pad), Right: unit.Dp(design.Pad),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return design.Status(gtx, f.theme,
				func(gtx layout.Context) layout.Dimensions {
					return design.Dot(gtx, f.theme, design.WarnKey, false)
				},
				func(gtx layout.Context) layout.Dimensions {
					return design.Words(gtx, f.theme, f.snap.Server.Notice, design.SmallSp, design.WarnKey, f.theme.MonoFont)
				})
		})
	})
}

// recordingFact words the one safety fact of the server screen.
func recordingFact(s ServerState) string {
	if s.Unknown {
		// A recording state that could not be learned must never read as
		// "off" — that is a promise of safety this state cannot make
		// (IAMT-311).
		return s.unknownText()
	}
	if s.AccessOpen() {
		return "ON — everything done through this open door is recorded on the gateway"
	}
	return "off — starts the moment the door opens"
}

// doorStateText is the door card's "state" fact: the CLI-honest reading
// of an unlearnable door — "unknown", never "closed" — ahead of the
// ordinary empty-state-means-closed default (IAMT-311).
func doorStateText(s ServerState) string {
	switch {
	case s.Unknown:
		return "unknown"
	case s.Door.State == "":
		return "closed"
	default:
		return s.Door.State
	}
}

// machineNameText is the Server tab's "machine" fact, tri-state like
// every other fact on this screen since round 3 (F-GUI-2): a known name,
// a confirmed absence (the id file was read successfully and is empty —
// orDash's ordinary dash), or "unknown" when the id file could not be
// read at all for a reason other than "not enrolled yet" — a
// permission-style failure (F-GUI-6: the server data directory is
// root-owned 0700, the exact IAMT-311 scenario one layer over: an
// unprivileged window cannot even stat the machine id). A bare dash in
// that case would be indistinguishable from "there genuinely is no
// name", which is not the fact this state carries.
func machineNameText(s SetupState) string {
	if s.MachineNameUnknown {
		return "unknown — could not read this machine's own registration (rights or filesystem problem)"
	}
	if s.MachineName != "" && s.OSUser != "" {
		// The pair, not the name: since 1.4 one machine carries one
		// registration per person, and on a box where two people are
		// signed in at once the name alone does not say which of them
		// this window is driving. See SetupState.OSUser.
		return s.MachineName + " (" + s.OSUser + ")"
	}
	return orDash(s.MachineName)
}

// layoutClientScreen is the entering person's screen (SPEC §3.1).
//
// A framed recording notice stood pinned above this page from 1.0 until
// 21.09.2026, when the maintainer had it taken off: remove the yellow
// frame and the warning, they are not needed. It cost a third of the first screenful
// and repeated a disclosure the product already makes where it counts --
// the first line of every session, and of every exec run, still says the
// session is recorded and names the machine and the expiry. A warning
// that is always on screen is one nobody reads; one that arrives with the
// thing it warns about is read every time.
func (f *Frame) layoutClientScreen(gtx layout.Context) layout.Dimensions {
	c := f.snap.Client

	lead, word, key := clientHeadline(c)

	// The heading FOLLOWS THE SUB-TAB. All three sub-tabs used to keep
	// the Machines heading, so "Machines you may enter / Ready" stood
	// over a screen about the connection string and over one about a
	// public key (21.09.2026). The state word is still the tab's --
	// "Ready" is true wherever you are standing inside it -- but the
	// line above it now says what you are looking at.
	sub := f.subTab([]string{"Machines", "Connection", "Key"})
	if !c.Connected {
		switch sub {
		case "Connection":
			lead = "The line your administrator gave you"
		case "Key":
			lead = "The key this machine shows the gateway"
		}
	}

	sections := []layout.Widget{
		posterOf(f.theme, lead, word, key),
	}

	if c.Connected {
		sections = append(sections, func(gtx layout.Context) layout.Dimensions {
			// The exact first line the far side shows (docs/USER.md §3).
			return design.Status(gtx, f.theme,
				func(gtx layout.Context) layout.Dimensions {
					return design.Dot(gtx, f.theme, design.GoodKey, false)
				},
				func(gtx layout.Context) layout.Dimensions {
					return design.Fixed(gtx, f.theme,
						"This session is recorded. Machine "+orDash(clipStr(c.ActiveMachine, 32))+
							", until "+grantUntilText(c.ActiveUntil)+".")
				})
		})
	}

	// Two sub-tabs (SPEC §7.1, 1.3): what this copy may enter, and what it
	// is. They are different errands — "where can I get in" is asked every
	// day, "which gateway am I bound to and what is my key" once at setup
	// and then only when something is wrong.
	const (
		subMachines   = "Machines"
		subConnection = "Connection"
		subKey        = "Key"
	)
	// Three, not two: gate 17 caught "Connection" holding both the
	// connection string and the public key overflowing a default window,
	// and the rule is to divide further rather than lean on the scrollbar.
	items := []string{subMachines, subConnection, subKey}

	// The strip joins the pinned group rather than scrolling with the
	// content: the way out of a page must not itself be below the fold.
	sections = append(sections, func(gtx layout.Context) layout.Dimensions {
		return f.subTabStrip(gtx, items)
	})
	pinned := len(sections)

	switch sub {
	case subConnection:
		sections = append(sections,
			// What this copy belongs to. Saving it is the first thing a
			// new client does and the only thing that makes the machine
			// list possible at all (IAMT-149).
			cardOf(f.theme, "The connection string your administrator gave you",
				f.layoutConnString),
		)
	case subKey:
		sections = append(sections,
			cardOf(f.theme, "Your public key",
				func(gtx layout.Context) layout.Dimensions {
					return f.layoutPublicKey(gtx, c)
				}),
		)
	default: // subMachines
		// Held commands stand ABOVE the machine list. They are the only
		// thing on this tab with a clock running on it -- five minutes --
		// and the list below is what a person reads every day, which is
		// exactly the wrong place to put something urgent.
		sections = append(sections, f.layoutHeldList)
		sections = append(sections,
			// The list, with the control that goes and asks for it pinned
			// to the right of its own heading — umtunnel's Refresh, in the
			// place umtunnel put it.
			// "Your machines", not "Machines you may enter": the poster
			// above already says the latter, and a card that repeats the
			// heading it sits under spends a line saying nothing.
			cardWithTools(f.theme, "Your machines",
				func(gtx layout.Context) layout.Dimensions {
					return f.layoutMachineList(gtx, f.snap.Client)
				},
				f.layoutRefreshButton),
		)
	}

	// The poster and the sub-tab strip stay pinned above the scrolling
	// part: the way out of a page must not itself be below the fold.
	return design.PinnedPage(gtx, f.theme, f.pageList(), pinned, sections...)
}

// clientHeadline is the state word of the client screen.
func clientHeadline(c ClientState) (lead, word string, key design.ColorKey) {
	switch {
	case c.Connected:
		return "You are working on " + orDash(clipStr(c.ActiveMachine, 40)), "Connected", design.GoodKey
	case c.Configured:
		return "Machines you may enter", "Ready", design.InkKey
	default:
		return "Save the connection string your administrator gave you", "Client", design.InkKey
	}
}

// layoutMachineList: one row per machine — reachability mark, name, the
// exact end of access, and the Connect control (USER.md §3 steps 3–4).
func (f *Frame) layoutMachineList(gtx layout.Context, c ClientState) layout.Dimensions {
	if len(c.Machines) == 0 {
		return design.Text(gtx, f.theme,
			"No machines yet. Save the connection string from your administrator — it carries your access.")
	}

	var children []layout.FlexChild
	for i, m := range c.Machines {
		m, idx := m, i
		children = append(children,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if f.btn("client/connect/" + strconv.Itoa(idx)).Clicked(gtx) {
					f.connectMachine(m)
				}
				if f.btn("client/prompt/" + strconv.Itoa(idx)).Clicked(gtx) {
					f.copyAgentPrompt(gtx, m.Name)
				}
				if f.btn("client/command/" + strconv.Itoa(idx)).Clicked(gtx) {
					f.openCommandWindow(m.Name)
				}
				if f.btn("client/mode/" + strconv.Itoa(idx)).Clicked(gtx) {
					f.openModeWindow(m.Name, m.Caps)
				}
				if f.btn("client/goal/" + strconv.Itoa(idx)).Clicked(gtx) {
					f.openGoalWindow(m.Name)
				}
				if f.btn("client/settings/" + strconv.Itoa(idx)).Clicked(gtx) {
					f.openSettingsWindow()
				}
				key := design.MutedKey
				if m.Online {
					key = design.GoodKey
				}
				return layout.Flex{
					Axis:      layout.Horizontal,
					Alignment: layout.Middle,
				}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Dot(gtx, f.theme, key, !m.Online)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Fixed(gtx, f.theme, orDash(clipStr(m.Name, 32)))
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return design.Hint(gtx, f.theme,
							// THE REMAINING TIME, not the stamp, in a LIST
							// (21.09.2026). A row here answers "can I get
							// in, and for how long" at a glance, and the
							// stamp plus the countdown together wrapped the
							// row onto two lines -- which costs more than
							// either fact is worth in a list. The exact
							// moment is one press away, in the window the
							// capability button opens, and it stands in
							// full beside the countdown on Admin -> Access,
							// where an administrator compares grants.
							accessLeft(m.Until, f.now())+" · sshd "+sshdWord(m.SshdListening))
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						// What this access is FOR, reachable from where the
						// work happens rather than only from Admin →
						// Access. The classifier judges every red command
						// against it, so the moment a person most wants to
						// set it is the moment they are about to work.
						// CompactButton, like its three neighbours: the
						// row was narrowed deliberately, and one button
						// built from the wider primitive stands out as a
						// mistake rather than as emphasis.
						return design.CompactButton(gtx, f.theme,
							f.btn("client/goal/"+strconv.Itoa(idx)), "Goal")
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						// The mode, in words, as a control. The row said
						// when the access ends and whether sshd answers,
						// and never which of the two kinds of access it
						// was -- a person had to infer it from which
						// buttons appeared. Pressing it opens the window
						// that explains both and, for an administrator,
						// changes this one (mode_window.go).
						return design.CompactButton(gtx, f.theme,
							f.btn("client/mode/"+strconv.Itoa(idx)), capWord(m.Caps))
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						// The command box used to live in this row, under
						// the machine's name. It opens in a window of its
						// own now (command_window.go): a row is a row, and
						// one that grows a field, a button and a screenful
						// of output has stopped being one.
						if !isExecOnlyCaps(m.Caps) {
							return layout.Dimensions{}
						}
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.CompactButton(gtx, f.theme,
									f.btn("client/command/"+strconv.Itoa(idx)), "Command")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						// "AI prompt", not "Copy AI prompt": the maintainer's
						// own wording (21.09.2026). What it does is said
						// by the line above the list the moment it is
						// pressed -- "the prompt ... is on the clipboard"
						// -- and a row has no room to say it twice.
						return design.CompactButton(gtx, f.theme, f.btn("client/prompt/"+strconv.Itoa(idx)),
							"AI prompt")
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						// An exec-only grant never gets a
						// Connect button in the first place — the
						// refusal (E_SSH_SHELL_FORBIDDEN) is now
						// immediate and explained, but the point is
						// that a person never has to hit it to
						// find that out. See client_exec.go's row
						// just below for what this machine offers
						// instead.
						if isExecOnlyCaps(m.Caps) {
							return layout.Dimensions{}
						}
						return design.CompactButton(gtx, f.theme, f.btn("client/connect/"+strconv.Itoa(idx)),
							"Connect")
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						// The gateway's own settings, last in the row and
						// square (21.09.2026). The maintainer asked for it
						// here -- a small square button at the end of
						// the row -- because this row is where the work
						// happens,
						// and the settings that decide whether a command
						// run here is allowed lived three screens away, or
						// in a file on the gateway host.
						//
						// Square, not a fifth word: four word-buttons
						// already sit here, and a fifth would push the
						// row past the window on a narrow screen.
						return design.SquareButton(gtx, f.theme,
							f.btn("client/settings/"+strconv.Itoa(idx)), "···")
					}),
				)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		)
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// layoutConnString is the client's own half of the product: which
// gateways this machine remembers, which one it is looking at, and the
// form that adds another.
//
// IT IS A LIST NOW (IAMT-431, 22.09.2026). It held one connection until
// that day, and a second gateway could only be had by destroying the
// first -- which made "my personal machines" and "the machine at work"
// mutually exclusive on one laptop. The maintainer asked for both, and for
// the switch between them to cost one press and ask nothing.
//
// It asks nothing because there is nothing to ask. Authentication in
// this product is the key in the client directory, one per machine, and
// every gateway that knows this person already holds its public half. A
// password box here would be a ceremony with no protocol behind it.
func (f *Frame) layoutConnString(gtx layout.Context) layout.Dimensions {
	if f.submitted(gtx, ctlClientSave) {
		f.saveConnectionString(false)
	}
	if f.btn(ctlClientSave).Clicked(gtx) {
		f.saveConnectionString(false)
	}
	if f.btn(ctlClientSave + "/replace").Clicked(gtx) {
		f.saveConnectionString(true)
	}

	word := "REMEMBER THIS GATEWAY"
	if f.busy(ctlClientSave) {
		word = "SAVING…"
	}
	said := f.saidUnder(ctlClientSave)
	configured := f.snap.Client.Configured

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(f.layoutGatewayList),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme, "add another gateway")
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "connection string",
				func(gtx layout.Context) layout.Dimensions {
					return design.TextBox(gtx, f.theme, f.editor(ctlClientSave),
						"iamtunnel://gateway.example:2222/alice#SHA256:…")
				},
				"the whole line, including everything after the # — it names the gateway, you, and the gateway's key")
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "call it",
				func(gtx layout.Context) layout.Dimensions {
					return design.TextBox(gtx, f.theme, f.editor(ctlClientName), "Work")
				},
				"what you will recognise it by later; left empty, its address names it")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.PrimaryButton(gtx, f.theme, f.btn(ctlClientSave), word)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					// The narrower guard this button now serves: a
					// gateway already saved, presenting a DIFFERENT host
					// key. Adding a second gateway never needs it, so it
					// only appears once there is something to re-key.
					if !configured {
						return layout.Dimensions{}
					}
					return layout.Inset{Left: unit.Dp(design.Gap)}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							return design.SecondaryButton(gtx, f.theme,
								f.btn(ctlClientSave+"/replace"), "Its key changed — accept it")
						})
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, f.theme, f.sel(ctlClientSave+"/said"), clipStr(said.text, 400), said.key)
		}),
	)
}

// layoutGatewayList is the remembered gateways, current one first in
// meaning if not in order: it is the one wearing the word.
//
// The row says who you are there as well as where it is, because "which
// gateway am I on" and "which of my identities is this" are halves of
// one question, and the rest of the window answers neither.
func (f *Frame) layoutGatewayList(gtx layout.Context) layout.Dimensions {
	list := f.snap.Client.Gateways
	current := f.snap.Client.Current
	said := f.saidUnder(ctlClientGateways)

	if len(list) == 0 {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Empty(gtx, f.theme,
					"No gateway yet. Paste the connection string your administrator gave you into the box "+
						"below — there is nothing else to enter, and no password anywhere in this product.")
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Said(gtx, f.theme, f.sel(ctlClientGateways+"/said"), clipStr(said.text, 300), said.key)
			}),
		)
	}

	var children []layout.FlexChild
	children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		return design.Hint(gtx, f.theme, "gateways this machine remembers")
	}))
	for i := range list {
		g := list[i]
		ctl := ctlClientGateways + "/" + strconv.Itoa(i)
		here := strings.EqualFold(g.Name, current)
		if f.btn(ctl + "/use").Clicked(gtx) {
			f.useGateway(g.Name)
		}
		if f.btn(ctl + "/forget").Clicked(gtx) {
			f.forgetGateway(ctl+"/forget", g.Name)
		}
		children = append(children,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.Fixed(gtx, f.theme, gatewayDisplayName(g))
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								key := design.MutedKey
								if here {
									key = design.GoodKey
								}
								return design.Said(gtx, f.theme, f.sel(ctl+"/who"), gatewayLine(g), key)
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if here {
							// No button on the one already in use: a
							// control that would do nothing is a
							// question about whether it did.
							return design.Hint(gtx, f.theme, "in use")
						}
						return design.CompactButton(gtx, f.theme, f.btn(ctl+"/use"), "Use")
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						// An armed ✕ says so on itself as well as in the
						// line under the list: the question is about ONE
						// row, and the row is where the eye is.
						mark := "✕"
						if f.confirming[ctl+"/forget"] {
							mark = "✕?"
						}
						return design.SquareButton(gtx, f.theme, f.btn(ctl+"/forget"), mark)
					}),
				)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		)
	}
	children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		return design.Said(gtx, f.theme, f.sel(ctlClientGateways+"/said"), clipStr(said.text, 300), said.key)
	}))
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// layoutRefreshButton is the control pinned right of the machines
// heading, plus the one sentence the ask came back with. Only the
// gateway knows the live grants, so nothing here is cached or guessed:
// the list is whatever the last answer said.
func (f *Frame) layoutRefreshButton(gtx layout.Context) layout.Dimensions {
	if f.btn(ctlClientRefresh).Clicked(gtx) {
		f.refreshMachines()
	}
	word := "Refresh"
	if f.busy(ctlClientRefresh) {
		word = "Asking…"
	}
	said := f.saidUnder(ctlClientRefresh)
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Right: unit.Dp(design.Gap)}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					return design.Said(gtx, f.theme, f.sel(ctlClientRefresh+"/said"), clipStr(said.text, 120), said.key)
				})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.SecondaryButton(gtx, f.theme, f.btn(ctlClientRefresh), word)
		}),
	)
}

// copyToClipboard puts text on the system clipboard (IAMT-223).
func copyToClipboard(gtx layout.Context, text string) {
	gtx.Execute(clipboard.WriteCmd{Type: "application/text", Data: io.NopCloser(strings.NewReader(text))})
}

// copyAgentPrompt is a machine row's "AI prompt" button (IAMT-223).
func (f *Frame) copyAgentPrompt(gtx layout.Context, machine string) {
	build := f.cfg.Actions.AgentPrompt
	if build == nil {
		f.say(ctlClientRefresh, noRuntime, design.BadKey)
		return
	}
	text, err := build(machine)
	if err != nil {
		f.say(ctlClientRefresh, err.Error(), design.BadKey)
		return
	}
	copyToClipboard(gtx, text)
	f.say(ctlClientRefresh, "The prompt for an AI agent on "+machine+" is on the clipboard.", design.GoodKey)
}

// publicKeyFingerprint is the SHA256 fingerprint of an authorized_keys
// line, in the form every other part of this system prints it.
//
// IT IS THE ONE THING THIS SCREEN WAS MISSING (21.09.2026). The Client
// -> Key tab showed the key itself and nothing else, while the
// administrator on the other end of the conversation sees a fingerprint
// -- on Admin -> People, on Set up, in the connection string. Two people
// on the telephone had a 68-character base64 blob on one side and
// "SHA256:…" on the other, and no way to check they were talking about
// the same key without one of them pasting the blob somewhere.
//
// The arithmetic is the SSH standard's own, and deliberately goes
// through the same ParseAuthorizedKey and Marshal that the gateway's
// auth.Fingerprint goes through: a second, hand-rolled parser of the
// same format is how two sides of one product start disagreeing about
// what a key is.
//
// A line that will not parse gets "" rather than a guess. The screen
// then simply does not show a fingerprint row, which is the honest
// outcome: a WRONG fingerprint is worse than none, because its whole
// purpose is to be compared.
func publicKeyFingerprint(authorizedKey string) string {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(authorizedKey)))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// layoutPublicKey shows the person's own public key to hand to the
// administrator (SPEC §3.1).
func (f *Frame) layoutPublicKey(gtx layout.Context, c ClientState) layout.Dimensions {
	if f.btn("client/copy-key").Clicked(gtx) && strings.TrimSpace(c.PublicKey) != "" {
		copyToClipboard(gtx, c.PublicKey)
		f.say(ctlClientRefresh, "Your public key is on the clipboard.", design.GoodKey)
	}
	if f.btn("client/copy-fp").Clicked(gtx) {
		if fp := publicKeyFingerprint(c.PublicKey); fp != "" {
			copyToClipboard(gtx, fp)
			f.say(ctlClientRefresh, "The fingerprint of your key is on the clipboard.", design.GoodKey)
		}
	}
	if strings.TrimSpace(c.PublicKey) == "" {
		return design.Text(gtx, f.theme,
			"No key yet — it could not be read or created on this machine. \"iamtunnel client key\" says why.")
	}
	fp := publicKeyFingerprint(c.PublicKey)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.CopyableBox(gtx, f.theme, f.sel("client/public-key"), clipStr(c.PublicKey, 96))
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if fp == "" {
				return layout.Dimensions{}
			}
			// The short form that can be read down a telephone, beside
			// the long one that has to be pasted. This is the value an
			// administrator sees for the same key, so it is the value
			// the two of them can actually compare.
			return design.Facts(gtx, f.theme, []design.FactRow{
				design.Fact("fingerprint", fp),
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// COMPACT, not full width (21.09.2026). This was the widest
			// control in the application -- a 923 px bar across the page
			// for "copy" -- while the buttons that hand out administrator
			// rights are 150 px. Weight on a screen means importance, and
			// this one had the most of it by a wide margin.
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.CompactButton(gtx, f.theme, f.btn("client/copy-key"), "Copy key")
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if fp == "" {
						return layout.Dimensions{}
					}
					return design.CompactButton(gtx, f.theme, f.btn("client/copy-fp"), "Copy fingerprint")
				}),
			)
		}),
	)
}

// layoutAdminScreen: handing out and taking back access (SPEC §3.3).
func (f *Frame) layoutAdminScreen(gtx layout.Context) layout.Dimensions {
	a := f.snap.Admin

	peopleBody := func(gtx layout.Context) layout.Dimensions {
		if len(a.People) == 0 {
			return design.Empty(gtx, f.theme, "No people yet. Everyone who may enter a machine appears here — press \"Add person\" above, or open a pairing window so somebody joins with their own key.")
		}
		var children []layout.FlexChild
		for _, p := range a.People {
			p, ctl := p, "admin/people/remove/"+p.Name
			// Rename (D-2a) is keyed by the person's own name for the
			// same reason the goal block is keyed by the pair: the form
			// belongs to this row, and a list that re-sorts between
			// fetches must never let one row's new name land under a
			// different person's button.
			renameCtl := "admin/rename/person/" + p.Name
			if f.btn(ctl).Clicked(gtx) {
				f.removePerson(ctl, p.Name)
			}
			if f.btn(renameCtl + "/disclose").Clicked(gtx) {
				f.renameForm(renameCtl)
			}
			keysCtl := personKeysCtl(p.Name)
			if f.btn(keysCtl + "/disclose").Clicked(gtx) {
				f.toggleForm(keysCtl)
			}
			role := "user"
			if p.Admin {
				role = "admin"
			}
			children = append(children, f.rowWithRemove(ctl,
				orDash(clipStr(p.Name, 24)),
				role+" · "+strconv.Itoa(p.Keys)+" key(s)", renameCtl, keysCtl, "Keys")...)
			children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return f.layoutRowRename(gtx, renameCtl, "new name for "+p.Name,
					func() { f.renamePerson(renameCtl, p.Name) })
			}), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return f.layoutPersonKeys(gtx, p)
			}))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	}

	machinesBody := func(gtx layout.Context) layout.Dimensions {
		if len(a.Machines) == 0 {
			return design.Empty(gtx, f.theme, "No machines yet. Every registered machine appears here — press \"Invite a machine\" above and hand the code to whoever runs it.")
		}
		var children []layout.FlexChild
		for _, m := range a.Machines {
			// Both actions on this row key and speak by the machine's ID
			// (D-2a), not its label: the label is what a rename changes,
			// and a row that then removed or renamed by its own new label
			// would answer a machine the gateway no longer knows by that
			// name. ID equals Name from enrolment until a rename parts
			// them, so nothing else about the row moves today.
			m, ctl := m, "admin/machines/remove/"+m.ID
			renameCtl := "admin/rename/machine/" + m.ID
			if f.btn(ctl).Clicked(gtx) {
				f.removeMachine(ctl, m.ID)
			}
			if f.btn(renameCtl + "/disclose").Clicked(gtx) {
				f.renameForm(renameCtl)
			}
			manageCtl := machineManageCtl(m.ID)
			if f.btn(manageCtl + "/disclose").Clicked(gtx) {
				f.toggleForm(manageCtl)
			}
			door := m.DoorState
			if door == "" {
				door = "closed"
			}
			online := "offline"
			if m.Online {
				online = "online"
			}
			detail := orDash(m.State) + " · door " + door + " · " + online
			if hostKeyMismatch(m) {
				// Said on the row itself, not only inside Manage: it is
				// the one reason a door stays shut that nothing but an
				// administrator's press can clear (IAMT-499).
				detail += " · sshd KEY CHANGED"
			}
			children = append(children, f.rowWithRemove(ctl,
				orDash(clipStr(m.Name, 24)), detail, renameCtl, manageCtl, "Manage")...)
			children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return f.layoutRowRename(gtx, renameCtl, "new label for "+m.Name,
					func() { f.renameMachine(renameCtl, m.ID) })
			}), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return f.layoutMachineManage(gtx, m)
			}))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	}

	grantsBody := func(gtx layout.Context) layout.Dimensions {
		if len(a.Grants) == 0 {
			return design.Empty(gtx, f.theme, "No grants yet. Who may enter which machine, and until when, is listed here — press \"New grant\" above. Being an administrator is not itself permission to enter a machine.")
		}
		var children []layout.FlexChild
		for i, g := range a.Grants {
			g, ctl := g, "admin/revoke/"+strconv.Itoa(i)
			// Extend (M-10) is keyed by the pair, not by the row's
			// position, for the same reason the goal block below is: the
			// deadline belongs to the grant, and a list that re-sorts
			// must never let one row's deadline land under a different
			// pair's button.
			extendCtl := "admin/extend/" + g.Person + "/" + g.Machine
			if f.btn(extendCtl + "/disclose").Clicked(gtx) {
				f.extendForm(extendCtl)
			}
			if f.btn(ctl).Clicked(gtx) {
				f.revokeAccess(ctl, g.Person, g.Machine)
			}
			extendWord := "Extend"
			if f.disclosedForm(extendCtl) {
				extendWord = "Hide"
			}
			word := "Revoke"
			if f.busy(ctl) {
				word = "Revoking…"
			}
			said := f.saidUnder(ctl)
			children = append(children,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{
						Axis:      layout.Horizontal,
						Alignment: layout.Middle,
					}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return design.Fixed(gtx, f.theme,
								orDash(clipStr(g.Person, 24))+" → "+
									orDash(clipStr(g.Machine, 24))+
									" · "+capWord(g.Caps)+
									" · until "+grantUntilLeft(g.Until, f.now()))
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.CompactButton(gtx, f.theme, f.btn(extendCtl+"/disclose"), extendWord)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.SecondaryButton(gtx, f.theme, f.btn(ctl), word)
						}),
					)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Said(gtx, f.theme, f.sel(ctl+"/said"), clipStr(said.text, 200), said.key)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return f.layoutGrantExtend(gtx, g)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return f.layoutGrantGoal(gtx, g)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
			)
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	}

	// Four sub-tabs instead of eight cards down one page (SPEC §7.1, 1.3).
	// Until 1.3 all eight stood in a column: People, Machines, Grants,
	// Grant access, then the four 1.2 cards. In the maintainer's live run the
	// window ended after the fourth, there was no scrollbar (IAMT-334),
	// and "Become an administrator" — the entry point to the whole
	// pairing flow — was simply invisible. His instruction was not "add a
	// scrollbar" but "if there are logical parts, separate them with
	// tabs", and the parts here really are independent: looking at who
	// may enter has nothing to do with joining as an administrator.
	//
	// The 1.2 cards stay live for whoever sees them, exactly as before:
	// the window cannot tell an administrator's key from any other
	// without asking the gateway, so a non-admin who presses a button
	// gets the gateway's own refusal under it, never a hidden control.
	// Grouping them behind a sub-tab does not hide them — a sub-tab strip
	// names every part it holds, which is precisely what the long page
	// failed to do.
	// The lists below live on the gateway, not here. Ask once, the first
	// time this tab is drawn (IAMT-357); the Refresh button under the
	// sub-tab strip asks again whenever the person wants.
	// The fetch on arrival lives in tabEntered (frame.go), with every
	// other tab that shows a list (IAMT-365).
	if f.btn(ctlAdminRefresh).Clicked(gtx) {
		f.refreshAdminLists()
	}

	const (
		subPeople     = "People"
		subMachines   = "Machines"
		subAccess     = "Access"
		subPairing    = "Pairing"
		subLive       = "Live"
		subSafety     = "Safety"
		subClassifier = "Classifier"
		subGateway    = "Gateway"
	)
	// Seven. Every split below was measured rather than guessed -- gate 17
	// renders each sub-tab at the default window size and refuses one
	// that needs a scrollbar, and it is what drove the count from four
	// to eight between 1.4 and 1.10.
	//
	// It came down from eight on 21.09.2026 the other way: Join, People
	// and Pairing were one errand told in three places. Join and People
	// merged; Pairing was measured over the window and stayed out.
	// Dividing is the rule's answer to a page that does not fit -- it was
	// never a reason to keep apart pages that do.
	items := adminSubTabOrder()

	var sections []layout.Widget
	// Every list-shaped sub-tab is built the same way since IAMT-359:
	// the heading with its one action on the right, whatever the last
	// action said, the form ONLY while it is open, then the list. The
	// maintainer named the rule himself after walking the product end to end
	// -- at the top there should be an Add button; press it, the fields
	// appear; afterwards everything hides and only the list remains -- and it is
	// the same rule on all three, because they are the same errand.
	switch f.subTab(items) {
	case subMachines:
		sections = []layout.Widget{
			// Not "machines" -- that is the word on the sub-tab the
			// reader has just clicked. The heading says what the list
			// answers (22.09.2026, same pass as Live, Safety and People).
			f.listSection("machines on this gateway", ctlAdminEnrolCode, "Invite a machine",
				machinesBody, f.layoutEnrolCodeForm, func(gtx layout.Context) layout.Dimensions {
					// A spent code draws nothing at all, clipboard
					// confirmation included (IAMT-390): the box beside
					// this card names the machine the code was minted
					// for, and once that name is a row in the list
					// below, the code already worked and a second
					// attempt can only be refused.
					if enrolCodeSpent(f.editor(ctlAdminEnrolCode+"/name").Text(), f.snap.Admin.Machines) {
						return layout.Dimensions{}
					}
					return f.layoutHandOver(gtx, ctlAdminEnrolCode, f.saidUnder(ctlAdminEnrolCode).give,
						"Copy enrol code", "The enrol code is on the clipboard.")
				}),
		}
	case subAccess:
		// The ledger and the form that adds to it, on ONE sub-tab. They
		// stood apart from 1.4 until 19.09.2026 for a reason that has
		// stopped being true: the form was permanently on screen, and
		// the pair did not fit the window. A form that appears only when
		// asked for costs the page nothing while it is closed, so the
		// split bought height at the price the maintainer actually noticed --
		// why two tabs here? It made no sense.
		sections = []layout.Widget{
			f.listSection("grants", ctlAdminGrant, "New grant",
				grantsBody, f.layoutGrantForm),
		}
	case subLive:
		// Who is inside right now, and a way to watch or cut it off.
		// Existed only as admin verbs in a terminal until 19.09.2026
		// (IAMT-360). Split from "Safety" on 20.09.2026 (IAMT-398): gate
		// 17 measured the two together over the default window once
		// IAMT-387 stopped capping a section's reported height at the
		// window's own — the card was always this tall, the cap had
		// just been hiding the true length behind a scroll gate that
		// could never fire. "Who is in my machines right now" and "how
		// strict is the policy" are different questions asked at
		// different times; splitting by that, not by a byte count,
		// also gives the safety mode switch room of its own, which is
		// what the maintainer asked for on 20.09.2026 in the first place
		// (IAMT-393).
		// The card used to be titled "Live" -- the sub-tab's own name --
		// over a body whose first heading was "who is inside right now".
		// Two headings, one of them a word the reader had just clicked.
		// The informative one is now the card's, and the body no longer
		// repeats it (21.09.2026).
		sections = []layout.Widget{
			cardOf(f.theme, "Who is inside right now", f.layoutLiveSection),
		}
	case subSafety:
		// How strict the gateway is right now, and a dry run against
		// its own rules. Lived on the Live sub-tab until IAMT-398 split
		// it off (see subLive's own comment for why).
		// The card's title says what the page answers, not the word the
		// reader has just clicked (21.09.2026): the sub-tab is already
		// called SAFETY, and a card headed "SAFETY" under it, whose
		// first heading was "SAFETY MODE", spent three rows saying
		// nothing new.
		sections = []layout.Widget{
			cardOf(f.theme, "How strict the gateway is right now", f.layoutSafetySection),
		}
	case subClassifier:
		// Replacing the typesafe.ai key the external classifier calls
		// with (SPEC IAMT-403). Its own sub-tab rather than a second
		// card on Safety: Safety already stood at 61 px of gate 17's
		// margin (measured 20.09.2026), and a field-and-button card of
		// this shape would have put it back over — the exact defect
		// IAMT-398 exists to catch.
		sections = []layout.Widget{
			cardOf(f.theme, "Classifier key", f.layoutClassifierKeySection),
		}
	case subGateway:
		// The gateway's own key and state (IAMT-499): "gateway
		// fingerprint", "backup" and "rotate-hostkey", which until
		// 24.09.2026 only the console had. A sub-tab of its own: it is
		// about the gateway, not about anybody on it.
		sections = []layout.Widget{
			cardOf(f.theme, "The gateway's own key and state", f.layoutGatewaySection),
		}
	case subPairing:
		// The window an administrator opens so somebody ELSE can walk in
		// with their own key. It belongs with People by errand and was
		// folded in on 21.09.2026 -- and taken back out the same hour,
		// because gate 17 measured the merged page over the default
		// window. It stays alone until the add-person form gives up
		// asking for a public key, which is the row that costs the height.
		sections = []layout.Widget{
			cardOf(f.theme, "Pairing window", f.layoutPairingCard),
		}
	default: // subPeople
		// One tab for everybody on this gateway, starting with you
		// (21.09.2026). It was two -- Join and People -- and the maintainer
		// asked whether they were one; they are, and the order they go in
		// is the order the questions are asked. Who am I here, then who
		// else is here.
		//
		// What is on the tab depends on the answer to the first, and not
		// to save room: a machine that has not joined CANNOT list the
		// people on its gateway -- it has no administrator's key to ask
		// with -- so a list drawn there would be an empty list, which
		// says "nobody" where the truth is "you have not asked yet".
		//
		// Pairing was meant to come here too. Gate 17 measured the three
		// together over the default window and refused them, which is the
		// rule working rather than an argument against it, so pairing
		// stayed on its own tab.
		if f.snap.Admin.ThisMachine == nil {
			sections = []layout.Widget{
				cardOf(f.theme, joinCardTitle(nil), f.layoutPairJoinForm),
			}
			break
		}
		sections = []layout.Widget{
			cardOf(f.theme, joinCardTitle(f.snap.Admin.ThisMachine), f.layoutPairJoinForm),
			// Not "people": the sub-tab above already says it. The
			// heading names what the list holds.
			f.listSection("everybody on this gateway", ctlAdminPeopleAdd, "Add person",
				peopleBody, f.layoutPeopleAddForm),
		}
	}

	deck, word, key := adminPosterDeck(f.snap.Admin)
	return design.SubTabPage(gtx, f.theme, f.pageList(),
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(posterOf(f.theme, deck, word, key)),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
				// The Refresh control rides the sub-tab strip rather
				// than taking a row of its own: one button serves the
				// whole tab, because every list on it comes from the
				// same fetch. A row of its own cost Admin/People the
				// default window, and gate 17 said so.
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					word := "Refresh"
					if f.busy(ctlAdminRefresh) {
						word = "ASKING…"
					}
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							return f.subTabStrip(gtx, items)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.SecondaryButton(gtx, f.theme, f.btn(ctlAdminRefresh), word)
						}),
					)
				}),
				// Only a FAILURE is worth a line here. A successful
				// fetch shows itself in the lists below, and a sentence
				// saying so would cost a row on every tab that is
				// already at the window's edge.
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					said := f.saidUnder(ctlAdminRefresh)
					return design.Said(gtx, f.theme, f.sel(ctlAdminRefresh+"/said"),
						clipStr(said.text, 200), said.key)
				}),
			)
		},
		sections...,
	)
}

// rowWithRemove is one row of a list that can be renamed or removed
// from: the name, what it is, the row's Rename control (whose form
// layoutRowRename draws under the row), and the control that takes the
// row away, with the row's own status line under it. The line belongs to
// the ROW, not to the page -- the confirm question and the gateway's
// refusal both have to appear beside the thing they are about, or a
// person with six machines reads a sentence and cannot tell which one it
// answered.
//
// moreCtl and moreWord are the row's third control (IAMT-499): a panel of
// its own -- a machine's Manage, a person's Keys -- disclosed under the
// row the same way the rename form is.
func (f *Frame) rowWithRemove(ctl, name, detail, renameCtl, moreCtl, moreWord string) []layout.FlexChild {
	said := f.saidUnder(ctl)
	word := "Remove"
	if f.confirming[ctl] {
		word = "Confirm"
	}
	if f.busy(ctl) {
		word = "Removing…"
	}
	renameWord := "Rename"
	if f.disclosedForm(renameCtl) {
		renameWord = "Hide"
	}
	if f.disclosedForm(moreCtl) {
		moreWord = "Hide"
	}
	return []layout.FlexChild{
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Fixed(gtx, f.theme, name)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme, detail)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.CompactButton(gtx, f.theme, f.btn(moreCtl+"/disclose"), moreWord)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.CompactButton(gtx, f.theme, f.btn(renameCtl+"/disclose"), renameWord)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.SecondaryButton(gtx, f.theme, f.btn(ctl), word)
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, f.theme, f.sel(ctl+"/said"), clipStr(said.text, 200), said.key)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
	}
}

// listSection is the one shape every list-shaped screen has since
// IAMT-359: heading and its single action, what that action last said,
// the form while it is open, and the list (SPEC 7.1).
//
// The order is deliberate. The list is what the person came for, so it
// is never pushed off the screen by a form nobody opened; the sentence
// the action left behind stays after the form has closed itself, because
// the answer outlives the question.
func (f *Frame) listSection(label, ctl, word string, list layout.Widget, form layout.Widget, kept ...layout.Widget) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if f.btn(ctl + "/disclose").Clicked(gtx) {
			f.toggleForm(ctl)
		}
		open := f.disclosedForm(ctl)
		head := word
		if open {
			head = "Hide"
		}
		said := f.saidUnder(ctl)

		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.SectionHead(gtx, f.theme, label, f.btn(ctl+"/disclose"), head)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if said.text == "" {
					return layout.Dimensions{}
				}
				return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx,
					func(gtx layout.Context) layout.Dimensions {
						return design.Said(gtx, f.theme, f.sel(ctl+"/said"), clipStr(said.text, 400), said.key)
					})
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if !open {
					return layout.Dimensions{}
				}
				return layout.Inset{Top: unit.Dp(design.Gap), Bottom: unit.Dp(design.Gap)}.Layout(gtx, form)
			}),
			// What the action HANDED BACK outlives the form that asked
			// for it. A one-time enrol code that vanished the instant
			// the form closed itself would be unrecoverable -- the
			// gateway never repeats it -- so it stays above the list
			// with its own Copy until it is dismissed.
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if len(kept) == 0 {
					return layout.Dimensions{}
				}
				return kept[0](gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
			layout.Rigid(list),
		)
	}
}

// layoutGrantForm is the Admin screen's own form: person, machine, until
// and capability, each on its own row — the maintainer's own correction of
// 20.09.2026 (IAMT-391): until and capability used to share one row,
// until as a raw RFC 3339 box with four presets as buttons under it, and
// the pair read as visually different from person and machine above
// them for no reason anyone could find. Why are the Until and Capability
// fields on one line? They should be laid out the same way as the
// previous fields, one under another, and they should also be
// drop-down lists. All four are now the same combo box in the same one-per-row
// layout; grantAccess turns until's word back into what "admin grants
// grant" (guiGrant, cmd/iamtunnel/gui_actions.go) actually reads.
func (f *Frame) layoutGrantForm(gtx layout.Context) layout.Dimensions {
	if f.btn(ctlAdminGrant).Clicked(gtx) {
		f.grantAccess()
	}
	word := "GRANT ACCESS"
	if f.busy(ctlAdminGrant) {
		word = "GRANTING…"
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "person",
				func(gtx layout.Context) layout.Dimensions {
					return f.combo(gtx, ctlAdminGrant+"/person", "alice", peopleNames(f.snap.Admin.People))
				}, "")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "machine",
				func(gtx layout.Context) layout.Dimensions {
					return f.combo(gtx, ctlAdminGrant+"/machine", "win-srv01", machineNames(f.snap.Admin.Machines))
				}, "")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "until",
				func(gtx layout.Context) layout.Dimensions {
					return f.combo(gtx, ctlAdminGrant+"/until", "until revoked", untilPresetWords())
				}, f.grantUntilHint())
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "capability",
				func(gtx layout.Context) layout.Dimensions {
					return f.combo(gtx, ctlAdminGrant+"/capability", "exec", []string{"exec", "shell"})
				}, "shell is interactive; exec is classified")
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if f.grantCapability() != "shell" {
				return layout.Dimensions{}
			}
			return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx, f.layoutShellCapabilityWarning)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.PrimaryButton(gtx, f.theme, f.btn(ctlAdminGrant), word)
		}),
	)
}

// layoutShellCapabilityWarning is the standing notice a "shell" grant
// carries (IAMT-400) — the maintainer's own conclusion once it was clear
// what
// shell and exec actually differ by: the Exec mode should be the
// default, and the shell mode should carry a warning that it is a
// dangerous mode that cannot be stopped.
//
// It names the REASON, not just the refusal, matching how the safety
// mode hint on Admin/Safety already puts the same fact ("interactive
// shell keystrokes are not classified"): an interactive shell carries
// keystrokes over the wire one at a time, so there is never a moment a
// whole command exists to grade. Log, warn, ask and block all read that
// absence the same way — nothing to judge — so all four do nothing on a
// shell grant, not just the strict ones. Saying only "shell is
// dangerous" would leave a reasonable person expecting SOME mode to
// help; saying why leaves them knowing exactly what they picked.
//
// It is not a dialog and not a one-time toast — the caller draws it for
// as long as "shell" stays picked, because the gap it names does not
// close once read once.
func (f *Frame) layoutShellCapabilityWarning(gtx layout.Context) layout.Dimensions {
	return widget.Border{
		Color:        f.theme.Color(design.WarnKey),
		Width:        unit.Dp(1),
		CornerRadius: unit.Dp(design.Radius),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top: unit.Dp(design.Pad), Bottom: unit.Dp(design.Pad),
			Left: unit.Dp(design.Pad), Right: unit.Dp(design.Pad),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return design.Status(gtx, f.theme,
				func(gtx layout.Context) layout.Dimensions {
					return design.Dot(gtx, f.theme, design.WarnKey, false)
				},
				func(gtx layout.Context) layout.Dimensions {
					return design.Words(gtx, f.theme,
						"No safety mode applies to a shell grant: the gateway sees keystrokes here, "+
							"never a whole command to classify, so log, warn, ask and block all do nothing.",
						design.SmallSp, design.WarnKey, f.theme.MonoFont)
				})
		})
	})
}

// goalPreviewHeight bounds the claimed-goal box at roughly five lines
// of Body text before it scrolls (SPEC IAMT-402 point 2, the maintainer's
// own
// words: about the first five lines of it are shown, and the rest is
// reachable by scrolling). It is a fixed pixel bound for the same reason
// transcriptExcerptHeight is one (live_watch.go, IAMT-366): an unbounded
// box lets a long goal push the Revoke button and every grant listed
// after it off the page, with nothing on screen to say why.
const goalPreviewHeight = 100

// layoutGrantGoal is one grant row's own goal block (SPEC IAMT-402):
// the working purpose an administrator claims for exactly this
// person-machine pair, so a context-aware classifier can judge a command
// against what it is FOR instead of in isolation. It belongs to the
// grant, which is why ctl is keyed by the pair rather than by the row's
// position in the list — see claimGoal's own comment.
//
// Three states, never two at once: no goal claimed yet (a bare "Claim
// goal" button), a goal claimed and the form closed (the bounded,
// scrolling, selectable box plus "Change goal"), and the claim form
// itself open. The claim form's box is cleared the instant it is opened,
// never when it closes — the maintainer's own decision against a stale
// goal outliving the form that would have let someone notice it
// (point 4): a deadline is a guess, while resetting to empty guarantees
// one cannot accidentally keep working under yesterday's goal.
func (f *Frame) layoutGrantGoal(gtx layout.Context, g Grant) layout.Dimensions {
	ctl := "admin/goal/" + g.Person + "/" + g.Machine
	discloseCtl := ctl + "/disclose"
	if f.btn(discloseCtl).Clicked(gtx) {
		f.openGoalForm(ctl)
	}
	if f.btn(ctl).Clicked(gtx) {
		f.claimGoal(ctl, g.Person, g.Machine)
	}
	open := f.disclosedForm(ctl)
	said := f.saidUnder(ctl)

	discloseWord := "Claim goal"
	if g.Goal != "" {
		discloseWord = "Change goal"
	}
	if open {
		discloseWord = "Hide"
	}
	saveWord := "SAVE TARGET"
	if f.busy(ctl) {
		saveWord = "SAVING…"
	}

	var body layout.Widget
	switch {
	case open:
		body = func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.Field(gtx, f.theme, "goal",
								func(gtx layout.Context) layout.Dimensions {
									return f.combo(gtx, ctl+"/box",
										"what is this access for right now?", g.RecentGoals)
								}, "")
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if !f.classifierIgnoresGoal() {
								return layout.Dimensions{}
							}
							return design.Hint(gtx, f.theme,
								"No effect while the classifier is rules: rules read text, not context. "+
									"It matters once the classifier is ai or both.")
						}),
						layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.PrimaryButton(gtx, f.theme, f.btn(ctl), saveWord)
						}),
					)
				})
		}
	case g.Goal != "":
		body = func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Max.Y = gtx.Dp(goalPreviewHeight)
					gtx.Constraints.Min.Y = gtx.Constraints.Max.Y
					return design.PageScrollbar(f.theme, f.namedList(ctl+"/scroll")).
						Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
							return design.CopyableBox(gtx, f.theme, f.sel(ctl+"/text"), g.Goal)
						})
				})
		}
	default:
		// SAY that none is claimed, rather than showing a button and
		// nothing else (21.09.2026). The goal is what a red command is
		// judged against, so "no goal" is a fact about how this grant
		// behaves -- and a screen that omits it leaves the reader to
		// guess whether the goal is absent or merely not drawn here.
		body = func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme,
						"no goal claimed — commands on this grant are judged with no context")
				})
		}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// Its own width, not the page's. A Rigid child of a vertical
			// Flex inherits the full width, and a secondary button fills
			// what it is given -- so this drew as a bar across the whole
			// screen under a row whose other buttons are ordinary size.
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.CompactButton(gtx, f.theme, f.btn(discloseCtl), discloseWord)
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Dimensions{}
				}),
			)
		}),
		layout.Rigid(body),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if said.text == "" {
				return layout.Dimensions{}
			}
			return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx,
				func(gtx layout.Context) layout.Dimensions {
					return design.Said(gtx, f.theme, f.sel(ctl+"/said"), clipStr(said.text, 300), said.key)
				})
		}),
	)
}

// layoutGrantExtend is one grant row's extend form (M-10), drawn between
// the row's own status line and its goal block, and only while its
// Extend control is toggled open — closed it costs no height at all,
// which is why the control sits on the row itself rather than growing a
// block of its own the way the goal block does: a grants list is already
// the tallest thing on this sub-tab, and a form nobody opened must not
// push the rows under it off the page.
//
// ctl is the same pair-keyed name extendForm and extendAccess use, so
// the comment there about re-sorting lists applies to this drawing too.
func (f *Frame) layoutGrantExtend(gtx layout.Context, g Grant) layout.Dimensions {
	ctl := "admin/extend/" + g.Person + "/" + g.Machine
	if !f.disclosedForm(ctl) {
		return layout.Dimensions{}
	}
	if f.btn(ctl).Clicked(gtx) {
		f.extendAccess(ctl, g.Person, g.Machine)
	}
	applyWord := "APPLY DEADLINE"
	if f.busy(ctl) {
		applyWord = "APPLYING…"
	}
	// The hint is the exact instant the box's word resolves to, computed
	// at the moment it is drawn, on the same terms grantUntilHint uses
	// for the grant form: a preset chosen on a card left open for another
	// hour must go on meaning "in an hour", never freeze at the instant
	// of the click. A word typed verbatim already shows the instant, and
	// an empty box is the state extendAccess refuses — the hint names the
	// way out instead of repeating the refusal nobody has triggered yet.
	hint := "pick a preset, or type RFC 3339; \"until revoked\" makes the grant indefinite"
	if word := strings.TrimSpace(f.editor(ctl + "/box").Text()); word != "" {
		hint = ""
		if resolved, ok := untilFromPreset(word, f.now()); ok {
			if resolved == "" {
				hint = "no expiry — the grant stands until revoked"
			} else {
				hint = resolved
			}
		}
	}
	said := f.saidUnder(ctl)
	return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Field(gtx, f.theme, "deadline",
						func(gtx layout.Context) layout.Dimensions {
							return f.combo(gtx, ctl+"/box", "new deadline", untilPresetWords())
						}, hint)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.PrimaryButton(gtx, f.theme, f.btn(ctl), applyWord)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if said.text == "" {
						return layout.Dimensions{}
					}
					return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							return design.Said(gtx, f.theme, f.sel(ctl+"/said"), clipStr(said.text, 300), said.key)
						})
				}),
			)
		})
}

// layoutRowRename is one people or machines row's rename form (D-2a),
// drawn under the row and only while its Rename control is toggled open
// — closed it costs no height at all, the same rule layoutGrantExtend
// follows: this sub-tab is already the tallest thing in the window, and
// a form nobody opened must not push the rows under it off the page.
//
// ctl is the same name renameForm and the row's apply action use, so the
// comment there about keys drawn from the row's own identity (not its
// position in a re-sorting list) applies here too. The box opens empty
// — renameForm clears it — and the placeholder names the row being
// renamed, so a press with nothing typed is a mistake you can see.
func (f *Frame) layoutRowRename(gtx layout.Context, ctl, placeholder string, apply func()) layout.Dimensions {
	if !f.disclosedForm(ctl) {
		return layout.Dimensions{}
	}
	if f.btn(ctl).Clicked(gtx) || f.submitted(gtx, ctl+"/box") {
		apply()
	}
	applyWord := "APPLY RENAME"
	if f.busy(ctl) {
		applyWord = "APPLYING…"
	}
	said := f.saidUnder(ctl)
	return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx,
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Field(gtx, f.theme, "new name",
						func(gtx layout.Context) layout.Dimensions {
							return design.TextBox(gtx, f.theme, f.editor(ctl+"/box"), placeholder)
						}, "")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.PrimaryButton(gtx, f.theme, f.btn(ctl), applyWord)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if said.text == "" {
						return layout.Dimensions{}
					}
					return layout.Inset{Top: unit.Dp(design.Tight)}.Layout(gtx,
						func(gtx layout.Context) layout.Dimensions {
							return design.Said(gtx, f.theme, f.sel(ctl+"/said"), clipStr(said.text, 300), said.key)
						})
				}),
			)
		})
}

// combo is a field that can be typed into and also offers the names the
// gateway already knows (IAMT-359).
//
// It replaces pickInto, whose strip of words sat UNDER the box in the
// same quiet capitals as the captions beside it. The maintainer read it as a
// caption -- which is exactly what it looked like -- and reported the
// lists as missing on a screen that was already drawing them.
func (f *Frame) combo(gtx layout.Context, ctl, hint string, options []string) layout.Dimensions {
	ed := f.editor(ctl)
	openBtn := f.btn(ctl + "/open")
	if openBtn.Clicked(gtx) {
		f.expanded[ctl] = !f.expanded[ctl]
	}
	dims, picked := design.ComboBox(gtx, f.theme, ed, hint, openBtn, f.expanded[ctl], options,
		func(name string) *widget.Clickable { return f.btn(ctl + "/pick/" + name) })
	if picked != "" {
		ed.SetText(picked)
		// Choosing is the end of choosing: the panel closes itself
		// rather than waiting for a second press somewhere else.
		f.expanded[ctl] = false
	}
	return dims
}

// untilPresets are the four answers to "until when" that cover the
// question in practice: the rest of a call, the rest of a working day,
// the rest of a day, and no end at all. They exist because the box above
// asks for RFC 3339 — "2026-09-13T18:00:00Z" — which is a machine's way
// of writing a time and which nobody types correctly at the second
// attempt, let alone the first.
//
// "until revoked" is the empty string on purpose: that is already what
// an empty box means to admin grants grant, so pressing it clears the
// box rather than inventing a word the command would have to learn.
var untilPresets = []struct {
	word string
	d    time.Duration
}{
	{"1 hour", time.Hour},
	{"8 hours", 8 * time.Hour},
	{"24 hours", 24 * time.Hour},
	{"until revoked", 0},
}

// untilPresetWords is the until combo's options, in the same order the
// four presets have always offered them.
func untilPresetWords() []string {
	words := make([]string, len(untilPresets))
	for i, p := range untilPresets {
		words[i] = p.word
	}
	return words
}

// untilFromPreset turns the word the until box holds — a preset, picked
// or typed — into what the gateway should be asked for, and reports
// whether it recognised the word at all. A box holding neither a known
// preset nor the empty string is read as typed verbatim (IAMT-391): the
// combo does not stop a person pasting their own RFC 3339 instant, and a
// function that refused anything it did not itself offer would be the
// same defect the four preset BUTTONS existed to fix, one layer up.
//
// It is separate from the drawing because it is the only part that can
// be wrong in a way a picture would not show: an offset computed from
// the wrong clock, a format the gateway then refuses, or "until revoked"
// writing the word instead of the empty string the command reads as
// indefinite.
func untilFromPreset(word string, now time.Time) (string, bool) {
	for _, p := range untilPresets {
		if p.word != word {
			continue
		}
		if p.d == 0 {
			return "", true
		}
		return now.Add(p.d).UTC().Format(time.RFC3339), true
	}
	return "", false
}

// grantUntilHint is the until field's own hint: the exact instant the
// current word resolves to, computed at the moment it is drawn — not
// when it was picked — for the same reason the presets themselves are
// (SPEC IAMT-391 point 5). "1 hour" chosen on a card left open for
// another hour must go on meaning "in one hour", never freeze at the
// instant of the click; recomputing on every frame is what keeps the
// word and the instant beside it agreeing.
func (f *Frame) grantUntilHint() string {
	text := strings.TrimSpace(f.editor(ctlAdminGrant + "/until").Text())
	resolved, ok := untilFromPreset(text, f.now())
	if !ok {
		if text == "" {
			return "no expiry — the grant stands until revoked"
		}
		// Typed verbatim rather than picked: the box already shows the
		// exact instant, so there is nothing a hint would add.
		return ""
	}
	if resolved == "" {
		return "no expiry — the grant stands until revoked"
	}
	at, err := time.Parse(time.RFC3339, resolved)
	if err != nil {
		return ""
	}
	return "ends " + untilText(at)
}

// peopleNames and machineNames are the picker's source: the names this
// snapshot already knows, in the order the lists above them show.
func peopleNames(people []Person) []string {
	names := make([]string, 0, len(people))
	for _, p := range people {
		if p.Name != "" {
			names = append(names, p.Name)
		}
	}
	return names
}

func machineNames(machines []AdminMachine) []string {
	names := make([]string, 0, len(machines))
	for _, m := range machines {
		if m.Name != "" {
			names = append(names, m.Name)
		}
	}
	return names
}

// enrolCodeSpent reports whether the invitation on screen has already
// been redeemed (SPEC §3.4, IAMT-390): a machine by the invited name now
// stands in the list the gateway itself just confirmed. That is checked
// by NAME, not by state ("verified" vs "enrolled"), because the one-time
// code is spent the instant the machine registers with it -- before the
// entry check that later flips "enrolled" to "verified" ever runs -- and
// a card still inviting a second use of an already-registered name would
// walk straight into the same refusal the maintainer hit on 20.09.2026, one
// row above the machine that proved the code had already worked.
func enrolCodeSpent(invitedName string, machines []AdminMachine) bool {
	invitedName = strings.TrimSpace(invitedName)
	if invitedName == "" {
		return false
	}
	for _, m := range machines {
		if strings.EqualFold(m.Name, invitedName) {
			return true
		}
	}
	return false
}

// layoutAlreadyJoined is what the Join card draws on a machine that has
// already joined (IAMT-356).
//
// On 19.09.2026 the maintainer restarted the window, went to JOIN, pasted the
// claim line still in hand, and was told "could not reach the
// gateway". They had joined an hour earlier; a claim line is one-time, and
// the gateway had simply refused a spent one. The card showed him a form
// that on that machine could never again succeed, and said nothing about
// the identity he already carried.
//
// So the card now answers the question first: who this machine is, where,
// and under which host key. Everything here is read from the saved record
// -- no network -- which is the point: this is exactly what a person needs
// to see when the network answer is the confusing one.
//
// The role is not claimed. The record does not carry one and the gateway
// is the only thing that knows; "you are an administrator" printed from
// the presence of a file would be a lie on any machine that joined as an
// ordinary user. The Admin tab's other sub-tabs answer that question by
// working or refusing, which is the truthful way to ask it.
func (f *Frame) layoutAlreadyJoined(gtx layout.Context, id *AdminIdentity) layout.Dimensions {
	if f.btn(ctlAdminForget).Clicked(gtx) {
		f.forgetAdminIdentity()
	}
	word := "FORGET THIS IDENTITY"
	if f.confirming[ctlAdminForget] {
		word = "PRESS AGAIN TO FORGET"
	}
	if f.busy(ctlAdminForget) {
		word = "FORGETTING…"
	}
	said := f.saidUnder(ctlAdminForget)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// The paragraph that used to open this card explained why the
		// claim form beside it was useless -- a spent line, refused by
		// the gateway rather than by the window. The form is gone as of
		// 21.09.2026, so the explanation had nothing left to explain and
		// went with it. What is left is what a person actually comes here
		// to read: who this machine is, where, and under which host key.
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Facts(gtx, f.theme, []design.FactRow{
				design.Fact("you are", orDash(id.Person)),
				design.Fact("on", orDash(id.Gateway)),
				design.Fact("host key", orDash(clipStr(id.HostKey, 96))),
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme,
				"Forgetting is local: the person record survives, and the machine key stays on disk. "+
					"To come back, paste the gateway's connection string on the Client tab — no claim line, no PIN.")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// Its own width, not the page's. A bar across the whole
			// column for a button nobody presses twice a year outweighed
			// every control that gets used (22.09.2026, same pass as
			// Copy key and Copy the line).
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.SecondaryButton(gtx, f.theme, f.btn(ctlAdminForget), word)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, f.theme, f.sel(ctlAdminForget+"/said"), clipStr(said.text, 400), said.key)
		}),
	)
}

// layoutPairJoinForm is the "Become an administrator" card (SPEC §3.5,
// §7.1): the reference and PIN a pairing window printed, then the button
// that spends them (guiAdminPair, cmd/iamtunnel/gui_actions.go). Enter in
// either box means the same as the button. After success this machine's
// own key is an administrator's key.
//
// One card at a time, never both (21.09.2026). A machine that has joined
// shows ONLY its identity, full width; a machine that has not shows ONLY
// the form. The two stood side by side for two days, and the maintainer's
// reading of that was the right one: two thirds of the card was a form
// for an errand already done, and the identity -- the part that answers
// "who am I here" -- was squeezed into the remaining third.
//
// What this costs is the one path where a joined machine pastes a fresh
// claim line or PIN. It is not lost, it is one press longer: FORGET
// THIS IDENTITY, and the form is back. That ordering is also the honest
// one, because pasting a new line over a live identity was never a
// continuation of anything -- it was replacing this machine's answer to
// "who am I", which is exactly what Forget says out loud.
func (f *Frame) layoutPairJoinForm(gtx layout.Context) layout.Dimensions {
	if f.btn(ctlAdminPairJoin).Clicked(gtx) ||
		f.submitted(gtx, ctlAdminPairJoin) {
		f.joinAsAdmin()
	}
	if f.btn(ctlAdminPairJoin+"/name").Clicked(gtx) ||
		f.submitted(gtx, ctlAdminPairJoin+"/name") {
		// The optional admin-name field is debounced into the join
		// action via the editor itself; the action reads the editor's
		// text at press time, no separate "Apply name" button needed.
	}
	word := "JOIN AS ADMINISTRATOR"
	if f.busy(ctlAdminPairJoin) {
		word = "JOINING…"
	}
	said := f.saidUnder(ctlAdminPairJoin)

	formBody := func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Deck(gtx, f.theme,
					"Two lines lead in here, and this box takes either. On a fresh gateway with no administrator "+
						"yet, \"gateway install\" prints a one-time claim line — that one makes you the FIRST "+
						"administrator. Later, an existing administrator opens a pairing window and hands you a "+
						"reference with a six-digit PIN. Either way the result is the same: THIS machine's key "+
						"becomes a permanent administrator key, and the Admin tab works from here.")
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Field(gtx, f.theme, "paste what you were given",
					func(gtx layout.Context) layout.Dimensions {
						return design.TextBox(gtx, f.theme, f.editor(ctlAdminPairJoin),
							"iamtunnel-claim://gw.example.net:2022#SHA256:abcd…:token")
					}, "the whole line the administrator sent you, exactly as it came")
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Field(gtx, f.theme, "administrator name (optional)",
					func(gtx layout.Context) layout.Dimensions {
						return design.TextBox(gtx, f.theme, f.editor(ctlAdminPairJoin+"/name"),
							"")
					}, "leave empty to let the gateway pick; occupied names become admin2, admin3, …")
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				text, key := f.joinPreview()
				if text == "" {
					return layout.Dimensions{}
				}
				return design.Said(gtx, f.theme, f.sel(ctlAdminPairJoin+"/preview"), clipStr(text, 400), key)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.PrimaryButton(gtx, f.theme, f.btn(ctlAdminPairJoin), word)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Said(gtx, f.theme, f.sel(ctlAdminPairJoin+"/said"), clipStr(said.text, 400), said.key)
			}),
		)
	}

	if id := f.snap.Admin.ThisMachine; id != nil {
		return f.layoutAlreadyJoined(gtx, id)
	}
	return formBody(gtx)
}

// pairingCardFacts decides what the "Pairing window" card's three fact
// rows show (SPEC §7.1). Once the stored expiry has passed, the PIN is
// dead — the gateway refuses it (E_PAIRING_EXPIRED) — so the card hides
// it instead of inviting a doomed join, and the closes-itself row says
// when the window lapsed. The check is client-side and recomputed at
// every layout, so a card left on screen flips over the moment the
// window lapses — at the same boundary the gateway grades by
// (!Expires.After(now): the expiry instant itself is already expired).
// It cannot see a window closed early from the far side — a Stop by
// another client, or its consumption by another admin's successful
// pair — that is remote state (IAMT-331).
func pairingCardFacts(w *PairingWindow, now time.Time) (pin, ref, closes string) {
	if w == nil {
		return "—", "—", "—"
	}
	if w.Gone {
		// The gateway ended the window (IAMT-331): the PIN is dead and is
		// hidden for the same reason the expired one is — nobody can join
		// with it, and a live-looking PIN invites a doomed join. When it
		// was closed, not when it would have closed, is the fact.
		return "—", orDash(w.Ref), "closed early (was to close " + untilText(w.Expires) + ")"
	}
	if w.Elsewhere {
		// Another window's Start minted the PIN and the reference; this
		// card shows only what the gateway told it: that a window is open
		// and when it closes itself (IAMT-331).
		return "—", "—", untilText(w.Expires) + " · " + leftText(w.Expires, now)
	}
	if !w.Expires.IsZero() && !w.Expires.After(now) {
		return "—", orDash(w.Ref), "expired " + untilText(w.Expires)
	}
	// THE COUNTDOWN, NOT ONLY THE STAMP (21.09.2026). This row governs a
	// window that lives TWO MINUTES and hands whoever reads it
	// administrator rights over the gateway, and it used to be written
	// as "closes itself 2026-09-12 16:42 UTC" -- a date and a time to
	// the minute, which nobody subtracts in their head faster than the
	// window closes. The stamp stays beside it: two people comparing
	// notes need it, and it survives a screenshot.
	return orDash(w.Pin), orDash(w.Ref), untilText(w.Expires) + " · " + leftText(w.Expires, now)
}

// pairingWindowState is the card's missing top line: whether a window is
// open at all.
//
// The screen showed a line, a PIN and a closing time, and offered both
// OPEN WINDOW and Close now, with nothing saying which state it was in.
// Pressing the orange one in that condition might, for all a reader
// could tell, open a second window, restart this one, or invalidate the
// PIN already sent. It does the third -- cmdAdminPairingStart replaces
// an open window in a single write, and the old PIN stops working the
// instant the new one lands (PROTOCOL 3.4) -- which is exactly the
// answer a person needs before pressing it, not after.
func pairingWindowState(w *PairingWindow, now time.Time) (string, design.ColorKey) {
	switch {
	case w == nil:
		return "no window is open", design.MutedKey
	case w.Gone:
		// The far side ended it — a Stop by another client, another
		// administrator's pair, a replacement (IAMT-331). The verdict is
		// the gateway's, arrived with its answer, not this card's timer.
		return "the window was closed early — its PIN no longer works", design.MutedKey
	case w.Elsewhere:
		// Open, but minted from another window: no PIN of ours is on the
		// line, yet somebody holds one (IAMT-331).
		return "a window is OPEN — opened from another window", design.WarnKey
	case w.Ref == "":
		return "no window is open", design.MutedKey
	case !w.Expires.IsZero() && !w.Expires.After(now):
		return "the last window has closed — its PIN no longer works", design.MutedKey
	default:
		return "a window is OPEN — anyone holding its line can become an administrator", design.WarnKey
	}
}

// pairingCardWakeUp reports when the card must ask Gio for its next
// frame: while a window is displayed and not yet lapsed, exactly at its
// expiry instant. A redraw there is the only thing that can flip an
// idle Admin tab — no mouse, no keys, no resize, and the elevation
// pulse runs on the other tabs (IAMT-330 round 3). Once the window has
// lapsed the wake-up stops: the flip happened, and the card must not
// spin asking for frames it does not need.
func pairingCardWakeUp(w *PairingWindow, now time.Time) (time.Time, bool) {
	// A window the gateway already ended has nothing left to count: the
	// flip happened the moment the answer landed (IAMT-331), and ticking
	// to the old expiry would spin at a PIN that is already dead.
	if w == nil || w.Gone || w.Expires.IsZero() || !w.Expires.After(now) {
		return time.Time{}, false
	}
	// ONCE A SECOND WHILE THE WINDOW IS OPEN, not once at the end
	// (21.09.2026). The card draws a countdown now, and a countdown that
	// only redraws when something else happens to wake the window is a
	// stopped clock on the most time-critical screen in the product.
	//
	// The cost is bounded by the thing being counted: a pairing window
	// lives two minutes, so this is at most ~120 frames, and the moment
	// it lapses the branch above stops asking. The last tick is clamped
	// to the expiry instant so the flip to "expired" still lands exactly
	// on the boundary the gateway grades by.
	next := now.Add(time.Second)
	if next.After(w.Expires) {
		next = w.Expires
	}
	return next, true
}

// adminPairingAfterStatus reconciles the window this window minted with
// the gateway's own word about its pairing window (IAMT-331): what the
// card may still draw as open, and what the far side has already ended.
//
// The gateway's word wins. A window is a thing the GATEWAY grades, and
// this process sees only what its own Start once printed: a Stop by
// another client, another administrator's successful pair, or a
// replacement opened from the far side ends the window without this one
// hearing a word — the one end of the window's life no timer here can
// see. The expiry still grades locally, at the same boundary the
// gateway uses (!Expires.After(now)); what the answer adds is
// everything the wall clock cannot know.
func adminPairingAfterStatus(w *PairingWindow, live PairingStatus, now time.Time) *PairingWindow {
	if live.Active {
		switch {
		case w == nil:
			// Somebody else's Start. There is no PIN and no reference to
			// show — those went to whoever opened it — but "no window is
			// open" beside another administrator's live window is the lie
			// this card exists not to tell.
			return &PairingWindow{Expires: live.Expires, Elsewhere: true}
		case w.Elsewhere:
			// The elsewhere window's only fact is its expiry; keep it
			// current, and let it vanish when the gateway stops saying it.
			if w.Expires.Equal(live.Expires) {
				return w
			}
			nw := *w
			nw.Expires = live.Expires
			return &nw
		case w.Gone || w.Expires.Equal(live.Expires):
			// Already ended, or confirmed verbatim: the card keeps what it
			// shows. A dead window must not resurrect because a NEW one
			// opened on the gateway — its PIN stays dead.
			return w
		default:
			// Same slot, different expiry: cmdAdminPairingStart replaces an
			// open window in one write, so the PIN this card is drawing is
			// already dead whatever the clock says.
			nw := *w
			nw.Gone = true
			return &nw
		}
	}
	// The gateway says no window is open.
	switch {
	case w == nil || w.Expires.IsZero():
		return w
	case !w.Expires.After(now):
		// Ran out on its own, and the gateway confirms it closed: that is
		// "expired", not "closed early" — one truth, not rewritten.
		return w
	case w.Elsewhere:
		// There was never a PIN here to mourn; the window is simply gone
		// from the screen.
		return nil
	default:
		nw := *w
		nw.Gone = true
		return &nw
	}
}

// layoutPairingCard is the "Pairing window" card (SPEC §3.5, §7.1):
// Start and Stop for an acting administrator; the facts show what the
// last Start produced — the PIN to hand over, the ready-to-paste
// reference and the moment the window closes itself. Before the first
// Start (and after a Stop) every fact is "—", exactly as the other
// unanswered facts on these screens draw.
func (f *Frame) layoutPairingCard(gtx layout.Context) layout.Dimensions {
	if f.btn(ctlAdminPairingStart).Clicked(gtx) {
		f.openPairingWindow()
	}
	if f.btn(ctlAdminPairingStop).Clicked(gtx) {
		f.closePairingWindow()
	}
	startWord := "OPEN WINDOW"
	if p := f.snap.Admin.Pairing; p != nil && !p.Gone &&
		(p.Ref != "" || p.Elsewhere) &&
		(p.Expires.IsZero() || p.Expires.After(f.now())) {
		// A start while a window is open REPLACES it in one write, and
		// the old PIN stops working the instant the new one lands
		// (cmdAdminPairingStart, PROTOCOL 3.4). The button says so,
		// because "OPEN WINDOW" beside an already-open window invites
		// exactly the press that silently kills a PIN somebody has
		// already been sent.
		startWord = "REPLACE THIS WINDOW"
	}
	if f.busy(ctlAdminPairingStart) {
		startWord = "OPENING…"
	}
	stopWord := "Close now"
	if f.busy(ctlAdminPairingStop) {
		stopWord = "CLOSING…"
	}

	w := f.snap.Admin.Pairing
	now := f.now()
	if at, wake := pairingCardWakeUp(w, now); wake {
		// One invalidation at the expiry instant: the frame that flips the
		// card to "expired" even on a tab nobody touches. No countdown is
		// drawn, so nothing invalidates per second, and once the window has
		// lapsed no further invalidation is scheduled at all.
		gtx.Execute(op.InvalidateCmd{At: at})
	}
	pin, ref, expires := pairingCardFacts(w, now)
	oneLine := pairingOneLine(w, now)
	startSaid := f.saidUnder(ctlAdminPairingStart)
	stopSaid := f.saidUnder(ctlAdminPairingStop)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// WHAT STATE AM I IN, first of all (21.09.2026). Everything
		// below reads differently depending on the answer, and the card
		// used to make a person infer it from whether a PIN happened to
		// be drawn.
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			word, key := pairingWindowState(w, now)
			return design.Said(gtx, f.theme, f.sel(ctlAdminPairingStart+"/state"), word, key)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),

		// The one line to hand over comes FIRST, above the parts it is
		// made of. What the administrator actually has to do is send
		// somebody one string; reading a PIN off one row and a
		// reference off another and joining them by hand is the work
		// 1.3 exists to remove (SPEC §3.6). The parts stay below for
		// the cases where the two really do travel separately.
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if oneLine == "" {
				return layout.Dimensions{}
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					// ABOVE THE LINE, NOT BELOW IT (21.09.2026). This is
					// the most consequential sentence in the product, and
					// it used to sit at the very bottom of the card in
					// the smallest grey type on the page -- where the
					// fold cut its last line in half. A person copies the
					// line the moment they see it; a warning underneath
					// arrives after the decision it was meant to inform.
					return design.Text(gtx, f.theme,
						"Whoever reads the line below inside the two minutes becomes an administrator "+
							"of this gateway. Send it to ONE person, and close the window as soon as "+
							"they are in.")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme, "send this one line to the new administrator")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return f.layoutHandOver(gtx, ctlAdminPairingStart, oneLine,
						"Copy the line", "The pairing line is on the clipboard.")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// THE REFERENCE ROW IS GONE (21.09.2026). It was the line
			// above minus the PIN -- the same credential on screen for
			// the third time, costing a row of a card that already
			// pushed its own buttons below the fold, and widening the
			// surface anybody behind the administrator can read.
			//
			// The PIN stays as its own row, because the two halves do
			// sometimes travel separately: the line by chat, the six
			// digits read aloud.
			_ = ref
			return design.Facts(gtx, f.theme, []design.FactRow{
				design.Fact("PIN", pin),
				design.Fact("closes itself", expires),
			})
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{
				Axis:      layout.Horizontal,
				Alignment: layout.Middle,
			}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.PrimaryButton(gtx, f.theme, f.btn(ctlAdminPairingStart), startWord)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.SecondaryButton(gtx, f.theme, f.btn(ctlAdminPairingStop), stopWord)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, f.theme, f.sel(ctlAdminPairingStart+"/said"), clipStr(startSaid.text, 400), startSaid.key)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, f.theme, f.sel(ctlAdminPairingStop+"/said"), clipStr(stopSaid.text, 200), stopSaid.key)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// This used to tell the administrator to send the PIN and
			// the reference over two different channels. That rule was
			// cancelled in 1.3 (RUNBOOK §1.4.1): it assumed an attacker
			// reading one channel and not the other, and in the one
			// live run there was ever only one channel — both halves
			// went through the same chat, in the same screenshot. It
			// protected nothing and doubled the work, and the advice
			// being visibly ignorable taught people to ignore advice.
			//
			// What is true, and is what the sentence says now, is the
			// residual risk the maintainer accepted in its place. It is
			// written in the present tense about a line that is on the
			// screen, so it only appears when that line is: a warning
			// about "this line" with no line above it reads as a bug
			// and gets discounted along with every other sentence here.
			if oneLine == "" {
				return design.Hint(gtx, f.theme,
					"Opening a window prints one line to send to the new administrator. "+
						"It is good for two minutes and for one person.")
			}
			// The warning itself now stands ABOVE the line, where it is
			// read before the line is copied. What is left here is the
			// one fact that only matters afterwards.
			return design.Hint(gtx, f.theme,
				"Closing the window early kills the PIN: the line already sent stops working.")
		}),
	)
}

// pairingOneLine renders the open window as the single string §3.6 puts
// in circulation: the reference and the PIN, in that order, separated by
// a space — byte-for-byte what the Join field on the other machine
// parses, and what `iamtunnel admin pair` takes.
//
// A window that has lapsed renders nothing at all. The facts below keep
// showing the reference in that case, because it is still true that this
// gateway was named; the one-line form is an instruction to act, and
// offering it past the expiry would be an instruction to fail.
func pairingOneLine(w *PairingWindow, now time.Time) string {
	if w == nil || w.Ref == "" || w.Pin == "" {
		return ""
	}
	if !w.Expires.IsZero() && !w.Expires.After(now) {
		return ""
	}
	return w.Ref + " " + w.Pin
}

// layoutPeopleAddForm is the "Add person" card (SPEC §7.1): name, role
// and public key — the same "people add" the console verb runs
// (guiAdminPeopleAdd). An empty role box means "user".
func (f *Frame) layoutPeopleAddForm(gtx layout.Context) layout.Dimensions {
	if f.btn(ctlAdminPeopleAdd).Clicked(gtx) ||
		f.submitted(gtx, ctlAdminPeopleAdd+"/name") {
		f.addPerson()
	}
	word := "ADD PERSON"
	if f.busy(ctlAdminPeopleAdd) {
		word = "ADDING…"
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "name",
				func(gtx layout.Context) layout.Dimensions {
					return design.TextBox(gtx, f.theme, f.editor(ctlAdminPeopleAdd+"/name"), "bob")
				}, "")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "role",
				func(gtx layout.Context) layout.Dimensions {
					return design.TextBox(gtx, f.theme, f.editor(ctlAdminPeopleAdd+"/role"), "user")
				}, "user or admin — empty means user")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "public key",
				func(gtx layout.Context) layout.Dimensions {
					return design.TextBox(gtx, f.theme, f.editor(ctlAdminPeopleAdd+"/key"), "ssh-ed25519 AAAA… person@laptop")
				}, "the person's own public key line — what they hand you, never a private key")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.PrimaryButton(gtx, f.theme, f.btn(ctlAdminPeopleAdd), word)
		}),
	)
}

// layoutHandOver draws a string the window is HANDING the person -- an
// invitation, a pairing line -- in the two forms people actually take one
// away in: a box that can be selected with the mouse, and under it a
// button that copies the whole of it (IAMT-355).
//
// Both, always. Neither covers the other: selecting is for the person who
// wants part of the line or trusts their own hands, the button is for the
// person who does not want to aim at ninety characters of base64. Before
// 19.09.2026 the enrol code had neither -- it was printed as a status
// line, which in gio is a label with no selection state behind it, so the
// maintainer could see the invitation and could not take it.
//
// The confirmation goes under a control key of its own. What was copied
// lives in said[name].give, and say() replaces the WHOLE saying under a
// key -- confirming under name itself would erase the very string the
// button had just copied.
func (f *Frame) layoutHandOver(gtx layout.Context, name, give, word, done string) layout.Dimensions {
	if strings.TrimSpace(give) == "" {
		return layout.Dimensions{}
	}
	copyCtl := name + "/copy"
	if f.btn(copyCtl).Clicked(gtx) {
		copyToClipboard(gtx, give)
		f.say(copyCtl, done, design.GoodKey)
	}
	said := f.saidUnder(copyCtl)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.CopyableBox(gtx, f.theme, f.sel(name), give)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// Compact, and in a row of its own so it takes only its own
			// width (21.09.2026). A copy button stretched across the
			// whole column was the heaviest control on two of these
			// pages -- heavier than OPEN WINDOW beside it, which hands
			// out administrator rights. Weight reads as importance.
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.CompactButton(gtx, f.theme, f.btn(copyCtl), word)
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if said.text == "" {
				return layout.Dimensions{}
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Said(gtx, f.theme, f.sel(copyCtl+"/said"), said.text, said.key)
				}),
			)
		}),
	)
}

// layoutEnrolCodeForm is the "Invite machine" card (SPEC §3.4, §7.1):
// one button, no boxes at all, and the invitation that comes back —
// shown under it in full, ready to be copied into the new machine's own
// Set up screen (guiAdminMachineEnrolCode).
//
// The two boxes this card used to have — machine name and OS user —
// asked the administrator to know, before the machine has ever spoken,
// two things only the machine knows about itself. He would have had to
// go and ask somebody else for a DOMAIN\user just to hand out an
// invitation. The machine now reports both when it registers, and the
// gateway records them as requested until its own login proves them.
func (f *Frame) layoutEnrolCodeForm(gtx layout.Context) layout.Dimensions {
	if f.btn(ctlAdminEnrolCode).Clicked(gtx) ||
		f.submitted(gtx, ctlAdminEnrolCode+"/name") {
		f.mintEnrolCode()
	}
	word := "INVITE A MACHINE"
	if f.busy(ctlAdminEnrolCode) {
		word = "ASKING…"
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "name",
				func(gtx layout.Context) layout.Dimensions {
					return design.TextBox(gtx, f.theme, f.editor(ctlAdminEnrolCode+"/name"), "office-pc")
				}, "one physical machine may hold several — one per person who works on it")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme,
				"Hand the machine's owner the one string that comes back. They paste it and nothing else — "+
					"the machine reports the account it runs as by itself.")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.PrimaryButton(gtx, f.theme, f.btn(ctlAdminEnrolCode), word)
		}),
	)
}

// layoutSetupScreen: first run on an unregistered machine (SPEC §3.4).
func (f *Frame) layoutSetupScreen(gtx layout.Context) layout.Dimensions {
	s := f.snap.Setup

	var lead, word string
	key := design.InkKey
	switch s.Status {
	case "verified":
		lead, word, key = "This machine is registered and checked", "Verified", design.GoodKey
	case "enrolled":
		lead, word, key = "Registered — the first entry check has not passed yet", "Enrolled", design.WarnKey
	case "failed":
		lead, word, key = orDash(s.Detail), "Failed", design.BadKey
	case "working":
		lead, word, key = "Talking to the gateway — 10–20 seconds", "Working", design.BusyKey
	default:
		lead, word, key = "First run on this machine", "Set up", design.InkKey
	}

	return design.Page(gtx, f.theme, f.pageList(),
		posterOf(f.theme, lead, word, key),
		func(gtx layout.Context) layout.Dimensions {
			return design.Deck(gtx, f.theme,
				"Ask the administrator for a one-time enrol code and paste it below. "+
					"It registers YOUR account on this machine, under the name the administrator chose, "+
					"and is good for 15 minutes. A colleague who also works on this machine asks for a "+
					"code of their own — the registrations sit side by side and every line in the log says whose it was.")
		},
		// The box the code is pasted into, and the one button that spends
		// it. Until IAMT-149 this was a read-only sample of what a code
		// looks like over a button that did nothing — a picture of a form
		// rather than a form.
		f.layoutEnrolField,
		f.layoutRegisterRow,
		func(gtx layout.Context) layout.Dimensions {
			rows := []design.FactRow{
				// "registration", not "machine name": what is recorded on
				// the gateway is the pair — the name the administrator
				// chose and the account it is bound to (SetupState.OSUser).
				// One row rather than two on purpose: they are one fact,
				// and the Set up screen has no room to spare (gate 17).
				design.Fact("registration", machineNameText(s)),
			}
			// "status" and "detail" USED TO BE HERE, and they were the
			// poster written out a second time: the big word above IS the
			// status, and the line beside it IS the detail. The screen
			// said one fact three times (21.09.2026) -- "Registered — the
			// first entry check has not passed yet" as the lead,
			// "registered, entry check pending" as the status, and the
			// lead again as the detail.
			//
			// The detail survives only when it is NOT what the poster
			// already said -- which is the case that carries information:
			// a refusal explains itself there.
			// Case-INSENSITIVE, because the two differ by exactly one
			// letter: the lead is "Registered -- the first entry check
			// has not passed yet" and the detail is the same sentence
			// beginning lower-case. The guard was written on 21.09.2026
			// and never once fired.
			if d := strings.TrimSpace(s.Detail); d != "" &&
				!strings.EqualFold(d, strings.TrimSpace(lead)) {
				rows = append(rows, design.Fact("detail", d))
			}
			return design.Facts(gtx, f.theme, rows)
		},
		func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme,
				"You will be asked to allow the program to make changes — administrator rights are required to open the door.")
		},
	)
}

// layoutEnrolField is the enrol code box: label in the facts column, the
// ruled box beside it, the explanation under it (umtunnel's EnrolView
// Row). The watermark is the shape of a real code, so the box teaches
// what to paste without pretending a code is already there.
func (f *Frame) layoutEnrolField(gtx layout.Context) layout.Dimensions {
	// Enter inside the box means the same as pressing the button: this
	// call also drains the editor's events for the frame, which Gio
	// requires whether or not anybody is listening to them.
	if f.submitted(gtx, ctlSetupRegister) {
		f.registerThisMachine()
	}
	return design.Field(gtx, f.theme, "enrol code",
		func(gtx layout.Context) layout.Dimensions {
			return design.TextBox(gtx, f.theme, f.editor(ctlSetupRegister),
				"iamtunnel-enrol://gateway.example:2222#<fingerprint>:<secret>")
		},
		"the whole line the administrator sent you — it works once and expires in 15 minutes")
}

// layoutRegisterRow is the button that spends the code, and the one
// sentence that says what came of it.
func (f *Frame) layoutRegisterRow(gtx layout.Context) layout.Dimensions {
	if f.btn(ctlSetupRegister).Clicked(gtx) {
		f.registerThisMachine()
	}
	word := "REGISTER THIS MACHINE"
	if f.busy(ctlSetupRegister) {
		word = "REGISTERING…"
	}
	said := f.saidUnder(ctlSetupRegister)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.PrimaryButton(gtx, f.theme, f.btn(ctlSetupRegister), word)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, f.theme, f.sel(ctlSetupRegister+"/said"), clipStr(said.text, 400), said.key)
		}),
	)
}

// layoutSettingsScreen: the few facts a person may look at here — and
// the honest statement that there is almost nothing to change, by design.
func (f *Frame) layoutSettingsScreen(gtx layout.Context) layout.Dimensions {
	st := f.snap.Settings

	return design.Page(gtx, f.theme, f.pageList(),
		posterOf(f.theme, "What may be changed here — almost nothing, by design", "Settings", design.InkKey),
		func(gtx layout.Context) layout.Dimensions {
			return design.Text(gtx, f.theme,
				themeFollowsNotice+" "+
					"Access is decided by grants and enrol codes, not by switches here.")
		},
		cardOf(f.theme, "This program",
			func(gtx layout.Context) layout.Dimensions {
				return design.Facts(gtx, f.theme, []design.FactRow{
					design.Fact("version", orDash(st.Version)),
					design.Fact("platform", orDash(st.Platform)),
					design.Fact("config file", orDash(st.ConfigPath)),
					design.Fact("data directory", orDash(st.DataDir)),
				})
			}),
		cardOf(f.theme, "Recordings on the gateway",
			func(gtx layout.Context) layout.Dimensions {
				return design.Facts(gtx, f.theme, []design.FactRow{
					design.Fact("gateway port", intOrDash(st.Port)),
					design.Fact("recordings kept", intOrDash(st.RetentionDays)+" days"),
					design.Fact("disk stop", intOrDash(st.DiskStopPercent)+"% full stops new sessions"),
				})
			}),
		func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme,
				"To change port, directories or retention edit the configuration file — see iamtunnel help config.")
		},
	)
}

// -------------------------------------------------------------------------
// Small shared pieces
// -------------------------------------------------------------------------

// posterOf is the screen's state headline as a lazy widget for design.Page.
// adminPosterDeck is the Admin tab's poster: the plain question the tab
// answers - except while the gateway's audit journal is not being
// written. Then every change is refused, and that is what the tab says
// before anything else (IAMT-451).
func adminPosterDeck(a AdminState) (lead, word string, key design.ColorKey) {
	if a.AuditProblem != "" {
		return "The gateway's audit journal is NOT being written — it refuses every change", "Admin", design.BadKey
	}
	return "Who may enter which machine, until when", "Admin", design.InkKey
}

func posterOf(th *design.Theme, lead, word string, key design.ColorKey) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return design.NewPoster(lead, word, key).Layout(gtx, th)
	}
}

// cardOf wraps a body in a titled section over a hairline, lazily.
func cardOf(th *design.Theme, title string, body layout.Widget) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return design.NewCard(title, body).Layout(gtx, th)
	}
}

// cardWithTools is cardOf with a control pinned to the right of the
// section's own heading — the place umtunnel puts a Refresh.
func cardWithTools(th *design.Theme, title string, body, tools layout.Widget) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return design.NewCard(title, body, tools).Layout(gtx, th)
	}
}

// booleanFact is one Facts row whose value is a state, colored honestly:
// Good when true, Warn when not.
func (f *Frame) booleanFact(label string, ok bool, okText, badText string) design.FactRow {
	key, text := design.WarnKey, badText
	if ok {
		key, text = design.GoodKey, okText
	}
	return design.FactRow{
		Label: label,
		Widget: func(gtx layout.Context) layout.Dimensions {
			return design.Status(gtx, f.theme,
				func(gtx layout.Context) layout.Dimensions {
					return design.Dot(gtx, f.theme, key, false)
				},
				func(gtx layout.Context) layout.Dimensions {
					return design.Fixed(gtx, f.theme, text)
				})
		},
	}
}

// tristateFact is booleanFact's IAMT-311 shape: whenever the snapshot
// could not learn this fact at all (s.Unknown), it draws the "could not
// check" sentence in Warn instead of reading ok's Go zero value (false)
// as a confident badText — "could not find out" and "definitely not"
// are different claims, and only the true one may be drawn here.
func (f *Frame) tristateFact(label string, s ServerState, ok bool, okText, badText string) design.FactRow {
	if s.Unknown {
		return f.unknownFactRow(label, s.unknownText())
	}
	return f.booleanFact(label, ok, okText, badText)
}

// unknownFactRow is one Facts row whose value could not be learned at
// all: same shape as booleanFact's Warn state, but its own wording
// rather than a fixed badText.
func (f *Frame) unknownFactRow(label, text string) design.FactRow {
	return design.FactRow{
		Label: label,
		Widget: func(gtx layout.Context) layout.Dimensions {
			return design.Status(gtx, f.theme,
				func(gtx layout.Context) layout.Dimensions {
					return design.Dot(gtx, f.theme, design.WarnKey, false)
				},
				func(gtx layout.Context) layout.Dimensions {
					return design.Fixed(gtx, f.theme, text)
				})
		},
	}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func intOrDash(n int) string {
	if n == 0 {
		return "—"
	}
	return strconv.Itoa(n)
}

func sshdWord(listening bool) string {
	if listening {
		return "listening"
	}
	return "not listening"
}

func untilText(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// leftText is how long is left until t, in the words a person would use
// out loud: "1:47 left", "42 m left", "1 h 19 m left", "3 d left".
//
// EVERY DEADLINE IN THIS PRODUCT WAS AN ABSOLUTE UTC STAMP UNTIL
// 21.09.2026 — "until 2026-09-12 18:00 UTC", "idle limit 17:40 UTC",
// "closes itself 16:42 UTC". The last of those governs a TWO-MINUTE
// window that hands somebody administrator rights over the gateway, and
// it was written as a date and a time to the minute. A person holding
// that window open cannot subtract in their head faster than it closes.
//
// The stamp stays: it is unambiguous, it survives a screenshot, and it
// is what two people comparing notes need. This goes BESIDE it.
//
// Under a minute counts seconds, because the pairing window is measured
// in them. Over a day drops to days, because nobody reads "73 h 12 m".
func leftText(t, now time.Time) string {
	if t.IsZero() {
		return "no deadline"
	}
	d := t.Sub(now)
	if d <= 0 {
		return "expired"
	}
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + " s left"
	case d < time.Hour:
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		// Under ten minutes the seconds matter: this is the shape the
		// pairing window is read in.
		if m < 10 {
			return strconv.Itoa(m) + ":" + twoDigits(s) + " left"
		}
		return strconv.Itoa(m) + " m left"
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		return strconv.Itoa(h) + " h " + strconv.Itoa(m) + " m left"
	default:
		return strconv.Itoa(int(d.Hours()/24)) + " d left"
	}
}

// twoDigits pads a second count so "1:7 left" never appears.
func twoDigits(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// grantUntilText is a grant's deadline; a zero one is an indefinite grant,
// named the way the session banner names it (IAMT-230).
func grantUntilText(t time.Time) string {
	if t.IsZero() {
		return "revoked"
	}
	return untilText(t)
}

// accessLeft is how a LIST row states a deadline: the remaining time
// alone, or "revoked" for a grant with none.
func accessLeft(t, now time.Time) string {
	if t.IsZero() {
		return grantUntilText(t)
	}
	return leftText(t, now)
}

// grantUntilLeft is a grant's deadline with what is left of it beside
// the stamp: "2026-09-12 18:00 UTC (1 h 19 m left)".
//
// Rows redraw on the status poll, every three seconds, so the number is
// at most that stale -- which is nothing at the hour-and-minute
// granularity a grant is measured in. The pairing window's countdown is
// the one that needs its own frame every second, and it has one.
//
// A grant with no deadline says so in words rather than showing a
// parenthesis with nothing useful in it.
func grantUntilLeft(t, now time.Time) string {
	if t.IsZero() {
		return grantUntilText(t)
	}
	return untilText(t) + " (" + leftText(t, now) + ")"
}

// clipStr bounds a name to maxRunes characters (SPEC §4.3 names are
// ASCII, so runes are enough), marking the cut with an ellipsis. The
// screens never trust names to be short: the runtime hands over what
// the gateway knows, and the layout must survive any length.
func clipStr(s string, maxRunes int) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxRunes-1]) + "…"
}

// adminSubTabOrder is the order of the Admin tab's sub-tabs, in one
// place so the strip and the test that guards it cannot drift apart.
//
// Join stands first because it is the first thing anyone does. A gateway
// with no administrator cannot answer any of the other five, and the
// very first act on a fresh install is to become one. It sat last until
// 19.09.2026, when the maintainer walked the setup end to end and had to hunt
// for it.
// joinCardTitle names the Join card for the machine it is drawn on: a
// question before joining, a statement after (IAMT-356).
func joinCardTitle(id *AdminIdentity) string {
	if id != nil {
		return "This machine has joined"
	}
	return "Become an administrator"
}

func adminSubTabOrder() []string {
	return []string{"People", "Machines", "Access", "Live", "Safety", "Classifier", "Pairing", "Gateway"}
}
