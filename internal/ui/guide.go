//go:build windows || linux || darwin

package ui

// The Guide tab: the whole thing, as a chart read downwards (IAMT-359).
//
// Asked for by the maintainer on 19.09.2026, after walking the product
// from a blank gateway to a live session with the steps being read out
// two or three at a time: the first screen should be some kind of chart,
// a process explaining step by step, on which computer to do what.
//
// The thing this fixes is not missing documentation. It is that the
// process spans THREE computers -- a gateway somewhere on the internet,
// the administrator's own machine, and the machine a specialist will
// enter -- and every window looks identical on all three. The
// maintainer's own correction during the walk-through was exactly this:
// saying "double click" does not say on which machine. So every box
// names its machine before it says anything else, and the box that
// happens HERE is the one with the coloured border.
//
// One chart, not one per role. A person who sees only their own steps
// learns what to press and not what they are part of; the maintainer
// asked
// for the whole process with their own place in it marked, and that is the
// shape that answers "what do I do next" and "why" at the same time.

import (
	"gioui.org/layout"
	"gioui.org/unit"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// guideSteps builds the chart. The same six steps on every machine, and
// no mark of progress on any of them.
//
// There used to be one: the step this window was at carried a coloured
// frame and "you are here", and the steps behind it carried a tick. The
// maintainer switched it off on 21.09 after opening the window on the
// machine
// being entered and finding step 1 -- a step that happens over SSH on the
// gateway -- framed as their place in the process, objecting that maybe
// the highlighted first step should not be shown at all, because there
// is no telling yet whether this is the client or the gateway.
//
// He is right about the cause, and it is not an error in the reckoning.
// One window is all four roles at once, and which of them a person means
// at the moment they look is written nowhere -- not in the state, not on
// disk, not in the gateway. Every rule we tried inferred it from local
// facts, and a wrong guess here is worse than no guess: a chart that
// confidently points at the wrong step teaches the wrong next move, while
// a chart with nothing lit still reads correctly as the whole process.
//
// So the flags are simply never set. design.Step keeps Here and Done for
// a caller that can honestly answer them; this one cannot.
func guideSteps(Snapshot) []design.Step {
	return []design.Step{{
		Number: "1",
		Where:  "on the gateway — over SSH",
		What:   "Install the gateway. It prints one line, once: the address, its host key and a one-time token.",
		How:    "sudo iamtunnel gateway install --public-host <address> --port 2022\n\nTo read it again later:\nsudo iamtunnel gateway status --public-host <address> --port 2022",
	}, {
		Number: "2",
		Where:  "on the administrator's computer",
		What:   "Become the first administrator: paste that line into the one field. This machine's key becomes an administrator's key.",
		How:    "ADMIN → JOIN → paste → JOIN AS ADMINISTRATOR",
	}, {
		Number: "3",
		Where:  "on the administrator's computer",
		What:   "Invite the machine a specialist will enter. You choose its name — it is what you grant access against and revoke by.",
		How:    "ADMIN → MACHINES → Invite a machine → Copy enrol code",
	}, {
		Number: "4",
		Where:  "on the machine to be entered",
		What:   "Register it with that code, then start its agent. Administrator rights are needed once, for the registration.",
		How:    "SET UP → paste the code → REGISTER THIS MACHINE\nthen SERVER → START",
	}, {
		Number: "5",
		Where:  "on the administrator's computer",
		What:   "Grant access. Being an administrator is not itself permission to enter a machine — the two are separate on purpose.",
		How:    "ADMIN → ACCESS → New grant → person, machine, until → GRANT ACCESS",
	}, {
		Number: "6",
		Where:  "on the computer that connects",
		What:   "Enter the machine. Everything visible on the screen is recorded from the first second.",
		How:    "CLIENT → refresh → Connect",
	}}
}

// layoutGuideScreen draws the chart.
func (f *Frame) layoutGuideScreen(gtx layout.Context) layout.Dimensions {
	steps := guideSteps(f.snap)

	sections := []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(posterOf(f.theme,
					"Three computers, six steps — for each gateway you use",
					"How it goes", design.InkKey)),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Text(gtx, f.theme,
						"This gives somebody temporary, recorded, revocable access to a machine that has no public "+
							"address and no open port -- a computer behind a home router, an office NAT, a firewall "+
							"nobody will reconfigure for you. Instead of opening a way in, both sides dial OUT to a "+
							"small gateway you rent, and the gateway puts the two ends together. You may have more "+
							"than one gateway -- one for your own machines, one at work -- and this program holds "+
							"them all and works with one at a time.")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Text(gtx, f.theme,
						"Access is a grant: one person, one machine, until a moment you choose, and gone the second "+
							"you revoke it. Everything done through it is recorded from the first second. And because "+
							"the one entering is increasingly not a person but an AI agent, a grant can be narrowed "+
							"to single commands rather than a shell -- and those commands are read, against the goal "+
							"you declared, before the machine ever sees them.")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return f.layoutGuidePicture(gtx)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Text(gtx, f.theme,
						"Nothing below is reachable until the step above it is done, which is why the rest of this "+
							"page is a chart and not a list.")
				}),
			)
		},
	}

	for i := range steps {
		s := steps[i]
		sections = append(sections, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.StepBox(gtx, f.theme, s)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if i == len(steps)-1 {
						return layout.Dimensions{}
					}
					return design.StepArrow(gtx, f.theme)
				}),
			)
		})
	}

	return design.Page(gtx, f.theme, f.pageList(), sections...)
}

// layoutGuidePicture is the shape of the thing, drawn once (21.09.2026),
// and redrawn on 22.09.2026 when it stopped being true.
//
// Asked for by the maintainer: a bigger word about what the program is
// for -- perhaps draw some chart showing one client plus one gateway and
// a couple of machines.
//
// TWO GATEWAYS, not one. The maintainer caught it the same hour the
// feature
// went in: the chart was now wrong, because it showed one gateway where
// there may be several. A picture on the first page is the
// one thing a reader takes away whole, so a picture that is out of date
// teaches the wrong shape faster than the text can correct it.
//
// Both arrows still point INTO a gateway, and that remains the whole
// content of the picture. A reader who takes only one thing from this
// page should take that one: nothing here listens, nothing needs a port
// opened, and the machine being entered is as unreachable from the
// internet after this product is installed as it was before. The
// gateways are the only things on the diagram with an address.
//
// What the second row adds is that a gateway is a WORLD, not a setting.
// The machines under the personal gateway and the machine under the
// work one never meet; neither gateway knows the other exists; the list
// of them is a fact about this computer alone. One program on the left,
// switching between them, is the honest shape of that.
//
// The machines are named win-vm, mac-01 and db-02 rather than "machine
// 1, 2, 3" because the point of the right-hand column is that they are
// different computers in different places -- a Windows box, a laptop, a
// database server -- held together by nothing except having dialled the
// same gateway.
func (f *Frame) layoutGuidePicture(gtx layout.Context) layout.Dimensions {
	label := func(top, bottom string) layout.Widget {
		return func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Fixed(gtx, f.theme, top)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme, bottom)
				}),
			)
		}
	}
	arrow := func(rightwards bool, under string) layout.Widget {
		return func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Arrow(gtx, f.theme, rightwards)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme, under)
				}),
			)
		}
	}

	// world is one gateway with the machines that dialled it: a row of
	// the picture, and the unit the rest of the program calls a gateway.
	world := func(name, note string, machines [][2]string) layout.Widget {
		return func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(4, func(gtx layout.Context) layout.Dimensions {
					return design.PlainBox(gtx, f.theme, label(name, note))
				}),
				layout.Flexed(2, arrow(false, "dial out")),
				layout.Flexed(4, func(gtx layout.Context) layout.Dimensions {
					var rows []layout.FlexChild
					for i := range machines {
						m := machines[i]
						if i > 0 {
							rows = append(rows, layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout))
						}
						rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.PlainBox(gtx, f.theme, label(m[0], m[1]))
						}))
					}
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
				}),
			)
		}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Flexed(3, func(gtx layout.Context) layout.Dimensions {
					return design.PlainBox(gtx, f.theme,
						label("the one who connects", "you, a specialist, or an AI agent -- one program, "+
							"holding every gateway you were given, on one at a time"))
				}),
				layout.Flexed(2, arrow(true, "dials out")),
				layout.Flexed(10, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(world("your own gateway",
							"a small rented server with one open port", [][2]string{
								{"win-vm", "behind a router"},
								{"mac-01", "on somebody's desk"},
							})),
						layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
						layout.Rigid(world("the gateway at work",
							"somebody else runs it; you are simply known to it", [][2]string{
								{"db-02", "in a locked rack"},
							})),
					)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme,
				"Neither end listens. Both dial a gateway and it joins them, so no machine here needs a public "+
					"address, an opened port or a VPN -- and each gateway's administrator decides who reaches "+
					"which of its machines.")
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme,
				"The two gateways never meet, and neither knows the other exists. Switching between them is one "+
					"press on the Client tab and asks for nothing: there are no passwords anywhere in this "+
					"product -- your key is one per computer, and every gateway that knows you already holds "+
					"its public half.")
		}),
	)
}
