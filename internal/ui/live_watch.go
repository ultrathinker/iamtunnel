//go:build windows || linux || darwin

package ui

// The Admin tab's "Live" sub-tab: what is happening on the gateway right
// now, and what one command would be judged to be (IAMT-360).
//
// Asked for by the maintainer on 19.09.2026, in the same breath as the
// rest
// of the interface work: why does this work only through the command
// line? They do not like doing it through the command line, and want it
// done in the interface as well.
//
// That objection was right. Everything here already existed as an admin
// verb -- sessions active, sessions tail, sessions kill, risk check --
// and the window offered none of it, so the one thing the product is FOR
// (watching what a stranger does on your machine) was reachable only by
// somebody who types commands. The gateway is the source in every case:
// a window that summarised its own guess about a live session would be
// the most dangerous kind of wrong.

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"gioui.org/layout"
	"gioui.org/unit"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

const (
	ctlAdminLive      = "admin/live"
	ctlAdminRiskCheck = "admin/risk-check"
)

// liveSubTabEmptyPollInterval is how often the Live sub-tab's empty
// promise is honoured. The "session appears here the second it starts"
// copy is a question the window asks the gateway every interval, not on
// every frame — a poll per frame would dial the gateway sixty times a
// second for an empty answer.
const liveSubTabEmptyPollInterval = 3 * time.Second

// watchState is what the Live sub-tab remembers between frames: which
// session is being followed and how far its transcript has been read.
//
// The offset is kept because tailing is resumable by design -- the
// gateway returns a slice from an offset and says how long the whole
// thing is -- and re-reading from zero on every tick would grow
// quadratically on a session that runs for an hour.
type watchState struct {
	id string

	// mu guards everything below it. Two goroutines touch this state:
	// the one that draws (Transcript) and the one begin() runs the
	// fetch on (ParseCast). Without the lock they walk the emulator's
	// screen buffer at the same time -- one resizing and scrolling it
	// while the other reads it line by line -- and the program does not
	// misbehave, it DIES: an index out of range in a goroutine nobody
	// recovers takes the whole process, both windows with it.
	//
	// That is what the maintainer hit on 19.09.2026, watching a live session
	// and pressing backspace: deleting characters makes the far side
	// redraw the line, which is exactly the traffic that lands a write
	// inside somebody else's read.
	//
	// It went unnoticed because gate 5 runs the suite under -race and
	// no test drove these two at once: the race needs a real fetch
	// landing during a real frame.
	mu     sync.Mutex
	offset int64
	total  int64
	live   bool

	// What arrives is asciicast, not text: a header line and one JSON
	// array per write to the screen. It goes through the same terminal
	// emulator the Session tab drives, for the reason stated in
	// record.ParseCast -- two readers of one format drift, and then the
	// text under one button quietly stops being the text under the
	// other. remainder carries the partial line across chunk edges: the
	// gateway stops an answer where it likes, including mid-event.
	vt        *record.VT
	remainder []byte
	// mode is how the bytes are read, as the gateway says with every
	// answer: an exec session's recording is not asciicast (IAMT-453).
	mode string

	// Who and where, carried so the separate window can name itself: a
	// second window with only a session number on it is a window you
	// cannot tell from the next one.
	person  string
	machine string
}

// watchCols and watchRows size the emulator this panel reads through.
// The recording's own header resizes it the moment the first line
// arrives, so these are only what an empty screen is before that.
const (
	watchCols = 120
	watchRows = 40

	// transcriptExcerptHeight bounds the panel's view of the session.
	// Unbounded, a long session pushed the controls under it off the
	// page (IAMT-366).
	transcriptExcerptHeight = 220
)

// watchSession starts following one session, from the beginning: the
// question "what has this person been doing" is almost never about the
// last two seconds.
func (f *Frame) watchSession(id, person, machine string) {
	f.watch = &watchState{
		id: id, person: person, machine: machine,
		vt: record.NewVT(watchCols, watchRows),
	}
	f.tailWatched()
}

// tailWatched asks for the next slice of the followed session.
//
// The very first call lands mid-recording, not at byte 0: a session
// that has been running for an hour is watched from where it is now,
// not from the first hour of a stranger's terminal. The
// probe that learns `total` is part of this same begin() so a watch
// started on a half-day-old recording still finds the live end.
func (f *Frame) tailWatched() {
	w := f.watch
	if w == nil {
		return
	}
	ask := f.cfg.Actions.AdminSessionTail
	if ask == nil {
		f.say(ctlAdminLive, noRuntime, design.BadKey)
		return
	}
	// The STATE is captured, not re-read through f.watch: that field is
	// written on the drawing goroutine, and reading it here would be a
	// second race on top of the one the lock below removes.
	w.mu.Lock()
	id, offset := w.id, w.offset
	w.mu.Unlock()

	f.begin(ctlAdminLive, "Reading the transcript.", func() (string, design.ColorKey) {
		// First call after a freshly-picked watch session: probe for
		// `total`, then jump to the last tailChunkLimit bytes. The probe
		// reuses the same action with a 1-byte limit, exactly as
		// pollLoop does for the Session tab.
		if offset == 0 {
			_, _, probeTotal, _, _, perr := ask(context.Background(), id, 0)
			if perr == nil {
				w.mu.Lock()
				if probeTotal > tailChunkLimit && w.offset == 0 {
					w.offset = probeTotal - tailChunkLimit
					offset = w.offset
				}
				w.total = probeTotal
				w.mu.Unlock()
			}
		}
		chunk, next, total, live, mode, err := ask(context.Background(), id, offset)
		if err != nil {
			return err.Error(), design.BadKey
		}
		w.mu.Lock()
		w.mode = mode
		if len(chunk) > 0 {
			w.remainder = record.ParserFor(mode)(chunk, w.remainder, w.vt)
		}
		w.offset, w.total, w.live = next, total, live
		w.mu.Unlock()
		if live {
			return "", design.GoodKey
		}
		return "This session has ended — what is shown is all of it.", design.MutedKey
	})
}

// checkRisk asks the GATEWAY what it would make of one command.
//
// The gateway and not a copy of the rules in this binary: the answer is
// only worth having if it is the answer the machine would actually get,
// and the two can differ for exactly as long as one side has been
// updated and the other has not.
func (f *Frame) checkRisk() {
	command := strings.TrimSpace(f.editor(ctlAdminRiskCheck).Text())
	if command == "" {
		f.say(ctlAdminRiskCheck, "Type a command above first — there is nothing to judge.", design.BadKey)
		return
	}
	ask := f.cfg.Actions.AdminRiskCheck
	if ask == nil {
		f.say(ctlAdminRiskCheck, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlAdminRiskCheck, "Asking the gateway.", func() (string, design.ColorKey) {
		level, rule, reason, err := ask(command)
		if err != nil {
			return err.Error(), design.BadKey
		}
		key := design.GoodKey
		switch level {
		case "red":
			key = design.BadKey
		case "yellow":
			key = design.WarnKey
		}
		msg := strings.ToUpper(level)
		if rule != "" {
			msg += " · " + rule
		}
		if reason != "" {
			msg += " — " + reason
		}
		if rule == "" {
			msg += " — no rule recognised this command. Green here means \"nothing matched\", not \"checked and safe\"."
		}
		return msg, key
	})
}

// setRiskMode changes the gateway's live safety mode. The selected value is
// revised only after the gateway accepts the write; a refusal therefore
// leaves both the button selection and the sentence honest.
func (f *Frame) setRiskMode(mode string) {
	ask := f.cfg.Actions.AdminRiskMode
	if ask == nil {
		f.say(ctlAdminRiskMode, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlAdminRiskMode, "Changing the safety mode.", func() (string, design.ColorKey) {
		gen, _ := f.gatewayNow()
		result, err := ask(mode)
		if err != nil {
			return err.Error(), design.BadKey
		}
		// The mode of the gateway this was asked of: a switch while it
		// was on its way leaves the new gateway's line alone (R1-CX F-16).
		f.reviseForGateway(gen, func(s *Snapshot) {
			// TWO FIELDS, not the whole struct. risk.mode answers about
			// the mode and says nothing about the classifier, so
			// assigning a fresh RiskMode here blanked Classifier,
			// ClassifierSource, ClassifierKey and the key's fingerprint
			// until the next AdminList fetch -- and with them the goal
			// caveat that reads "no effect while the classifier is
			// rules", which would then say the wrong thing.
			//
			// cmd/iamtunnel's own half of this action already had the
			// lesson written above it ("Mode/Source only ... review19
			// finding 5's own bug, one field over"). The same mistake
			// was living here, one file over from the note about it.
			s.Admin.RiskMode.Mode = result.Mode
			s.Admin.RiskMode.Source = result.Source
		})
		msg := "Safety mode is " + strings.ToUpper(result.Mode) + " (" + result.Source + ")."
		if result.Changed && result.Previous != "" {
			msg += " Changed from " + strings.ToUpper(result.Previous) + "."
		}
		return msg, design.GoodKey
	})
}

// killSession ends one session immediately.
func (f *Frame) killSession(ctl, id string) {
	kill := f.cfg.Actions.AdminSessionKill
	if kill == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.begin(ctl, "Cutting.", func() (string, design.ColorKey) {
		msg, err := kill(id)
		if err != nil {
			return err.Error(), design.BadKey
		}
		f.refreshAdminLists()
		return msg, design.GoodKey
	})
}

// layoutLiveSection draws the sessions happening right now, the
// transcript of the one being followed, and the command checker.
//
// When the live list is empty the section still asks the gateway for
// it — the empty message promised "a live session appears here the
// second it starts", and that promise is met by the same refresh the
// toolbar button asks for. Without this an empty list
// stayed empty until the user pressed Refresh.
func (f *Frame) layoutLiveSection(gtx layout.Context) layout.Dimensions {
	sessions := f.snap.Admin.ActiveSessions

	if f.btn(ctlAdminLive + "/more").Clicked(gtx) {
		f.tailWatched()
	}
	if f.btn(ctlAdminLive + "/close").Clicked(gtx) {
		f.watch = nil
	}
	if f.btn(ctlAdminLive+"/window").Clicked(gtx) && f.watch != nil {
		f.openTranscriptWindow(f.watch.id, f.watch.person, f.watch.machine)
	}

	// The promise of the empty card — "a live session appears here the
	// second it starts" — is a fetch on its own. Throttled to one per
	// `liveSubTabEmptyPollInterval` so an idle sub-tab dials the
	// gateway at a human pace, not once per repaint.
	if len(sessions) == 0 && f.cfg.Actions.AdminList != nil && !f.busy(ctlAdminRefresh) {
		f.mu.Lock()
		last := f.liveSubTabLastFetch
		f.mu.Unlock()
		if last.IsZero() || time.Since(last) >= liveSubTabEmptyPollInterval {
			f.refreshAdminLists()
			f.mu.Lock()
			f.liveSubTabLastFetch = time.Now()
			f.mu.Unlock()
		}
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if len(sessions) == 0 {
				return design.Empty(gtx, f.theme,
					"Nobody is inside any machine at this moment. A live session appears here the second it starts, with a way to watch it and a way to cut it.")
			}
			var rows []layout.FlexChild
			for i := range sessions {
				s := sessions[i]
				watchCtl := ctlAdminLive + "/watch/" + strconv.Itoa(i)
				killCtl := ctlAdminLive + "/kill/" + strconv.Itoa(i)
				if f.btn(watchCtl).Clicked(gtx) {
					f.watchSession(s.ID, s.Person, s.Machine)
				}
				if f.btn(killCtl).Clicked(gtx) {
					f.killSession(killCtl, s.ID)
				}
				killWord := "Cut off"
				if f.busy(killCtl) {
					killWord = "CUTTING…"
				}
				said := f.saidUnder(killCtl)
				rows = append(rows,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return design.Fixed(gtx, f.theme,
									orDash(clipStr(s.Person, 24))+" → "+orDash(clipStr(s.Machine, 24))+
										// "since revoked" reads as the session
										// once having existed; a zero Started
										// means it never began, so say "—" —
										// untilText is honest here, grantUntilText
										// lies.
										" · since "+untilText(s.Started))
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.SecondaryButton(gtx, f.theme, f.btn(watchCtl), "Watch")
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(design.Tight)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.DangerButton(gtx, f.theme, f.btn(killCtl), killWord)
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Said(gtx, f.theme, f.sel(killCtl+"/said"), clipStr(said.text, 200), said.key)
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				)
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		}),

		// --- the transcript ------------------------------------------
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			w := f.watch
			if w == nil {
				return layout.Dimensions{}
			}
			said := f.saidUnder(ctlAdminLive)
			word := "Read more"
			if f.busy(ctlAdminLive) {
				word = "READING…"
			}
			// One read of the shared state per frame, under the lock,
			// into locals. Reading it field by field through the layout
			// below would scatter a dozen unguarded reads across the
			// path of the fetch goroutine instead of one.
			w.mu.Lock()
			text := ""
			if w.vt != nil {
				text = strings.TrimRight(w.vt.Transcript(), " \n")
			}
			offset, total, live := w.offset, w.total, w.live
			w.mu.Unlock()

			state := "ended"
			if live {
				state = "live"
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.SectionHead(gtx, f.theme,
						"transcript · "+w.id+" · "+state, f.btn(ctlAdminLive+"/close"), "Close")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					// A bounded, SCROLLING excerpt (IAMT-366). It used
					// to be an unbounded box, and a session of any real
					// length pushed the rest of the tab -- including the
					// controls that stop it -- off the bottom of the
					// page, with no bar on screen to say so.
					//
					// The excerpt is deliberately short: this panel
					// answers "is anything happening". Reading what
					// somebody is doing belongs in the window the button
					// beside it opens.
					if text == "" {
						text = "(nothing yet)"
					}
					gtx.Constraints.Max.Y = gtx.Dp(transcriptExcerptHeight)
					gtx.Constraints.Min.Y = gtx.Constraints.Max.Y
					return design.PageScrollbar(f.theme, f.namedList(ctlAdminLive+"/scroll")).
						Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
							// The same gutter the pages keep: the bar has
							// its own strip, and text flush against that
							// strip reads as clipped.
							return layout.Inset{Right: unit.Dp(design.Gap)}.Layout(gtx,
								func(gtx layout.Context) layout.Dimensions {
									return design.CopyableBox(gtx, f.theme, f.sel(ctlAdminLive+"/text"), text)
								})
						})
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme,
						"read "+strconv.FormatInt(offset, 10)+" of "+strconv.FormatInt(total, 10)+" bytes")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.SecondaryButton(gtx, f.theme, f.btn(ctlAdminLive+"/more"), word)
						}),
						layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.PrimaryButton(gtx, f.theme, f.btn(ctlAdminLive+"/window"), "OPEN IN A WINDOW")
						}),
					)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Said(gtx, f.theme, f.sel(ctlAdminLive+"/said"), clipStr(said.text, 300), said.key)
				}),
			)
		}),
	)
}

// layoutSafetySection is the Admin tab's "Safety" sub-tab: the live safety
// mode switch and the dry-run command checker (IAMT-360), split out of
// layoutLiveSection on 20.09.2026 (IAMT-398). Gate 17 measured the three
// parts together over the default window and refused them the moment
// IAMT-387 stopped capping a section's reported height at the window's
// own — the card had always been this tall, the cap had only been hiding
// it behind a scroll gate that could never fire. "Who is in my machines
// right now" (layoutLiveSection) and "how strict is the policy" are
// different questions asked at different times, so the split follows
// that rather than a byte count — and it gives the safety mode switch a
// page of its own, which is what the maintainer asked for when it could not
// find it on 20.09.2026 in the first place (IAMT-393).
func (f *Frame) layoutSafetySection(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		// --- safety mode ------------------------------------------------
		//
		// ONE EDITOR, TWO ROUTES TO IT (21.09.2026). The mode used to be
		// changed here AND in the window the "···" button opens from a
		// machine's row. Two independent editors of the same gateway-wide
		// switch is the kind of thing that reads fine and ages badly: the
		// one that is pressed less often drifts, and a dangerous setting
		// must not have two half-maintained forms.
		//
		// The window won because it is the only one holding the WHOLE
		// pair — who judges a command (rules / ai / both) and what is done
		// when the answer is red — and because the maintainer asked for exactly
		// that: all the settings for this server should be shown there,
		// in the pop-up.
		// The half that lived here could never offer the other half.
		//
		// This page keeps what it is for: saying what the policy IS right
		// now, in words, on the administrator's own tab, and opening the
		// editor in one press. The reason the switch came to this tab in
		// the first place (IAMT-393 — the maintainer could not find it) is
		// served by that, and the dry-run checker below is untouched.
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if f.btn(ctlAdminRiskMode + "/window").Clicked(gtx) {
				f.openSettingsWindow()
			}
			rm := f.snap.Admin.RiskMode
			known := rm.Mode != "" || rm.Classifier != ""
			current := rm.Mode
			if current == "" {
				current = "—"
			}
			source := rm.Source
			if source == "" {
				source = "unknown"
			}
			classifier := rm.Classifier
			if classifier == "" {
				classifier = "unknown"
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					// NOT THREE UNKNOWNS IN A ROW (21.09.2026). Before
					// the Admin lists have been fetched once, all three
					// of these are empty, and the line read "Checked by:
					// UNKNOWN · when red: — · source: unknown" -- on
					// the page that owns this product's whole
					// differentiator. Three unknowns say one thing, so
					// say it once, in a sentence, and say what to do.
					if !known {
						return design.Fixed(gtx, f.theme,
							"Not read yet — press Refresh above to ask the gateway what its policy is.")
					}
					return design.Fixed(gtx, f.theme,
						"Checked by: "+strings.ToUpper(classifier)+" · when red: "+
							strings.ToUpper(current)+" · source: "+source)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme,
						"Only EXEC commands are classified; interactive shell keystrokes never are. "+
							"Warn reports and lets through; Ask stops a red command until you approve that exact "+
							"command; Block stops it outright.")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					// Compact, not a full-width orange bar. Weight on a
					// page means importance, and a bar across the whole
					// column for "open the editor" outweighed every
					// control that actually changes something.
					return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return design.CompactButton(gtx, f.theme,
								f.btn(ctlAdminRiskMode+"/window"), "Change these settings")
						}),
					)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					said := f.saidUnder(ctlAdminRiskMode)
					return design.Said(gtx, f.theme, f.sel(ctlAdminRiskMode+"/said"), clipStr(said.text, 400), said.key)
				}),
			)
		}),

		// --- the command checker -----------------------------------------
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if f.btn(ctlAdminRiskCheck).Clicked(gtx) || f.submitted(gtx, ctlAdminRiskCheck) {
				f.checkRisk()
			}
			word := "CHECK THIS COMMAND"
			if f.busy(ctlAdminRiskCheck) {
				word = "ASKING…"
			}
			said := f.saidUnder(ctlAdminRiskCheck)
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Heading(gtx, f.theme, "what would the gateway make of a command")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Text(gtx, f.theme,
						"A dry run against the gateway's own rules — nothing is executed anywhere. "+
							"Classification works on grants with the EXEC capability, where the gateway sees the "+
							"whole command before a byte of it reaches the machine. In an interactive SHELL there "+
							"is no such moment: what travels is keystrokes.")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Field(gtx, f.theme, "command",
						func(gtx layout.Context) layout.Dimensions {
							return design.TextBox(gtx, f.theme, f.editor(ctlAdminRiskCheck), "rm -rf /var/lib/postgresql")
						}, "")
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.PrimaryButton(gtx, f.theme, f.btn(ctlAdminRiskCheck), word)
				}),
				layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Said(gtx, f.theme, f.sel(ctlAdminRiskCheck+"/said"), clipStr(said.text, 400), said.key)
				}),
			)
		}),
	)
}

// layoutClassifierKeySection is the Admin tab's "Classifier" sub-tab
// (SPEC IAMT-403): a one-shot field for replacing the typesafe.ai key
// the external classifier calls with. It is not internal/ui/design's
// usual TextBox-plus-field decoration for a secret — there is no
// secret-specific control in that package to reach for instead, so
// this is the SAME ordinary field every other box on these screens is,
// and the key it
// holds is treated as one exactly because that field cannot promise
// anything more.
//
// The box empties itself the instant Replace is pressed, before the
// gateway has even answered (setClassifierKey, point 1) — never on a
// successful result only, which would leave a refused or inconclusive
// attempt sitting in the box. Nothing here ever shows the key: not the
// field, not the confirmation, not this caption. The gateway's outcome
// is one of three words, first in its own sentence and its own color,
// exactly as checkRisk's own answer already reads.
func (f *Frame) layoutClassifierKeySection(gtx layout.Context) layout.Dimensions {
	if f.btn(ctlAdminClassifierKey).Clicked(gtx) || f.submitted(gtx, ctlAdminClassifierKey) {
		f.setClassifierKey()
	}
	key := f.snap.Admin.RiskMode
	// "Replace" only when there is something to replace (21.09.2026).
	// On a gateway that has never had a key -- which is every gateway on
	// the day it is installed -- the one control on this page invited an
	// administrator to replace a key that does not exist, and the field
	// under it said "cleared the instant Replace is pressed".
	word := "SET KEY"
	verb := "Set"
	if key.ClassifierKey {
		word, verb = "REPLACE KEY", "Replace"
	}
	if f.busy(ctlAdminClassifierKey) {
		word = "ASKING…"
	}
	said := f.saidUnder(ctlAdminClassifierKey)
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Hint(gtx, f.theme, "key on this gateway now")
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			// The fact the paragraph below has always promised.
			switch {
			case key.ClassifierKeyFingerprint != "":
				return design.Fixed(gtx, f.theme, key.ClassifierKeyFingerprint)
			case key.ClassifierKey:
				return design.Fixed(gtx, f.theme, "present (the gateway did not report a fingerprint)")
			default:
				return design.Fixed(gtx, f.theme,
					"none — the AI classifier cannot be selected until a key is set")
			}
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Text(gtx, f.theme,
				verb+"s the key the external risk classifier (\"ai\"/\"both\" mode) calls typesafe.ai with. "+
					"The gateway trials the new key with one real request before switching to it, so a refusal "+
					"here never disturbs a key that is already working. The key itself is never shown once "+
					"pasted below — only whether the gateway now has one, and its fingerprint.")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Field(gtx, f.theme, "new key",
				func(gtx layout.Context) layout.Dimensions {
					return design.TextBox(gtx, f.theme, f.editor(ctlAdminClassifierKey), "paste the new typesafe.ai key")
				}, "cleared the instant "+verb+" is pressed — never kept, never shown again")
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.PrimaryButton(gtx, f.theme, f.btn(ctlAdminClassifierKey), word)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, f.theme, f.sel(ctlAdminClassifierKey+"/said"), clipStr(said.text, 400), said.key)
		}),
	)
}

// riskModeWords is the safety ladder as the window offers it, in
// escalating order — and the ONE place the window names it.
//
// It is a function rather than a literal inside the row because of how
// this list last went wrong (IAMT-400): "ask" was added to the gateway
// and to the CLI in the same wave as the row itself, by a different
// track, and nobody wrote the fourth button. The window then offered
// three of the four modes the gateway knew, and the one mode a person
// would actually leave switched on was the one they could not reach.
//
// A canary now reads this function and the gateway's own RiskAction
// constants and fails when the two disagree, which only works if there
// is exactly one list here to read.
func riskModeWords() []string {
	return []string{"Log", "Warn", "Ask", "Block"}
}
