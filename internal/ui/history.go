//go:build windows || linux || darwin

package ui

// Who was on which machine, when, and what they ran.
//
// Asked for by the maintainer on 21.09.2026: a full history an
// administrator
// can read -- yesterday, last week, last month -- with filters and pages,
// so that the whole list is not shown at once -- say, twenty or fifty
// entries per page.
//
// The journal has held all of this since 1.0 and nothing in the window
// ever showed it. That is the same shape of hole as the missing Remove
// button and the unviewable held commands: a capability that exists,
// works, is reachable from a terminal, and is invisible to the person the
// product is for.
//
// ONE ROW IS ONE VISIT. The gateway groups its events by session before
// answering, because a session writes a start, some risk decisions and a
// stop, and a reader wants a line per visit rather than four lines to
// reassemble. What the row cannot say -- the whole transcript -- opens in
// the window that already exists for watching a live session.
//
// WHAT THE HISTORY OUTLIVES. Recordings are pruned at ninety days, and
// sooner when the disk fills; the journal is not pruned with them. So a
// row can outlive its recording, and the screen says so rather than
// opening an empty window: "the recording is gone" is an answer, and a
// blank page is not.

import (
	"context"
	"strconv"
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

const (
	ctlHistory       = "history"
	ctlHistoryPerson = ctlHistory + "/person"
	// The machine filter. The heading has promised "who was on WHICH
	// MACHINE, and when" since the tab existed, the gateway has accepted
	// a machine filter since the same day, and the window sent an empty
	// string for it -- so half of the question the screen asks could not
	// be asked (21.09.2026).
	ctlHistoryMachine = ctlHistory + "/machine"
	ctlHistoryRange   = ctlHistory + "/range"
	ctlHistorySize    = ctlHistory + "/size"
	ctlHistoryPrev    = ctlHistory + "/prev"
	ctlHistoryNext    = ctlHistory + "/next"
	ctlHistoryReload  = ctlHistory + "/reload"
	ctlHistoryExport  = ctlHistory + "/export"
)

// historyRanges are the four periods, in the order a person reaches for
// them. "All" is last because a history that opens on everything is a
// history that opens slowly on the day it matters.
var historyRanges = []string{"Today", "7 days", "30 days", "All"}

// historySizes: twenty fits the window, fifty is for scanning. The
// maintainer named both.
var historySizes = []string{"20", "50"}

// historySince turns a chosen period into the earliest moment it covers,
// or the zero time for "All".
func historySince(choice string, now time.Time) time.Time {
	switch choice {
	case "Today":
		y, m, d := now.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, now.Location())
	case "7 days":
		return now.AddDate(0, 0, -7)
	case "30 days":
		return now.AddDate(0, 0, -30)
	default:
		return time.Time{}
	}
}

// historyOutcomeKey colours the outcome word. A visit that ended by
// itself is not news; one the gateway cut off is.
func historyOutcomeKey(outcome, riskLevel string) design.ColorKey {
	switch {
	case riskLevel == "red":
		return design.BadKey
	case riskLevel == "yellow":
		return design.WarnKey
	case outcome == "ended", outcome == "ok":
		return design.MutedKey
	default:
		return design.BadKey
	}
}

// historyWhen shortens an RFC 3339 instant to what a person reads. The
// full instant stays in the detail window; a column of thirty-character
// timestamps is a column nobody scans.
func historyWhen(ts string) string {
	if ts == "" {
		return "—"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return clipStr(ts, 19)
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// layoutHistoryScreen is the whole tab.
func (f *Frame) layoutHistoryScreen(gtx layout.Context) layout.Dimensions {
	h := f.snap.History

	sections := []layout.Widget{
		posterOf(f.theme, "Who was on which machine, and when", "History", design.InkKey),
		f.layoutHistoryFilters,
		f.layoutHistoryRows,
	}
	// The poster and the filter bar are pinned: the controls that change
	// what is listed must not scroll away from the list they change.
	_ = h
	return design.PinnedPage(gtx, f.theme, f.pageList(), 2, sections...)
}

func (f *Frame) layoutHistoryFilters(gtx layout.Context) layout.Dimensions {
	h := f.snap.History

	people := []string{"Everyone"}
	for _, p := range f.snap.Admin.People {
		people = append(people, p.Name)
	}
	machines := []string{"Any machine"}
	for _, m := range f.snap.Admin.Machines {
		machines = append(machines, m.Name)
	}

	if f.btn(ctlHistoryReload).Clicked(gtx) {
		f.refreshHistory(0)
	}
	if f.btn(ctlHistoryExport).Clicked(gtx) {
		f.openExportWindow()
	}
	if f.btn(ctlHistoryPrev).Clicked(gtx) && h.Offset > 0 {
		next := h.Offset - f.historyPageSize()
		if next < 0 {
			next = 0
		}
		f.refreshHistory(next)
	}
	if f.btn(ctlHistoryNext).Clicked(gtx) && h.Offset+len(h.Rows) < h.Total {
		f.refreshHistory(h.Offset + f.historyPageSize())
	}

	word := "Refresh"
	if f.busy(ctlHistory) {
		word = "Reading…"
	}
	said := f.saidUnder(ctlHistory)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme, "period")
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return f.pickOne(gtx, ctlHistoryRange, historyRanges, f.historyRange(), func(string) { f.refreshHistory(0) })
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(design.Wide)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme, "per page")
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return f.pickOne(gtx, ctlHistorySize, historySizes, strconv.Itoa(f.historyPageSize()), func(string) { f.refreshHistory(0) })
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} }),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.SecondaryButton(gtx, f.theme, f.btn(ctlHistoryReload), word)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					// Beside Refresh, because it exports what Refresh
					// fetched: the same three filters, all of their rows
					// rather than the page on screen.
					return design.SecondaryButton(gtx, f.theme, f.btn(ctlHistoryExport), "Export…")
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme, "person")
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return f.combo(gtx, ctlHistoryPerson, "Everyone", people)
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme, "machine")
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return f.combo(gtx, ctlHistoryMachine, "Any machine", machines)
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return design.Said(gtx, f.theme, f.sel(ctlHistory+"/said"), clipStr(said.text, 300), said.key)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if h.Total == 0 {
				return layout.Dimensions{}
			}
			// Where this page sits in the whole. Without it "no more
			// rows" and "the end of the list" are the same screen.
			from := h.Offset + 1
			to := h.Offset + len(h.Rows)
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return design.Hint(gtx, f.theme,
						strconv.Itoa(from)+"–"+strconv.Itoa(to)+" of "+strconv.Itoa(h.Total))
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} }),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if h.Offset == 0 {
						return layout.Dimensions{}
					}
					return design.SecondaryButton(gtx, f.theme, f.btn(ctlHistoryPrev), "Newer")
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if to >= h.Total {
						return layout.Dimensions{}
					}
					return design.SecondaryButton(gtx, f.theme, f.btn(ctlHistoryNext), "Older")
				}),
			)
		}),
		layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
	)
}

func (f *Frame) layoutHistoryRows(gtx layout.Context) layout.Dimensions {
	h := f.snap.History
	if len(h.Rows) == 0 {
		if f.busy(ctlHistory) {
			return design.Text(gtx, f.theme, "Reading the journal…")
		}
		return design.Empty(gtx, f.theme,
			"Nothing in this period. Widen it, or clear the person and machine filters — the "+
				"journal keeps every session the gateway ever carried, including the ones it refused.")
	}

	var children []layout.FlexChild
	for i := range h.Rows {
		r := h.Rows[i]
		ctl := ctlHistory + "/row/" + strconv.Itoa(i)
		if r.SessionID != "" && f.btn(ctl).Clicked(gtx) {
			// The FINISHED reader, not the live one. A row in this list
			// is by definition a visit that is over, and the live reader
			// answers such a row with an empty window (IAMT-427).
			f.openHistoryTranscript(r.SessionID, r.Person, r.Machine)
		}
		children = append(children,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.Fixed(gtx, f.theme,
									historyWhen(r.Started)+"  "+orDash(clipStr(r.Person, 16))+
										" → "+orDash(clipStr(r.Machine, 16))+"  "+r.Kind)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.Said(gtx, f.theme, f.sel(ctl+"/outcome"),
									historyLine(r), historyOutcomeKey(r.Outcome, r.RiskLevel))
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if r.SessionID == "" {
							// No session id: refused before a session
							// existed, so there is nothing recorded to
							// open. Saying nothing is better than a
							// button that would answer "not found".
							return layout.Dimensions{}
						}
						return design.SecondaryButton(gtx, f.theme, f.btn(ctl), "Transcript")
					}),
				)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
		)
	}
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
}

// historyLine is the second line of a row: what happened, then what was
// run, then what it was for.
func historyLine(r HistoryRow) string {
	parts := []string{r.Outcome}
	if r.Ended != "" {
		parts = append(parts, "until "+historyWhen(r.Ended))
	}
	if r.Risks > 0 {
		word := strconv.Itoa(r.Risks) + " risk decision"
		if r.Risks > 1 {
			word += "s"
		}
		if r.RiskLevel != "" {
			word += " (worst " + r.RiskLevel + ")"
		}
		if r.RiskReason != "" {
			word += ": " + r.RiskReason
		}
		parts = append(parts, word)
	}
	line := strings.Join(parts, " · ")
	if r.Command != "" {
		line += "\n" + clipStr(strings.ReplaceAll(r.Command, "\n", " "), 120)
	}
	if r.Goal != "" {
		line += "\ngoal: " + clipStr(r.Goal, 120)
	}
	return line
}

// pickOne is a segmented control whose choice is remembered by the frame.
//
// design.Segmented reports which segment was pressed and nothing more --
// it holds no state, deliberately, so that a caller who already knows the
// answer (the safety mode lives on the gateway) cannot drift from it.
// Here the answer lives nowhere else, so the frame keeps it, in the same
// map its text boxes use.
func (f *Frame) pickOne(gtx layout.Context, ctl string, items []string, active string, onPick func(string)) layout.Dimensions {
	dims, pressed := design.Segmented(gtx, f.theme, items, active,
		func(word string) *widget.Clickable { return f.btn(ctl + "/" + word) })
	if pressed != "" && pressed != active {
		f.editor(ctl).SetText(pressed)
		if onPick != nil {
			onPick(pressed)
		}
	}
	return dims
}

// choiceOf reads back a pickOne choice.
func (f *Frame) choiceOf(ctl string) string {
	return strings.TrimSpace(f.editor(ctl).Text())
}

// historyRange and historyPageSize read the two segmented choices,
// falling back to the defaults the tab opens with.
func (f *Frame) historyRange() string {
	if v := f.choiceOf(ctlHistoryRange); v != "" {
		return v
	}
	return historyRanges[1] // 7 days
}

func (f *Frame) historyPageSize() int {
	if v := f.choiceOf(ctlHistorySize); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 20
}

// refreshHistory asks the gateway for one page and writes it into the
// snapshot.
func (f *Frame) refreshHistory(offset int) {
	ask := f.cfg.Actions.SessionsHistory
	if ask == nil {
		f.say(ctlHistory, noRuntime, design.BadKey)
		return
	}
	person := f.editor(ctlHistoryPerson).Text()
	if strings.EqualFold(strings.TrimSpace(person), "everyone") {
		person = ""
	}
	machine := f.editor(ctlHistoryMachine).Text()
	if strings.EqualFold(strings.TrimSpace(machine), "any machine") {
		machine = ""
	}
	since := historySince(f.historyRange(), time.Now())
	from := ""
	if !since.IsZero() {
		from = since.UTC().Format(time.RFC3339)
	}
	limit := f.historyPageSize()

	f.begin(ctlHistory, "Reading the journal.", func() (string, design.ColorKey) {
		var page HistoryPage
		err := f.forCurrentGateway(func(ctx context.Context) (func(*Snapshot), error) {
			got, err := ask(ctx, strings.TrimSpace(person), strings.TrimSpace(machine),
				from, "", limit, offset)
			if err != nil {
				return nil, err
			}
			page = got
			return func(s *Snapshot) { s.History = got }, nil
		})
		if err != nil {
			return err.Error(), design.BadKey
		}
		if page.Total == 0 {
			return "", design.MutedKey
		}
		return "", design.MutedKey
	})
}
