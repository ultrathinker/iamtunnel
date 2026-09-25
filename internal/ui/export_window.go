//go:build windows || linux || darwin

package ui

// Taking the history off the screen (IAMT-428).
//
// The maintainer, 22.09.2026: it should be possible to look at every
// person's history, and to export quickly either one person's whole
// dialogue or everything over a given period, so that afterwards it is
// possible to analyse who did what on the server.
//
// Two asks in one sentence, and they turn out to be the same button. The
// tab already has the three filters -- person, machine, period -- and
// "one person's whole dialogue" is that filter with a person in it,
// while "everything over a period" is the same filter with the person
// left on Everyone. So Export writes WHAT THE SCREEN IS SHOWING, only
// all of it rather than the current page, and the two requests are one
// feature with no mode switch between them.
//
// WHAT IS WRITTEN. A folder holding:
//
//   - index.txt      one line per session, in the order the tab lists
//     them: when, who, on what, how it ended, the goal.
//   - all.txt        every transcript end to end, under those same
//     headers -- the "one dialogue" reading, and the file to feed to
//     something that analyses.
//   - NNN_*.txt      one file per session, for reading a single visit
//     without scrolling through a month.
//
// No .cast: the maintainer was asked and said it is not wanted. The raw
// asciicast is only useful to a player, and a folder of files that no
// text tool will open is a folder somebody has to be taught about.
//
// NO CEILING on size, also the maintainer's decision. A cap would have to be a guess
// about which month matters, and an export silently missing the sessions
// that ran long is worse than one that takes a minute.
//
// WHY A WINDOW AND A TYPED PATH. Gio has no native folder picker, and the
// maintainer asked to be asked where things go rather than have them appear
// somewhere the product chose. The field opens on a sensible default so
// the common case is one press, and it is a field so the uncommon case
// is possible at all.

import (
	"context"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// exportPageSize is how many rows one history request brings back while
// an export collects them. Larger than anything the tab offers: nobody
// is reading these, and a month of sessions should cost a handful of
// round trips rather than a hundred.
const exportPageSize = 200

// exportFilter is the question the Export button inherits from the tab:
// the same person, machine and period the list on screen was built from.
type exportFilter struct {
	Person  string
	Machine string
	From    string
	Period  string
}

// exportDeps are the three gateway calls an export makes. Passed in
// rather than reached for so that the whole of exportHistory can be
// tested without a window, a gateway or a network.
type exportDeps struct {
	History    func(ctx context.Context, person, machine, from, to string, limit, offset int) (HistoryPage, error)
	Recordings func(ctx context.Context, machine, from, to string) ([]RecordingRef, error)
	Fetch      func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error)
}

// exportResult is what the window reports when the work is done.
type exportResult struct {
	Dir          string
	Sessions     int
	Transcripts  int
	MissingBytes int
	// FailedTranscripts counts recordings whose bytes could NOT be read
	// — the gateway refused, the network died, the file vanished between
	// the listing and the fetch. It is NOT MissingBytes, which counts
	// recordings that were pruned months ago and is a normal answer: this
	// one is a failure, and an export that had any is incomplete.
	FailedTranscripts int
	// Failures names them, one line each, for index.txt: which session,
	// and what the gateway said. The window cannot list them all, so the
	// file that stays on disk has to.
	Failures []string
}

// exportNoteKey is the colour the window reports an outcome in. Green
// only for a WHOLE export (M-5b, review F-19): when a recording could not
// be read, the person must not close the window believing the archive is
// complete, because the folder they are leaving behind is missing
// transcripts and says so only in a file nobody has opened yet.
func exportNoteKey(res exportResult, err error) design.ColorKey {
	switch {
	case err != nil:
		return design.BadKey
	case res.FailedTranscripts > 0:
		return design.WarnKey
	default:
		return design.GoodKey
	}
}

// openExportWindow asks where to put the export and then makes it.
func (f *Frame) openExportWindow() {
	deps := exportDeps{
		History:    f.cfg.Actions.SessionsHistory,
		Recordings: f.cfg.Actions.AdminRecordings,
		Fetch:      f.cfg.Actions.AdminRecordingFetch,
	}
	if deps.History == nil || deps.Recordings == nil || deps.Fetch == nil {
		f.say(ctlHistory, noRuntime, design.BadKey)
		return
	}
	if testing.Testing() {
		panic("ui: openExportWindow invoked in test binary; tests must never open a real window")
	}

	person := strings.TrimSpace(f.editor(ctlHistoryPerson).Text())
	if strings.EqualFold(person, "everyone") {
		person = ""
	}
	machine := strings.TrimSpace(f.editor(ctlHistoryMachine).Text())
	if strings.EqualFold(machine, "any machine") {
		machine = ""
	}
	period := f.historyRange()
	from := ""
	if since := historySince(period, time.Now()); !since.IsZero() {
		from = since.UTC().Format(time.RFC3339)
	}

	filter := exportFilter{Person: person, Machine: machine, From: from, Period: period}
	go runExportWindow(f.windowTheme(), filter, deps)
}

// exportDefaultDir is the path the field opens on: a new, dated folder
// under the person's home, named after what is being exported. Dated
// because two exports of the same filter are two different answers --
// the second one has whatever happened since -- and overwriting the
// first silently would lose that.
func exportDefaultDir(filter exportFilter, now time.Time) string {
	name := "iamtunnel-history"
	if filter.Person != "" {
		name += "-" + safeFileWord(filter.Person)
	}
	if filter.Machine != "" {
		name += "-" + safeFileWord(filter.Machine)
	}
	name += "-" + now.Format("2006-01-02_150405")
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return name
	}
	return filepath.Join(home, name)
}

// exportSubject is the sentence at the top of the window and of the
// index: exactly which slice of the history this is.
func exportSubject(filter exportFilter) string {
	who := "everyone"
	if filter.Person != "" {
		who = filter.Person
	}
	where := "every machine"
	if filter.Machine != "" {
		where = filter.Machine
	}
	return who + " · " + where + " · " + strings.ToLower(filter.Period)
}

func runExportWindow(theme *design.Theme, filter exportFilter, deps exportDeps) {
	defer guardWindow("export window", nil)

	w := new(app.Window)
	w.Option(
		app.Title("iamtunnel - export history"),
		app.Size(unit.Dp(760), unit.Dp(420)),
	)
	w.Perform(system.ActionCenter)

	box := new(widget.Editor)
	box.SingleLine = true
	box.SetText(exportDefaultDir(filter, time.Now()))

	var ops op.Ops
	var exportBtn, closeBtn widget.Clickable
	var noteSel, subjectSel widget.Selectable

	var mu sync.Mutex
	note, noteKey := "", design.MutedKey
	busy, finished := false, false

	// The window's own context, cancelled when it closes: an export of a
	// month of recordings is minutes of fetching, and a person who shuts
	// the window has said they no longer want it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := func(dir string) {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			mu.Lock()
			note, noteKey = "Say which folder to write into.", design.BadKey
			mu.Unlock()
			return
		}
		mu.Lock()
		if busy {
			mu.Unlock()
			return
		}
		busy, finished = true, false
		note, noteKey = "Reading the journal.", design.MutedKey
		mu.Unlock()

		go func() {
			// Every recording is rendered here by the same emulator the
			// gateway records with, fed a stranger's terminal output. A
			// fault in it ends this export and leaves the process - and
			// the live-session controls in it - standing (IAMT-441).
			defer guardWindow("export worker", func(string) {
				mu.Lock()
				note, noteKey = "The export stopped unexpectedly: a recording could not be read to the end.", design.BadKey
				busy = false
				mu.Unlock()
				w.Invalidate()
			})
			say := func(s string) {
				mu.Lock()
				note, noteKey = s, design.MutedKey
				mu.Unlock()
				w.Invalidate()
			}
			res, err := exportHistory(ctx, deps, filter, dir, say)
			mu.Lock()
			if err != nil {
				note, noteKey = err.Error(), exportNoteKey(res, err)
			} else {
				note, noteKey = exportDoneLine(res), exportNoteKey(res, nil)
				finished = true
			}
			busy = false
			mu.Unlock()
			w.Invalidate()
		}()
	}

	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			cancel()
			return
		case app.ViewEvent:
			applyTitleBarTheme(viewHandle(e), theme.IsDark())
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			if closeBtn.Clicked(gtx) {
				w.Perform(system.ActionClose)
			}
			if exportBtn.Clicked(gtx) {
				start(box.Text())
			}
			mu.Lock()
			shownNote, shownKey, shownBusy, shownDone := note, noteKey, busy, finished
			mu.Unlock()

			paint.FillShape(gtx.Ops, theme.Color(design.PageKey),
				clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Op())
			layout.Inset{
				Top: unit.Dp(design.Gap), Bottom: unit.Dp(design.Gap),
				Left: unit.Dp(design.Gap), Right: unit.Dp(design.Gap),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Heading(gtx, theme, "Export this history to a folder")
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Text(gtx, theme,
							"Everything the list is filtered to, not just the page on screen: one file per "+
								"session, one index, and all of them end to end in all.txt for reading or "+
								"analysing as a single conversation.")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Hint(gtx, theme, "exporting")
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.CopyableBox(gtx, theme, &subjectSel, exportSubject(filter))
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Gap)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Field(gtx, theme, "folder", func(gtx layout.Context) layout.Dimensions {
							return design.TextBox(gtx, theme, box, "where to write")
						}, "It is created if it is not there. An existing folder is written into, not emptied.")
					}),
					layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return design.Said(gtx, theme, &noteSel, shownNote, shownKey)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						word := "EXPORT"
						switch {
						case shownBusy:
							word = "EXPORTING..."
						case shownDone:
							word = "EXPORT AGAIN"
						}
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return design.PrimaryButton(gtx, theme, &exportBtn, word)
							}),
							layout.Rigid(layout.Spacer{Width: unit.Dp(design.Gap)}.Layout),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return design.SecondaryButton(gtx, theme, &closeBtn, "Close")
							}),
						)
					}),
				)
			})
			e.Frame(gtx.Ops)
		}
	}
}

// exportDoneLine says what landed, including what did not.
//
// A count of transcripts that is lower than the count of sessions is not
// a failure and must not read as one: the journal outlives the
// recordings, so an old page exports rows whose bytes were pruned months
// ago. It must not read as a success either -- somebody analysing the
// result has to know that some visits are a header and nothing else.
//
// The two ways of having no text are counted separately and read
// differently, because they mean different things to whoever is holding
// the folder (M-5b, review F-19): a pruned recording is the archive
// working as designed, an unreadable one is the export having failed at
// something, and the sentence says which.
func exportDoneLine(res exportResult) string {
	line := "Wrote " + strconv.Itoa(res.Sessions) + " session"
	if res.Sessions != 1 {
		line += "s"
	}
	line += " to " + res.Dir + "."
	if res.MissingBytes > 0 {
		line += " " + strconv.Itoa(res.MissingBytes) + " of them have no recording left — " +
			"the journal keeps the visit after the transcript is pruned."
	}
	if res.FailedTranscripts > 0 {
		line += " " + strconv.Itoa(res.FailedTranscripts) + " recording"
		if res.FailedTranscripts != 1 {
			line += "s"
		}
		line += " could not be read, so this export is incomplete — index.txt names every one of them."
	}
	return line
}

// exportHistory is the whole job, without a window anywhere in it.
func exportHistory(
	ctx context.Context,
	deps exportDeps,
	filter exportFilter,
	dir string,
	say func(string),
) (exportResult, error) {
	res := exportResult{Dir: dir}
	if say == nil {
		// A progress line nobody is watching -- the tests, and any
		// future caller without a window -- is a no-op, not a crash.
		say = func(string) {}
	}

	rows, err := exportCollectRows(ctx, deps, filter, say)
	if err != nil {
		return res, err
	}
	if len(rows) == 0 {
		return res, fmt.Errorf("nothing matches this filter, so there is nothing to export")
	}
	res.Sessions = len(rows)

	// ONE listing for the whole export. Resolving each row separately
	// would be one directory scan of the gateway per session, which on a
	// month of history is the difference between a minute and an hour.
	say("Asking which recordings still exist.")
	refs, err := deps.Recordings(ctx, filter.Machine, "", "")
	if err != nil {
		return res, err
	}
	bySession := make(map[string]RecordingRef, len(refs))
	for _, r := range refs {
		if r.SessionID != "" {
			bySession[r.SessionID] = r
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return res, fmt.Errorf("the export folder did not open: %w", err)
	}

	var index strings.Builder
	var all strings.Builder
	index.WriteString("iamtunnel history export\n")
	index.WriteString(exportSubject(filter) + "\n")
	index.WriteString("taken " + time.Now().Format("2006-01-02 15:04:05") + "\n")
	index.WriteString(strings.Repeat("-", 72) + "\n")

	for i, r := range rows {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		n := i + 1
		say("Reading " + strconv.Itoa(n) + " of " + strconv.Itoa(len(rows)) + ".")

		header := exportHeader(r, n)
		body := ""
		switch ref, ok := bySession[r.SessionID]; {
		case r.SessionID == "":
			body = "(this row was refused before a session existed, so nothing was recorded)"
		case !ok:
			res.MissingBytes++
			body = "(no recording left — recordings are kept ninety days, and sooner deleted when the disk fills)"
		default:
			text, ferr := exportOneTranscript(ctx, deps.Fetch, ref)
			if ferr != nil {
				// One unreadable recording must not lose the other
				// three hundred. The failure is written where it
				// happened, in the file that would have held the text,
				// and it is COUNTED (M-5b, review F-19): an apology in a
				// text file is not a number the window can report, and
				// without the number the window went green over an
				// export that had lost everything.
				res.FailedTranscripts++
				body = "(this recording did not read: " + ferr.Error() + ")"
				res.Failures = append(res.Failures, strconv.Itoa(n)+". "+exportLine(r)+" — "+ferr.Error())
			} else {
				res.Transcripts++
				body = text
			}
		}

		index.WriteString(strconv.Itoa(n) + ". " + exportLine(r) + "\n")
		all.WriteString(header + "\n" + body + "\n\n")

		name := exportFileName(r, n)
		if werr := exportWrite(filepath.Join(dir, name), header+"\n"+body+"\n"); werr != nil {
			return res, fmt.Errorf("%s did not write: %w", name, werr)
		}
		index.WriteString("   " + name + "\n")
	}

	// The failures are listed in the index as well as where they
	// happened (M-5b, review F-19). index.txt is the one file somebody
	// opens first, after the window is closed and the sentence it showed
	// is gone: it has to say that this export is short and of what.
	if len(res.Failures) > 0 {
		index.WriteString("\n" + strings.Repeat("-", 72) + "\n")
		index.WriteString(strconv.Itoa(len(res.Failures)) + " recording(s) could not be read — " +
			"this export is incomplete:\n")
		for _, f := range res.Failures {
			index.WriteString("   " + f + "\n")
		}
	}

	if err := exportWrite(filepath.Join(dir, "index.txt"), index.String()); err != nil {
		return res, fmt.Errorf("index.txt did not write: %w", err)
	}
	if err := exportWrite(filepath.Join(dir, "all.txt"), all.String()); err != nil {
		return res, fmt.Errorf("all.txt did not write: %w", err)
	}
	return res, nil
}

// exportWrite puts one file of the export on disk.
//
// Through datafile rather than os.WriteFile, and not only because the
// gate says so. The folder is a path a PERSON typed, which is the one
// place in this product where the destination is neither our own data
// directory nor a temp file of our own making: a symlink or a hard link
// sitting where all.txt is about to go would, with a plain write, be
// followed into whatever it points at, with this process's rights. The
// datafile primitive refuses that and replaces the file atomically, so
// a second export into the same folder rewrites it rather than failing
// half way and leaving yesterday's text under today's index.
func exportWrite(path, text string) error {
	return datafile.WriteFileAtomic(path, []byte(text), datafile.WithMode(0o600))
}

// exportCollectRows walks the history a page at a time until it has
// every row the filter matches.
//
// ONE SNAPSHOT, or the pages do not join (M-5a, review F-18). The
// history is a list that grows at the NEW end while this loop reads it,
// and offset/limit is an offset into whatever the list looks like at
// that moment: a session that starts between two pages pushes the rows
// already read one place down, so the next page hands one of them out a
// second time and the new session is never seen at all. The export then
// answers a different question on every request, and the folder it
// writes is neither the history as it was when the person pressed the
// button nor as it is when the last page came back.
//
// So the boundary is fixed HERE, before the first request, and sent as
// `to` with every page: every request answers the same question, the one
// the history asked when the export began. A session that starts while
// the export runs is simply not in this export — the next one will have
// it, which is why the folder is dated.
//
// The snapshot is by timestamp, and the gateway's `to` bounds EVENTS,
// not sessions: a visit that began before the boundary and ends after it
// is still a row here (its start event is inside), it just shows the
// outcome it had at the boundary. Nothing that was true when the person
// pressed the button is lost.
//
// Deduplication is the second belt: the boundary makes repeats
// impossible against a gateway that honours it, and this loop must not
// depend on that. Rows are keyed the way the gateway keys them — session
// id, actor and object, which is what makes two rows two rows for it —
// so a session is written once and a refusal (a row with no session id
// at all) is never merged with another refusal.
//
// It stops on a page that adds nothing as well as on the total, because
// a total is a number the gateway reports and a loop that trusts it
// alone is a loop that can spin forever on a gateway that reports it
// wrong.
func exportCollectRows(
	ctx context.Context,
	deps exportDeps,
	filter exportFilter,
	say func(string),
) ([]HistoryRow, error) {
	to := time.Now().UTC().Format(time.RFC3339)
	seen := make(map[string]bool)
	var rows []HistoryRow
	offset, read := 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, err := deps.History(ctx, filter.Person, filter.Machine, filter.From, to, exportPageSize, offset)
		if err != nil {
			return nil, err
		}
		if len(page.Rows) == 0 {
			return rows, nil
		}
		for _, r := range page.Rows {
			if r.SessionID != "" {
				key := r.SessionID + "|" + r.Person + "|" + r.Machine
				if seen[key] {
					continue
				}
				seen[key] = true
			}
			rows = append(rows, r)
		}
		// The offset follows the rows the gateway SENT, not the rows
		// kept: a dropped repeat must not pull the next page backwards.
		offset += len(page.Rows)
		read += len(page.Rows)
		if say != nil {
			say("Read " + strconv.Itoa(read) + " of " + strconv.Itoa(page.Total) + " sessions.")
		}
		if page.Total > 0 && read >= page.Total {
			return rows, nil
		}
	}
}

// exportHeader is the block above one transcript, in every file it
// appears in. Repeated deliberately: all.txt is read in one scroll, and
// a transcript with no header above it belongs to whoever was above.
func exportHeader(r HistoryRow, n int) string {
	var b strings.Builder
	b.WriteString(strings.Repeat("=", 72) + "\n")
	b.WriteString("#" + strconv.Itoa(n) + "  " + orDash(r.Person) + " → " + orDash(r.Machine) + "\n")
	b.WriteString("started: " + historyWhen(r.Started) + "\n")
	if r.Ended != "" {
		b.WriteString("ended:   " + historyWhen(r.Ended) + "\n")
	}
	b.WriteString("kind:    " + orDash(r.Kind) + "\n")
	b.WriteString("outcome: " + orDash(r.Outcome) + "\n")
	if r.Goal != "" {
		b.WriteString("goal:    " + r.Goal + "\n")
	}
	if r.Risks > 0 {
		line := strconv.Itoa(r.Risks) + " risk decision"
		if r.Risks > 1 {
			line += "s"
		}
		if r.RiskLevel != "" {
			line += ", worst " + r.RiskLevel
		}
		if r.RiskRule != "" {
			line += " (" + r.RiskRule + ")"
		}
		if r.RiskReason != "" {
			line += ": " + r.RiskReason
		}
		b.WriteString("risk:    " + line + "\n")
	}
	if r.Command != "" {
		b.WriteString("command: " + strings.ReplaceAll(r.Command, "\n", " ") + "\n")
	}
	b.WriteString("session: " + orDash(r.SessionID) + "\n")
	b.WriteString(strings.Repeat("=", 72))
	return b.String()
}

// exportOneTranscript reads one whole recording and renders it.
//
// From byte zero to the end, never from where a window happens to be
// looking: a transcript that starts mid-stream is a replay window, not a
// record, and the whole point of an export is that somebody can be shown
// it later and believe it.
//
// The reader is chosen from the recording's mode. The two formats are
// not distinguishable from their bytes -- ParseExec says at length what
// happens when the wrong one is used, and the short version is a blank
// page and no error.
func exportOneTranscript(
	ctx context.Context,
	fetch func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error),
	ref RecordingRef,
) (string, error) {
	vt := record.NewVT(200, 50)
	var remainder []byte
	var offset int64
	part := ref.Part()
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		chunk, next, total, err := fetch(ctx, ref.ID, part, offset)
		if err != nil {
			return "", err
		}
		if len(chunk) > 0 {
			if ref.Mode == "exec" {
				remainder = record.ParseExec(chunk, remainder, vt)
			} else {
				remainder = record.ParseCast(chunk, remainder, vt)
			}
		}
		// No progress and no more to come: done. The two conditions are
		// separate because a gateway that answers an empty chunk while
		// claiming there is more left would otherwise be a loop.
		if next <= offset || next >= total {
			break
		}
		offset = next
	}
	text := strings.TrimRight(vt.Transcript(), " \n")
	if text == "" {
		return "(the recording is there but holds nothing — the session ended before anything was written)", nil
	}
	return text, nil
}
