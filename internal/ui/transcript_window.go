//go:build windows || linux || darwin

package ui

// The transcript in a window of its own (IAMT-366).
//
// Asked for by the maintainer on 19.09.2026, watching a live session in
// the Admin tab: having it appear right in this window is very
// inconvenient, so add a button that shows it in a separate window,
// resizable and able to go full screen.
//
// They are describing the difference between a STATUS and a VIEW. A panel
// on a tab answers "is anything happening"; reading what somebody is
// actually doing on your machine is the other kind of thing entirely --
// it wants the whole screen, it wants to stay open while you look
// elsewhere, and it is the only part of this product a person watches
// rather than operates.
//
// So the panel keeps a short, scrolling excerpt, and a button opens this:
// a second window, resizable and maximisable like any other, that
// follows the session by itself.
//
// It polls rather than sharing the Frame's watch state. Sharing would
// tie the window's life to whatever the tab is doing -- close the panel
// and the window goes blind -- and the two are meant to be independent:
// that independence is the whole request.

import (
	"context"
	"image"
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
	"gioui.org/widget/material"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// transcriptPollInterval is how often a window following a LIVE session
// asks for more. The console watcher uses the same rhythm: fast enough
// that a person reading over somebody's shoulder sees the shoulder move,
// slow enough that an hour-long session is not a thousand dials.
const transcriptPollInterval = time.Second

// openTranscriptWindow opens a second window following one session.
//
// Nothing is returned and nothing is awaited: the window owns its own
// goroutine, its own emulator and its own polling, and the tab that
// opened it may be closed, switched away from or pointed at another
// session without touching it.
func (f *Frame) openTranscriptWindow(id, person, machine string) {
	ask := f.cfg.Actions.AdminSessionTail
	if ask == nil {
		f.say(ctlAdminLive, noRuntime, design.BadKey)
		return
	}
	f.startTranscriptWindow(liveTranscriptFeed(ask, id), id, person, machine)
}

// startTranscriptWindow is the half both openers share: the test guard
// and the window's own theme.
func (f *Frame) startTranscriptWindow(feed transcriptFeed, id, person, machine string) {
	// The same guard Run carries: this opens a REAL operating-system
	// window, and a test that reached it would not fail -- it would
	// hang the package's whole test run behind a window nobody sees.
	if testing.Testing() {
		panic("ui: openTranscriptWindow invoked in test binary; tests must never open a real window")
	}
	// Its OWN theme, because it draws on its own goroutine and a
	// text shaper is not safe for two (frame.go, windowTheme).
	go runTranscriptWindow(f.windowTheme(), feed, id, person, machine)
}

// transcriptFeed is where one window's bytes come from.
//
// There are two sources and they are not interchangeable. A LIVE session
// is followed through sessions.tail, which reads the in-memory registry
// of recordings currently being written; a FINISHED one is read through
// recordings.fetch, off the disk. The gateway drops a session from the
// live registry a few seconds after it ends, so sessions.tail answers a
// history row with a truthful, useless emptiness -- and that is exactly
// what the maintainer met on 22.09.2026: a session that had just finished, a
// Transcript button, and an empty window. The window had one feed, and
// it was the wrong one for the button History put it behind.
type transcriptFeed func(ctx context.Context, offset int64) (transcriptChunk, error)

// transcriptChunk is one answer from a feed.
type transcriptChunk struct {
	Data  []byte
	Next  int64
	Total int64

	// Live is whether more is still being written. A finished recording
	// says false on the first answer, which is what stops the polling.
	Live bool

	// Exec picks the reader. The two recording formats look enough alike
	// -- lines of JSON in a file named after a session -- that the wrong
	// reader returns no error and no text (record.ParseExec says why).
	// So the feed, which knows the recording's metadata, decides; the
	// window never guesses from the bytes.
	Exec bool

	// Note replaces the window's own status line when it is not empty.
	// A recording that was pruned needs a sentence of its own: the row
	// in History outlives the bytes, and "0 of 0" is not an answer.
	Note string
}

// liveTranscriptFeed follows a session that is still running. The
// gateway names the recording's format with every answer (IAMT-453): a
// live exec session is an exec recording, not a cast.
func liveTranscriptFeed(ask func(ctx context.Context, id string, offset int64) ([]byte, int64, int64, bool, string, error), id string) transcriptFeed {
	return func(ctx context.Context, offset int64) (transcriptChunk, error) {
		chunk, next, total, live, mode, err := ask(ctx, id, offset)
		if err != nil {
			return transcriptChunk{}, err
		}
		return transcriptChunk{Data: chunk, Next: next, Total: total, Live: live, Exec: mode == record.LiveModeExec}, nil
	}
}

// transcriptWindow is one such window's whole state.
type transcriptWindow struct {
	id      string
	heading string

	mu        sync.Mutex
	vt        *record.VT
	remainder []byte
	offset    int64
	total     int64
	live      bool
	note      string
	noteKey   design.ColorKey

	// noteSel is the text-selection state of the note line. It must
	// outlive the window that draws it for the same reason a
	// scrollbar's drag must: a selection rebuilt every frame would be
	// lost the instant the mouse moved — every Said in the
	// window is selectable, including the only error line that wasn't.
	noteSel *widget.Selectable
}

func runTranscriptWindow(
	theme *design.Theme,
	feed transcriptFeed,
	id, person, machine string,
) {
	// This window dies alone if it dies at all (IAMT-367). Its panic is
	// written down with its stack, and the process -- which holds the
	// controls that stop a live session -- keeps standing.
	defer guardWindow("transcript window", nil)

	tw := &transcriptWindow{
		id:      id,
		heading: orDash(person) + " → " + orDash(machine) + "  ·  " + id,
		vt:      record.NewVT(watchCols, watchRows),
		live:    true,
	}

	w := new(app.Window)
	w.Option(
		app.Title("iamtunnel — "+tw.heading),
		app.Size(unit.Dp(900), unit.Dp(620)),
	)

	// Centred by GIO, before the window is shown.
	//
	// This used to be a SetWindowPos of my own on the first view event,
	// and the maintainer watched the result: it first pops up on the
	// left and then moves to the centre. That is right, and the cause is in gio's
	// own order of operations -- os_windows.go configures and SHOWS the
	// window, and only then hands over the handle in a Win32ViewEvent.
	// Anything done from that event is by definition a move of a window
	// that is already on the screen.
	//
	// gio has system.ActionCenter for exactly this, and it computes the
	// same thing (the work area of the window's own monitor, so the
	// taskbar is not counted as room and a second screen is respected).
	// Performed before the first Event, it is queued as an initial action
	// and applied inside Configure -- the SetWindowPos that runs BEFORE
	// ShowWindow. No jump, no syscalls here, and no chance of the
	// deadlock the hand-rolled version had.
	w.Perform(system.ActionCenter)

	done := make(chan struct{})
	// The reader. It stops when the window is gone OR when the session
	// has ended and everything written before the end has been drained:
	// polling a finished recording forever would be a dial a second for
	// as long as somebody leaves the window open.
	//
	// The first fetch opens at the END of the recording, not the
	// beginning: a session that has been running for hours before
	// somebody opened the window is watched live, not from byte 0.
	// The probe asks for one byte to learn `total`.
	//
	// The exit condition uses stillLive (the state AFTER this fetch),
	// not the pre-fetch `live`: a session that ends in this fetch must
	// not trigger one more poll just to discover what this fetch
	// already knew (avoiding two more ticks after the end of the session).
	go func() {
		// This goroutine feeds the emulator bytes a machine chose, and it
		// was the one goroutine of this window with no guard: a fault in
		// the emulator took the whole process down, the controls that stop
		// a live session with it (IAMT-441). Now the reading stops and the
		// window says so.
		defer guardWindow("transcript poller", func(string) {
			tw.mu.Lock()
			tw.note, tw.noteKey = "The transcript stops here: the rest of this recording could not be drawn.", design.BadKey
			tw.mu.Unlock()
			w.Invalidate()
		})
		probe, err := feed(context.Background(), 0)
		if err == nil {
			tw.mu.Lock()
			// A finished recording is read from the START: the person
			// opened it to read the whole visit, and it is not growing
			// under them. Only a live session, which may have been
			// running for hours before anybody looked, opens at the end.
			if probe.Live && probe.Total > tailChunkLimit && tw.offset == 0 {
				tw.offset = probe.Total - tailChunkLimit
			}
			tw.total = probe.Total
			tw.mu.Unlock()
		}
		for {
			select {
			case <-done:
				return
			default:
			}
			tw.mu.Lock()
			offset := tw.offset
			tw.mu.Unlock()

			c, err := feed(context.Background(), offset)
			stillLive := c.Live
			caughtUp := tw.take(c, err)
			w.Invalidate()

			if err == nil && !stillLive && caughtUp {
				return
			}
			select {
			case <-done:
				return
			case <-time.After(transcriptPollInterval):
			}
		}
	}()

	var ops op.Ops
	var list widget.List
	list.Axis = layout.Vertical
	list.ScrollToEnd = true
	var sel widget.Selectable
	for {
		switch e := w.Event().(type) {
		case app.DestroyEvent:
			close(done)
			return
		case app.ViewEvent:
			applyTitleBarTheme(viewHandle(e), theme.IsDark())
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			tw.layout(gtx, theme, &list, &sel)
			e.Frame(gtx.Ops)
		}
	}
}

// take folds one answer from the feed into the window's state and says
// whether everything there is has now been read.
//
// The lock is released by defer and not by a last line: the emulator fed
// here parses a stranger's output, and if it ever panics the poller's
// guard survives that - a lock left held would freeze the window's next
// frame for good instead (IAMT-441).
func (tw *transcriptWindow) take(c transcriptChunk, err error) (caughtUp bool) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	switch {
	case err != nil:
		tw.note, tw.noteKey = err.Error(), design.BadKey
	default:
		if len(c.Data) > 0 {
			if c.Exec {
				tw.remainder = record.ParseExec(c.Data, tw.remainder, tw.vt)
			} else {
				tw.remainder = record.ParseCast(c.Data, tw.remainder, tw.vt)
			}
		}
		tw.offset, tw.total, tw.live = c.Next, c.Total, c.Live
		switch {
		case c.Note != "":
			tw.note, tw.noteKey = c.Note, design.MutedKey
		case c.Live:
			tw.note, tw.noteKey = "", design.MutedKey
		default:
			tw.note, tw.noteKey = "This session has ended — what is shown is all of it.", design.MutedKey
		}
	}
	return tw.offset >= tw.total
}

func (tw *transcriptWindow) layout(gtx layout.Context, th *design.Theme, list *widget.List, sel *widget.Selectable) layout.Dimensions {
	tw.mu.Lock()
	text := strings.TrimRight(tw.vt.Transcript(), " \n")
	offset, total, live := tw.offset, tw.total, tw.live
	note, noteKey := tw.note, tw.noteKey
	noteSel := tw.noteSel
	if noteSel == nil {
		noteSel = &widget.Selectable{}
		tw.noteSel = noteSel
	}
	tw.mu.Unlock()

	if text == "" {
		text = "(nothing yet)"
	}
	state := "ended"
	if live {
		state = "live"
	}

	// The page's own background, painted first: a window that inherited
	// whatever the compositor had would flash white on a dark desktop.
	paint.FillShape(gtx.Ops, th.Color(design.PageKey),
		clip.Rect(image.Rectangle{Max: gtx.Constraints.Max}).Op())
	return layout.Inset{
		Top: unit.Dp(design.Gap), Bottom: unit.Dp(design.Gap),
		Left: unit.Dp(design.Gap), Right: unit.Dp(design.Gap),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Heading(gtx, th, tw.heading+"  ·  "+state)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Hint(gtx, th,
					"read "+strconv.FormatInt(offset, 10)+" of "+strconv.FormatInt(total, 10)+" bytes")
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return design.Said(gtx, th, noteSel, note, noteKey)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(design.Tight)}.Layout),
			// The transcript takes everything left, and scrolls. This is
			// what the window is for.
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				return design.PageScrollbar(th, list).Layout(gtx, 1, func(gtx layout.Context, _ int) layout.Dimensions {
					// The same gutter the pages keep: the bar has its own
					// strip, and a transcript flush against that strip
					// reads as clipped rather than as ended.
					return layout.Inset{Right: unit.Dp(design.Gap)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return transcriptLabel(gtx, th, text, sel)
					})
				})
			}),
		)
	})
}

// transcriptLabel draws the transcript text itself.
func transcriptLabel(gtx layout.Context, th *design.Theme, text string, sel *widget.Selectable) layout.Dimensions {
	lbl := material.Label(th.Material, design.SmallSp, text)
	lbl.Color = th.Color(design.InkKey)
	lbl.Font = th.MonoFont
	lbl.SelectionColor = th.Color(design.SpotDimKey)
	lbl.State = sel
	return lbl.Layout(gtx)
}
