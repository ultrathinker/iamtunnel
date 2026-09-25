//go:build windows || linux || darwin

package design

// The selection-state registry (IAMT-335).
//
// Said and CopyableBox carry selection states their CALLERS own (the
// Frame keeps one per named control, IAMT-355). The plain typography
// pieces — Words and everything drawn through it — have no caller to
// take a state from: they are package functions called from over a
// hundred places, and threading a *widget.Selectable through all of
// them would change every one of those call sites to keep a property
// the piece itself can own.
//
// So the design package owns the states, keyed by everything that
// shapes one drawn label — its text, size, color key and font. The key
// makes two different labels two different states; the same caption
// drawn again (next frame, after a tab switch, after a theme change —
// none of which touch the key) finds the state it had, and a selection
// made on it survives the redraw.
//
// The registry is bounded: texts that stop being drawn (a countdown
// line, a row that left a list) give their entry up once newer texts
// have filled the table, roughly the least-recently-seen first. A
// person mid-drag on a label that is ON SCREEN refreshes the entry
// every frame, so eviction can only take text that has been off screen
// for a long time. Selectable itself clamps offsets to the text it is
// given, so even a stale entry cannot select beyond what is drawn.
//
// One table serves every window of the process. Two windows drawing the
// same shaped text share one state: a selection made on one would show
// on the other's identical string. That is a cosmetic overlap on a
// string that is already identical, bought instead of a per-window
// identity the design package has no way to learn.

import (
	"sync"
	"time"

	giofont "gioui.org/font"
	"gioui.org/unit"
	"gioui.org/widget"
)

// textKey identifies one drawn label by everything that shapes it.
type textKey struct {
	txt  string
	size unit.Sp
	key  ColorKey
	font giofont.Font
}

// selectionStatesMax bounds the table. A real window draws far fewer
// distinct shaped texts than this; the bound exists so a pathological
// feed of ever-changing labels cannot grow the table without end.
const selectionStatesMax = 512

var (
	selectionMu     sync.Mutex
	selectionStates = map[textKey]selectionEntry{}
)

type selectionEntry struct {
	sel      *widget.Selectable
	lastSeen time.Time
}

// selectableFor returns the selection state of the label that draws
// this key's text, creating it on first sight — the same discipline
// Frame.btn and Frame.sel use for the controls they keep.
func selectableFor(key textKey) *widget.Selectable {
	selectionMu.Lock()
	defer selectionMu.Unlock()
	if e, ok := selectionStates[key]; ok {
		e.lastSeen = time.Now()
		selectionStates[key] = e
		return e.sel
	}
	if len(selectionStates) >= selectionStatesMax {
		oldestKey, oldestSeen := textKey{}, time.Time{}
		found := false
		for k, e := range selectionStates {
			if !found || e.lastSeen.Before(oldestSeen) {
				oldestKey, oldestSeen, found = k, e.lastSeen, true
			}
		}
		if found {
			delete(selectionStates, oldestKey)
		}
	}
	s := &widget.Selectable{}
	selectionStates[key] = selectionEntry{sel: s, lastSeen: time.Now()}
	return s
}
