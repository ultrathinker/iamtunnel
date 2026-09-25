package record

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

type parserState int

const (
	stateGround parserState = iota
	stateEscape
	stateCSI
	stateCSIIgnore
	stateOSC
	stateOSCIgnore
	stateCharset
)

const (
	defaultCols     = 80
	defaultRows     = 24
	maxSeqBuf       = 512
	maxHistoryLines = 10000
)

// MaxCols and MaxRows bound the screen the emulator holds (IAMT-442).
//
// A screen is allocated whole, rows*cols cells of a rune and an Attr
// each, and its size comes from the far end of a connection: a pty-req
// or window-change the gateway relays, or a .cast the window reads back.
// Unbounded, one pty-req of 4294967295x4294967295 asked the gateway for
// more memory than exists, and a Go process that cannot allocate is
// ended outright - no recover, every session with it. At the bound a
// screen is about 8.5 MB.
//
// The gateway clamps a request where it parses it, so that the machine
// gets the same size the recording parses in (fixPTYSize, human_role.go);
// the bound here holds for every other way a size can arrive.
const (
	MaxCols = 1000
	MaxRows = 500
)

// boundSize is the screen size the emulator uses for a requested one: a
// dimension that is not positive is the default, one past the bound is
// the bound.
func boundSize(cols, rows int) (int, int) {
	if cols <= 0 {
		cols = defaultCols
	}
	if rows <= 0 {
		rows = defaultRows
	}
	return min(cols, MaxCols), min(rows, MaxRows)
}

// ColorKind tells what the rest of a Color value means. Only one of the
// three coloured kinds carries data; the fourth, ColorDefault, means
// "follow the terminal's default foreground/background" and is what an
// unset / reset SGR produces.
type ColorKind uint8

const (
	// ColorDefault is the unset state: no FG/BG override. Cells rendered
	// this way use whatever the host terminal (or theme) chooses for
	// "no SGR" — i.e. plain text.
	ColorDefault ColorKind = iota
	// ColorNamed is one of the 16 ANSI colours: 0..7 are the basic set,
	// 8..15 are the bright variants (the 90–97 / 100–107 SGR range).
	// Index carries the colour number; R/G/B are unused.
	ColorNamed
	// Color256 is an index into the 256-colour xterm palette
	// (SGR 38/48 ; 5 ; n). Index carries the palette entry; R/G/B unused.
	Color256
	// ColorRGB is a 24-bit colour (SGR 38/48 ; 2 ; r ; g ; b). R/G/B
	// carry the channels; Index is unused.
	ColorRGB
)

// Color is one half of a cell's appearance: the FG or BG override that
// was in effect when the cell was written. The zero value is a default
// colour (ColorDefault / Index 0 / 0,0,0) — that is also what every cell
// holds before any SGR has touched its row.
type Color struct {
	Kind    ColorKind
	Index   uint8
	R, G, B uint8
}

// Attr is the SGR state in effect when a cell was written: FG and BG
// overrides plus three style bits (bold / underline / reverse). It is a
// value type on purpose — every cell holds a copy, and Screen()/History()
// copy it again into the per-line Attrs slice, so the parser never has
// to worry about aliasing.
type Attr struct {
	FG, BG    Color
	Bold      bool
	Underline bool
	Reverse   bool
}

// Line is one rendered line: the visible text and, per rune, the
// attribute that was in effect when that rune was written. Attrs may be
// shorter than Text in runes — any missing entry means "default
// attribute" (see applySGR's reset path and the erase paths, which all
// blank both the cell and its attribute). This keeps memory flat for
// the common all-default case: an SGR-free row uses 0 attribute bytes.
type Line struct {
	Text  string
	Attrs []Attr
}

// VT represents a virtual terminal screen matrix and escape sequence interpreter.
// It tracks cursor position, screen cells, scrollback history, and parses ANSI/VT
// escape codes into human-readable text.
type VT struct {
	mu sync.RWMutex

	cols int
	rows int

	cursorX int
	cursorY int

	savedX int
	savedY int

	screen     [][]rune
	screenAttr [][]Attr // per-cell SGR state, parallel to screen (rows×cols)
	history    []string
	// head is the first maxHistoryLines lines the session ever put into
	// history, kept when the ring below drops them (R4 F-05): the start of
	// a session is what an audit reads first, and one long listing used to
	// push it out of the transcript. Strings only - the transcript is text.
	head []string
	// historyAttr[i] holds the per-rune attributes of history[i]; nil if
	// the line never had a non-default attribute (the common case).
	historyAttr [][]Attr

	droppedHistoryLines int64

	state   parserState
	seqBuf  []byte
	oscTerm bool

	// curAttr is the SGR state assembled so far — every printable rune
	// written from this point on carries a copy of it. It lives outside
	// the screen/history bookkeeping on purpose: changing it must not
	// rewrite any cell already on screen, only ones written next.
	curAttr Attr

	wrapPending bool // Deferred wrap flag for ECMA-48/xterm autowrap

	// pendingRow/pendingText hold the content of a whole-row erase (EL)
	// awaiting resolution - SPEC 6.5 round 4. Content lands here instead
	// of history immediately: whether it belongs in the transcript depends
	// on what happens next (see resolvePendings doc comment), which is not
	// known at the moment of the erase itself. At most one row can be
	// pending at a time: every way the cursor leaves a row goes through
	// advanceLine or moveCursorY, and both resolve the row being left
	// before the cursor lands anywhere else. pendingRow is -1 when idle.
	pendingRow      int
	pendingText     string
	pendingTextAttr []Attr // parallel to pendingText's runes; nil when the row had no colour

	// committedRows counts the leading screen rows whose content has
	// already been written to history by commitPrefix - they are blank
	// because they were logged, not because nothing was ever shown there,
	// so Transcript renders the live tail starting at committedRows rather
	// than printing them a second time as empty lines. Commits always run
	// from the top of the screen down (see commitPrefix), so the logged
	// region is always a prefix and a single count describes it exactly;
	// that is also why a shift of the screen only has to add to or subtract
	// from this one number instead of moving a per-row flag array.
	committedRows int

	pendingBytes []byte
}

// NewVT creates a new VT emulator with specified dimensions.
func NewVT(cols, rows int) *VT {
	cols, rows = boundSize(cols, rows)

	vt := &VT{
		cols: cols,
		rows: rows,
	}
	vt.initScreen()
	return vt
}

// Reset clears all VT state and re-initializes the emulator at the given
// dimensions. Use it to replay a byte range from scratch — the live-session
// tab does this when the user scrolls backward: prepend older bytes to the
// held range and rebuild the emulator by playing the whole range in order,
// because a terminal is a sequential state machine and feeding bytes out of
// order silently corrupts the cursor, the screen, and the parser state.
//
// The held range the caller replays here almost never starts at byte 0 of
// the .cast (the initial tail fetch lands mid-recording), so the rebuilt
// emulator has no knowledge of state that existed before the replay
// window: cursor position, SGR, scrollback and the last clear. The first
// screens the viewer shows after this are therefore approximate until the
// caller extends the replay window back to byte 0. This is a fact of
// mid-stream replay, not a bug in Reset itself; the live-session code is
// expected to say so in its own comments.
func (v *VT) Reset(cols, rows int) {
	v.mu.Lock()
	defer v.mu.Unlock()

	cols, rows = boundSize(cols, rows)

	v.cols = cols
	v.rows = rows
	v.cursorX = 0
	v.cursorY = 0
	v.savedX = 0
	v.savedY = 0
	v.screen = nil
	v.screenAttr = nil
	v.history = nil
	v.historyAttr = nil
	v.head = nil
	v.droppedHistoryLines = 0
	v.state = stateGround
	v.seqBuf = nil
	v.oscTerm = false
	v.curAttr = Attr{}
	v.wrapPending = false
	v.pendingRow = -1
	v.pendingText = ""
	v.pendingTextAttr = nil
	v.pendingBytes = nil
	v.committedRows = 0

	v.initScreen()
}

func (v *VT) initScreen() {
	v.screen = make([][]rune, v.rows)
	v.screenAttr = make([][]Attr, v.rows)
	for r := 0; r < v.rows; r++ {
		row := make([]rune, v.cols)
		attr := make([]Attr, v.cols)
		for c := 0; c < v.cols; c++ {
			row[c] = ' '
		}
		v.screen[r] = row
		v.screenAttr[r] = attr
	}
	v.history = nil
	v.historyAttr = nil
	v.curAttr = Attr{}
	v.pendingRow = -1
	v.committedRows = 0
}

// Write processes a byte chunk through the VT interpreter.
func (v *VT) Write(p []byte) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	var data []byte
	if len(v.pendingBytes) > 0 {
		data = make([]byte, len(v.pendingBytes)+len(p))
		copy(data, v.pendingBytes)
		copy(data[len(v.pendingBytes):], p)
		v.pendingBytes = nil
	} else {
		data = p
	}

	nConsumed := len(p)
	i := 0
	dataLen := len(data)

	for i < dataLen {
		if !utf8.FullRune(data[i:]) {
			// Incomplete UTF-8 rune at the end of chunk.
			// Preserve remaining bytes for next Write.
			v.pendingBytes = make([]byte, dataLen-i)
			copy(v.pendingBytes, data[i:])
			break
		}

		r, size := utf8.DecodeRune(data[i:])
		i += size

		v.processRune(r)
	}

	return nConsumed, nil
}

func (v *VT) processRune(r rune) {
	switch v.state {
	case stateGround:
		v.handleGround(r)
	case stateEscape:
		v.handleEscape(r)
	case stateCSI:
		v.handleCSI(r)
	case stateCSIIgnore:
		v.handleCSIIgnore(r)
	case stateOSC:
		v.handleOSC(r)
	case stateOSCIgnore:
		v.handleOSCIgnore(r)
	case stateCharset:
		// Charset selection (e.g., ESC ( B) - consume 1 char and return to ground
		v.state = stateGround
	}
}

// runeWidth returns 2 for East Asian Wide/Fullwidth characters, and 1 for others.
func runeWidth(r rune) int {
	if r < 0x1100 {
		return 1
	}
	if (r >= 0x1100 && r <= 0x115F) || // Hangul Jamo
		r == 0x2329 || r == 0x232A ||
		(r >= 0x2E80 && r <= 0x303E) || // CJK Radicals, Kangxi, CJK symbols
		(r >= 0x3040 && r <= 0x309F) || // Hiragana
		(r >= 0x30A0 && r <= 0x30FF) || // Katakana
		(r >= 0x3100 && r <= 0x312F) || // Bopomofo
		(r >= 0x3130 && r <= 0x318F) || // Hangul Compatibility Jamo
		(r >= 0x3200 && r <= 0x32FF) || // Enclosed CJK Letters and Months
		(r >= 0x3400 && r <= 0x4DBF) || // CJK Unified Ideographs Extension A
		(r >= 0x4E00 && r <= 0x9FFF) || // CJK Unified Ideographs
		(r >= 0xAC00 && r <= 0xD7A3) || // Hangul Syllables
		(r >= 0xF900 && r <= 0xFAFF) || // CJK Compatibility Ideographs
		(r >= 0xFE10 && r <= 0xFE19) || // Vertical forms
		(r >= 0xFE30 && r <= 0xFE6F) || // CJK Compatibility Forms
		(r >= 0xFF01 && r <= 0xFF60) || // Fullwidth Forms
		(r >= 0xFFE0 && r <= 0xFFE6) ||
		(r >= 0x20000 && r <= 0x2FFFD) ||
		(r >= 0x30000 && r <= 0x3FFFD) {
		return 2
	}
	return 1
}

func (v *VT) handleGround(r rune) {
	switch r {
	case 0x1B: // ESC
		v.state = stateEscape
		v.seqBuf = v.seqBuf[:0]
		// wrapPending is NOT cleared just for entering an escape sequence -
		// see handleEscape's comment. A pending wrap at the right margin
		// must survive a following SGR/OSC/mode-set (e.g. the colour reset
		// PSReadLine emits right at column 80) and only be resolved by an
		// actual cursor move or by the next printed character.
	case '\r':
		v.cursorX = 0
		v.wrapPending = false
	case '\n':
		v.cursorX = 0
		v.advanceLine()
		v.wrapPending = false
	case '\b': // Backspace (rubout) - non-destructive cursor left motion
		if v.cursorX > 0 {
			v.cursorX--
		}
		v.wrapPending = false
	case '\t': // Tab
		v.wrapPending = false
		nextTab := (v.cursorX/8 + 1) * 8
		if nextTab >= v.cols {
			v.cursorX = 0
			v.advanceLine()
		} else {
			for c := v.cursorX; c < nextTab; c++ {
				v.screen[v.cursorY][c] = ' '
				v.screenAttr[v.cursorY][c] = Attr{}
			}
			v.cursorX = nextTab
		}
	case 0x07: // Bell - ignore
	case 0x00: // NUL - ignore
	case 0x7F: // DEL - ignore
	default:
		// Ignore non-printable control characters below 0x20
		if r < 0x20 {
			return
		}

		w := runeWidth(r)

		// If autowrap was deferred from previous right-margin character, wrap now
		if v.wrapPending {
			v.cursorX = 0
			v.advanceLine()
			v.wrapPending = false
		}

		// Double-width character at last column cannot fit; wrap before drawing
		if w == 2 && v.cursorX >= v.cols-1 {
			if v.cursorY < v.rows && v.cursorX < v.cols {
				v.beforeWriteToRow(v.cursorY)
				v.screen[v.cursorY][v.cursorX] = ' '
				v.screenAttr[v.cursorY][v.cursorX] = Attr{}
			}
			v.cursorX = 0
			v.advanceLine()
			v.wrapPending = false
		}

		if v.cursorY < v.rows && v.cursorX < v.cols {
			// SPEC §6.5 round 4: printing into a row that has a whole-row
			// erase awaiting resolution means that erase was a same-row
			// redraw (progress bar, PSReadLine), not a real "shown then
			// cleared" - discard rather than commit it.
			v.beforeWriteToRow(v.cursorY)
			v.screen[v.cursorY][v.cursorX] = r
			v.screenAttr[v.cursorY][v.cursorX] = v.curAttr
			if w == 2 && v.cursorX+1 < v.cols {
				v.screen[v.cursorY][v.cursorX+1] = 0 // trailing half-cell marker
				v.screenAttr[v.cursorY][v.cursorX+1] = v.curAttr
			}
		}

		if w == 2 {
			if v.cursorX+2 >= v.cols {
				v.cursorX = v.cols - 1
				v.wrapPending = true
			} else {
				v.cursorX += 2
				v.wrapPending = false
			}
		} else {
			if v.cursorX >= v.cols-1 {
				v.cursorX = v.cols - 1
				v.wrapPending = true
			} else {
				v.cursorX++
				v.wrapPending = false
			}
		}
	}
}

func (v *VT) handleEscape(r rune) {
	// wrapPending ("we are sitting past the last column, the next printable
	// character wraps first") is deliberately NOT cleared just for entering
	// an escape sequence: a real terminal keeps it pending across SGR and
	// other non-repositioning sequences, and only drops it on an actual
	// cursor move or on printing the next character (handleGround does that
	// itself). Only the cases below that truly reposition the cursor clear
	// it explicitly.
	switch r {
	case '[':
		v.state = stateCSI
		v.seqBuf = v.seqBuf[:0]
	case ']':
		v.state = stateOSC
		v.seqBuf = v.seqBuf[:0]
	case '(', ')', '*', '+':
		v.state = stateCharset
	case '7', 's': // Save cursor
		v.savedX = v.cursorX
		v.savedY = v.cursorY
		v.state = stateGround
	case '8', 'u': // Restore cursor
		v.cursorX = clamp(v.savedX, 0, v.cols-1)
		v.moveCursorY(clamp(v.savedY, 0, v.rows-1))
		v.wrapPending = false
		v.state = stateGround
	case 'M': // Reverse Index (scroll down if at top)
		if v.cursorY > 0 {
			v.moveCursorY(v.cursorY - 1)
		} else {
			v.scrollDown(1) // resolves pending itself (see its own call)
		}
		v.wrapPending = false
		v.state = stateGround
	case 'c': // RIS - Reset to Initial State: full clear, cursor home.
		// SPEC §6.5 (round 3): preserve exactly like ED 2/3 before wiping;
		// round 4: settle any unresolved EL pending first (same reasoning
		// as ED's own resolvePending call).
		v.resolvePending()
		v.pushRowsToHistory(v.rows - 1)
		for r := 0; r < v.rows; r++ {
			for c := 0; c < v.cols; c++ {
				v.screen[r][c] = ' '
				v.screenAttr[r][c] = Attr{}
			}
		}
		v.cursorX, v.cursorY = 0, 0
		v.savedX, v.savedY = 0, 0
		v.wrapPending = false
		v.curAttr = Attr{}
		v.state = stateGround
	case '=', '>': // Alternate / numeric keypad mode
		v.state = stateGround
	case 0x1B: // Double ESC, remain in escape state
		v.seqBuf = v.seqBuf[:0]
	case 0x7F: // DEL - ignore
		// stay in escape
	default:
		// Unknown escape code, return to ground
		v.state = stateGround
	}
}

func (v *VT) handleCSI(r rune) {

	if r == 0x1B {
		v.state = stateEscape
		v.seqBuf = v.seqBuf[:0]
		return
	}

	if r == 0x7F {
		return
	}

	// If sequence buffer gets too large (garbage protection), enter ignore state
	if len(v.seqBuf) >= maxSeqBuf {
		v.state = stateCSIIgnore
		return
	}

	// CSI parameter (0x30–0x3F) and intermediate (0x20–0x2F) bytes
	if (r >= 0x30 && r <= 0x3F) || (r >= 0x20 && r <= 0x2F) {
		v.seqBuf = append(v.seqBuf, byte(r))
		return
	}

	// Final command byte: 0x40–0x7E
	if r >= 0x40 && r <= 0x7E {
		v.executeCSI(r)
		v.state = stateGround
		v.seqBuf = v.seqBuf[:0]
		return
	}

	// Invalid byte in CSI - transition to ignore state until final byte
	v.state = stateCSIIgnore
}

func (v *VT) handleCSIIgnore(r rune) {
	if r == 0x1B {
		v.state = stateEscape
		v.seqBuf = v.seqBuf[:0]
		return
	}
	if r >= 0x40 && r <= 0x7E {
		v.state = stateGround
		v.seqBuf = v.seqBuf[:0]
		return
	}
}

func (v *VT) executeCSI(cmd rune) {
	// See handleEscape's comment: wrapPending is cleared here only for the
	// commands that actually reposition the cursor, not for every CSI
	// (SGR/mode-set/erase land here too and must leave it alone).
	switch cmd {
	case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'f', 'd', 'u':
		v.wrapPending = false
	}

	s := string(v.seqBuf)
	isPrivate := strings.HasPrefix(s, "?")
	if isPrivate {
		s = s[1:]
	}

	params := parseParams(s)

	// Every parameter below is a number the machine chose, anywhere in
	// the int range. A coordinate is combined with one only through
	// addSat and then clamped onto the screen, never with a bare + or -:
	// that is what keeps 0 <= cursorX < cols and 0 <= cursorY < rows
	// (IAMT-441, see addSat).
	switch cmd {
	case 'A': // Cursor Up
		n := paramDefault(params, 0, 1)
		if n < 0 {
			n = 1
		}
		v.moveCursorY(clamp(addSat(v.cursorY, -n), 0, v.rows-1))
	case 'B': // Cursor Down
		n := paramDefault(params, 0, 1)
		if n < 0 {
			n = 1
		}
		v.moveCursorY(clamp(addSat(v.cursorY, n), 0, v.rows-1))
	case 'C': // Cursor Forward (Right)
		n := paramDefault(params, 0, 1)
		if n < 0 {
			n = 1
		}
		v.cursorX = clamp(addSat(v.cursorX, n), 0, v.cols-1)
	case 'D': // Cursor Backward (Left)
		n := paramDefault(params, 0, 1)
		if n < 0 {
			n = 1
		}
		v.cursorX = clamp(addSat(v.cursorX, -n), 0, v.cols-1)
	case 'E': // Cursor Next Line
		n := paramDefault(params, 0, 1)
		if n < 0 {
			n = 1
		}
		v.moveCursorY(clamp(addSat(v.cursorY, n), 0, v.rows-1))
		v.cursorX = 0
	case 'F': // Cursor Previous Line
		n := paramDefault(params, 0, 1)
		if n < 0 {
			n = 1
		}
		v.moveCursorY(clamp(addSat(v.cursorY, -n), 0, v.rows-1))
		v.cursorX = 0
	case 'G': // Cursor Horizontal Absolute (1-based)
		col := paramDefault(params, 0, 1)
		v.cursorX = clamp(addSat(col, -1), 0, v.cols-1)
	case 'H', 'f': // Cursor Position (row, col - 1-based)
		row := paramDefault(params, 0, 1)
		col := paramDefault(params, 1, 1)
		v.moveCursorY(clamp(addSat(row, -1), 0, v.rows-1))
		v.cursorX = clamp(addSat(col, -1), 0, v.cols-1)
	case 'd': // Line Position Absolute (1-based)
		row := paramDefault(params, 0, 1)
		v.moveCursorY(clamp(addSat(row, -1), 0, v.rows-1))
	case 'J': // Erase in Display
		// An unresolved EL pending erase elsewhere on screen (round 4) must
		// settle - in order - before this clear does its own sweep, or its
		// row would read as plain blank and the pending content would leak
		// through unresolved, surfacing later out of order.
		v.resolvePending()
		mode := paramDefault(params, 0, 0)
		switch mode {
		case 0: // Clear from cursor to end of screen
			// SPEC §6.5 (round 3, IAMT-215): a clear must not delete
			// already-shown text from the transcript. Everything the screen
			// is showing down to the last non-blank row is preserved before
			// the blanking below, exactly as scrollUp would preserve it.
			v.pushRowsToHistory(v.rows - 1)
			for c := v.cursorX; c < v.cols; c++ {
				v.screen[v.cursorY][c] = ' '
				v.screenAttr[v.cursorY][c] = Attr{}
			}
			for r := v.cursorY + 1; r < v.rows; r++ {
				for c := 0; c < v.cols; c++ {
					v.screen[r][c] = ' '
					v.screenAttr[r][c] = Attr{}
				}
			}
		case 1: // Clear from beginning of screen to cursor
			to := v.cursorY - 1
			if v.cursorX == v.cols-1 {
				to = v.cursorY
			}
			if to >= 0 {
				v.pushRowsToHistory(to)
			}
			for r := 0; r < v.cursorY; r++ {
				for c := 0; c < v.cols; c++ {
					v.screen[r][c] = ' '
					v.screenAttr[r][c] = Attr{}
				}
			}
			for c := 0; c <= v.cursorX && c < v.cols; c++ {
				v.screen[v.cursorY][c] = ' '
				v.screenAttr[v.cursorY][c] = Attr{}
			}
		case 2, 3: // Clear entire screen (mode 3 also erases xterm's own
			// scrollback - we have no separate buffer to purge there, and
			// wouldn't purge history even if we did: SPEC §6.5 requires the
			// transcript to keep everything it has already shown).
			v.pushRowsToHistory(v.rows - 1)
			for r := 0; r < v.rows; r++ {
				for c := 0; c < v.cols; c++ {
					v.screen[r][c] = ' '
					v.screenAttr[r][c] = Attr{}
				}
			}
		}
	case 'K': // Erase in Line
		mode := paramDefault(params, 0, 0)
		switch mode {
		case 0: // Clear from cursor to end of line
			// Only a whole-row erase (cursor already at column 0) is a
			// "clear" candidate at all per SPEC §6.5; a mid-line erase
			// starting past column 0 is PSReadLine redrawing the tail of
			// the line being edited - the row is not blank, it is the same
			// input line mid-edit, so it is never a candidate.
			// setPendingErase defers the decision (see its doc comment):
			// this whole-row erase is only really a "clear" if the row is
			// still blank once the cursor leaves it (resolvePending);
			// printing back into it first (beforeWriteToRow) means it
			// was a same-row redraw instead.
			if v.cursorX == 0 {
				v.setPendingErase(v.cursorY)
			} else {
				for c := v.cursorX; c < v.cols; c++ {
					v.screen[v.cursorY][c] = ' '
					v.screenAttr[v.cursorY][c] = Attr{}
				}
			}
		case 1: // Clear from start of line to cursor
			if v.cursorX >= v.cols-1 {
				v.setPendingErase(v.cursorY)
			} else {
				for c := 0; c <= v.cursorX && c < v.cols; c++ {
					v.screen[v.cursorY][c] = ' '
					v.screenAttr[v.cursorY][c] = Attr{}
				}
			}
		case 2: // Clear entire line - always whole-row, regardless of column.
			v.setPendingErase(v.cursorY)
		}
	case 'L': // Insert Line(s)
		n := paramDefault(params, 0, 1)
		v.insertLines(n)
	case 'M': // Delete Line(s)
		n := paramDefault(params, 0, 1)
		v.deleteLines(n)
	case 'P': // Delete Character(s)
		n := paramDefault(params, 0, 1)
		v.deleteChars(n)
	case '@': // Insert Character(s)
		n := paramDefault(params, 0, 1)
		v.insertChars(n)
	case 'X': // Erase Character(s)
		n := paramDefault(params, 0, 1)
		if v.cursorX < v.cols && n > 0 {
			end := min(v.cols, addSat(v.cursorX, n))
			for c := v.cursorX; c < end; c++ {
				v.screen[v.cursorY][c] = ' '
				v.screenAttr[v.cursorY][c] = Attr{}
			}
		}
	case 'S': // Scroll Up
		n := paramDefault(params, 0, 1)
		v.scrollUp(n)
	case 'T': // Scroll Down
		n := paramDefault(params, 0, 1)
		v.scrollDown(n)
	case 's': // Save cursor
		v.savedX = v.cursorX
		v.savedY = v.cursorY
	case 'u': // Restore cursor
		v.cursorX = clamp(v.savedX, 0, v.cols-1)
		v.cursorY = clamp(v.savedY, 0, v.rows-1)
	case 'm': // SGR (colors/styles) - applied to curAttr, never reaches Transcript()
		v.applySGR(params)
	case 'h', 'l': // Set/Reset Mode (e.g. cursor visibility, alt screen) - stripped
	}
}

func (v *VT) handleOSC(r rune) {
	// OSC (window title etc.) never repositions the cursor - wrapPending is
	// deliberately left untouched here (see handleEscape's comment).

	if r == 0x7F {
		return
	}

	if r == 0x07 { // BEL terminates OSC
		v.state = stateGround
		v.seqBuf = v.seqBuf[:0]
		return
	}

	if r == 0x1B { // ESC \ may terminate OSC
		v.oscTerm = true
		return
	}

	if v.oscTerm {
		v.oscTerm = false
		if r == '\\' {
			v.state = stateGround
			v.seqBuf = v.seqBuf[:0]
			return
		}
		v.state = stateEscape
		v.handleEscape(r)
		return
	}

	if len(v.seqBuf) >= maxSeqBuf {
		v.state = stateOSCIgnore
		return
	}

	v.seqBuf = append(v.seqBuf, byte(r))
}

func (v *VT) handleOSCIgnore(r rune) {
	if r == 0x07 { // BEL terminates OSC
		v.state = stateGround
		v.seqBuf = v.seqBuf[:0]
		return
	}
	if r == 0x1B {
		v.oscTerm = true
		return
	}
	if v.oscTerm {
		v.oscTerm = false
		if r == '\\' {
			v.state = stateGround
			v.seqBuf = v.seqBuf[:0]
			return
		}
		v.state = stateEscape
		v.handleEscape(r)
		return
	}
}

// appendHistoryLines appends lines (and their per-rune attributes) to
// history, in order, and applies the same maxHistoryLines eviction every
// caller needs (a natural scroll, a screen clear preserving what it
// erases, a resize reflowing overflow) - one place decides how the
// scrollback budget is spent instead of three copies of the same
// eviction arithmetic drifting apart.
//
// attrs[i] is parallel to lines[i]; a nil entry means "all-default
// attribute" (the common case, kept as a nil slice rather than a
// zero-length one so History() can return the same nil out the other
// end without ever allocating). The eviction is applied symmetrically:
// lines and attrs are sliced together, and historyAttr is rebuilt (or
// re-sliced) the same way history is - dropping a line must drop its
// attributes too, otherwise DroppedHistoryLines() would understate the
// memory really released.
func (v *VT) appendHistoryLines(lines []string, attrs [][]Attr) {
	if len(lines) == 0 {
		return
	}
	if room := maxHistoryLines - len(v.head); room > 0 {
		v.head = append(v.head, lines[:min(room, len(lines))]...)
	}
	v.history = append(v.history, lines...)
	v.historyAttr = append(v.historyAttr, attrs...)
	if len(v.history) > maxHistoryLines {
		overflow := len(v.history) - maxHistoryLines
		v.droppedHistoryLines += int64(overflow)
		if cap(v.history) > 2*maxHistoryLines {
			newHist := make([]string, maxHistoryLines)
			newAttr := make([][]Attr, maxHistoryLines)
			copy(newHist, v.history[overflow:])
			copy(newAttr, v.historyAttr[overflow:])
			v.history = newHist
			v.historyAttr = newAttr
		} else {
			v.history = v.history[overflow:]
			v.historyAttr = v.historyAttr[overflow:]
		}
	}
}

// commitPrefix writes screen rows [0, to] into history, in screen order,
// using `lastLine` in place of row `to`'s own cell content (resolvePending
// passes the text an erase already wiped off the row; the clear paths pass
// the row as it still reads). It then blanks the whole range and records
// it as logged in committedRows.
//
// When `lastAttr` is non-nil it carries the per-rune attributes of
// lastLine (only resolvePending goes down that path - the cell content
// it stands in for has already been blanked by setPendingErase).
// Otherwise the attributes are pulled live from screenAttr.
//
// Committing always starts at the top of the screen rather than at the
// erased row - SPEC §6.5 (round 5). Transcript prints history before the
// live screen tail, so any row above `to` that is still showing content
// would otherwise land in the transcript AFTER content that appeared
// later. Rounds 3-4 only swept upward while rows were non-blank, which
// reordered the transcript as soon as a blank separator line sat between
// two blocks of output ("A1\n\nB1" + erase of B1 printed B1 before A1) and
// dropped the separator as well. Taking the whole prefix keeps interior
// blank lines exactly where they were shown; only leading blank rows are
// dropped, which is what stops a clear that walks a mostly-empty screen
// (conhost's "cls") from flooding the transcript with empty lines.
func (v *VT) commitPrefix(to int, lastLine string, lastAttr []Attr) {
	first := 0
	for first < to && rowToString(v.screen[first]) == "" {
		first++
	}
	lines := make([]string, 0, to-first+1)
	attrs := make([][]Attr, 0, to-first+1)
	for r := first; r < to; r++ {
		lines = append(lines, rowToString(v.screen[r]))
		attrs = append(attrs, rowAttrSlice(v.screen[r], v.screenAttr[r], v.cols))
	}
	lines = append(lines, lastLine)
	attrs = append(attrs, lastAttr)
	v.appendHistoryLines(lines, attrs)
	for r := 0; r <= to; r++ {
		for c := 0; c < v.cols; c++ {
			v.screen[r][c] = ' '
			v.screenAttr[r][c] = Attr{}
		}
	}
	v.committedRows = to + 1
}

// pushRowsToHistory preserves everything the screen has shown down to row
// `to` before a clear blanks it - SPEC §6.5 (round 3, IAMT-215): content
// erased by ED 0/1/2/3 or ESC c must survive in the transcript exactly as
// content pushed off the top by a natural scroll already does. Rows below
// the last non-blank one are dropped, so a clear reaching into screen
// space that never held anything (again, "cls") contributes nothing.
func (v *VT) pushRowsToHistory(to int) {
	last := -1
	for r := to; r >= 0; r-- {
		if rowToString(v.screen[r]) != "" {
			last = r
			break
		}
	}
	if last < 0 {
		return
	}
	v.commitPrefix(last, rowToString(v.screen[last]), rowAttrSlice(v.screen[last], v.screenAttr[last], v.cols))
}

// setPendingErase records a whole-row erase (EL) of row `row` without
// deciding yet whether it belongs in the transcript, and blanks the row so
// the screen behaves normally meanwhile. resolvePending commits it if the
// cursor leaves the row while it is still blank; beforeWriteToRow throws it
// away if something is printed back into the row first, because that makes
// the erase an in-place redraw rather than text that was shown and cleared.
//
// Attributes ride along with the text - if a row was shown red-on-black,
// pendingTextAttr carries a slice of Attr with the red FG, and commitPrefix
// hands it to history together with the text. A screen that was reset to
// default before the EL keeps pendingTextAttr nil, and Screen()/History()
// return a Line with Attrs shorter than Text (the contract).
func (v *VT) setPendingErase(row int) {
	if content := rowToString(v.screen[row]); content != "" {
		v.pendingRow = row
		v.pendingText = content
		v.pendingTextAttr = rowAttrSlice(v.screen[row], v.screenAttr[row], v.cols)
	}
	for c := 0; c < v.cols; c++ {
		v.screen[row][c] = ' '
		v.screenAttr[row][c] = Attr{}
	}
}

// beforeWriteToRow settles row `row`'s bookkeeping just before a printable
// character is written into it:
//   - a pending erase of this row is discarded, never committed: the
//     erase-then-print pair was a same-row redraw (progress bar, PSReadLine
//     editing), and SPEC §6.5 says a redraw belongs in the transcript as
//     its final state only, never as the intermediate frame that got
//     erased.
//   - if the row sits inside the already-logged prefix, that prefix shrinks
//     to end above it: fresh content now occupies the row, starting its own
//     lifecycle, so Transcript must render it again instead of skipping it.
func (v *VT) beforeWriteToRow(row int) {
	if v.pendingRow == row {
		v.pendingRow = -1
		v.pendingText = ""
		v.pendingTextAttr = nil
	}
	if row < v.committedRows {
		v.committedRows = row
	}
}

// resolvePending finalizes an outstanding pending erase, if any: the cursor
// has moved off the row (advanceLine/moveCursorY call this before leaving)
// without anything being printed back into it, so unlike beforeWriteToRow's
// case this really was a "shown, then cleared" line and belongs in the
// transcript - together with everything still standing above it, in order.
func (v *VT) resolvePending() {
	if v.pendingRow < 0 {
		return
	}
	row, text, attr := v.pendingRow, v.pendingText, v.pendingTextAttr
	v.pendingRow = -1
	v.pendingText = ""
	v.pendingTextAttr = nil
	v.commitPrefix(row, text, attr)
}

// advanceLine moves the cursor down one row, scrolling if already at the
// bottom - the shared tail of \n, tab overflow, deferred autowrap and
// double-width wrap.
func (v *VT) advanceLine() {
	if v.cursorY+1 >= v.rows {
		v.scrollUp(1)
		v.cursorY = v.rows - 1
		return
	}
	v.resolvePending()
	v.cursorY++
}

// moveCursorY relocates the cursor to a different row, resolving any
// pending erase on the row being left first - a no-op if the row is not
// actually changing (e.g. Cursor Up already at row 0 clamps to row 0,
// which must not look like a departure and commit a still-being-edited
// line).
func (v *VT) moveCursorY(newY int) {
	if newY != v.cursorY {
		v.resolvePending()
	}
	v.cursorY = newY
}

func (v *VT) scrollUp(n int) {
	if n <= 0 {
		return
	}
	if n > v.rows {
		n = v.rows
	}
	// Row indices are about to shift - resolve pending erases first (see
	// resolvePending's doc comment).
	v.resolvePending()

	// Rows inside the already-logged prefix are blank precisely because
	// commitPrefix wrote them to history; scrolling them off must not add
	// a second, empty copy of each behind the text they already produced.
	if skip := min(n, v.committedRows); skip < n {
		lines := make([]string, 0, n-skip)
		attrs := make([][]Attr, 0, n-skip)
		for i := skip; i < n; i++ {
			lines = append(lines, rowToString(v.screen[i]))
			attrs = append(attrs, rowAttrSlice(v.screen[i], v.screenAttr[i], v.cols))
		}
		v.appendHistoryLines(lines, attrs)
	}

	for r := 0; r < v.rows-n; r++ {
		copy(v.screen[r], v.screen[r+n])
		copy(v.screenAttr[r], v.screenAttr[r+n])
	}
	for r := v.rows - n; r < v.rows; r++ {
		for c := 0; c < v.cols; c++ {
			v.screen[r][c] = ' '
			v.screenAttr[r][c] = Attr{}
		}
	}
	v.committedRows = max(0, v.committedRows-n)
}

func (v *VT) scrollDown(n int) {
	if n <= 0 {
		return
	}
	if n > v.rows {
		n = v.rows
	}
	v.resolvePending()

	for r := v.rows - 1; r >= n; r-- {
		copy(v.screen[r], v.screen[r-n])
		copy(v.screenAttr[r], v.screenAttr[r-n])
	}
	for r := 0; r < n; r++ {
		for c := 0; c < v.cols; c++ {
			v.screen[r][c] = ' '
			v.screenAttr[r][c] = Attr{}
		}
	}
	v.committedRows = min(v.rows, v.committedRows+n)
}

func (v *VT) insertLines(n int) {
	if n <= 0 || v.cursorY >= v.rows {
		return
	}
	if n > v.rows-v.cursorY {
		n = v.rows - v.cursorY
	}
	v.resolvePending()
	for r := v.rows - 1; r >= v.cursorY+n; r-- {
		copy(v.screen[r], v.screen[r-n])
		copy(v.screenAttr[r], v.screenAttr[r-n])
	}
	for r := v.cursorY; r < v.cursorY+n && r < v.rows; r++ {
		for c := 0; c < v.cols; c++ {
			v.screen[r][c] = ' '
			v.screenAttr[r][c] = Attr{}
		}
	}
	if v.cursorY < v.committedRows {
		v.committedRows = min(v.rows, v.committedRows+n)
	}
}

func (v *VT) deleteLines(n int) {
	if n <= 0 || v.cursorY >= v.rows {
		return
	}
	if n > v.rows-v.cursorY {
		n = v.rows - v.cursorY
	}
	v.resolvePending()
	for r := v.cursorY; r < v.rows-n; r++ {
		copy(v.screen[r], v.screen[r+n])
		copy(v.screenAttr[r], v.screenAttr[r+n])
	}
	for r := v.rows - n; r < v.rows; r++ {
		for c := 0; c < v.cols; c++ {
			v.screen[r][c] = ' '
			v.screenAttr[r][c] = Attr{}
		}
	}
	if v.cursorY < v.committedRows {
		v.committedRows = max(v.cursorY, v.committedRows-n)
	}
}

func (v *VT) insertChars(n int) {
	if n <= 0 || v.cursorX >= v.cols {
		return
	}
	if n > v.cols-v.cursorX {
		n = v.cols - v.cursorX
	}
	row := v.screen[v.cursorY]
	attr := v.screenAttr[v.cursorY]
	for c := v.cols - 1; c >= v.cursorX+n; c-- {
		row[c] = row[c-n]
		attr[c] = attr[c-n]
	}
	for c := v.cursorX; c < v.cursorX+n && c < v.cols; c++ {
		row[c] = ' '
		attr[c] = Attr{}
	}
}

func (v *VT) deleteChars(n int) {
	if n <= 0 || v.cursorX >= v.cols {
		return
	}
	if n > v.cols-v.cursorX {
		n = v.cols - v.cursorX
	}
	row := v.screen[v.cursorY]
	attr := v.screenAttr[v.cursorY]
	for c := v.cursorX; c < v.cols-n; c++ {
		row[c] = row[c+n]
		attr[c] = attr[c+n]
	}
	for c := v.cols - n; c < v.cols; c++ {
		row[c] = ' '
		attr[c] = Attr{}
	}
}

// Flush processes any remaining incomplete UTF-8 bytes at stream end.
func (v *VT) Flush() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.pendingBytes) > 0 {
		for len(v.pendingBytes) > 0 {
			r, size := utf8.DecodeRune(v.pendingBytes)
			v.pendingBytes = v.pendingBytes[size:]
			v.processRune(r)
		}
	}

	// SPEC §6.5 round 4: end of stream is one of the three points a pending
	// erase resolves at (row still blank, screen clear, end of stream) -
	// a session that ends mid-redraw must not silently drop a line that
	// was genuinely shown and erased, just because the cursor never moved
	// off it again.
	v.resolvePending()
}

// Resize changes the virtual terminal dimensions.
func (v *VT) Resize(newCols, newRows int) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if newCols <= 0 || newRows <= 0 {
		return
	}
	newCols, newRows = boundSize(newCols, newRows)

	v.wrapPending = false
	// Row indices are about to be entirely rebuilt - resolve pending
	// erases first (see resolvePending's doc comment), otherwise their
	// content (already blanked off-screen, held only in v.pendingText)
	// would be silently lost rather than reflowed into history or the new
	// screen.
	v.resolvePending()

	// Collection starts below the already-logged prefix: those rows are
	// blank only because commitPrefix wrote them to history, so reflowing
	// them into the new screen would reintroduce them as empty lines under
	// the text they already produced.
	//
	// reflowPair keeps text and attributes together as a logical line:
	// when a screen row is too wide for newCols the reflow splits it into
	// multiple screen rows (and into multiple history lines if it still
	// does not fit when newRows is reached), and the attribute slice has
	// to be split the same way so colour stays glued to the rune it
	// belonged to. Tracking them as a pair also means a line that goes
	// to history keeps its attrs and a line that lands on the new screen
	// keeps its attrs, without a second parallel pass over the cells.
	base := v.committedRows
	type reflowPair struct {
		line string
		attr []Attr
	}
	var collected []reflowPair
	for r := base; r < v.rows; r++ {
		line := rowToString(v.screen[r])
		attr := rowAttrSlice(v.screen[r], v.screenAttr[r], v.cols)
		lineRunes := []rune(line)
		attrIdx := 0
		if len(lineRunes) > newCols {
			for len(lineRunes) > 0 {
				take := min(len(lineRunes), newCols)
				pair := reflowPair{line: string(lineRunes[:take])}
				if attr != nil {
					pair.attr = append([]Attr(nil), attr[attrIdx:attrIdx+take]...)
				}
				collected = append(collected, pair)
				lineRunes = lineRunes[take:]
				attrIdx += take
			}
		} else {
			collected = append(collected, reflowPair{line: line, attr: attr})
		}
	}

	lastNonEmpty := -1
	for i := len(collected) - 1; i >= 0; i-- {
		if collected[i].line != "" {
			lastNonEmpty = i
			break
		}
	}
	if lastNonEmpty >= 0 {
		collected = collected[:lastNonEmpty+1]
	} else {
		collected = nil
	}

	if len(collected) > newRows {
		excess := len(collected) - newRows
		histLines := make([]string, excess)
		histAttrs := make([][]Attr, excess)
		for i := 0; i < excess; i++ {
			histLines[i] = collected[i].line
			histAttrs[i] = collected[i].attr
		}
		v.appendHistoryLines(histLines, histAttrs)
		collected = collected[excess:]
	}

	newScreen := make([][]rune, newRows)
	newScreenAttr := make([][]Attr, newRows)
	for r := 0; r < newRows; r++ {
		newRow := make([]rune, newCols)
		newAttr := make([]Attr, newCols)
		var lineRunes []rune
		var lineAttr []Attr
		if r < len(collected) {
			lineRunes = []rune(collected[r].line)
			lineAttr = collected[r].attr
		}
		for c := 0; c < newCols; c++ {
			if c < len(lineRunes) {
				newRow[c] = lineRunes[c]
				if c < len(lineAttr) {
					newAttr[c] = lineAttr[c]
				}
			} else {
				newRow[c] = ' '
				newAttr[c] = Attr{}
			}
		}
		newScreen[r] = newRow
		newScreenAttr[r] = newAttr
	}

	v.cols = newCols
	v.rows = newRows
	v.screen = newScreen
	v.screenAttr = newScreenAttr
	// Content moved up by `base` rows in the reflow above, so the cursor
	// moves with it - otherwise it would be left pointing that many rows
	// below the line it was actually on.
	v.committedRows = 0
	v.cursorX = clamp(v.cursorX, 0, v.cols-1)
	v.cursorY = clamp(v.cursorY-base, 0, v.rows-1)
}

func rowToString(row []rune) string {
	var sb strings.Builder
	for _, r := range row {
		if r != 0 {
			sb.WriteRune(r)
		}
	}
	return strings.TrimRight(sb.String(), " ")
}

// rowAttrSlice returns the per-RUNE attribute view of a screen row: one
// entry for each rune rowToString will emit, in the same order.
//
// It takes the rune row as well as the attribute row, and that is the
// whole point of the signature. Attributes are stored per CELL, and a
// cell is not a rune: a double-width character (CJK) occupies two cells,
// and the second one holds rune 0 as a trailing-half marker. rowToString
// skips those cells; an attribute walk that did not would hand back one
// entry too many for every wide rune on the line, and every attribute
// after it would be shifted — so `\x1b[31m<wide>\x1b[0mX` painted the X
// red. The review of IAMT-339 found it; the fix is not to skip the
// marker in a second place but to walk the same cells as the text, here,
// in one function that cannot disagree with itself.
//
// Trailing blanks are dropped to match rowToString's TrimRight, so the
// two never differ in length either.
//
// When no emitted rune carries a non-default attribute the result is
// nil: a line of an SGR-free session then costs no slice at all, and the
// "Attrs shorter than Text means default from here" contract falls out
// for free.
func rowAttrSlice(runes []rune, row []Attr, width int) []Attr {
	if len(row) == 0 {
		return nil
	}
	end := len(row)
	if end > width {
		end = width
	}
	if len(runes) < end {
		end = len(runes)
	}
	// One entry per emitted rune, and remember where the last
	// non-blank rune was so the trailing-space trim matches rowToString.
	out := make([]Attr, 0, end)
	lastNonBlank := -1
	lastSet := -1
	for i := 0; i < end; i++ {
		r := runes[i]
		if r == 0 {
			continue // never written, or the trailing half of a wide rune
		}
		if r != ' ' {
			lastNonBlank = len(out)
		}
		if row[i] != (Attr{}) {
			lastSet = len(out)
		}
		out = append(out, row[i])
	}
	// TrimRight of the text drops trailing spaces; the attributes of
	// those spaces go with them.
	if lastNonBlank+1 < len(out) {
		out = out[:lastNonBlank+1]
		if lastSet > lastNonBlank {
			lastSet = -1
			for i := range out {
				if out[i] != (Attr{}) {
					lastSet = i
				}
			}
		}
	}
	if lastSet < 0 {
		return nil
	}
	return out[:lastSet+1]
}

// Transcript returns the full human-readable transcript:
// all lines scrolled into history followed by active screen lines.
// Trailing whitespace on each line is trimmed.
func (v *VT) Transcript() string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Find the last active row on screen
	lastActiveRow := -1
	for r := v.rows - 1; r >= 0; r-- {
		line := rowToString(v.screen[r])
		if line != "" {
			lastActiveRow = r
			break
		}
	}

	// History is the head the session began with, then the ring. While the
	// ring has dropped no more than the head holds, the two overlap and
	// together are the whole history; past that, the lines between them
	// are left out and a marker stands where they were (R4 F-05).
	var resultLines []string
	tail := v.history
	if v.droppedHistoryLines > 0 {
		resultLines = append(resultLines, v.head...)
		if overlap := int64(len(v.head)) - v.droppedHistoryLines; overlap > 0 {
			tail = tail[overlap:]
		} else if omitted := -overlap; omitted > 0 {
			resultLines = append(resultLines, fmt.Sprintf("[... %d lines truncated / %d lines omitted here; the full session is in the .cast recording ...]", omitted, omitted))
		}
	}
	resultLines = append(resultLines, tail...)

	// The live tail starts below the already-logged prefix: those rows are
	// blank only because their content is already in history above, and
	// rendering them again would add empty lines between history and
	// whatever is still live further down the screen.
	for r := v.committedRows; r <= lastActiveRow; r++ {
		resultLines = append(resultLines, rowToString(v.screen[r]))
	}

	if len(resultLines) == 0 {
		return ""
	}

	return strings.Join(resultLines, "\n")
}

// DroppedHistoryLines returns the total count of lines truncated from scrollback history.
func (v *VT) DroppedHistoryLines() int64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.droppedHistoryLines
}

// Screen returns the CURRENT screen as a row-by-row list of Lines
// (history excluded), top to bottom. Each row that is part of the
// already-committed prefix (see commitPrefix / vt.rows) is blank by
// construction, so it shows up here as Line{Text: "", Attrs: nil} -
// mirror of what Transcript() does for the textual artefact, so a
// downstream renderer can pick either view without learning two rules
// for "what is blank".
func (v *VT) Screen() []Line {
	v.mu.RLock()
	defer v.mu.RUnlock()

	out := make([]Line, v.rows)
	for r := 0; r < v.rows; r++ {
		text := rowToString(v.screen[r])
		out[r] = Line{Text: text, Attrs: rowAttrSlice(v.screen[r], v.screenAttr[r], v.cols)}
	}
	return out
}

// HistoryTotal returns the number of lines currently in scrollback
// (the same count that Transcript() and Screen() can derive, exposed
// here so the live-session tab can compute its own scroll position
// without re-walking the slice).
func (v *VT) HistoryTotal() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.history)
}

// History returns scrollback lines, oldest first, starting at index
// `from` and stopping after `max` entries. It mirrors HistoryTotal() in
// staying read-only, and matches Transcript()'s rule about the dropped
// prefix: any line scrolled off the top is reported here, and the
// "[... N lines truncated ...]" banner itself is NOT - that banner is
// a transcript-only construct, and the live viewer is expected to
// render it (or not) on its own once HistoryTotal + dropped tells it
// there is a gap.
//
// Out-of-range requests are clamped, not errored: `from < 0` becomes
// 0, `from > total` becomes total (yielding an empty slice), and
// `max <= 0` is an empty slice too. The live viewer passes whatever
// its scroll position already produced; if the user scrolled past the
// end, an empty result is exactly what it wants.
func (v *VT) History(from, max int) []Line {
	v.mu.RLock()
	defer v.mu.RUnlock()

	total := len(v.history)
	if from < 0 {
		from = 0
	}
	if from > total {
		from = total
	}
	if max <= 0 || from >= total {
		return nil
	}
	end := from + max
	if end > total {
		end = total
	}
	out := make([]Line, end-from)
	for i, line := range v.history[from:end] {
		entry := Line{Text: line}
		if from+i < len(v.historyAttr) && v.historyAttr[from+i] != nil {
			entry.Attrs = append([]Attr(nil), v.historyAttr[from+i]...)
		}
		out[i] = entry
	}
	return out
}

// Cursor returns current cursor position (0-based: col, row).
func (v *VT) Cursor() (int, int) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.cursorX, v.cursorY
}

// Size returns terminal dimensions (cols, rows).
func (v *VT) Size() (int, int) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.cols, v.rows
}

func parseParams(s string) []int {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ";")
	res := make([]int, len(parts))
	for i, p := range parts {
		val, err := strconv.Atoi(p)
		if err != nil {
			var numErr *strconv.NumError
			if errors.As(err, &numErr) && numErr.Err == strconv.ErrRange {
				if strings.HasPrefix(p, "-") {
					res[i] = -1000000
				} else {
					res[i] = 1000000
				}
			} else {
				res[i] = 0
			}
		} else {
			res[i] = val
		}
	}
	return res
}

func paramDefault(params []int, index int, def int) int {
	if index >= len(params) || params[index] == 0 {
		return def
	}
	return params[index]
}

// applySGR walks the parsed SGR parameter list and folds each code into
// v.curAttr. It deliberately consumes only the parameter set the
// contract names (round 2 of IAMT-339 / docs/notes §2): 0 (reset), 1/22
// (bold), 4/24 (underline), 7/27 (reverse), 30–37 / 90–97 (FG), 39
// (default FG), 40–47 / 100–107 (BG), 49 (default BG), and 38/48 with
// the `5;n` (palette 256) and `2;r;g;b` (RGB) extensions. Every other
// code - 2, 3, 5, 6, 8, 9, 21, 23, 25, 26, 28, 29, 51, 52, 53, etc. -
// is skipped silently along with its sub-parameters, the same way the
// pre-existing parser already ignored the whole SGR for Transcript().
// Unknown codes must not throw, must not lose the parameters that follow
// them, and must not leak into the transcript: the contract is "the
// human-readable text is unchanged", not "the SGR state is unchanged".
func (v *VT) applySGR(params []int) {
	// An empty parameter list is the canonical "\x1b[m" reset form
	// (executeCSI hands us an empty slice when seqBuf is empty); treat it
	// as a single 0.
	if len(params) == 0 {
		v.curAttr = Attr{}
		return
	}

	for i := 0; i < len(params); i++ {
		p := params[i]
		switch {
		case p == 0:
			v.curAttr = Attr{}
		case p == 1:
			v.curAttr.Bold = true
		case p == 4:
			v.curAttr.Underline = true
		case p == 7:
			v.curAttr.Reverse = true
		case p == 22:
			v.curAttr.Bold = false
		case p == 24:
			v.curAttr.Underline = false
		case p == 27:
			v.curAttr.Reverse = false
		case p >= 30 && p <= 37:
			v.curAttr.FG = Color{Kind: ColorNamed, Index: uint8(p - 30)}
		case p == 38:
			// 38/48 are extended-colour introducers. We look ahead one
			// (palette) or three (RGB) parameters and consume them, so a
			// malformed introducer (e.g. "38;5" with no index) leaves the
			// remaining params to the loop, which simply does nothing
			// with them - which is exactly the silent-ignore contract.
			switch {
			case i+1 < len(params) && params[i+1] == 5 && i+2 < len(params):
				v.curAttr.FG = Color{Kind: Color256, Index: clampU8(params[i+2])}
				i += 2
			case i+1 < len(params) && params[i+1] == 2 && i+4 < len(params):
				v.curAttr.FG = Color{
					Kind: ColorRGB,
					R:    clampU8(params[i+2]),
					G:    clampU8(params[i+3]),
					B:    clampU8(params[i+4]),
				}
				i += 4
			}
		case p == 39:
			v.curAttr.FG = Color{}
		case p >= 40 && p <= 47:
			v.curAttr.BG = Color{Kind: ColorNamed, Index: uint8(p - 40)}
		case p == 48:
			switch {
			case i+1 < len(params) && params[i+1] == 5 && i+2 < len(params):
				v.curAttr.BG = Color{Kind: Color256, Index: clampU8(params[i+2])}
				i += 2
			case i+1 < len(params) && params[i+1] == 2 && i+4 < len(params):
				v.curAttr.BG = Color{
					Kind: ColorRGB,
					R:    clampU8(params[i+2]),
					G:    clampU8(params[i+3]),
					B:    clampU8(params[i+4]),
				}
				i += 4
			}
		case p == 49:
			v.curAttr.BG = Color{}
		case p >= 90 && p <= 97:
			// Bright FG: 8..15 in the named-colour numbering, kept as
			// the actual index rather than the raw SGR number so the
			// host renderer can map it the same way it maps 30..37.
			v.curAttr.FG = Color{Kind: ColorNamed, Index: uint8(p - 90 + 8)}
		case p >= 100 && p <= 107:
			v.curAttr.BG = Color{Kind: ColorNamed, Index: uint8(p - 100 + 8)}
			// Anything else falls through silently: unknown SGR codes
			// must not disturb curAttr and must not surface to the
			// transcript.
		}
	}
}

// clampU8 coerces a parsed SGR integer into a uint8 cell. parseParams
// already turns parse errors into 0, so the only thing left to clamp is
// the rare out-of-range positive; we mask rather than reject so a
// palette index of 256 or an RGB channel of 300 lands as the largest
// representable value rather than poisoning curAttr with -1.
func clampU8(n int) uint8 {
	if n < 0 {
		return 0
	}
	if n > 0xFF {
		return 0xFF
	}
	return uint8(n)
}

// addSat is a + b, saturated at the ends of the int range instead of
// wrapped around them.
//
// parseParams hands a CSI parameter through as whatever the machine
// printed, math.MaxInt included (it clamps only a number that does not
// fit in an int at all). A cursor move that added one to a coordinate
// with a bare + wrapped to a huge negative, min() against the screen
// edge kept the negative, and the next printable character indexed the
// screen with it: one printf in any shell panicked the bridge goroutine
// and took the gateway down with every session on it (IAMT-441). A
// saturated sum stays on the side of the screen the parameter points
// to, so the clamp that follows lands the cursor on that edge.
func addSat(a, b int) int {
	if b > 0 && a > math.MaxInt-b {
		return math.MaxInt
	}
	if b < 0 && a < math.MinInt-b {
		return math.MinInt
	}
	return a + b
}

func clamp(val, low, high int) int {
	if val < low {
		return low
	}
	if val > high {
		return high
	}
	return val
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// OmittedLines is how many lines of history the transcript leaves out: the
// middle of a session longer than its head and its tail together (R4 F-05).
// DroppedHistoryLines counts what the ring alone has dropped.
func (v *VT) OmittedLines() int64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if omitted := v.droppedHistoryLines - int64(len(v.head)); omitted > 0 {
		return omitted
	}
	return 0
}
