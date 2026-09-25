package gateway

// IAMT-409: the pair's recent-command buffer feeding the external classifier.
//
// Three pieces live here:
//
//   - responseCapture and its two wrappers take the first lines of what the
//     machine answered (stdout through the Bridge target wrapper, stderr
//     through the exec copy source), so the exec teardown in
//     serveHumanSession can store one entry per completed exec.
//   - pairRecentCommandHistory converts the state snapshot's buffer into the
//     wire shape risk.RecentCommandContext. Stored entries are already
//     scrubbed — the scrub happened once, at write time, and is not repeated.
//   - recordRecentCommand commits the entry through internal state, which
//     owns trimming (max commands, character budget) the same way it owns
//     goal trimming.

import (
	"bytes"
	"io"
	"strings"
	"sync"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

const (
	// recentCommandResponseLines is how many first lines of the machine's
	// answer one entry keeps. The classifier needs shape, not a transcript;
	// two lines separate "file copied" from a usage/error dump well enough.
	recentCommandResponseLines = 2

	// recentCommandResponseBytes bounds what those lines may occupy before a
	// "…" marks the cut. One very long line without it could eat the whole
	// character budget of every entry in the pair's buffer.
	recentCommandResponseBytes = 256
)

// responseCapture accumulates the first recentCommandResponseLines lines of a
// completed exec's machine output. Both the stdout copy (core.Bridge's target
// reader) and the stderr copy feed one instance; Write order between them is
// whatever reached the gateway first, which is exactly the "first lines the
// machine answered" framing the classifier gets.
type responseCapture struct {
	mu     sync.Mutex
	text   strings.Builder
	lines  int
	capped bool
	done   bool
	// pending is the start of a line whose end has not arrived yet: a Read
	// boundary is the transport's, not the output's (R4 review N-05). It
	// never grows past recentCommandResponseBytes - past that the line is
	// cut there anyway.
	pending []byte
}

func newResponseCapture() *responseCapture { return &responseCapture{} }

// add records the next chunk of machine output. It never blocks and never
// holds on to more than the configured first lines. A line is what ends in
// a newline, however many chunks it arrived in (R4 review N-05).
func (c *responseCapture) add(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	c.pending = append(c.pending, p...)
	for !c.done {
		i := bytes.IndexByte(c.pending, '\n')
		if i < 0 {
			if len(c.pending) > recentCommandResponseBytes {
				// Longer than a kept line may be: it is cut here whatever
				// comes after, so there is nothing to wait for.
				c.emitLocked(c.pending)
				c.pending = nil
			}
			return
		}
		line := c.pending[:i]
		c.emitLocked(line)
		c.pending = c.pending[i+1:]
	}
	c.pending = nil
}

// emitLocked records one complete line. Empty lines are skipped.
func (c *responseCapture) emitLocked(line []byte) {
	line = bytes.TrimSuffix(line, []byte{'\r'})
	if len(line) == 0 {
		return
	}
	if c.text.Len() > 0 {
		c.text.WriteByte('\n')
	}
	if c.text.Len()+len(line) > recentCommandResponseBytes {
		c.text.WriteString(truncateWithEllipsis(string(line), recentCommandResponseBytes-c.text.Len()))
		c.capped = true
	} else {
		c.text.Write(line)
	}
	c.lines++
	if c.capped || c.lines >= recentCommandResponseLines {
		c.done = true
	}
}

// Response returns the captured text: up to the first two non-empty lines the
// machine answered, bounded by recentCommandResponseBytes, a "…" marking a cut.
func (c *responseCapture) Response() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The answer ended without a newline: its last line is still a line.
	if !c.done && len(c.pending) > 0 {
		c.emitLocked(c.pending)
		c.pending = nil
	}
	return c.text.String()
}

// truncateWithEllipsis cuts s to at most limit bytes on a rune boundary and
// ends the result with "…" when anything was cut. A limit too small to hold
// the marker returns the marker alone.
func truncateWithEllipsis(s string, limit int) string {
	const marker = "…"
	if limit <= len(marker) {
		return marker
	}
	cut := limit - len(marker)
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + marker
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// captureStream wraps the Bridge target so every machine stdout byte the
// gateway reads also lands in the capture. Only Read is overridden; Write,
// Close and CloseWrite pass through untouched, so capture never changes what
// the human receives or when the bridge ends.
type captureStream struct {
	core.Stream
	c *responseCapture
}

func (cs captureStream) Read(p []byte) (int, error) {
	n, err := cs.Stream.Read(p)
	if n > 0 {
		cs.c.add(p[:n])
	}
	return n, err
}

// captureReader does the same for the exec stderr copy's source, which is a
// plain reader (the nested session's stderr), not a full core.Stream.
type captureReader struct {
	r io.Reader
	c *responseCapture
}

func (cr captureReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		cr.c.add(p[:n])
	}
	return n, err
}

// pairRecentCommandHistory lifts the pair's stored buffer into the request
// shape. Entries go out as stored: newest first, already scrubbed at write
// time — re-scrubbing here could mangle values that legitimately contain
// scrub markers, and would silently rewrite history the journal vouches for.
func pairRecentCommandHistory(st state.State, person, machine string) []risk.RecentCommandContext {
	rec, ok := st.RecentCommandsFor(person, machine)
	if !ok || len(rec.Entries) == 0 {
		return nil
	}
	out := make([]risk.RecentCommandContext, 0, len(rec.Entries))
	for _, e := range rec.Entries {
		out = append(out, risk.RecentCommandContext{Command: e.Command, Exit: e.Exit, Response: e.Response})
	}
	return out
}

// recordRecentCommand commits one completed exec to the pair's buffer through
// a Store.Update so trimming and persistence follow the state layer's rules.
// maxCommands/budget come from the live config; RecordCommand clamps them to
// the state layer's own ceiling. A failure here never fails the session: the
// pair may legitimately be gone (removed mid-session), and the buffer is
// context for the classifier, not a durability promise.
func (g *Gateway) recordRecentCommand(person, machine, command, exit, response string) {
	scrubbed := risk.ScrubCommand(command)
	err := g.cfg.Store.Update(func(draft *state.State) error {
		_, err := draft.RecordCommand(person, machine, state.RecentCommand{
			Command:  scrubbed,
			Exit:     exit,
			Response: response,
			At:       state.NewZonedTime(g.cfg.Now()),
		}, g.cfg.RecentCommandsMax, g.cfg.RecentCommandsBudget)
		return err
	})
	if err != nil {
		// No event on purpose: an unknown pair after removal is a routine
		// race, and a per-command journal line for classifier context would
		// be noise the owner did not ask for.
		return
	}
}
