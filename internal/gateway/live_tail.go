package gateway

// live_tail.go — which recording each LIVE session is currently writing
// into, so that a session can be watched while it is still happening
// (IAMT-338).
//
// Why this exists at all. Everything the product knows about a finished
// session it finds by walking the recordings directory for `.meta` files
// (scanRecordings), and `.meta` is written by the recorder's finalize —
// at the END. So a session in progress is, to `recordings.list` and to
// `recordings.fetch`, simply not there. That is correct for an archive
// and useless for a live view, and no amount of cleverness in the
// reader fixes it: the name of the file a live session is writing into
// is not derivable from the outside.
//
// It is not derivable on purpose. A recording's name comes from the
// clock, the person and the machine, and when that name is already
// taken the recorder takes the NEXT one rather than refuse the session
// or overwrite the earlier recording (record/sessionname.go). A clock
// that does not advance — a frozen test clock, a coarse platform clock —
// makes that the ordinary case rather than the exotic one. So the only
// party that knows where a live session is being written is the session
// itself, and it has to say so.
//
// Hence this registry: one entry per live recording, added when the
// recorder is created and removed when the session is over. It holds a
// path and nothing else — no handles, no buffers, no copy of the stream.
// The reader opens the file by name like any other reader, which keeps
// the whole watching feature outside the session's own hot path: a slow
// or stuck watcher cannot slow down, block, or break the session it is
// watching. That property is worth more here than the latency it costs.

import (
	"encoding/base64"
	"io"
	"os"
	"sync"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// liveRecordings maps a live session id to the cast file it is writing
// into. The zero value is ready to use.
type liveRecordings struct {
	mu   sync.Mutex
	byID map[string]liveEntry

	// recordMu serialises the first-watch record - check, journal write,
	// mark - so first requests that arrive together write one
	// session.watch, not one each (R4 review N-09). It is taken only while
	// a watch is not yet recorded; every later poll reads the mark alone.
	recordMu sync.Mutex

	// now is the clock the grace period is measured against. Nil means
	// time.Now, which is what production uses; a test sets it so that
	// expiry can be checked without waiting out the real grace period.
	// A rule that cannot be tested except by sleeping tends not to be
	// tested at all.
	now func() time.Time
}

func (l *liveRecordings) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// liveEntry is one registered recording. It outlives the session by a
// short grace period - see drainGrace.
type liveEntry struct {
	path string
	// mode is how path is read: record.LiveModeCast or LiveModeExec
	// (IAMT-453). A watcher is told before it opens the bytes.
	mode string
	// machine is the machine the session is happening ON. It is kept
	// here because the access rule has to survive the end of the
	// session: once a session is over the ACL no longer lists it, and
	// without this the machine that was watching would lose the right to
	// read the last seconds of its own session at the exact moment
	// those seconds became interesting.
	machine string
	// ended is the zero time while the session is running, and the
	// moment it finished afterwards.
	ended time.Time
	// watchers are the admins whose watching of this session is already
	// in the journal (R4 F-01): the first request of each is recorded,
	// whatever offset it asks for - the offset is the watcher's choice.
	watchers map[string]bool
}

// drainGrace is how long a finished recording stays readable through
// this registry after its session ends.
//
// Without it the last thing the specialist did was the one thing the
// owner could never see. The viewer polls once a second; the session
// ends; the entry vanished the same instant, and the next poll was
// answered "nothing here, and by the way your offset is the total" - a
// number that was not true, chosen so the viewer would stop. Whatever
// was written between the final poll and the end of the session was
// then unreachable, and it is precisely the part a person leans in for:
// the last command and what it printed.
//
// Ten seconds is ten polls: enough for a viewer to drain the tail it
// was already following, short enough that a finished session is not
// kept readable in any meaningful sense. It changes nothing about who
// may read: the access rule still admits only the machine the session
// belonged to (ownsSession), which is why a finished session cannot be
// discovered through this window - only drained by somebody already
// watching it.
const drainGrace = 10 * time.Second

// add registers a live session's cast file. An empty path is ignored:
// the recorder behind core.Recording is an interface, and a
// substitute that cannot name its own files simply has nothing to
// register — that is a test double, not a failure.
func (l *liveRecordings) add(sessionID, castPath, machine string) {
	l.addFile(sessionID, record.LiveFile{Path: castPath, Mode: record.LiveModeCast}, machine)
}

// addFile registers a live session's recording of either kind - a cast
// file or an exec recording - with the way it is read (IAMT-453).
func (l *liveRecordings) addFile(sessionID string, f record.LiveFile, machine string) {
	if sessionID == "" || f.Path == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byID == nil {
		l.byID = make(map[string]liveEntry)
	}
	l.byID[sessionID] = liveEntry{path: f.Path, mode: f.Mode, machine: machine}
}

// remove ends a session. The entry is not dropped at once: it is marked
// finished and kept for drainGrace, so a viewer that was following the
// session can still read the bytes written just before it ended. See
// drainGrace for why that matters.
//
// Safe to call for a session that was never registered, and calling it
// twice does not extend the grace period.
func (l *liveRecordings) remove(sessionID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.byID[sessionID]
	if !ok {
		return
	}
	if e.ended.IsZero() {
		e.ended = l.clock()
		l.byID[sessionID] = e
	}
	l.sweepLocked()
}

// sweepLocked drops entries whose grace period has run out. It is run
// from the registry's own operations rather than from a timer: the map
// only grows when a session starts, so there is always a caller around
// when it matters, and a gateway with no sessions needs no goroutine.
func (l *liveRecordings) sweepLocked() {
	now := l.clock()
	for id, e := range l.byID {
		if !e.ended.IsZero() && now.Sub(e.ended) > drainGrace {
			delete(l.byID, id)
		}
	}
}

// path answers where a live session is being recorded. The second
// result separates "this session is live and here is its file" from
// "this session is not live", which is the distinction a watcher needs
// to know whether to keep asking.
// Three results, because a watcher needs three states apart:
// known-and-running (keep asking), known-but-finished (read what is
// left, then stop), and unknown (there is nothing here and never will
// be). The middle one is what lets a viewer drain the bytes written
// just before the session ended - see drainGrace.
func (l *liveRecordings) path(sessionID string) (castPath string, known, live bool) {
	f, known, live := l.file(sessionID)
	return f.Path, known, live
}

// file is path with the way the file is read (IAMT-453).
func (l *liveRecordings) file(sessionID string) (f record.LiveFile, known, live bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked()
	e, ok := l.byID[sessionID]
	if !ok {
		return record.LiveFile{}, false, false
	}
	return record.LiveFile{Path: e.path, Mode: e.mode}, true, e.ended.IsZero()
}

// watchRecorded reports whether who's watching of sessionID is already in
// the journal (R4 F-01). A session the registry does not know counts as
// recorded: nothing is read from it, so there is nothing to record.
func (l *liveRecordings) watchRecorded(sessionID, who string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.byID[sessionID]
	return !ok || e.watchers[who]
}

// markWatchRecorded remembers that who's watching of sessionID is in the
// journal. It is called only after the event is on disk (R4 review N-07):
// marked first, a failed write left the watch marked and never recorded.
func (l *liveRecordings) markWatchRecorded(sessionID, who string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.byID[sessionID]
	if !ok {
		return
	}
	if e.watchers == nil {
		e.watchers = make(map[string]bool)
	}
	e.watchers[who] = true
	l.byID[sessionID] = e
}

// machineOf reports which machine a registered session belongs to, and
// whether the registry knows it at all. It is how the access rule keeps
// working for a session that has just ended: see liveEntry.machine.
func (l *liveRecordings) machineOf(sessionID string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked()
	e, ok := l.byID[sessionID]
	if !ok {
		return "", false
	}
	return e.machine, true
}

// len reports how many recordings are live. Only tests use it, and they
// use it to prove the registry does not leak entries: an entry that
// outlives its session would keep a watcher polling a file nobody
// writes to any more, and would grow without bound on a busy gateway.
func (l *liveRecordings) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.byID)
}

// cmdSessionsTail serves the bytes a LIVE session has written into its
// cast file so far (IAMT-338). It is the one command that can see a
// session while it is still happening.
//
// The shape deliberately repeats recordings.fetch (PROTOCOL §6):
// offset in, one bounded chunk plus the current total out, caller
// repeats with offset+len until it has caught up. That command already
// solved "hand me a big file through a protocol that carries one JSON
// object per exec", and a second answer to the same question would be a
// second thing to get wrong. The one field it adds is `live`, which is
// what a watcher needs and an archive reader does not: `false` means
// nothing more will ever be appended, so read to `total` and stop
// asking.
//
// Two things it deliberately does NOT do:
//
//   - It does not stream. A watcher polls about once a second, and the
//     delay that costs is accepted: PROTOCOL §1.2 gives an exec one JSON
//     object, so streaming is a new capability rather than a new
//     command. Push down the control channel is the upgrade, not this.
//   - It does not read through the recorder. The file is opened by name,
//     like any other reader, so a watcher that is slow, stuck or
//     malicious cannot slow down, block or break the session it is
//     watching. A live view that can hurt the session it observes would
//     be a worse feature than no live view.
func cmdSessionsTail(g *Gateway, person string, _ time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto  int    `json:"proto"`
		ID     string `json:"id"`
		Offset int64  `json:"offset"`
		Limit  int64  `json:"limit"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if req.Offset < 0 {
		return nil, errf("E_JSON_INVALID", 3, "offset must be >= 0, got %d", req.Offset)
	}
	if req.Limit < 1 || req.Limit > 1<<20 {
		return nil, errf("E_JSON_INVALID", 3, "limit must be between 1 and 1048576, got %d", req.Limit)
	}

	file, known, live := g.live.file(req.ID)
	if !known {
		// Not live: either it never existed, or it finished. Both are
		// the same answer here — there is nothing left to follow — and
		// saying which would leak whether a session id ever existed to
		// a caller who is allowed to ask but was not allowed to watch.
		return map[string]any{
			"id": req.ID, "offset": req.Offset, "total": req.Offset,
			"live": false, "data": "",
		}, nil
	}

	// No journal line per poll, deliberately. A watcher asks about once
	// a second for as long as it is watching, so logging the READ would
	// put one admin.op into events.jsonl per second per watcher and bury
	// everything that matters under it. The first request of each admin
	// is the durable fact that watching began - the first by who asked,
	// not by offset 0 (R4 F-01): the offset is the watcher's own choice,
	// and a watch that started at 1 used to leave no trace at all. The
	// machine path records its own session.watch in noteWatching and
	// passes an empty person here.
	if person != "" && g != nil && g.cfg.Log != nil && !g.live.watchRecorded(req.ID, person) {
		g.live.recordMu.Lock()
		defer g.live.recordMu.Unlock()
	}
	if person != "" && g != nil && g.cfg.Log != nil && !g.live.watchRecorded(req.ID, person) {
		details := map[string]interface{}{}
		if g.aclE != nil {
			for _, session := range g.aclE.Sessions() {
				if session.ID.String() == req.ID {
					details["person"] = session.Person
					break
				}
			}
		}
		// The watch is served only once it is on disk (R4 review N-07): a
		// failed write refuses this read and leaves the watcher unmarked,
		// so the next poll writes the event instead of skipping it.
		if err := g.appendEventChecked(events.Event{
			Type:    events.EventSessionWatch,
			Actor:   person,
			Object:  req.ID,
			Result:  "ok",
			Details: details,
		}); err != nil {
			return nil, errf("E_AUDIT_UNAVAILABLE", 1, "watching session %q has to be recorded in the audit journal, and the journal could not be written: %v", req.ID, err)
		}
		g.live.markWatchRecorded(req.ID, person)
		// And the command's own record in the shape a command's record has
		// (F-02, round-3 review 24.09.2026): the typed event above is
		// what the History tab reads, this line is what the verdict on a
		// LOST record is matched against. One per watch, not per poll -
		// the same condition the event is written under, so the promise
		// "no journal line per poll" is untouched.
		g.logAdminOp(person, "sessions.tail", req.ID, "ok", nil)
	}

	f, err := state.OpenExistingDataFile(file.Path, os.O_RDONLY)
	if err != nil {
		return nil, errf("E_NOT_FOUND", 2, "session %q is not readable: %v", req.ID, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	total := info.Size()
	var data []byte
	if req.Offset < total {
		buf := make([]byte, req.Limit)
		n, rerr := f.ReadAt(buf, req.Offset)
		if rerr != nil && rerr != io.EOF {
			return nil, errf("E_INTERNAL", 70, "%v", rerr)
		}
		data = buf[:n]
	}
	// live is the SESSION's state, not the file's: a finished recording
	// is still served here for a short grace period so a viewer can
	// drain the bytes written just before the end (drainGrace), and it
	// must say live:false while doing so. total is measured either way,
	// so the viewer reads to a real number and then stops of its own
	// accord instead of being told a convenient one.
	//
	// mode says how the bytes are read - "exec" for an exec session's
	// line-per-event recording, "cast" for asciicast - because a reader
	// has to know before it opens them (IAMT-453; PROTOCOL §6).
	return map[string]any{
		"id": req.ID, "offset": req.Offset, "total": total,
		"live": live, "data": base64.StdEncoding.EncodeToString(data), "mode": file.Mode,
	}, nil
}
