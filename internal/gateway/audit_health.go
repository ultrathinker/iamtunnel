package gateway

// audit_health.go - what the gateway does when its audit journal stops
// writing (IAMT-451).
//
// appendEvent used to drop Append's answer on the floor. A journal that
// could not write - a full disk, a file gone read-only, a failed fsync, an
// event it refused - let grants, revocations and logins go through with
// nothing on record, and nothing anywhere said so. Now the first write
// that fails turns the gateway's audit state to failing, and it stays
// failing until a write succeeds again. While it is failing:
//
//   - a command that would write to the journal is refused with
//     E_AUDIT_UNAVAILABLE. The commands that write nothing (readOnly in
//     commandTable) still run: they are how an operator finds out what is
//     wrong, gateway.status first of all;
//   - a new session to a machine is refused, and so are enrolment,
//     pairing and the bootstrap claim;
//   - a command whose own record is the write that failed has done its
//     work already - that cannot be taken back - and says so instead of
//     reporting success. "Its own record" is meant literally: the verdict
//     is about the journal writes lost for the person the command is run
//     for, never about somebody else's (F-01, round-1 review 24.09.2026 -
//     until then a parallel administrator's failed write answered a
//     command that had been recorded with "nowhere on record").
//
// Sessions already running go on. Their recordings are written on their
// own terms (SPEC §6.5): a recording that cannot be written ends its
// session by itself, and a journal hiccup must not become a way to cut
// every session on the gateway. That they run while nothing is journaled
// is in plain view: gateway.status gives the audit state and the number
// of live sessions side by side.
//
// The state is published three ways, and none of them needs the journal:
// gateway.status carries it; the gateway keeps it in AuditHealthFile in
// its data directory, which is what `gateway status` and the window's
// Gateway tab read on the gateway's own machine; and each change is one
// line on Config.Diagnostics - the service's log.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// AuditHealthFile is the file in the gateway's data directory that says
// whether the audit journal is being written, as AuditHealth JSON.
const AuditHealthFile = "audit-health.json"

// AuditHealth is the audit journal's state as the gateway publishes it:
// the "audit" object of gateway.status and the content of
// AuditHealthFile.
type AuditHealth struct {
	// OK is false from the first write that failed until the next one
	// that succeeded.
	OK bool `json:"ok"`
	// Since is when the current state began (RFC 3339): the failure, the
	// recovery, or the gateway's start.
	Since string `json:"since,omitempty"`
	// Error is the latest write failure; it stays after a recovery, so the
	// last thing that went wrong is still there to read.
	Error string `json:"error,omitempty"`
	// LostWrites counts the journal entries lost since the gateway started.
	LostWrites uint64 `json:"lostWrites"`
}

// ReadAuditHealth reads AuditHealthFile from a gateway data directory.
// found is false when the file is not there - a gateway from before 1.14,
// or one that has never started.
func ReadAuditHealth(dataDir string) (h AuditHealth, found bool, err error) {
	raw, err := state.ReadDataFile(filepath.Join(dataDir, AuditHealthFile))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return AuditHealth{}, false, nil
		}
		return AuditHealth{}, false, err
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return AuditHealth{}, false, fmt.Errorf("%s: %w", AuditHealthFile, err)
	}
	return h, true, nil
}

type auditHealth struct {
	mu      sync.Mutex
	failing bool
	since   time.Time
	lastErr string
	lost    uint64
	// watched counts, per (person, command), the journal writes lost
	// since the gateway started, for the commands this gateway runs.
	// F-01 (round-1 review, 24.09.2026) and F-03 (round-2 review,
	// 24.09.2026): the verdict on a command has to be about the command's
	// OWN record, and a journal write reaches noteAudit without saying
	// which command made it. What a lost write does carry is who wrote it
	// (its actor) and which command wrote it (its op, in the result -
	// logAdminOp writes "<op>:<result>"), and that pair is exact enough:
	// a parallel administrator's loss cannot accuse this command, and
	// neither can another command of the SAME administrator running at
	// the same time - which the person alone could not tell apart.
	//
	// The map holds ONLY the names watchActor has been given, which are
	// the people runCommand runs for: a sender-chosen login name
	// (IAMT-447) or a pre-authentication fingerprint cannot add a key to
	// it, so neither memory nor the map's contents are the sender's to
	// size.
	watched map[string]uint64
}

func (h *auditHealth) snapshot() AuditHealth {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := AuditHealth{OK: !h.failing, Error: h.lastErr, LostWrites: h.lost}
	if !h.since.IsZero() {
		out.Since = h.since.UTC().Format(time.RFC3339)
	}
	return out
}

// auditWatch is one command's watch: the keys its own journal lines are
// counted under, and how many of each had been lost when the command
// started. A command may have more than one - one op is the rule, and a
// command whose line is called something else declares it (F-02, round-3
// review 24.09.2026) - and the verdict is "any of them grew".
type auditWatch struct {
	keys []string
	was  []uint64
}

// watchCmd registers one command that is starting, run for actor, and
// takes the count of ITS OWN journal writes lost so far, one per op it
// writes about itself. The command asks again when it is done: only a
// loss in between is its own.
func (h *auditHealth) watchCmd(actor string, ops []string) auditWatch {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.watched == nil {
		h.watched = make(map[string]uint64)
	}
	w := auditWatch{keys: make([]string, 0, len(ops)), was: make([]uint64, 0, len(ops))}
	for _, op := range ops {
		k := auditWatchKey(actor, op)
		if _, seen := h.watched[k]; !seen {
			h.watched[k] = 0
		}
		w.keys = append(w.keys, k)
		w.was = append(w.was, h.watched[k])
	}
	return w
}

// lostSince reports whether any of the records this watch covers has been
// lost since it was taken. Ops nobody watched are not followed; for them
// the answer is no, which is not a claim that nothing was lost - it is
// that nothing lost was theirs, as far as the gateway can tell (see
// auditHealth.watched).
func (h *auditHealth) lostSince(w auditWatch) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, k := range w.keys {
		if h.watched[k] > w.was[i] {
			return true
		}
	}
	return false
}

// watchActor registers a one-off role - pairing, bootstrap, enrolment -
// as someone whose journal losses are the business of the run that is
// starting, and returns how many of that actor's writes have been lost so
// far. It is the actor-wide watch runAuditedRole uses, and it stays
// actor-wide on purpose: those roles write typed events rather than
// admin.op lines, so there is no op to key them by (F-03's (person, op)
// watch is for commands; see watchCmd).
func (h *auditHealth) watchActor(actor string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.watched == nil {
		h.watched = make(map[string]uint64)
	}
	if _, seen := h.watched[actor]; !seen {
		h.watched[actor] = 0
	}
	return h.watched[actor]
}

// lostForActor is how many journal writes have been lost for actor since
// the gateway started. Actors only ever seen by watchActor are followed;
// for anyone else the answer is zero, which is not a claim that nothing
// was lost - it is that nothing lost was theirs, as far as the gateway
// can tell (see auditHealth.watched).
func (h *auditHealth) lostForActor(actor string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.watched[actor]
}

// auditWatchKey names one command's own journal writes: the person it is
// run for and the command itself. The NUL cannot occur in either, so the
// two can never be read as one another.
func auditWatchKey(actor, op string) string { return actor + "\x00" + op }

// adminOpOf is the command an event is a record of, for the events a
// command writes about itself: logAdminOp puts the op at the front of the
// result ("people.add:ok", "people.keys.remove:failed"). Empty for every
// other event - a session, a door, a login - and an event the gateway
// cannot attribute to a command is not counted against any of them.
func adminOpOf(e events.Event) string {
	if e.Type != events.EventAdminOp {
		return ""
	}
	op, _, found := strings.Cut(e.Result, ":")
	if !found {
		return ""
	}
	return op
}

// journalAppend writes one entry. journalAppendFn is a test-only seam, nil
// in production (like probeDeadlineFn): the tests that need a journal
// that fails and then recovers set it, since a real one cannot be made to
// do that on demand.
func (g *Gateway) journalAppend(e events.Event) error {
	if fn := g.journalAppendFn.Load(); fn != nil {
		return (*fn)(e)
	}
	return g.cfg.Log.Append(e)
}

// noteAudit folds the outcome of one journal write into the audit state
// and publishes the state when it changes. The event is what carries the
// write's actor, which is the one attribution a command's verdict may use
// (F-01): a write lost for somebody else is counted, and is not any
// command's own loss.
func (g *Gateway) noteAudit(err error, e events.Event) {
	h := &g.audit
	h.mu.Lock()
	changed := false
	switch {
	case err != nil:
		h.noteLostLocked(e)
		h.lastErr = err.Error()
		if !h.failing {
			h.failing, h.since, changed = true, g.cfg.Now(), true
		}
	case h.failing:
		h.failing, h.since, changed = false, g.cfg.Now(), true
	}
	h.mu.Unlock()
	if changed {
		g.publishAudit(true)
	}
}

// noteLostLocked counts one lost journal write: the total, and every watch
// the write belongs to. Two kinds of watch, one per kind of writer: a
// command is followed by (person, op), a one-off role (pairing,
// bootstrap, enrolment) by its actor alone - its records are typed events
// rather than admin.op lines, so it has no op to be keyed on. A lost
// admin.op line bumps both when both are watching, which is what a role's
// watch has always counted (R1-CX F-15). Must be called with h.mu held.
func (h *auditHealth) noteLostLocked(e events.Event) {
	h.lost++
	if op := adminOpOf(e); op != "" {
		k := auditWatchKey(e.Actor, op)
		if _, followed := h.watched[k]; followed {
			h.watched[k]++
		}
	}
	if _, followed := h.watched[e.Actor]; followed {
		h.watched[e.Actor]++
	}
}

// publishAudit writes the current audit state to AuditHealthFile and, when
// announce is set, one line to Diagnostics. Both are best effort: whatever
// broke the journal may break these too, and gateway.status still answers.
// auditPublishMu keeps two changes from landing out of order: each
// publish takes the state as it is when its turn comes.
//
// Nothing is published once Close has begun. The journal is closed by its
// owner after the gateway, and a write that comes later fails with "log is
// closed" - not the journal breaking, but the gateway's own stop - and the
// data directory is no longer the gateway's to write in.
func (g *Gateway) publishAudit(announce bool) {
	g.auditPublishMu.Lock()
	defer g.auditPublishMu.Unlock()
	if g.auditClosed.Load() {
		return
	}
	snap := g.audit.snapshot()
	if g.cfg.DataDir != "" {
		if raw, err := json.MarshalIndent(snap, "", "  "); err == nil {
			_ = datafile.WriteFileAtomic(filepath.Join(g.cfg.DataDir, AuditHealthFile), append(raw, '\n'),
				datafile.WithAdoptOwnerFn(adoptOwnership))
		}
	}
	if !announce || g.cfg.Diagnostics == nil {
		return
	}
	if !snap.OK {
		fmt.Fprintf(g.cfg.Diagnostics, "iamtunnel gateway: the audit journal is NOT being written (since %s): %s. Commands that change anything, new sessions, enrolment and pairing are refused until it writes again.\n",
			snap.Since, snap.Error)
		return
	}
	if snap.LostWrites > 0 {
		fmt.Fprintf(g.cfg.Diagnostics, "iamtunnel gateway: the audit journal is written again (since %s); %d entries were lost while it was not.\n",
			snap.Since, snap.LostWrites)
	}
}

// auditRefusal is why an operation that has to be journaled may not
// start now, or nil when the journal is writing.
func (g *Gateway) auditRefusal() *cmdError {
	snap := g.audit.snapshot()
	if snap.OK {
		return nil
	}
	return errf("E_AUDIT_UNAVAILABLE", 1,
		"the gateway's audit journal has not been written since %s (%s); nothing that has to be recorded is done until it writes again - gateway status shows the state",
		snap.Since, snap.Error)
}

// auditLost is the answer of an operation that did its work while the
// journal lost the record of it.
func (g *Gateway) auditLost(what string) *cmdError {
	snap := g.audit.snapshot()
	return errf("E_AUDIT_UNAVAILABLE", 1,
		"%s was carried out, but the audit journal could not record it (%s); it is in force, and nowhere on record",
		what, snap.Error)
}

// runAuditedRole runs one one-shot role -- the pairing, the bootstrap
// claim, the enrolment -- under the same audit guarantee runCommand gives
// an admin command (F-15, 24.09.2026). The roles checked the journal only
// before the work, and their last write -- the pairing's admin.op, the
// claim's bootstrap:ok, the enrolment's enrol.verified -- could be the
// write the journal lost: the key, the administrator or the machine left
// in force, the client told "ok", nothing on record. The loss is now the
// answer, in IAMT-451's own words.
func (g *Gateway) runAuditedRole(actor, what string, run func() (any, *cmdError)) (any, *cmdError) {
	// IAMT-451: not while the audit journal cannot record it.
	if cerr := g.auditRefusal(); cerr != nil {
		return nil, cerr
	}
	lost := g.audit.watchActor(actor)
	res, cerr := run()
	if cerr == nil && g.audit.lostForActor(actor) > lost {
		return nil, g.auditLost(what)
	}
	return res, cerr
}

// afterAuditWatchFn is the seam a test parks a command on once its audit
// watch is open and before it has done anything: the window in which
// another command of the same administrator can lose its own record
// (F-03, round-2 review 24.09.2026). It names the person and the
// command so a test can pick one session out of many. Production leaves
// it nil.
var afterAuditWatchFn func(person, command string)
