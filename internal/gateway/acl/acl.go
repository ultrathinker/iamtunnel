package acl

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// View is the slice of gateway state the ACL reads. It exists so the ACL
// owns no storage and no files: the state package provides the
// implementation, and tests provide a fake. The ACL deliberately knows
// nothing else about state.json.
//
// Where each answer MUST come from - two different worlds, and mixing
// them creates two sources of truth that will drift apart:
//
//   - PersonExists     - from the persisted state file (state.json,
//     owned by the state package): a person is a written fact.
//   - MachineExists    - from the persisted state file: registration is
//     a written fact.
//   - MachineVerified  - from the persisted state file: the pinned sshd
//     host key (state verified, SPEC 3.4) is a written fact.
//   - MachineOnline    - from MEMORY ONLY: it is a fact about a live
//     tunnel connection of the running gateway (the machine registry,
//     id -> conn). It cannot be stored in the state file - a file
//     cannot know whether a TCP tunnel is up right now - and every
//     implementation must answer it from the in-memory registry, never
//     from disk.
//
// The view is read on every decision; answers must reflect the current
// world, not a snapshot taken at construction time.
type View interface {
	// PersonExists reports whether the person is known to the gateway.
	// Source: persisted state (state.json).
	PersonExists(person string) bool
	// MachineExists reports whether the machine is registered.
	// Source: persisted state (state.json).
	MachineExists(machine string) bool
	// MachineVerified reports state verified (SPEC 3.4), i.e. the
	// machine's sshd host key has been pinned.
	// Source: persisted state (state.json).
	MachineVerified(machine string) bool
	// MachineOnline reports whether the machine has a live tunnel to
	// the gateway right now.
	// Source: in-memory machine registry of the RUNNING gateway - never
	// the state file.
	MachineOnline(machine string) bool
}

// Grant is one permission "person -> machine until T" (SPEC 4.3). The
// deadline is optional; absence is distinct from zero time. When absent
// (Until == nil), the grant remains valid until an administrator explicitly
// revokes it (SPEC §4.3, IAMT-123). A revoked grant keeps its RevokedAt
// so the denial can say "revoked" rather than "no grant".
type Grant struct {
	Person    string
	Machine   string
	Until     *time.Time
	Caps      []string // ["shell"] permits shell and exec; ["exec"] permits exec only
	RevokedAt *time.Time
}

// HasUntil returns true if the Until deadline was specified in the grant.
func (g Grant) HasUntil() bool {
	return g.Until != nil
}

// IsUntilZero returns true if the Until deadline is present and set to zero time.
func (g Grant) IsUntilZero() bool {
	return g.Until != nil && g.Until.IsZero()
}

// ExecOnly reports whether this grant forbids interactive shell requests.
func (g Grant) ExecOnly() bool {
	return len(g.Caps) == 1 && g.Caps[0] == "exec"
}

// Decision is the answer to "may person X enter machine Y right now".
type Decision struct {
	Allowed bool
	Reason  DenyReason // ReasonNone when Allowed is true
}

// Limits caps live sessions; zero means unlimited. Negative values are
// rejected at NewEngine.
type Limits struct {
	PerPerson  int
	PerMachine int
}

// SessionID identifies one live session inside this engine. The zero
// value is never issued: the id field is unexported (no outsider can
// forge an arbitrary number) and the engine's counter starts at one,
// so in the event journal zero means exactly "no session" and is
// marshalled as null, never as a number.
type SessionID struct{ n uint64 }

// Valid reports whether the id was actually issued by the engine.
func (id SessionID) Valid() bool { return id.n > 0 }

// Uint64 returns the numeric form of a valid id.
func (id SessionID) Uint64() uint64 { return id.n }

// String renders the id for logs; a zero id never looks like a number.
func (id SessionID) String() string {
	if id.n == 0 {
		return "session:<invalid>"
	}
	return "session:" + strconv.FormatUint(id.n, 10)
}

// MarshalJSON writes a zero id as null so the journal can never
// mistake "no session" for session number zero.
func (id SessionID) MarshalJSON() ([]byte, error) {
	if id.n == 0 {
		return []byte("null"), nil
	}
	return []byte(strconv.FormatUint(id.n, 10)), nil
}

// Session describes a live session as its owner opened it.
type Session struct {
	ID       SessionID
	Person   string
	Machine  string
	OpenedAt time.Time
	ExecOnly bool
}

// ErrNoGrant is returned by Revoke when there is nothing to revoke.
var ErrNoGrant = errors.New("acl: no grant for this person-machine pair")

// The single clock rule (SPEC 6.4): every time value entering this
// package arrives as an argument from the gateway's UTC clock. Nothing
// here ever calls time.Now, which is what makes deadlines testable.

type grantKey struct{ person, machine string }

type liveSession struct {
	session  Session
	onRevoke func(DenyReason) // may be nil: no notification requested
}

// Engine answers access questions, counts live sessions and runs the
// revocation/expiry notifications. It is safe for concurrent use; one
// mutex covers grants, sessions and counters, which is what makes
// "revoked the instant it happens" race-free even against a session
// opened a millisecond earlier (see Revoke).
type Engine struct {
	view   View
	limits Limits

	mu         sync.Mutex
	grants     map[grantKey]*Grant
	sessions   map[SessionID]*liveSession
	nextID     uint64 // issued as SessionID{n: ++nextID}; starts at zero so no issued id is zero
	perPerson  map[string]int
	perMachine map[string]int
}

// NewEngine wires the ACL to a state view and session limits.
func NewEngine(view View, limits Limits) (*Engine, error) {
	if view == nil {
		return nil, errors.New("acl: view is required")
	}
	if limits.PerPerson < 0 || limits.PerMachine < 0 {
		return nil, errors.New("acl: negative session limit")
	}
	return &Engine{
		view:       view,
		limits:     limits,
		grants:     make(map[grantKey]*Grant),
		sessions:   make(map[SessionID]*liveSession),
		perPerson:  make(map[string]int),
		perMachine: make(map[string]int),
	}, nil
}

// AddGrant installs the permission, replacing any previous grant for the
// same pair - including a revoked one: re-granting is how an admin gives
// access back (SPEC 3.3). The deadline is validated here, at write time,
// not at check time (SPEC 4.3: contradictory pairs are rejected on
// entry). issuedAt is the gateway's notion of "now" at issuance.
func (e *Engine) AddGrant(g Grant, issuedAt time.Time) error {
	if err := validateGrant(g, issuedAt); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	gg := g
	e.grants[grantKey{g.Person, g.Machine}] = &gg
	return nil
}

func validateGrant(g Grant, issuedAt time.Time) error {
	if g.Person == "" {
		return errors.New("acl: grant names no person")
	}
	if g.Machine == "" {
		return errors.New("acl: grant names no machine")
	}
	if g.HasUntil() {
		if g.IsUntilZero() {
			return errors.New("acl: deadline is zero time")
		}
		// "Deadline without a zone" surfaces here as time.Local: whoever
		// parsed it fell back to the gateway's local zone, which the SPEC
		// forbids (times are ISO-8601 with zone, UTC preferred).
		if g.Until.Location() == time.Local {
			return errors.New("acl: deadline carries no explicit zone; use UTC")
		}
		if !g.Until.After(issuedAt) {
			return errors.New("acl: deadline is in the past or not after the issue time")
		}
	}
	// The capability set is part of the grant (SPEC 4.3). A grant has exactly
	// one capability: shell preserves the original shell-and-exec behaviour,
	// while exec permits only a non-interactive command.
	if len(g.Caps) != 1 || (g.Caps[0] != "shell" && g.Caps[0] != "exec") {
		return errors.New("acl: caps must be exactly [\"shell\"] or [\"exec\"] in 1.0")
	}
	return nil
}

// Revoke marks the grant revoked at now and kills every live session
// running on it immediately, notifying each owner with DenyGrantRevoked
// (SPEC 6.4: revocation closes live sessions without delay). The engine
// lock spans "mark + collect", so a session opened a millisecond before
// the revoke is killed exactly like an old one: either it is already in
// the registry when Revoke runs, or it never opens. Callbacks run after
// the lock is released, so a callback may call back into the engine.
// Returns how many live sessions were killed.
func (e *Engine) Revoke(person, machine string, now time.Time) (int, error) {
	return e.RevokeBecause(person, machine, now, DenyGrantRevoked)
}

// RevokeBecause is Revoke for a caller that takes the grant away only to
// put it back changed - narrowed, shortened, moved to a new name - and
// tells the owners of the ended sessions why (IAMT-440). Told "revoked",
// they went to ask for access they still had.
func (e *Engine) RevokeBecause(person, machine string, now time.Time, why DenyReason) (int, error) {
	e.mu.Lock()
	g, ok := e.grants[grantKey{person, machine}]
	if !ok {
		e.mu.Unlock()
		return 0, ErrNoGrant
	}
	if g.RevokedAt == nil {
		t := now
		g.RevokedAt = &t
	}
	ids := make([]SessionID, 0)
	for id, ls := range e.sessions {
		if ls.session.Person == person && ls.session.Machine == machine {
			ids = append(ids, id)
		}
	}
	notes := e.killLocked(ids, why)
	e.mu.Unlock()
	runNotes(notes)
	return len(ids), nil
}

// Check answers "may this person open another session on this machine
// right now". It counts live sessions, so it also refuses when a session
// limit is full. now is the gateway's UTC time, injected.
func (e *Engine) Check(person, machine string, now time.Time) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	if reason := e.checkLocked(person, machine, now); reason != ReasonNone {
		return Decision{Allowed: false, Reason: reason}
	}
	return Decision{Allowed: true, Reason: ReasonNone}
}

// Order of checks is part of the contract: the first applicable reason
// wins, so a given state always denies with the same reason.
func (e *Engine) checkLocked(person, machine string, now time.Time) DenyReason {
	if !e.view.PersonExists(person) {
		return DenyUnknownPerson
	}
	if !e.view.MachineExists(machine) {
		return DenyUnknownMachine
	}
	g, ok := e.grants[grantKey{person, machine}]
	if !ok {
		return DenyNoGrant
	}
	if g.RevokedAt != nil {
		return DenyGrantRevoked
	}
	if g.HasUntil() && !now.Before(*g.Until) {
		return DenyGrantExpired
	}
	if !e.view.MachineVerified(machine) {
		return DenyMachineUnverified
	}
	if !e.view.MachineOnline(machine) {
		return DenyMachineOffline
	}
	if e.limits.PerPerson > 0 && e.perPerson[person] >= e.limits.PerPerson {
		return DenyPersonSessionLimit
	}
	if e.limits.PerMachine > 0 && e.perMachine[machine] >= e.limits.PerMachine {
		return DenyMachineSessionLimit
	}
	return ReasonNone
}

// OpenSession atomically checks and registers a live session. On success
// the owner receives a Session and must Close it exactly once when done;
// on denial it receives a *DenyError with the typed reason. onRevoke, if
// not nil, is called once with the reason if the session is later killed
// by Revoke or SweepExpired - the single line the person sees (SPEC
// 6.4). It is never called for a normal Close.
func (e *Engine) OpenSession(person, machine string, now time.Time, onRevoke func(DenyReason)) (*Session, error) {
	e.mu.Lock()
	if reason := e.checkLocked(person, machine, now); reason != ReasonNone {
		e.mu.Unlock()
		return nil, &DenyError{Reason: reason}
	}
	e.nextID++
	if e.nextID == 0 {
		e.nextID = 1
	}
	g := e.grants[grantKey{person, machine}]
	s := &Session{ID: SessionID{n: e.nextID}, Person: person, Machine: machine, OpenedAt: now, ExecOnly: g.ExecOnly()}
	e.sessions[s.ID] = &liveSession{session: *s, onRevoke: onRevoke}
	e.perPerson[person]++
	e.perMachine[machine]++
	e.mu.Unlock()
	return s, nil
}

// Close closes the session the owner is done with. It is idempotent on
// purpose: closing a session that Revoke or SweepExpired already killed
// reports false and changes nothing, so all three ways out - normal
// close, revocation, expiry - converge on the same counters. now is
// accepted for symmetry with the rest of the API (call sites log it).
func (e *Engine) Close(id SessionID, now time.Time) bool {
	if !id.Valid() {
		return false // zero ids are never issued and never close anything
	}
	e.mu.Lock()
	_, alive := e.sessions[id]
	if alive {
		e.killLocked([]SessionID{id}, ReasonNone)
	}
	e.mu.Unlock()
	return alive
}

// SweepExpired kills every live session whose grant deadline has passed
// by now, notifying owners with DenyGrantExpired. Revoke is synchronous
// because the admin action itself is the event; expiry has no such
// event, so the gateway drives it from a ticker - one second is a good
// period (SPEC 6.4 wants expiry to bite without noticeable delay).
// Returns how many sessions were killed.
func (e *Engine) SweepExpired(now time.Time) int {
	e.mu.Lock()
	var expiredIDs, revokedIDs []SessionID
	for id, ls := range e.sessions {
		g, ok := e.grants[grantKey{ls.session.Person, ls.session.Machine}]
		if !ok {
			continue
		}
		if g.RevokedAt != nil {
			revokedIDs = append(revokedIDs, id)
		} else if g.HasUntil() && !now.Before(*g.Until) {
			expiredIDs = append(expiredIDs, id)
		}
	}
	notes := e.killLocked(revokedIDs, DenyGrantRevoked)
	notes = append(notes, e.killLocked(expiredIDs, DenyGrantExpired)...)
	e.mu.Unlock()
	runNotes(notes)
	return len(revokedIDs) + len(expiredIDs)
}

// ParseSessionID parses the string form String() produces back into a
// SessionID. It is the admin surface's way to turn "sessions active"
// output back into an argument for Kill (PROTOCOL §6, "sessions.kill"):
// nothing else in this package needs to forge an id from text.
func ParseSessionID(s string) (SessionID, error) {
	if !strings.HasPrefix(s, "session:") {
		return SessionID{}, fmt.Errorf("acl: %q is not a valid session id (want \"session:<positive integer>\")", s)
	}
	rawNum := strings.TrimPrefix(s, "session:")
	n, err := strconv.ParseUint(rawNum, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != rawNum {
		return SessionID{}, fmt.Errorf("acl: %q is not a valid session id (want \"session:<positive integer>\")", s)
	}
	return SessionID{n: n}, nil
}

// Sessions returns a snapshot of every currently live session. It exists
// for the admin "sessions active" listing (SPEC §3.3): the engine is the
// only place that knows what is live right now, so a caller must not
// reconstruct this from the state file.
func (e *Engine) Sessions() []Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Session, 0, len(e.sessions))
	for _, ls := range e.sessions {
		out = append(out, ls.session)
	}
	return out
}

// Kill forcibly ends one specific live session by id and notifies its
// owner with reason, exactly like Revoke does for every session of a
// grant. Close (above) is deliberately silent - it is used when a session
// ends on its own and there is no one left to notify - but admin
// "sessions kill" (SPEC §3.3) needs the owner's channel to actually close,
// which only the notification callback can do. Returns whether a live
// session was found and killed.
func (e *Engine) Kill(id SessionID, now time.Time, reason DenyReason) bool {
	if !id.Valid() {
		return false
	}
	e.mu.Lock()
	_, alive := e.sessions[id]
	var notes []killNote
	if alive {
		notes = e.killLocked([]SessionID{id}, reason)
	}
	e.mu.Unlock()
	runNotes(notes)
	return alive
}

// SessionCounts returns snapshots of the live-session counters, keyed by
// person and by machine. Absent key means zero.
func (e *Engine) SessionCounts() (perPerson, perMachine map[string]int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := make(map[string]int, len(e.perPerson))
	for k, v := range e.perPerson {
		p[k] = v
	}
	m := make(map[string]int, len(e.perMachine))
	for k, v := range e.perMachine {
		m[k] = v
	}
	return p, m
}

// GrantsFor returns a snapshot of every active (unrevoked, unexpired) grant
// for the specified person. Machines that no longer exist according to the
// view are omitted. The engine is the single source of truth for living
// permissions: callers must ask the engine rather than reading state files
// directly to prevent drift between advertised and enforced access.
func (e *Engine) GrantsFor(person string, now time.Time) []Grant {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.view.PersonExists(person) {
		return nil
	}
	out := make([]Grant, 0)
	for k, g := range e.grants {
		if k.person != person {
			continue
		}
		if g.RevokedAt != nil {
			continue
		}
		if g.HasUntil() && !now.Before(*g.Until) {
			continue
		}
		if !e.view.MachineExists(k.machine) {
			continue
		}
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Machine < out[j].Machine
	})
	return out
}

type killNote struct {
	cb  func(DenyReason)
	why DenyReason
}

// killLocked removes the sessions, keeps the counters exact and returns
// the notifications to deliver. Callers must run runNotes after
// releasing e.mu: callbacks may re-enter the engine.
func (e *Engine) killLocked(ids []SessionID, why DenyReason) []killNote {
	var notes []killNote
	for _, id := range ids {
		ls, ok := e.sessions[id]
		if !ok {
			continue
		}
		delete(e.sessions, id)
		if n := e.perPerson[ls.session.Person]; n <= 1 {
			delete(e.perPerson, ls.session.Person)
		} else {
			e.perPerson[ls.session.Person] = n - 1
		}
		if n := e.perMachine[ls.session.Machine]; n <= 1 {
			delete(e.perMachine, ls.session.Machine)
		} else {
			e.perMachine[ls.session.Machine] = n - 1
		}
		if ls.onRevoke != nil {
			notes = append(notes, killNote{cb: ls.onRevoke, why: why})
		}
	}
	return notes
}

// runNotes delivers each notification in its own goroutine: the caller
// of Revoke or SweepExpired never blocks on a subscriber. This matters
// because SweepExpired runs on the gateway's one-second timer - a slow
// session owner must not stall the sweep of everyone else. The lock is
// already released by the time this runs, so a callback may re-enter
// the engine safely.
func runNotes(notes []killNote) {
	for _, n := range notes {
		go n.cb(n.why)
	}
}
