package state

import (
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const CurrentSchema = 1

// MaxGoalHistory is the durable per-person/per-machine history bound. The
// current declaration is separate from this list: clearing the current goal
// never erases the audit history, and loading a history never promotes an old
// entry back to current.
const MaxGoalHistory = 20

// MaxGoalBytes bounds one goal stored in state.json. Goals are operator
// context, not command payloads, but an unbounded admin field would still be
// an easy state-file growth primitive.
const MaxGoalBytes = 4096

// MaxRecentCommands is the structural ceiling of the per-pair recent-command
// buffer (IAMT-409). The configured maximum (config: recent_commands_max,
// default 10) may never exceed it: this constant is what Validate holds a
// hand-edited or carried-over state.json to, the way MaxGoalHistory does for
// goals.
const MaxRecentCommands = 20

// zonedRegex matches ISO-8601 timestamps that explicitly include a timezone
// (either 'Z'/'z' or '+/-HH:MM' or '+/-HHMM').
// This follows the strict lesson from umtunnel/Middle.cs (line 70).
var zonedRegex = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?\s*([Zz]|[+-]\d{2}:?\d{2})$`)

// ZonedTime wraps time.Time and strictly validates that any parsed or
// deserialized timestamp is an ISO-8601 string with an explicit time zone.
type ZonedTime struct {
	time.Time
	raw string
}

// NewZonedTime creates a ZonedTime from a time.Time.
func NewZonedTime(t time.Time) ZonedTime {
	return ZonedTime{Time: t}
}

// ParseZonedTime parses an ISO-8601 string ensuring it has an explicit time zone.
func ParseZonedTime(s string) (ZonedTime, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ZonedTime{}, fmt.Errorf("%w: timestamp is empty", ErrInvalidTime)
	}
	if !zonedRegex.MatchString(s) {
		return ZonedTime{}, fmt.Errorf("%w: %q (must be ISO-8601 with timezone, e.g. 2026-09-12T12:00:00Z)", ErrInvalidTime, s)
	}

	// Normalize space to 'T' for standard RFC3339 parser
	normalized := strings.Replace(s, " ", "T", 1)

	// If timezone is +HHMM without colon, insert colon for RFC3339
	if idx := strings.LastIndexAny(normalized, "+-"); idx != -1 && len(normalized)-idx == 5 {
		if !strings.Contains(normalized[idx:], ":") {
			normalized = normalized[:idx+3] + ":" + normalized[idx+3:]
		}
	}

	t, err := time.Parse(time.RFC3339Nano, normalized)
	if err != nil {
		t, err = time.Parse(time.RFC3339, normalized)
		if err != nil {
			return ZonedTime{}, fmt.Errorf("%w: %v", ErrInvalidTime, err)
		}
	}

	return ZonedTime{Time: t, raw: s}, nil
}

// String returns RFC3339 representation or raw string.
func (zt ZonedTime) String() string {
	if zt.raw != "" {
		return zt.raw
	}
	if zt.IsZero() {
		return "0001-01-01T00:00:00Z"
	}
	return zt.Time.Format(time.RFC3339Nano)
}

// MarshalJSON marshals ZonedTime to JSON.
func (zt ZonedTime) MarshalJSON() ([]byte, error) {
	if zt.IsZero() {
		return json.Marshal("0001-01-01T00:00:00Z")
	}
	return json.Marshal(zt.Time.Format(time.RFC3339Nano))
}

// UnmarshalJSON unmarshals and validates that the JSON string is a valid ISO-8601 with timezone.
func (zt *ZonedTime) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := ParseZonedTime(s)
	if err != nil {
		return err
	}
	*zt = parsed
	return nil
}

// Key represents a public key associated with a Person.
type Key struct {
	Fingerprint string    `json:"fingerprint"`
	Pub         string    `json:"pub"`
	Added       ZonedTime `json:"added"`
}

// Person represents a human user or administrator in the gateway.
type Person struct {
	Name string `json:"name"`
	Role string `json:"role"` // "user" | "admin"
	Keys []Key  `json:"keys"`
}

// Door represents an ephemeral open access door on a machine.
// Sessions is a pointer so that "absent" is distinct from "zero" (§4.3, Defect 8).
type Door struct {
	ID                string     `json:"id"`
	PubKey            string     `json:"pubkey"`
	Opened            ZonedTime  `json:"opened"`
	Sessions          *int       `json:"sessions,omitempty"`
	ClosesWhenIdle    *ZonedTime `json:"closesWhenIdle,omitempty"`
	ClosesAtTheLatest *ZonedTime `json:"closesAtTheLatest,omitempty"`
}

// HasSessions returns true if sessions was specified on the door.
func (d Door) HasSessions() bool {
	return d.Sessions != nil
}

// SessionCount returns the session count, or 0 if unspecified.
func (d Door) SessionCount() int {
	if d.Sessions == nil {
		return 0
	}
	return *d.Sessions
}

// EnrolPending is the one-time secret and ephemeral public key that an
// enrol code (PROTOCOL §3.2) is currently bound to: while it is set, the
// holder of the matching secret may dial as username "enrol" with the
// matching key and complete the registration exactly once. The hash is
// HMAC-SHA-256 of the raw secret under the gateway's enrolHMACKey; the
// raw secret itself is never persisted (state.json is read by anyone who
// reaches the disk). The successful enrol transaction clears this in
// the same atomic write that creates the machine entry (PROTOCOL §3.2:
// "one atomic write creates the machine as enrolled and removes the
// temporary public key / marks the secret as used").
type EnrolPending struct {
	SecretHash [32]byte  `json:"secretHash"` // raw HMAC output; JSON marshals [32]byte as an array of 32 numbers
	PublicKey  string    `json:"publicKey"`  // ssh-ed25519 authorized_keys line
	Expires    ZonedTime `json:"expires"`
}

// PendingEnrolment is a not-yet-consumed enrol code minted by
// `machines.enrol-code`. With IAMT-336 / 1.3, the code is unbound: the
// machine name and OS user are NOT bound at mint time and are sent by
// the machine itself in the enrol body (PROTOCOL §3.2/§6, SPEC §3.4).
// The pending entry therefore carries only the secret hash, the
// ephemeral public key the machine dials with, and the expiry.
//
// Two JSON fields are kept for backwards compatibility with state.json
// files written before IAMT-336: `name` and `osUser`. The new code
// never sets them — they are present in the struct only so old files
// still unmarshal without error. They are not consulted by any code
// path that creates or consumes an enrolment. The JSON tags stay (no
// `omitempty`) so an old file's values still round-trip into memory
// if an old build reads them.
//
// Lookups go by secret hash (`FindPendingEnrolmentBySecretHash`)
// rather than by machine name — there is no name to look up by.
type PendingEnrolment struct {
	Name       string    `json:"name,omitempty"`
	OSUser     string    `json:"osUser,omitempty"`
	SecretHash [32]byte  `json:"secretHash"`
	PublicKey  string    `json:"publicKey"`
	Expires    ZonedTime `json:"expires"`
}

// BootstrapPending is the one-time secret and ephemeral public key that
// the bootstrap reference (PROTOCOL §3.3) is currently bound to. While
// it is set, the holder of the matching token may dial as username
// "bootstrap" and complete admin.claim exactly once. After admin.claim
// succeeds this is cleared in the same atomic write.
type BootstrapPending struct {
	SecretHash [32]byte  `json:"secretHash"`
	PublicKey  string    `json:"publicKey"`
	Expires    ZonedTime `json:"expires"`
}

// PairingPending is the active pairing window (PROTOCOL §3.4, IAMT-323):
// the six-digit PIN an administrator-to-be must present, hashed under
// the same gateway HMAC key as every other one-time secret. Unlike
// BootstrapPending it carries no public key: the client dials with its
// own permanent key instead of one derived from the secret, so there is
// nothing to bind up front. While it is set, a well-formed key may dial
// as username "pairing" and complete admin.pair exactly once within the
// TTL; the field is cleared in the same atomic write that creates the
// admin. Starting a new window overwrites an active one; stopping clears
// it.
type PairingPending struct {
	SecretHash [32]byte  `json:"secretHash"`
	Expires    ZonedTime `json:"expires"`

	// Misses is how many wrong PINs THIS window has been asked, counted
	// across every address (M-13, code review 23.09.2026, review F-06).
	// The per-address limiter bans one address after three misses; that
	// is worth nothing against an attacker with an IPv6 /64 or a
	// botnet, and a six-digit PIN is 10^6 guesses. The count lives on
	// the window because the window is what the attacker is spending
	// the guesses on: past the limit it is cleared in the same atomic
	// write that recorded the miss, and the search has to start over
	// against a PIN that has never been seen. Omitted when zero, so a
	// window written by an earlier build round-trips byte for byte.
	Misses int `json:"misses,omitempty"`
}

// The closed value sets of the two §4.3 machine fields that record what the
// gateway has learned about a machine. Named constants rather than loose
// strings because both sets are interfaces: hkstatus is read by the door rule
// ("mismatch forbids the door") and osUserStatus decides whether a login may
// use verifiedOsUser at all, so a typo in either would silently disable a
// guard instead of failing loudly.
const (
	// HostKeyStatusUnverified: the gateway has never compared the target sshd
	// host key of this machine against the pinned one. It is the state of
	// every machine that has not been probed yet, i.e. of every record written
	// before these fields existed.
	HostKeyStatusUnverified = "unverified"
	// HostKeyStatusMatch: the last comparison agreed with sshdHostKey.
	HostKeyStatusMatch = "match"
	// HostKeyStatusMismatch: the last comparison found a DIFFERENT key. The
	// suspicion is remembered here; §4.3 forbids opening the door while it is
	// set. (Writing it, and enforcing the door rule, is IAMT-91 steps 2-4.)
	HostKeyStatusMismatch = "mismatch"

	// OSUserStatusPending: the OS user has not yet been proved by an SSH
	// public-key user-auth probe.
	OSUserStatusPending = "pending"
	// OSUserStatusVerified: the probe succeeded and verifiedOsUser holds the
	// account it succeeded for.
	OSUserStatusVerified = "verified"
	// OSUserStatusRejected: the probe was attempted and refused.
	OSUserStatusRejected = "rejected"
)

// Machine represents a registered target machine behind NAT.
//
// The five fields below sshdHostKey are the §4.3 record of what the gateway
// has LEARNED about the machine: which sshd host key it actually presented,
// whether that key matched the pinned one, which OS user was asked for and
// whether it was proved. They are memory, not policy: the comparison itself
// happens in the live handshake, and these fields are what makes its outcome
// survive a restart. Absent means "never checked" - see applySpecDefaults.
type Machine struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	State       string  `json:"state"` // "enrolled" | "verified"
	MachineKey  string  `json:"machineKey"`
	SSHDHostKey *string `json:"sshdHostKey,omitempty"`
	// ObservedSSHDHostKey is the host key the target sshd presented at the last
	// observation. Optional: absent is not the zero key, it is "never seen".
	ObservedSSHDHostKey *string `json:"observedSSHDHostKey,omitempty"`
	// HostKeyStatus is one of the HostKeyStatus* values above (§4.3 closed set).
	HostKeyStatus string `json:"hostKeyStatus"`
	// RequestedOSUser is the unconfirmed account from Set up or
	// `machines set-user`. The gateway logs in only as VerifiedOSUser.
	RequestedOSUser string `json:"requestedOsUser"`
	// VerifiedOSUser is the account an SSH public-key user-auth probe actually
	// succeeded for. Optional: absent is not "", it is "never proved".
	VerifiedOSUser *string `json:"verifiedOsUser,omitempty"`
	// OSUserStatus is one of the OSUserStatus* values above (§4.3 closed set).
	OSUserStatus string        `json:"osUserStatus"`
	OSUser       string        `json:"osUser"`
	Door         *Door         `json:"door,omitempty"`
	EnrolPending *EnrolPending `json:"enrolPending,omitempty"`
}

// IsValidHostKeyStatus reports whether s is a member of the §4.3
// hostKeyStatus set. The empty string is deliberately NOT a member: it means
// "the field was not in the file", which the disk boundary turns into
// HostKeyStatusUnverified before anyone compares against it.
func IsValidHostKeyStatus(s string) bool {
	switch s {
	case HostKeyStatusUnverified, HostKeyStatusMatch, HostKeyStatusMismatch:
		return true
	default:
		return false
	}
}

// IsValidOSUserStatus reports whether s is a member of the §4.3 osUserStatus
// set. Empty is not a member, for the same reason as above.
func IsValidOSUserStatus(s string) bool {
	switch s {
	case OSUserStatusPending, OSUserStatusVerified, OSUserStatusRejected:
		return true
	default:
		return false
	}
}

// applySpecDefaults fills the §4.3 defaults of the two closed-set machine
// fields into a record that does not carry them yet.
//
// It exists for one reason: state.json files written before these fields
// existed contain no hostKeyStatus and no osUserStatus, and such a file is not
// broken - it is a record of a gateway that never checked. Absent therefore
// means HostKeyStatusUnverified ("never compared") and OSUserStatusPending
// ("never proved"), never the empty string, which is not a member of either
// closed set and would make every later comparison against these fields
// silently false.
//
// It never fails and it never invents anything else: a default is applied only
// where the field is empty, so a recorded suspicion ("mismatch") can never be
// overwritten by loading a file.
func (m *Machine) applySpecDefaults() {
	if m == nil {
		return
	}
	if m.HostKeyStatus == "" {
		m.HostKeyStatus = HostKeyStatusUnverified
	}
	if m.OSUserStatus == "" {
		m.OSUserStatus = OSUserStatusPending
	}
}

// applyMachineDefaults applies applySpecDefaults to every machine of the state.
func (s *State) applyMachineDefaults() {
	if s == nil {
		return
	}
	for i := range s.Machines {
		s.Machines[i].applySpecDefaults()
	}
}

// applyGrantCapsCompat collapses a pre-1.6 caps list to the single element
// 1.6 requires, and runs in the load pipeline BEFORE Validate.
//
// Until 1.6 the loader accepted any non-empty list whose every element was
// "shell" - ["shell"], ["shell","shell"] and so on all meant the same thing,
// because nothing interpreted the field. 1.6 gives caps a meaning and writes
// exactly one element, so the strict form is right for every WRITE. Making
// the READ equally strict was an accident of unifying the three validators,
// and it is not a cheap accident: Validate runs on every open of the store,
// so a hand-restored state.json carrying the old shape would not lose one
// grant - it would stop the gateway from starting at all. The gateway is
// what hands out access to machines; refusing to boot is the most expensive
// failure it owns, and no writer we ever shipped could produce that file.
//
// So: strict on the way out, tolerant on the way in. The duplicate form is
// normalised here and never reaches Validate, and an unknown capability is
// still a refusal - being tolerant about a shape is not the same as being
// tolerant about a meaning.
func (s *State) applyGrantCapsCompat() {
	for i := range s.Grants {
		caps := s.Grants[i].Caps
		if len(caps) < 2 {
			continue
		}
		allShell := true
		for _, c := range caps {
			if c != "shell" {
				allShell = false
				break
			}
		}
		if allShell {
			s.Grants[i].Caps = []string{"shell"}
		}
	}
}

// Grant represents an access permission from a person to a machine.
//
// Machine holds the machine *id*, never its name: the id is assigned once at enrol
// and is the only stable handle on a machine. A name is a label and may be reused,
// so a grant pointing at a name follows the label onto whatever box wears it next.
//
// MachineKeyFingerprint pins the identity of the machine the grant was issued
// against: the OpenSSH fingerprint of machine.machineKey at the moment of issue.
// A machine that is re-keyed - or removed and re-enrolled under the same id - no
// longer matches the pin, and the grant is revoked explicitly with an audit record
// instead of quietly resurrecting access. The field is mandatory. §4.3 lists only
// {person, machine, until, caps}; this one extra field is the minimum needed to bind
// a grant to an identity rather than to a reusable label (see REPORT-R3.md).
//
// Until is a pointer so that "absent" is distinct from "zero time" (Gate 6).
type Grant struct {
	Person                string     `json:"person"`
	Machine               string     `json:"machine"`
	MachineKeyFingerprint string     `json:"machineKeyFingerprint"`
	Until                 *ZonedTime `json:"until,omitempty"`
	Caps                  []string   `json:"caps"`
}

// GoalHistoryEntry is one explicit goal declaration. History is stored
// newest first so the bounded eviction rule is a simple tail truncation.
type GoalHistoryEntry struct {
	Goal  string    `json:"goal"`
	SetAt ZonedTime `json:"setAt"`
}

// GoalRecord is the current goal and its durable history for one person and
// machine pair. Current may be empty after an explicit clear while History
// remains available for review.
type GoalRecord struct {
	Person  string             `json:"person"`
	Machine string             `json:"machine"`
	Current string             `json:"current"`
	History []GoalHistoryEntry `json:"history,omitempty"`
}

// RecentCommand is one executed exec command kept as the classifier's context
// (IAMT-409). Command and Response are already scrubbed (risk.ScrubCommand
// is applied by the gateway AT WRITE TIME, not at send time): the state
// stores clean text. Exit is "" when the command reported no outcome (the
// machine vanished before an exit status arrived), otherwise a decimal code
// or "signal <name>". Response holds the first lines of the machine's
// output; trimming against the limits is RecordCommand's job.
type RecentCommand struct {
	Command  string    `json:"command"`
	Exit     string    `json:"exit,omitempty"`
	Response string    `json:"response,omitempty"`
	At       ZonedTime `json:"at"`
}

// CommandHistoryRecord is the bounded recent-command buffer of one person and
// machine pair (IAMT-409). Entries is newest-first, like GoalRecord.History,
// so the bounded eviction is the same tail truncation. It exists so the
// classifier sees the course of the agent's work and not one command in a
// vacuum — the storage mirrors the goals exactly because exec mode gives
// every command its own session, and a per-session memory would remember
// nothing.
type CommandHistoryRecord struct {
	Person  string          `json:"person"`
	Machine string          `json:"machine"`
	Entries []RecentCommand `json:"entries,omitempty"`
}

// RecentCommandBudgetOverhead is the per-entry cost, in characters, charged
// against the configured budget beyond the command/response/exit text itself:
// the JSON object's keys and punctuation the request actually sends.
const RecentCommandBudgetOverhead = 8

// ExternalRiskKeyState is deliberately metadata only. It records whether an
// active classifier key exists and a non-reversible fingerprint of it; the
// key itself never crosses the state boundary.
type ExternalRiskKeyState struct {
	Present     bool   `json:"present"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// HasUntil returns true if the Until deadline was specified in the grant.
func (g Grant) HasUntil() bool {
	return g.Until != nil
}

// IsUntilZero returns true if the Until deadline is present and set to zero time.
func (g Grant) IsUntilZero() bool {
	return g.Until != nil && g.Until.IsZero()
}

// State is the root data structure of state.json (§4.3).
//
// PendingEnrolments is additive to schema 1: a file written before
// IAMT-203 simply has no such key, which decodes as a nil slice — the
// zero value already means "no pending enrolments", so no migration or
// schema bump is needed.
type State struct {
	Schema            int                    `json:"schema"`
	People            []Person               `json:"people"`
	Machines          []Machine              `json:"machines"`
	Grants            []Grant                `json:"grants"`
	PendingEnrolments []PendingEnrolment     `json:"pendingEnrolments,omitempty"`
	BootstrapPending  *BootstrapPending      `json:"bootstrapPending,omitempty"`
	PairingPending    *PairingPending        `json:"pairingPending,omitempty"`
	Goals             []GoalRecord           `json:"goals,omitempty"`
	CommandHistory    []CommandHistoryRecord `json:"commandHistory,omitempty"`
	ExternalRiskKey   *ExternalRiskKeyState  `json:"externalRiskKey,omitempty"`
}

// NewState returns an initialized empty State with the current schema.
func NewState() *State {
	return &State{
		Schema:            CurrentSchema,
		People:            make([]Person, 0),
		Machines:          make([]Machine, 0),
		Grants:            make([]Grant, 0),
		PendingEnrolments: make([]PendingEnrolment, 0),
		Goals:             make([]GoalRecord, 0),
	}
}

// Clone creates a deep copy of the State.
func (s *State) Clone() *State {
	if s == nil {
		return nil
	}
	cp := &State{
		Schema:            s.Schema,
		People:            make([]Person, len(s.People)),
		Machines:          make([]Machine, len(s.Machines)),
		Grants:            make([]Grant, len(s.Grants)),
		PendingEnrolments: make([]PendingEnrolment, len(s.PendingEnrolments)),
		Goals:             make([]GoalRecord, len(s.Goals)),
		CommandHistory:    make([]CommandHistoryRecord, len(s.CommandHistory)),
	}
	copy(cp.PendingEnrolments, s.PendingEnrolments)
	for i, goal := range s.Goals {
		cp.Goals[i] = GoalRecord{
			Person:  goal.Person,
			Machine: goal.Machine,
			Current: goal.Current,
			History: make([]GoalHistoryEntry, len(goal.History)),
		}
		copy(cp.Goals[i].History, goal.History)
	}
	for i, hist := range s.CommandHistory {
		cp.CommandHistory[i] = CommandHistoryRecord{
			Person:  hist.Person,
			Machine: hist.Machine,
			Entries: make([]RecentCommand, len(hist.Entries)),
		}
		copy(cp.CommandHistory[i].Entries, hist.Entries)
	}

	for i, p := range s.People {
		cp.People[i] = Person{
			Name: p.Name,
			Role: p.Role,
			Keys: make([]Key, len(p.Keys)),
		}
		copy(cp.People[i].Keys, p.Keys)
	}

	for i, m := range s.Machines {
		cp.Machines[i] = Machine{
			ID:              m.ID,
			Name:            m.Name,
			State:           m.State,
			MachineKey:      m.MachineKey,
			HostKeyStatus:   m.HostKeyStatus,
			RequestedOSUser: m.RequestedOSUser,
			OSUserStatus:    m.OSUserStatus,
			OSUser:          m.OSUser,
		}
		if m.SSHDHostKey != nil {
			v := *m.SSHDHostKey
			cp.Machines[i].SSHDHostKey = &v
		}
		// The two observed facts are pointers, so a shallow copy would hand the
		// caller a handle on the store's own memory: Get() returns a Clone, and a
		// caller mutating *m.ObservedSSHDHostKey must not be able to rewrite what
		// the store remembers about a host key mismatch.
		if m.ObservedSSHDHostKey != nil {
			v := *m.ObservedSSHDHostKey
			cp.Machines[i].ObservedSSHDHostKey = &v
		}
		if m.VerifiedOSUser != nil {
			v := *m.VerifiedOSUser
			cp.Machines[i].VerifiedOSUser = &v
		}
		if m.Door != nil {
			doorCopy := *m.Door
			if m.Door.Sessions != nil {
				sess := *m.Door.Sessions
				doorCopy.Sessions = &sess
			}
			if m.Door.ClosesWhenIdle != nil {
				cwi := *m.Door.ClosesWhenIdle
				doorCopy.ClosesWhenIdle = &cwi
			}
			if m.Door.ClosesAtTheLatest != nil {
				ctl := *m.Door.ClosesAtTheLatest
				doorCopy.ClosesAtTheLatest = &ctl
			}
			cp.Machines[i].Door = &doorCopy
		}
		if m.EnrolPending != nil {
			epCopy := *m.EnrolPending
			cp.Machines[i].EnrolPending = &epCopy
		}
	}

	for i, g := range s.Grants {
		cp.Grants[i] = Grant{
			Person:                g.Person,
			Machine:               g.Machine,
			MachineKeyFingerprint: g.MachineKeyFingerprint,
			Caps:                  make([]string, len(g.Caps)),
		}
		copy(cp.Grants[i].Caps, g.Caps)
		if g.Until != nil {
			u := *g.Until
			cp.Grants[i].Until = &u
		}
	}

	if s.BootstrapPending != nil {
		bp := *s.BootstrapPending
		cp.BootstrapPending = &bp
	}

	if s.PairingPending != nil {
		pp := *s.PairingPending
		cp.PairingPending = &pp
	}

	if s.ExternalRiskKey != nil {
		kp := *s.ExternalRiskKey
		cp.ExternalRiskKey = &kp
	}

	return cp
}

// ValidateGoalText validates one goal. Empty text is allowed because it is
// the explicit clear operation; callers that persist history entries apply
// the non-empty check separately.
func ValidateGoalText(goal string) error {
	if !utf8.ValidString(goal) {
		return fmt.Errorf("goal goal is not valid UTF-8")
	}
	if len(goal) > MaxGoalBytes {
		return fmt.Errorf("goal goal exceeds %d bytes", MaxGoalBytes)
	}
	if strings.IndexByte(goal, 0) >= 0 {
		return fmt.Errorf("goal goal contains NUL")
	}
	return nil
}

func cloneGoalRecord(in GoalRecord) GoalRecord {
	out := GoalRecord{
		Person:  in.Person,
		Machine: in.Machine,
		Current: in.Current,
		History: make([]GoalHistoryEntry, len(in.History)),
	}
	copy(out.History, in.History)
	return out
}

// GoalFor returns a copy of the pair's record. The boolean is false when
// the pair has never had an goal declaration; a missing record and an
// existing record whose current goal was explicitly cleared are distinct.
func (s *State) GoalFor(person, machine string) (GoalRecord, bool) {
	if s == nil {
		return GoalRecord{}, false
	}
	for _, goal := range s.Goals {
		if goal.Person == person && goal.Machine == machine {
			return cloneGoalRecord(goal), true
		}
	}
	return GoalRecord{}, false
}

// SetGoal records an explicit current goal for a person/machine pair. A
// non-empty goal is inserted at the front of the bounded history. An empty
// goal clears only Current and deliberately leaves History intact.
func (s *State) SetGoal(person, machine, goal string, now time.Time) (GoalRecord, error) {
	if s == nil {
		return GoalRecord{}, fmt.Errorf("state is nil")
	}
	if !s.HasPerson(person) {
		return GoalRecord{}, fmt.Errorf("goal person %q does not exist", person)
	}
	if _, ok := s.MachineByID(machine); !ok {
		return GoalRecord{}, fmt.Errorf("goal machine %q does not exist", machine)
	}
	if err := ValidateGoalText(goal); err != nil {
		return GoalRecord{}, err
	}
	goal = strings.TrimSpace(goal)
	if err := ValidateGoalText(goal); err != nil {
		return GoalRecord{}, err
	}

	index := -1
	for i := range s.Goals {
		if s.Goals[i].Person == person && s.Goals[i].Machine == machine {
			index = i
			break
		}
	}
	if index < 0 {
		s.Goals = append(s.Goals, GoalRecord{Person: person, Machine: machine})
		index = len(s.Goals) - 1
	}
	record := &s.Goals[index]
	if goal == "" {
		record.Current = ""
		return cloneGoalRecord(*record), nil
	}
	record.Current = goal
	record.History = append([]GoalHistoryEntry{{Goal: goal, SetAt: NewZonedTime(now)}}, record.History...)
	if len(record.History) > MaxGoalHistory {
		record.History = record.History[:MaxGoalHistory]
	}
	return cloneGoalRecord(*record), nil
}

// RecentCommandsFor returns a copy of the pair's recent-command buffer
// (IAMT-409). The boolean is false when the pair has none.
func (s *State) RecentCommandsFor(person, machine string) (CommandHistoryRecord, bool) {
	if s == nil {
		return CommandHistoryRecord{}, false
	}
	for _, hist := range s.CommandHistory {
		if hist.Person == person && hist.Machine == machine {
			return cloneCommandHistoryRecord(hist), true
		}
	}
	return CommandHistoryRecord{}, false
}

// RecordCommand prepends one executed command to the pair's buffer and trims
// it to maxCommands entries within the total character budget (IAMT-409).
// The caller has already scrubbed Command and Response — scrubbing here a
// second time would hide a caller that forgot; the state stores only what it
// is given. A missing person or machine refuses the write for the same
// reason SetGoal does, and a removed pair's buffer is dropped by reconcile.
func (s *State) RecordCommand(person, machine string, entry RecentCommand, maxCommands, budget int) (CommandHistoryRecord, error) {
	if s == nil {
		return CommandHistoryRecord{}, fmt.Errorf("state is nil")
	}
	if !s.HasPerson(person) {
		return CommandHistoryRecord{}, fmt.Errorf("recent-command person %q does not exist", person)
	}
	if _, ok := s.MachineByID(machine); !ok {
		return CommandHistoryRecord{}, fmt.Errorf("recent-command machine %q does not exist", machine)
	}
	if strings.TrimSpace(entry.Command) == "" {
		return CommandHistoryRecord{}, fmt.Errorf("recent-command command must not be empty")
	}
	if entry.At.IsZero() {
		return CommandHistoryRecord{}, fmt.Errorf("recent-command timestamp must not be zero")
	}
	if maxCommands < 1 {
		maxCommands = 1
	}
	if maxCommands > MaxRecentCommands {
		maxCommands = MaxRecentCommands
	}

	index := -1
	for i := range s.CommandHistory {
		if s.CommandHistory[i].Person == person && s.CommandHistory[i].Machine == machine {
			index = i
			break
		}
	}
	if index < 0 {
		s.CommandHistory = append(s.CommandHistory, CommandHistoryRecord{Person: person, Machine: machine})
		index = len(s.CommandHistory) - 1
	}
	record := &s.CommandHistory[index]
	record.Entries = append([]RecentCommand{entry}, record.Entries...)
	record.Entries = TrimRecentCommands(record.Entries, maxCommands, budget)
	return cloneCommandHistoryRecord(*record), nil
}

// TrimRecentCommands is the bounded-eviction rule of the recent-command
// buffer, as one pure function so the write path and any read-side
// re-trim share it exactly. Entries arrive newest-first. The newest entry
// always survives: if it alone exceeds the budget its RESPONSE is cut first
// (the machine's answer matters less than what was asked), then its COMMAND,
// each cut carrying the ellipsis at the cut. Older entries beyond the budget
// are dropped whole — a half-command from yesterday answers nothing.
func TrimRecentCommands(entries []RecentCommand, maxCommands, budget int) []RecentCommand {
	if len(entries) > maxCommands {
		entries = entries[:maxCommands]
	}
	if budget < 1 {
		budget = 1
	}
	if len(entries) == 0 {
		return entries
	}
	cost := func(e RecentCommand) int {
		return len(e.Command) + len(e.Response) + len(e.Exit) + RecentCommandBudgetOverhead
	}
	if cost(entries[0]) > budget {
		entries[0] = truncateRecentCommand(entries[0], budget)
	}
	used := cost(entries[0])
	kept := 1
	for kept < len(entries) && used+cost(entries[kept]) <= budget {
		used += cost(entries[kept])
		kept++
	}
	return entries[:kept]
}

// truncateRecentCommand shrinks one entry to the budget: response first,
// command second, ellipsis at every cut.
func truncateRecentCommand(e RecentCommand, budget int) RecentCommand {
	ellipsis := "…"
	base := len(e.Command) + len(e.Exit) + RecentCommandBudgetOverhead
	if base > budget {
		keep := budget - len(e.Exit) - RecentCommandBudgetOverhead - len(ellipsis)
		if keep < 0 {
			keep = 0
		}
		cut := e.Command[:utf8Cut(e.Command, keep)]
		e.Command = cut + ellipsis
		e.Response = ""
		return e
	}
	room := budget - base - len(ellipsis)
	if room < 0 {
		room = 0
	}
	e.Response = e.Response[:utf8Cut(e.Response, room)] + ellipsis
	return e
}

// utf8Cut returns the byte length of the longest prefix of s within limit
// bytes that does not split a rune.
func utf8Cut(s string, limit int) int {
	if limit >= len(s) {
		return len(s)
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return cut
}

func cloneCommandHistoryRecord(in CommandHistoryRecord) CommandHistoryRecord {
	out := CommandHistoryRecord{Person: in.Person, Machine: in.Machine, Entries: make([]RecentCommand, len(in.Entries))}
	copy(out.Entries, in.Entries)
	return out
}

// MachineByID returns a copy of the machine registered under the given id.
func (s *State) MachineByID(id string) (Machine, bool) {
	if s == nil {
		return Machine{}, false
	}
	for _, m := range s.Machines {
		if m.ID == id {
			return m, true
		}
	}
	return Machine{}, false
}

// HasPerson reports whether a person with that name is registered.
func (s *State) HasPerson(name string) bool {
	if s == nil {
		return false
	}
	for _, p := range s.People {
		if p.Name == name {
			return true
		}
	}
	return false
}

// HasAnyAdmin reports whether the state already has at least one person
// with role "admin". Used to refuse admin.claim after the gateway has
// been initialised: the bootstrap path is one-shot, even if its token
// file is still readable on disk (PROTOCOL §3.3).
func (s *State) HasAnyAdmin() bool {
	if s == nil {
		return false
	}
	for _, p := range s.People {
		if p.Role == "admin" {
			return true
		}
	}
	return false
}

// FindEnrolPendingByKey returns the machine id and the EnrolPending
// entry whose ephemeral PublicKey matches the given authorized_keys
// line. The second return is false when no machine currently has a
// pending enrol for that key — i.e. the key has already been consumed,
// expired, or was never issued. Note this is by PUBLIC KEY, not by the
// secret: the secret arrives only inside the "enrol" exec body, and
// the SSH handshake has already authenticated the key before that body
// is read. One secretHash maps to exactly one EnrolPending, so a public
// key fingerprint lookup is enough to find the right machine.
func (s *State) FindEnrolPendingByKey(pubKey string) (string, *EnrolPending, bool) {
	if s == nil {
		return "", nil, false
	}
	for i := range s.Machines {
		m := &s.Machines[i]
		if m.EnrolPending == nil {
			continue
		}
		if m.EnrolPending.PublicKey == pubKey {
			return m.ID, m.EnrolPending, true
		}
	}
	return "", nil, false
}

// FindPendingEnrolmentBySecretHash resolves a pending enrolment from the
// HMAC-SHA-256 hash of its raw secret (state.HashEnrolSecret). This is
// the IAMT-336 replacement for FindPendingEnrolmentByKey and
// PendingEnrolmentByName: the enrol code no longer binds a machine
// name at mint time, so the secret hash is the only key that
// identifies which pending entry a given enrol body should consume.
//
// Hash comparison uses hmac.Equal (constant-time) and a nil state is
// treated as "no pending enrolments". The boolean is false iff no
// entry matches — including the empty state case.
func (s *State) FindPendingEnrolmentBySecretHash(hash [32]byte) (*PendingEnrolment, bool) {
	if s == nil {
		return nil, false
	}
	for i := range s.PendingEnrolments {
		if hmac.Equal(s.PendingEnrolments[i].SecretHash[:], hash[:]) {
			return &s.PendingEnrolments[i], true
		}
	}
	return nil, false
}

// FindPendingEnrolmentByFingerprint resolves a pending enrolment from
// the SHA256 fingerprint of its ephemeral public key — the identity the
// SSH handshake established, and the only one an enrol connection has
// before its exec body arrives.
//
// It exists to tell two failures apart that the secret hash alone
// cannot: a caller whose invitation is still sitting right here but who
// presented the wrong secret (a typo, a truncated paste), and a caller
// whose invitation was redeemed or revoked between the handshake and
// the exec body (a replay, which is the sign that an invitation leaked).
// Both look identical to FindPendingEnrolmentBySecretHash — no entry
// matches — and reporting a typo as a replay would turn the one signal
// an operator watches for into noise.
func (s *State) FindPendingEnrolmentByFingerprint(fingerprint string) (*PendingEnrolment, bool) {
	if s == nil || fingerprint == "" {
		return nil, false
	}
	for i := range s.PendingEnrolments {
		fp, err := ComputeFingerprint(s.PendingEnrolments[i].PublicKey)
		if err == nil && fp == fingerprint {
			return &s.PendingEnrolments[i], true
		}
	}
	return nil, false
}

// GrantAccess issues a grant from person to the machine with the given id, pinning the
// machine's current key. This is the supported way to create a grant: it is what makes
// the grant point at an identity (id + key) instead of at a reusable label.
func (s *State) GrantAccess(person, machineID string, until *ZonedTime, caps ...string) error {
	if s == nil {
		return fmt.Errorf("state is nil")
	}
	if !s.HasPerson(person) {
		return fmt.Errorf("cannot grant: person %q does not exist", person)
	}
	m, ok := s.MachineByID(machineID)
	if !ok {
		return fmt.Errorf("cannot grant: machine %q does not exist (grants reference machine id, not name)", machineID)
	}
	fp, err := ComputeFingerprint(m.MachineKey)
	if err != nil {
		return fmt.Errorf("cannot grant on machine %q: %w", machineID, err)
	}
	for _, g := range s.Grants {
		if g.Person == person && g.Machine == machineID {
			return fmt.Errorf("cannot grant: %s already has a grant on machine %q", person, machineID)
		}
	}
	if len(caps) == 0 {
		caps = []string{"shell"}
	}
	g := Grant{
		Person:                person,
		Machine:               machineID,
		MachineKeyFingerprint: fp,
		Caps:                  append([]string(nil), caps...),
	}
	if until != nil {
		u := *until
		g.Until = &u
	}
	s.Grants = append(s.Grants, g)
	return nil
}

// RevokeAccess removes the grant for the pair (person, machine id) if it is present.
func (s *State) RevokeAccess(person, machineID string) bool {
	if s == nil {
		return false
	}
	for i, g := range s.Grants {
		if g.Person == person && g.Machine == machineID {
			s.Grants = append(s.Grants[:i], s.Grants[i+1:]...)
			return true
		}
	}
	return false
}

// SetGrantCaps changes what an existing grant permits, leaving its
// deadline and its machine-key fingerprint alone. It reports the previous
// capability, and false when there is no such grant.
//
// It exists because changing a mode is ONE intent and must be one
// operation. The alternative available until 21.09.2026 was to revoke and
// grant again -- GrantAccess refuses a pair that already has a grant --
// and that leaves a moment with no grant at all. A failure in that moment
// takes the access away instead of changing it, and the person who asked
// for "exec instead of shell" is left with neither.
func (s *State) SetGrantCaps(person, machineID string, caps []string) (string, bool) {
	if s == nil {
		return "", false
	}
	for i := range s.Grants {
		if s.Grants[i].Person == person && s.Grants[i].Machine == machineID {
			was := ""
			if len(s.Grants[i].Caps) > 0 {
				was = s.Grants[i].Caps[0]
			}
			s.Grants[i].Caps = append([]string(nil), caps...)
			return was, true
		}
	}
	return "", false
}

// SetGrantUntil changes when an existing grant expires, leaving its
// capability and its machine-key fingerprint alone. It reports the
// previous deadline (nil when the grant had none), and false when there
// is no such grant.
//
// Same reason as SetGrantCaps: moving a deadline is ONE intent. The
// revoke-then-grant alternative refuses a pair that already has a grant
// only after the revoke has landed, leaving a moment with no grant -- a
// failure there takes the access away instead of extending it. Whether
// the new deadline shortens the old one, and therefore whether live
// sessions must die, is the caller's decision: the store records the
// fact, it does not judge it.
func (s *State) SetGrantUntil(person, machineID string, until *ZonedTime) (*ZonedTime, bool) {
	if s == nil {
		return nil, false
	}
	for i := range s.Grants {
		if s.Grants[i].Person == person && s.Grants[i].Machine == machineID {
			was := s.Grants[i].Until
			if until != nil {
				u := *until
				s.Grants[i].Until = &u
			} else {
				s.Grants[i].Until = nil
			}
			return was, true
		}
	}
	return nil, false
}

// RenamePerson changes a person's name and moves every reference that
// travels by name — grants and goals — in the SAME state mutation.
//
// One mutation is not a convenience. reconcileGrants withdraws every
// grant whose person has vanished, and reconcileGoals drops their goals;
// renaming the Person row alone would therefore cascade-revoke the very
// access a rename is meant to preserve. Renaming all three inside the
// caller's single Update closure means the reconcile pass never sees an
// intermediate state where grants point at a person who is not there.
//
// The grants keep their machine-key pins, deadlines and capabilities
// untouched. The pair (new name, machine) is new to reconcileGrants'
// eyes, but the pin travels inside the grant record itself, so the
// identity the grant was issued against is exactly what survives.
//
// RenameMachine is the display-label counterpart: machines are
// referenced by id everywhere durable, so only Machine.Name changes and
// there is nothing to carry along. It refuses a name already taken by
// another machine's name or id — the client resolves machines by name,
// and an ambiguous name resolves to the wrong box.
func (s *State) RenamePerson(from, to string) (bool, error) {
	if s == nil {
		return false, fmt.Errorf("state is nil")
	}
	if !s.HasPerson(from) {
		return false, nil
	}
	if s.HasPerson(to) {
		return false, fmt.Errorf("person %q already exists", to)
	}
	for i := range s.People {
		if s.People[i].Name == from {
			s.People[i].Name = to
		}
	}
	for i := range s.Grants {
		if s.Grants[i].Person == from {
			s.Grants[i].Person = to
		}
	}
	for i := range s.Goals {
		if s.Goals[i].Person == from {
			s.Goals[i].Person = to
		}
	}
	return true, nil
}

// RenameMachine changes the display label of one machine. The id is the
// only durable handle (Grant.Machine, GoalRecord.Machine, the journal)
// and does not move; see RenamePerson for the collision rule.
func (s *State) RenameMachine(id, name string) (bool, error) {
	if s == nil {
		return false, fmt.Errorf("state is nil")
	}
	if _, ok := s.MachineByID(id); !ok {
		return false, nil
	}
	for _, m := range s.Machines {
		if m.ID != id && (m.Name == name || m.ID == name) {
			return false, fmt.Errorf("machine name %q is already taken", name)
		}
	}
	for i := range s.Machines {
		if s.Machines[i].ID == id {
			s.Machines[i].Name = name
		}
	}
	return true, nil
}

// RevocationReason explains why the store withdrew a grant on its own.
type RevocationReason string

const (
	// RevokedMachineRemoved: the machine the grant was issued for is gone.
	RevokedMachineRemoved RevocationReason = "machine-removed"
	// RevokedMachineRekeyed: the machine still carries the same id but presents a
	// different machineKey, i.e. it is different hardware or a re-enrolled box.
	RevokedMachineRekeyed RevocationReason = "machine-key-changed"
	// RevokedPersonRemoved: the person the grant was issued to is gone.
	RevokedPersonRemoved RevocationReason = "person-removed"
)

// Revocation is the audit record of a grant withdrawn by the store during a
// transaction. Every revocation has to reach the event log (§3.5): access
// disappearing without a trace is the failure mode this machinery exists to prevent.
type Revocation struct {
	Person       string
	Machine      string
	PinnedKeyFP  string
	CurrentKeyFP string
	Caps         []string
	Reason       RevocationReason
}

// String renders the revocation for the journal and for error messages.
func (r Revocation) String() string {
	switch r.Reason {
	case RevokedMachineRekeyed:
		return fmt.Sprintf("grant %s -> %s revoked: machine key changed (grant was pinned to %s, machine now presents %s)",
			r.Person, r.Machine, r.PinnedKeyFP, r.CurrentKeyFP)
	case RevokedMachineRemoved:
		return fmt.Sprintf("grant %s -> %s revoked: machine no longer exists (grant was pinned to %s)",
			r.Person, r.Machine, r.PinnedKeyFP)
	default:
		return fmt.Sprintf("grant %s -> %s revoked: person no longer exists", r.Person, r.Machine)
	}
}

// grantPair identifies a grant by the pair of principals it authorizes.
type grantPair struct {
	person  string
	machine string
}

// reconcileGrants brings draft.Grants in line with the people and machines of the
// draft, using prev - the last state known to be valid - to tell two very different
// situations apart:
//
//   - a grant that already existed and lost its target (machine deleted, machine
//     re-keyed, person deleted) is *revoked*: dropped from the draft and reported as a
//     Revocation so the caller writes it to the event log;
//   - a grant that appears in this very transaction and points at nothing is left
//     untouched, so that Validate rejects the whole transaction loudly. A grant into
//     the void is an operator mistake, not a cascade.
//
// The pin of a pre-existing pair is carried over from prev and cannot be rewritten by
// the transaction: re-pinning an old grant onto a new key is exactly the resurrection
// this guards against. Creating a grant for a pair that did not exist before is an
// explicit act of issuing access, so such a grant may be pinned here to the key the
// machine presents in this transaction.
func reconcileGrants(prev, draft *State) []Revocation {
	if draft == nil {
		return nil
	}

	prevGrants := make(map[grantPair]Grant)
	if prev != nil {
		for _, g := range prev.Grants {
			prevGrants[grantPair{g.Person, g.Machine}] = g
		}
	}

	machineFP := make(map[string]string, len(draft.Machines))
	for _, m := range draft.Machines {
		fp, err := ComputeFingerprint(m.MachineKey)
		if err != nil {
			// Unusable key material: Validate rejects the machine itself.
			fp = ""
		}
		machineFP[m.ID] = fp
	}

	var revocations []Revocation
	kept := make([]Grant, 0, len(draft.Grants))

	for _, g := range draft.Grants {
		old, existed := prevGrants[grantPair{g.Person, g.Machine}]
		if !existed {
			// New pair: pin it to the machine present in this transaction unless the
			// caller stated a pin itself - then Validate checks what was stated.
			if g.MachineKeyFingerprint == "" {
				if fp, ok := machineFP[g.Machine]; ok && fp != "" {
					g.MachineKeyFingerprint = fp
				}
			}
			kept = append(kept, g)
			continue
		}

		// Pre-existing pair: its identity is whatever it was pinned to, not what this
		// transaction claims it to be.
		g.MachineKeyFingerprint = old.MachineKeyFingerprint

		if !draft.HasPerson(g.Person) {
			revocations = append(revocations, Revocation{
				Person: g.Person, Machine: g.Machine,
				PinnedKeyFP: g.MachineKeyFingerprint,
				Caps:        append([]string(nil), g.Caps...),
				Reason:      RevokedPersonRemoved,
			})
			continue
		}
		fp, ok := machineFP[g.Machine]
		if !ok {
			revocations = append(revocations, Revocation{
				Person: g.Person, Machine: g.Machine,
				PinnedKeyFP: g.MachineKeyFingerprint,
				Caps:        append([]string(nil), g.Caps...),
				Reason:      RevokedMachineRemoved,
			})
			continue
		}
		if fp != g.MachineKeyFingerprint {
			revocations = append(revocations, Revocation{
				Person: g.Person, Machine: g.Machine,
				PinnedKeyFP: g.MachineKeyFingerprint, CurrentKeyFP: fp,
				Caps:   append([]string(nil), g.Caps...),
				Reason: RevokedMachineRekeyed,
			})
			continue
		}
		kept = append(kept, g)
	}

	draft.Grants = kept
	return revocations
}

// reconcileGoals drops any Goals entry whose person or machine no longer
// exists in the draft. Goals has no cascade of its own (unlike Grants,
// there is no separate command that withdraws a goal when its target
// disappears), and Validate requires every Goals entry to reference an
// existing person and machine (review19 finding 1) - without this, removing
// a machine or person that ever had a goal declared for it fails validation
// forever, recoverable only by hand-editing state.json.
//
// Unlike a grant, a stale goal carries no live access to revoke and no
// session to kill, so there is nothing to report to the event log the way
// reconcileGrants reports a Revocation: this is a plain cascade delete, not
// an audited withdrawal. It also happens to be the right call on privacy
// grounds - a goal can hold sensitive free text, and removing the person or
// machine it was declared for is exactly when it should stop being kept.
func reconcileGoals(draft *State) {
	if draft == nil {
		return
	}
	kept := make([]GoalRecord, 0, len(draft.Goals))
	for _, goal := range draft.Goals {
		if !draft.HasPerson(goal.Person) {
			continue
		}
		if _, ok := draft.MachineByID(goal.Machine); !ok {
			continue
		}
		kept = append(kept, goal)
	}
	draft.Goals = kept
}

// reconcileRecentCommands drops any recent-command buffer (IAMT-409) whose
// person or machine no longer exists, for the same reasons as reconcileGoals:
// Validate requires the reference to resolve, and a removed pair's command
// history is exactly the thing that should stop being kept.
func reconcileRecentCommands(draft *State) {
	if draft == nil {
		return
	}
	kept := make([]CommandHistoryRecord, 0, len(draft.CommandHistory))
	for _, hist := range draft.CommandHistory {
		if !draft.HasPerson(hist.Person) {
			continue
		}
		if _, ok := draft.MachineByID(hist.Machine); !ok {
			continue
		}
		kept = append(kept, hist)
	}
	draft.CommandHistory = kept
}
