package admin

// commands.go is the typed request/response surface for the SPEC §3.3
// admin command groups plus whoami, mirroring the shapes
// internal/gateway/admin_role.go renders. Every function marshals proto:1
// into the request and unmarshals the raw result into the shape it
// promises; a response that does not fit the shape becomes a returned
// error through the same DisallowUnknownFields discipline the gateway
// itself uses for requests, not a panic.
//
// Every function below calls unmarshalResult and checks its error BEFORE
// returning the value it filled in: "return out, unmarshalResult(...)"
// would evaluate the (still zero) out ahead of the call that fills it in
// (Go evaluates a return statement's operands left to right), silently
// handing back zero values on success. That shape is deliberately never
// used here.

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// unmarshalResult decodes raw into v strictly: an unknown field or wrong
// type in a result the gateway sent is exactly the kind of "garbage from
// the gateway" this client must never trust blindly.
func unmarshalResult(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return fmt.Errorf("admin: response has no result")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("admin: result does not match the expected shape: %w", err)
	}
	return nil
}

// Whoami --------------------------------------------------------------

type WhoamiResult struct {
	Subject    string `json:"subject"`
	Role       string `json:"role"`
	ServerTime string `json:"serverTime"`
	Person     string `json:"person,omitempty"`
}

func (c *Conn) Whoami() (WhoamiResult, error) {
	var out WhoamiResult
	raw, err := c.Exec("whoami", map[string]any{"proto": 1})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// people.* --------------------------------------------------------------

type KeyView struct {
	Fingerprint string `json:"fingerprint"`
	Pub         string `json:"pubkey"`
	Added       string `json:"added"`
}

type PersonView struct {
	Name string    `json:"name"`
	Role string    `json:"role"`
	Keys []KeyView `json:"keys"`
}

func (c *Conn) PeopleAdd(name, role string, keys []string) (PersonView, error) {
	var out PersonView
	raw, err := c.Exec("people.add", map[string]any{"proto": 1, "name": name, "role": role, "keys": keys})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

func (c *Conn) PeopleRemove(name string) (bool, error) {
	var out struct {
		Removed string `json:"removed"`
	}
	raw, err := c.Exec("people.remove", map[string]any{"proto": 1, "name": name})
	if err != nil {
		return false, err
	}
	if err := unmarshalResult(raw, &out); err != nil {
		return false, err
	}
	return out.Removed == name, nil
}

// PeopleRename changes a person's name on the gateway. Grants and goals
// move with the name; sessions opened under the old name are closed and
// their count is reported.
func (c *Conn) PeopleRename(from, to string) (terminated int, err error) {
	var out struct {
		From               string `json:"from"`
		To                 string `json:"to"`
		TerminatedSessions int    `json:"terminatedSessions"`
	}
	raw, err := c.Exec("people.rename", map[string]any{"proto": 1, "from": from, "to": to})
	if err != nil {
		return 0, err
	}
	if err := unmarshalResult(raw, &out); err != nil {
		return 0, err
	}
	return out.TerminatedSessions, nil
}

func (c *Conn) PeopleList() ([]PersonView, error) {
	var out struct {
		People []PersonView `json:"people"`
	}
	raw, err := c.Exec("people.list", map[string]any{"proto": 1})
	if err != nil {
		return nil, err
	}
	err = unmarshalResult(raw, &out)
	return out.People, err
}

func (c *Conn) PeopleKeysAdd(name, pubkey string) (KeyView, error) {
	var out struct {
		Person string  `json:"person"`
		Key    KeyView `json:"key"`
	}
	raw, err := c.Exec("people.keys.add", map[string]any{"proto": 1, "name": name, "pubkey": pubkey})
	if err != nil {
		return KeyView{}, err
	}
	err = unmarshalResult(raw, &out)
	return out.Key, err
}

func (c *Conn) PeopleKeysRemove(name, fingerprint string) error {
	_, err := c.Exec("people.keys.remove", map[string]any{"proto": 1, "name": name, "fingerprint": fingerprint})
	return err
}

func (c *Conn) PeopleConnectionString(name string) (string, error) {
	var out struct {
		ConnectionString string `json:"connectionString"`
	}
	raw, err := c.Exec("people.connection-string", map[string]any{"proto": 1, "name": name})
	if err != nil {
		return "", err
	}
	err = unmarshalResult(raw, &out)
	return out.ConnectionString, err
}

// machines.* ------------------------------------------------------------

// MachineView mirrors internal/gateway's machineView field for field, and the
// mirror is not optional: unmarshalResult decodes with DisallowUnknownFields,
// so a field the gateway adds and this struct does not carry turns every
// machines.list into an "unknown field" error rather than a longer table.
type MachineView struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	State               string `json:"state"`
	Online              bool   `json:"online"`
	OSUser              string `json:"osUser"`
	RequestedOSUser     string `json:"requestedOsUser"`
	VerifiedOSUser      string `json:"verifiedOsUser,omitempty"`
	OSUserStatus        string `json:"osUserStatus"`
	HostKeyStatus       string `json:"hostKeyStatus"`
	ObservedSSHDHostKey string `json:"observedSSHDHostKey,omitempty"`
	DoorState           string `json:"doorState"`
	DoorOpen            bool   `json:"doorOpen"`
	Reservations        uint32 `json:"reservations"`
}

// PendingEnrolmentView mirrors internal/gateway's pendingEnrolmentView
// (IAMT-336 / 1.3: codes are unbound, so the view only carries the
// expiry — no name, no osUser).
type PendingEnrolmentView struct {
	Expires string `json:"expires"`
}

func (c *Conn) MachinesList() ([]MachineView, []PendingEnrolmentView, error) {
	var out struct {
		Machines          []MachineView          `json:"machines"`
		PendingEnrolments []PendingEnrolmentView `json:"pendingEnrolments"`
	}
	raw, err := c.Exec("machines.list", map[string]any{"proto": 1})
	if err != nil {
		return nil, nil, err
	}
	err = unmarshalResult(raw, &out)
	return out.Machines, out.PendingEnrolments, err
}

// MachineMineView is the item returned by machines.mine (PROTOCOL §6).
type MachineMineView struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Until         string `json:"until"`
	Online        bool   `json:"online"`
	State         string `json:"state"`
	SSHDListening bool   `json:"sshdListening"`
	DoorOpen      bool   `json:"doorOpen"`
	// Caps is the grant's own capability ("shell" or "exec") — added 1.8
	// alongside the same field in internal/gateway/admin_role.go's
	// machineMineView and internal/client.Machine; this package's strict
	// decoder rejects the wire response otherwise.
	Caps []string `json:"caps"`
}

func (c *Conn) MachinesMine() ([]MachineMineView, error) {
	var out struct {
		Machines []MachineMineView `json:"machines"`
	}
	raw, err := c.Exec("machines.mine", map[string]any{"proto": 1})
	if err != nil {
		return nil, err
	}
	err = unmarshalResult(raw, &out)
	return out.Machines, err
}

func (c *Conn) MachinesRemove(id string) error {
	_, err := c.Exec("machines.remove", map[string]any{"proto": 1, "id": id})
	return err
}

// MachinesRename changes a machine's display label. Its id -- the only
// thing grants, goals and the journal reference -- does not move, so
// nothing else about the machine changes.
func (c *Conn) MachinesRename(id, name string) error {
	_, err := c.Exec("machines.rename", map[string]any{"proto": 1, "id": id, "name": name})
	return err
}

// GrantsSetCaps changes what an existing grant permits without taking it
// away first, and reports what it was and how many live sessions the
// change closed. Narrowing shell to exec closes them; widening does not.
func (c *Conn) GrantsSetCaps(person, machine, capability string) (was string, terminated int, err error) {
	// Every field the gateway sends, including the one this caller does
	// not read. unmarshalResult decodes STRICTLY -- an unknown field is
	// an error, not a shrug -- which is right, because a client that
	// quietly ignored a field it did not expect would go on working
	// while drifting out of step with the gateway. The cost is that the
	// struct must mirror the answer, all of it, and on 21.09.2026 it did
	// not: pressing the button got "unknown field \"caps\""
	// AFTER the gateway had already changed the grant.
	var out struct {
		Caps       []string `json:"caps"`
		Was        string   `json:"was"`
		Terminated int      `json:"terminatedSessions"`
	}
	raw, err := c.Exec("grants.set-caps", map[string]any{
		"proto": 1, "person": person, "machine": machine, "caps": []string{capability},
	})
	if err != nil {
		return "", 0, err
	}
	if err := unmarshalResult(raw, &out); err != nil {
		return "", 0, err
	}
	return out.Was, out.Terminated, nil
}

// GrantsExtend moves the deadline of an existing grant (PROTOCOL §6
// "grants.extend"). An empty until makes the grant indefinite. The
// gateway tears down live sessions only when the new deadline cuts the
// old one short; a plain extension leaves every open session alone.
// Until is reported in the gateway's answer the same way grantView
// reports it: the field is absent when there is no deadline.
func (c *Conn) GrantsExtend(person, machine, until string) (newUntil string, was string, terminated int, err error) {
	var out struct {
		Until              *string `json:"until"`
		Was                *string `json:"was"`
		TerminatedSessions int     `json:"terminatedSessions"`
	}
	raw, err := c.Exec("grants.extend", map[string]any{
		"proto": 1, "person": person, "machine": machine, "until": until,
	})
	if err != nil {
		return "", "", 0, err
	}
	if err := unmarshalResult(raw, &out); err != nil {
		return "", "", 0, err
	}
	if out.Until != nil {
		newUntil = *out.Until
	}
	if out.Was != nil {
		was = *out.Was
	}
	return newUntil, was, out.TerminatedSessions, nil
}

func (c *Conn) MachinesSetUser(id, osUser string) error {
	_, err := c.Exec("machines.set-user", map[string]any{"proto": 1, "id": id, "osUser": osUser})
	return err
}

// MachinesInvite mints a one-time enrol code (PROTOCOL §3.2, SPEC §3.4
// step 1 — IAMT-336 / 1.3). It takes no arguments: the invitation is
// not bound to a machine name or to an OS user; both are facts the
// enrolling machine reports about itself in the enrol body, and the
// code itself is the only authorisation to register. TTL is 15 minutes.
//
// The "machines.enrol-code" wire command rejects any old `machine` /
// `osUser` body fields with E_JSON_FIELD_UNKNOWN, so callers from
// before 1.3 cannot silently mint a code that ignores their arguments.
// MachinesInvite mints one invitation for the registration the
// administrator wants to create, under the name he chooses. Since 1.4
// that name is the only argument: the OS account the machine will log
// in as is the machine's own report, made when it redeems this code.
func (c *Conn) MachinesInvite(name string) (code, expires string, err error) {
	var out struct {
		EnrolCode string `json:"enrolCode"`
		Expires   string `json:"expires"`
	}
	raw, err := c.Exec("machines.enrol-code", map[string]any{"proto": 1, "name": name})
	if err != nil {
		return "", "", err
	}
	if err := unmarshalResult(raw, &out); err != nil {
		return "", "", err
	}
	return out.EnrolCode, out.Expires, nil
}

// grants.* --------------------------------------------------------------

type GrantView struct {
	Person  string   `json:"person"`
	Machine string   `json:"machine"`
	Until   string   `json:"until"`
	Caps    []string `json:"caps"`
}

func (c *Conn) GrantsGrant(person, machine, until string, capability ...string) (GrantView, error) {
	var out struct {
		Grant GrantView `json:"grant"`
	}
	caps := grantCapsOrDefault(capability)
	raw, err := c.Exec("grants.grant", map[string]any{"proto": 1, "person": person, "machine": machine, "until": until, "caps": caps})
	if err != nil {
		return GrantView{}, err
	}
	err = unmarshalResult(raw, &out)
	return out.Grant, err
}

func (c *Conn) GrantsRevoke(person, machine string) (terminatedSessions int, err error) {
	var out struct {
		Revoked            bool `json:"revoked"`
		TerminatedSessions int  `json:"terminatedSessions"`
	}
	raw, err := c.Exec("grants.revoke", map[string]any{"proto": 1, "person": person, "machine": machine})
	if err != nil {
		return 0, err
	}
	if err := unmarshalResult(raw, &out); err != nil {
		return 0, err
	}
	return out.TerminatedSessions, nil
}

func (c *Conn) GrantsList(person, machine string) ([]GrantView, error) {
	var out struct {
		Grants []GrantView `json:"grants"`
	}
	req := map[string]any{"proto": 1}
	if person != "" {
		req["person"] = person
	}
	if machine != "" {
		req["machine"] = machine
	}
	raw, err := c.Exec("grants.list", req)
	if err != nil {
		return nil, err
	}
	err = unmarshalResult(raw, &out)
	return out.Grants, err
}

// sessions.* ------------------------------------------------------------

type SessionView struct {
	ID       string `json:"id"`
	Person   string `json:"person"`
	Machine  string `json:"machine"`
	Started  string `json:"started"`
	BytesIn  int64  `json:"bytesIn"`
	BytesOut int64  `json:"bytesOut"`
}

func (c *Conn) SessionsActive() ([]SessionView, error) {
	var out struct {
		Sessions []SessionView `json:"sessions"`
	}
	raw, err := c.Exec("sessions.active", map[string]any{"proto": 1})
	if err != nil {
		return nil, err
	}
	err = unmarshalResult(raw, &out)
	return out.Sessions, err
}

func (c *Conn) SessionsKill(id, reason string) error {
	req := map[string]any{"proto": 1, "id": id}
	if reason != "" {
		req["reason"] = reason
	}
	_, err := c.Exec("sessions.kill", req)
	return err
}

// SessionTail is one chunk of a LIVE session's cast file (IAMT-338).
// Live reports whether more will ever be appended: false means read to
// Total and stop asking.
type SessionTail struct {
	ID     string `json:"id"`
	Offset int64  `json:"offset"`
	Total  int64  `json:"total"`
	Live   bool   `json:"live"`
	Data   string `json:"data"`
	// Mode is how Data is read: "exec" for an exec session's recording,
	// anything else - "cast", or nothing from a gateway before 1.14 - for
	// asciicast (IAMT-453).
	Mode string `json:"mode,omitempty"`
}

// SessionsTail follows a session that is still happening. The caller
// repeats with offset+len(decoded data) until offset reaches Total, the
// same way RecordingsFetch walks a finished recording.
func (c *Conn) SessionsTail(id string, offset, limit int64) (SessionTail, error) {
	var out SessionTail
	raw, err := c.Exec("sessions.tail", map[string]any{"proto": 1, "id": id, "offset": offset, "limit": limit})
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	return out, nil
}

// recordings.* ----------------------------------------------------------

type RecordingView struct {
	ID      string `json:"id"`
	Machine string `json:"machine"`
	Person  string `json:"person"`

	// SessionID -- the identifier the session ran under; the history
	// view shows this one. The ID above is a hash of the recording's
	// path on the gateway and is not shown in the history line.
	SessionID string `json:"sessionId"`

	// Mode: "exec" — a single command, recorded line by line; otherwise
	// a terminal session in asciicast format. The reader must know
	// which BEFORE opening the bytes.
	Mode string `json:"mode,omitempty"`

	Started  string `json:"started"`
	Ended    string `json:"ended"`
	BytesIn  int64  `json:"bytesIn"`
	BytesOut int64  `json:"bytesOut"`
}

// RecordingsList filters recordings by machine (if given) and/or by the
// time window [from, to] (RFC3339, inclusive on StartedAt — PROTOCOL
// §6 recordings.list). Protocol §6 makes from?/to? optional; an empty
// string in either one lifts the corresponding filter.
func (c *Conn) RecordingsList(machine, from, to string) ([]RecordingView, error) {
	var out struct {
		Recordings []RecordingView `json:"recordings"`
	}
	req := map[string]any{"proto": 1}
	if machine != "" {
		req["machine"] = machine
	}
	if from != "" {
		req["from"] = from
	}
	if to != "" {
		req["to"] = to
	}
	raw, err := c.Exec("recordings.list", req)
	if err != nil {
		return nil, err
	}
	err = unmarshalResult(raw, &out)
	return out.Recordings, err
}

type RecordingChunk struct {
	ID     string `json:"id"`
	Part   string `json:"part"`
	Offset int64  `json:"offset"`
	Total  int64  `json:"total"`
	SHA256 string `json:"sha256"`
	Data   string `json:"data"` // base64
}

func (c *Conn) RecordingsFetch(id, part string, offset, limit int64) (RecordingChunk, error) {
	var out RecordingChunk
	raw, err := c.Exec("recordings.fetch", map[string]any{"proto": 1, "id": id, "part": part, "offset": offset, "limit": limit})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// SessionsHistory reads one page of the session history, newest first,
// and reports how many rows the filter matched in total so a caller can
// say "1-20 of 137" without asking again.
//
// limit 0 means "the gateway's own page size", not "everything": the
// unbounded answer is what made this unusable over a month of history.
func (c *Conn) SessionsHistory(person, machine, from, to string, limit, offset int) (SessionHistoryPage, error) {
	var out SessionHistoryPage
	req := map[string]any{"proto": 1}
	if person != "" {
		req["person"] = person
	}
	if machine != "" {
		req["machine"] = machine
	}
	if from != "" {
		req["from"] = from
	}
	if to != "" {
		req["to"] = to
	}
	if limit > 0 {
		req["limit"] = limit
	}
	if offset > 0 {
		req["offset"] = offset
	}
	raw, err := c.Exec("sessions.history", req)
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// SessionHistoryPage is one page plus the size of the whole answer.
type SessionHistoryPage struct {
	Sessions []SessionHistoryView `json:"sessions"`
	Total    int                  `json:"total"`
	Offset   int                  `json:"offset"`
	Limit    int                  `json:"limit"`
}

// SessionHistoryView is one SESSION, not one event: a visit, with when it
// began, when it ended and what happened in between.
type SessionHistoryView struct {
	SessionID  string `json:"sessionId,omitempty"`
	Person     string `json:"person"`
	Machine    string `json:"machine"`
	Started    string `json:"started"`
	Ended      string `json:"ended,omitempty"`
	Kind       string `json:"kind"`
	Command    string `json:"command,omitempty"`
	Goal       string `json:"goal,omitempty"`
	Outcome    string `json:"outcome"`
	Risks      int    `json:"risks"`
	RiskLevel  string `json:"riskLevel,omitempty"`
	RiskRule   string `json:"riskRule,omitempty"`
	RiskReason string `json:"riskReason,omitempty"`
}

// RiskCheckResult is a command classification without executing it.
type RiskCheckResult struct {
	Level         string `json:"level"`
	Rule          string `json:"rule"`
	Reason        string `json:"reason"`
	Classifier    string `json:"classifier"`
	Goal          string `json:"goal"`
	GoalApplied   bool   `json:"goalApplied"`
	ExternalError string `json:"externalError,omitempty"`
}

func (c *Conn) RiskCheck(command string) (RiskCheckResult, error) {
	return c.RiskCheckWithGoal(command, "")
}

func (c *Conn) RiskCheckWithGoal(command, goal string) (RiskCheckResult, error) {
	var out RiskCheckResult
	req := map[string]any{"proto": 1, "command": command}
	if goal != "" {
		req["goal"] = goal
	}
	raw, err := c.Exec("risk.check", req)
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// goal.* --------------------------------------------------------------

type GoalHistoryView struct {
	Goal  string `json:"goal"`
	SetAt string `json:"setAt"`
}

type GoalView struct {
	Person  string            `json:"person"`
	Machine string            `json:"machine"`
	Goal    string            `json:"goal"`
	History []GoalHistoryView `json:"history,omitempty"`
}

func (c *Conn) GoalSet(person, machine, goal string) (GoalView, error) {
	var out GoalView
	raw, err := c.Exec("goal.set", map[string]any{"proto": 1, "person": person, "machine": machine, "goal": goal})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

func (c *Conn) GoalCurrent(person, machine string) (GoalView, error) {
	var out GoalView
	raw, err := c.Exec("goal.current", map[string]any{"proto": 1, "person": person, "machine": machine})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

func (c *Conn) GoalHistory(person, machine string) (GoalView, error) {
	var out GoalView
	raw, err := c.Exec("goal.history", map[string]any{"proto": 1, "person": person, "machine": machine})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// GoalList returns every (person, machine) pair that carries a goal
// record, each row with the current goal and bounded history - the
// whole table in ONE round trip, so a page with many grants does not
// dial the gateway once per row (IAMT-405).
type GoalListView struct {
	Goals []GoalView `json:"goals"`
}

func (c *Conn) GoalList() (GoalListView, error) {
	var out GoalListView
	raw, err := c.Exec("goal.list", map[string]any{"proto": 1})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// RiskKeyReplace is deliberately write-only: the request carries the new
// key, while the response contains only presence and a safe fingerprint.
type RiskKeyReplaceResult struct {
	Replaced    bool   `json:"replaced"`
	Present     bool   `json:"present"`
	Fingerprint string `json:"fingerprint"`
}

func (c *Conn) RiskKeyReplace(key string) (RiskKeyReplaceResult, error) {
	var out RiskKeyReplaceResult
	raw, err := c.Exec("risk.key", map[string]any{"proto": 1, "key": key})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// machines.rekey / machines.verify --------------------------------------
//
// Both commands return MachineView. The gateway fills the same host-key and
// OS-user evidence for list and verify, while the client keeps strict decoding
// so a promised response field cannot disappear silently at this boundary.

func (c *Conn) MachinesRekey(id, confirmFingerprint string) (oldKey, newKey string, err error) {
	var out struct {
		ID            string `json:"id"`
		OldHostKey    string `json:"oldHostKey"`
		NewHostKey    string `json:"newHostKey"`
		State         string `json:"state"`
		HostKeyStatus string `json:"hostKeyStatus"`
	}
	raw, err := c.Exec("machines.rekey", map[string]any{"proto": 1, "id": id, "confirmFingerprint": confirmFingerprint})
	if err != nil {
		return "", "", err
	}
	if err := unmarshalResult(raw, &out); err != nil {
		return "", "", err
	}
	return out.OldHostKey, out.NewHostKey, nil
}

func (c *Conn) MachinesVerify(id string) (MachineView, error) {
	var out MachineView
	raw, err := c.Exec("machines.verify", map[string]any{"proto": 1, "id": id})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// gateway.* ---------------------------------------------------------------

func (c *Conn) GatewayFingerprint() ([]string, error) {
	var out struct {
		Fingerprints []string `json:"fingerprints"`
	}
	raw, err := c.Exec("gateway.fingerprint", map[string]any{"proto": 1})
	if err != nil {
		return nil, err
	}
	err = unmarshalResult(raw, &out)
	return out.Fingerprints, err
}

// GatewayStatusResult mirrors the actual result shape of
// internal/gateway's cmdGatewayStatus, which differs from the
// PROTOCOL §6 table (no "version"/"draining"/"diskPercent" in this
// build).
type GatewayStatusResult struct {
	Online           bool                `json:"online"`
	Fingerprints     []string            `json:"fingerprints"`
	MachinesOnline   int                 `json:"machinesOnline"`
	MachinesVerified int                 `json:"machinesVerified"`
	Sessions         int                 `json:"sessions"`
	ServerTime       string              `json:"serverTime"`
	Risk             GatewayRiskStatus   `json:"risk"`
	ExternalRiskKey  ClassifierKeyStatus `json:"externalRiskKey"`
	// Audit is whether the gateway's audit journal is being written
	// (IAMT-451). nil means the gateway does not say - one from before
	// 1.14 - which is not the same as saying it is fine.
	Audit *GatewayAuditStatus `json:"audit,omitempty"`
	// Pairing is the state of the gateway's pairing window (IAMT-331):
	// whether one is open and when it closes itself. nil means the
	// gateway does not say - one from before this field - which is not
	// the same as saying none is open. The PIN never appears here.
	Pairing *GatewayPairingStatus `json:"pairing,omitempty"`
	// Version is the build that answers; DiskPercent how full the disk of
	// its recordings is (nil when it could not be read - DiskError says
	// why - or the gateway is older than 1.14); Draining whether it is
	// stopping (IAMT-466).
	Version     string `json:"version,omitempty"`
	DiskPercent *int   `json:"diskPercent,omitempty"`
	DiskError   string `json:"diskError,omitempty"`
	Draining    bool   `json:"draining"`
}

// GatewayAuditStatus is the audit journal's state. While OK is false the
// gateway refuses everything that would have to be journaled.
type GatewayAuditStatus struct {
	OK         bool   `json:"ok"`
	Since      string `json:"since,omitempty"`
	Error      string `json:"error,omitempty"`
	LostWrites uint64 `json:"lostWrites"`
	// ReadError is set when the gateway could not read its journal to count
	// the last day's risk events; the risk counts are zero then.
	ReadError string `json:"readError,omitempty"`
}

// GatewayPairingStatus is the gateway's pairing window as gateway.status
// reports it (IAMT-331): Active with the moment it closes itself. It
// never carries the PIN — the PIN travels once, in pairing.start's
// reply.
type GatewayPairingStatus struct {
	Active  bool   `json:"active"`
	Expires string `json:"expires,omitempty"`
}

// Problem is the one line an operator must read, or "" when there is
// nothing to say.
func (a *GatewayAuditStatus) Problem() string {
	switch {
	case a == nil:
		return ""
	case !a.OK:
		return fmt.Sprintf("the audit journal is NOT being written (since %s): %s - commands that change anything, new sessions, enrolment and pairing are refused until it writes again", a.Since, a.Error)
	case a.ReadError != "":
		return "the audit journal cannot be read: " + a.ReadError
	}
	return ""
}

type ClassifierKeyStatus struct {
	Present     bool   `json:"present"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// GatewayRiskStatus is the preceding 24-hour risk activity assembled by the
// gateway from its journal. LatestRed is nil when no red command occurred.
type GatewayRiskStatus struct {
	Mode       string `json:"mode"`
	Source     string `json:"source"`
	Classifier string `json:"classifier"`
	// ClassifierSource is "config" or "live", the same distinction Source
	// draws for the mode. ClassifierKey says whether this gateway holds a
	// key at all, which is what decides whether ai and both can be chosen.
	ClassifierSource string                `json:"classifierSource"`
	ClassifierKey    bool                  `json:"classifierKey"`
	Yellow           int                   `json:"yellow"`
	Red              int                   `json:"red"`
	Blocked          int                   `json:"blocked"`
	LatestRed        *GatewayLatestRedRisk `json:"latestRed,omitempty"`
}

// RiskModeResult is the live risk-action response. An empty mode in the
// request reads the current value; a non-empty one persists the switch.
type RiskModeResult struct {
	Mode     string `json:"mode"`
	Source   string `json:"source"`
	Changed  bool   `json:"changed"`
	Previous string `json:"previous"`
}

func (c *Conn) RiskMode(mode string) (RiskModeResult, error) {
	var out RiskModeResult
	req := map[string]any{"proto": 1}
	if mode != "" {
		req["mode"] = mode
	}
	raw, err := c.Exec("risk.mode", req)
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// RiskSourceResult is the live classifier-choice response. An empty
// classifier in the request reads the current value; a non-empty one
// persists the switch.
type RiskSourceResult struct {
	Classifier string `json:"classifier"`
	Source     string `json:"source"`
	Changed    bool   `json:"changed"`
	Previous   string `json:"previous"`
}

func (c *Conn) RiskSource(classifier string) (RiskSourceResult, error) {
	var out RiskSourceResult
	req := map[string]any{"proto": 1}
	if classifier != "" {
		req["classifier"] = classifier
	}
	raw, err := c.Exec("risk.source", req)
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// RiskApprovalResult is the machine-readable result of approving one pending
// red command. Approval is not execution: the exact command must be rerun by
// the same person before ExpiresAt, and the gateway consumes it once.
type RiskApprovalResult struct {
	ApprovalID string `json:"approvalId"`
	Approved   bool   `json:"approved"`
	Changed    bool   `json:"changed"`
	ExpiresAt  string `json:"expiresAt"`
}

func (c *Conn) RiskApprove(approvalID string) (RiskApprovalResult, error) {
	var out RiskApprovalResult
	raw, err := c.Exec("risk.approve", map[string]any{"proto": 1, "approvalId": approvalID})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// HeldCommand is one command the gateway stopped and is holding for its
// person to settle. The command is whole, not scrubbed: a person deciding
// whether it may run must see what they are deciding about.
type HeldCommand struct {
	ApprovalID  string `json:"approvalId"`
	Machine     string `json:"machine"`
	Command     string `json:"command"`
	Rule        string `json:"rule"`
	Reason      string `json:"reason"`
	Level       string `json:"level"`
	RequestedAt string `json:"requestedAt"`
	ExpiresAt   string `json:"expiresAt"`
}

// RiskPending lists what the gateway is holding for this person.
func (c *Conn) RiskPending() ([]HeldCommand, error) {
	var out struct {
		Pending []HeldCommand `json:"pending"`
	}
	raw, err := c.Exec("risk.pending", map[string]any{"proto": 1})
	if err != nil {
		return nil, err
	}
	if err := unmarshalResult(raw, &out); err != nil {
		return nil, err
	}
	return out.Pending, nil
}

// RiskDeny throws one held command away. Refusing is not the same as
// letting it lapse: a refused command is settled, and the list says so at
// once instead of showing it as still under consideration for five
// minutes.
func (c *Conn) RiskDeny(approvalID string) error {
	var out struct {
		Denied string `json:"denied"`
	}
	raw, err := c.Exec("risk.deny", map[string]any{"proto": 1, "approvalId": approvalID})
	if err != nil {
		return err
	}
	return unmarshalResult(raw, &out)
}

type GatewayLatestRedRisk struct {
	Time    string `json:"time"`
	Person  string `json:"person"`
	Machine string `json:"machine"`
	Rule    string `json:"rule"`
}

func (c *Conn) GatewayStatus() (GatewayStatusResult, error) {
	var out GatewayStatusResult
	raw, err := c.Exec("gateway.status", map[string]any{"proto": 1})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// gateway.backup / gateway.rotate-hostkey (remote, admin-issued) delegate
// to internal/gateway/lifecycle.go, the same implementation the local
// "iamtunnel gateway backup|rotate-hostkey" CLI verbs run.

func (c *Conn) GatewayBackup() (id, created string, size int64, sha256 string, err error) {
	var out struct {
		Backup struct {
			ID      string `json:"id"`
			Created string `json:"created"`
			Size    int64  `json:"size"`
			SHA256  string `json:"sha256"`
		} `json:"backup"`
	}
	raw, err := c.Exec("gateway.backup", map[string]any{"proto": 1})
	if err != nil {
		return "", "", 0, "", err
	}
	if err := unmarshalResult(raw, &out); err != nil {
		return "", "", 0, "", err
	}
	return out.Backup.ID, out.Backup.Created, out.Backup.Size, out.Backup.SHA256, nil
}

func (c *Conn) GatewayRotateHostkey() (oldFP, newFP string, err error) {
	var out struct {
		OldFingerprint string `json:"oldFingerprint"`
		NewFingerprint string `json:"newFingerprint"`
	}
	raw, err := c.Exec("gateway.rotate-hostkey", map[string]any{"proto": 1})
	if err != nil {
		return "", "", err
	}
	if err := unmarshalResult(raw, &out); err != nil {
		return "", "", err
	}
	return out.OldFingerprint, out.NewFingerprint, nil
}

// AdminClaimResult is the PROTOCOL §6 result of admin.claim (bootstrap-
// login). internal/gateway serves it from the bootstrap-login role
// (bootstrap_role.go), separately from admin_role.go's command table.
// Exec is reused unchanged: the caller dials with the bootstrap
// ephemeral signer instead of a normal person key (see cmd/iamtunnel's
// admin claim wiring).
type AdminClaimResult struct {
	Person string `json:"person"`
	Role   string `json:"role"`
}

func (c *Conn) AdminClaim(bootstrapToken, pubkey string) (AdminClaimResult, error) {
	var out AdminClaimResult
	raw, err := c.Exec("admin.claim", map[string]any{"proto": 1, "bootstrap": bootstrapToken, "pubkey": pubkey})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// pairing.* / admin.pair -------------------------------------------------
//
// The PIN-pairing surface (SPEC §3.5, PROTOCOL §3.4 — IAMT-323):
// pairing.start/pairing.stop run on a normal admin login; admin.pair is
// the single exec of the "pairing" login, where the caller is not yet
// anybody and its own key is the thing being registered.

// PairingStartResult mirrors internal/gateway's pairingStartResult: the
// PIN (hand it to the new admin over a side channel — it is not in the
// journal), the window expiry, and the pairing reference
// <host>:<port>#<fingerprint> the new admin enters next to the PIN.
type PairingStartResult struct {
	Pin     string `json:"pin"`
	Expires string `json:"expires"`
	Ref     string `json:"ref"`
}

// PairingStart opens a new pairing window; an open window is replaced —
// the old PIN stops working the moment the new one lands.
func (c *Conn) PairingStart() (PairingStartResult, error) {
	var out PairingStartResult
	raw, err := c.Exec("pairing.start", map[string]any{"proto": 1})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// PairingStop closes the pairing window and reports whether one was
// actually open (the command is idempotent, PROTOCOL §3.4).
func (c *Conn) PairingStop() (bool, error) {
	var out struct {
		Stopped bool `json:"stopped"`
	}
	raw, err := c.Exec("pairing.stop", map[string]any{"proto": 1})
	if err != nil {
		return false, err
	}
	if err := unmarshalResult(raw, &out); err != nil {
		return false, err
	}
	return out.Stopped, nil
}

// PairClaim runs the pairing exec ("admin.pair"): a correct PIN
// permanently registers the caller's own long-term key — the one this
// connection authenticated with — as a new admin and burns the window in
// the same atomic write. The response shape is admin.claim's.
func (c *Conn) PairClaim(pin, pubkey string) (AdminClaimResult, error) {
	var out AdminClaimResult
	raw, err := c.Exec("admin.pair", map[string]any{"proto": 1, "pin": pin, "pubkey": pubkey})
	if err != nil {
		return out, err
	}
	err = unmarshalResult(raw, &out)
	return out, err
}

// grantCapsOrDefault answers what a grant may do when the caller did not
// say: exec, not shell (IAMT-400).
//
// The two are not equally safe defaults, and the asymmetry is not a
// matter of taste. On an exec grant the gateway sees the whole command
// before a byte of it reaches the machine, so every safety mode -- warn,
// ask, block -- has a moment to act in. On a shell grant what travels is
// keystrokes; there is no point at which a command exists to be read, and
// so NO safety mode applies at all.
//
// A default is what people get when they have not thought about it, and
// "no safety at all" is the wrong thing to hand somebody who has not
// thought about it. Asking for a shell stays one word away.
//
// It is a named function rather than two lines inside GrantsGrant so the
// rule can be tested without a gateway on the other end of a socket.
func grantCapsOrDefault(capability []string) []string {
	if len(capability) != 0 && capability[0] != "" {
		return capability
	}
	return []string{"exec"}
}
