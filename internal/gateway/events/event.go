package events

import (
	"errors"
	"fmt"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// EventType categorizes events defined in SPEC §3.5.
type EventType string

const (
	// Admin operations
	EventAdminOp EventType = "admin.op"

	// Authentication: success and failure, address, fingerprint
	EventAuthSuccess EventType = "auth.success"
	EventAuthFailure EventType = "auth.failure"

	// A refusal with no key behind it: the connection failed the SSH
	// handshake before offering a single key - a scanner dropping after the
	// version exchange, a client speaking only an auth method the gateway
	// does not. auth.failure cannot carry it: its validator demands a
	// fingerprint, and none exists, so dropping the attempt there hid
	// exactly the sweep a brute force opens with (R1-CX F-03, 24.09.2026).
	// Actor and object are the client's address; the fingerprint is absent
	// by definition, never redacted.
	EventAuthHandshakeFailure EventType = "auth.handshake_failure"

	// Machine tunnel lifecycle makes a valid reconnect distinguishable from
	// a rejected simultaneous duplicate.
	EventMachineConnected    EventType = "machine.connected"
	EventMachineDisconnected EventType = "machine.disconnected"
	EventMachineRejected     EventType = "machine.rejected"

	// Registration transitions
	EventEnrolStart    EventType = "enrol.start"
	EventEnrolVerified EventType = "enrol.verified"
	EventEnrolFailed   EventType = "enrol.failed"

	// Door open and close
	EventDoorOpen  EventType = "door.open"
	EventDoorClose EventType = "door.close"

	// Door sanitize: the only control-channel operation that removes every
	// marked line from administrators_authorized_keys without naming one id.
	// Outcome is in the Event.Result field, not in a separate type: "ok" on
	// success, "timeout" if the machine never answered, "refused" if the
	// machine replied ok:false. This matches the convention every other
	// event in this dictionary already follows (auth.failure carries
	// "denied" / "rate limited until ..." in Result; session.drop carries
	// "timeout" / "recording: ..." in Result) and the IAMT-104 decision
	// for door.* specifically — door.open and door.close are a single
	// type apiece with the outcome in Result, not a name per outcome.
	EventDoorSanitize EventType = "door.sanitize"

	// Sessions: start, stop, drop
	EventSessionStart EventType = "session.start"
	EventSessionStop  EventType = "session.stop"
	EventSessionDrop  EventType = "session.drop"
	EventSessionRisk  EventType = "session.risk"
	// A human approval lifecycle for a red command in ask mode. The result is
	// pending, approved, consumed, expired or denied; details carry the
	// approval id, scrubbed command, rule, red level and timestamps.
	EventRiskApproval EventType = "risk.approval"

	// Host key mismatch
	EventHostKeyMismatch EventType = "hostkey.mismatch"

	// Rotation
	EventHostKeyRotate EventType = "hostkey.rotate"
	EventLogRotate     EventType = "log.rotate"

	// Access withdrawn by the gateway itself, without an admin asking for it:
	// the machine a grant was issued against was removed or presents another key.
	EventGrantRevoke EventType = "grant.revoke"

	// The owner of a machine began watching a session happening on it
	// (IAMT-343). Actor is the machine that asked, object is the session
	// id, and details carry the person whose session it is.
	//
	// Written ONCE, when the watching starts, not on every poll: the
	// live view is a poll loop, and an event per poll would bury the
	// journal under one machine's curiosity. "Began" is the fact worth
	// keeping — that somebody looked at all is what a person asks about
	// afterwards, not how many times the window refreshed.
	EventSessionWatch EventType = "session.watch"

	// Session transcript exported to text files for a human to read
	// (IAMT-342). Actor is whoever asked for the export, object is
	// "person -> machine", details carry the export folder path and the
	// part count. Written by the window-side exporter
	// (internal/record/export), not by the gateway.
	EventRecordingExport EventType = "recording.export"
)

// ErrInvalidEvent wraps every validation failure of an event, so that a caller can
// tell "this event is not loggable" from "the log is broken".
var ErrInvalidEvent = errors.New("invalid event")

// IsValidEventType checks whether an EventType is one of the known SPEC §3.5 event types.
func IsValidEventType(t EventType) bool {
	switch t {
	case EventAdminOp,
		EventAuthSuccess,
		EventAuthFailure,
		EventAuthHandshakeFailure,
		EventMachineConnected,
		EventMachineDisconnected,
		EventMachineRejected,
		EventEnrolStart,
		EventEnrolVerified,
		EventEnrolFailed,
		EventDoorOpen,
		EventDoorClose,
		EventDoorSanitize,
		EventSessionStart,
		EventSessionStop,
		EventSessionDrop,
		EventSessionRisk,
		EventRiskApproval,
		EventHostKeyMismatch,
		EventHostKeyRotate,
		EventLogRotate,
		EventGrantRevoke,
		EventSessionWatch,
		EventRecordingExport:
		return true
	default:
		return false
	}
}

// Event represents a single line in events.jsonl (§3.5).
type Event struct {
	Time        state.ZonedTime        `json:"time"`
	Type        EventType              `json:"type"`
	Actor       string                 `json:"actor"`
	Object      string                 `json:"object"`
	Result      string                 `json:"result"`
	Address     string                 `json:"address,omitempty"`
	Fingerprint string                 `json:"fingerprint,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	// PrevHash is the hash of the line before this one in a chained
	// journal (IAMT-467, chain.go); set by the log when it writes the line,
	// never by the caller.
	PrevHash string `json:"prev_hash,omitempty"`
}

// Validate checks whether the event conforms to SPEC §3.5 requirements.
func (e Event) Validate() error {
	if e.Time.IsZero() {
		return fmt.Errorf("%w: event time cannot be zero or empty", ErrInvalidEvent)
	}
	if !IsValidEventType(e.Type) {
		return fmt.Errorf("%w: unknown event type %q", ErrInvalidEvent, e.Type)
	}
	if e.Type == EventAuthSuccess || e.Type == EventAuthFailure {
		// §3.5 lists "auth (success/failure, address, fingerprint)": both, not either.
		// A failure without a fingerprint cannot be correlated with the key that was
		// offered, and one without an address cannot be rate-limited by (address,
		// fingerprint) as §6.1 requires - so both are demanded here, and the message
		// now says exactly what the code enforces.
		hasAddr := e.Address != "" || detail(e.Details, "address") != ""
		hasFP := e.Fingerprint != "" || detail(e.Details, "fingerprint") != ""
		switch {
		case !hasAddr && !hasFP:
			return fmt.Errorf("%w: auth event %s requires both address and fingerprint per SPEC §3.5, got neither", ErrInvalidEvent, e.Type)
		case !hasAddr:
			return fmt.Errorf("%w: auth event %s requires an address per SPEC §3.5", ErrInvalidEvent, e.Type)
		case !hasFP:
			return fmt.Errorf("%w: auth event %s requires a fingerprint per SPEC §3.5", ErrInvalidEvent, e.Type)
		}
	}
	if e.Type == EventAuthHandshakeFailure {
		// R1-CX F-03: a pre-key handshake failure has an address and no
		// fingerprint - none was ever offered, and the absence is the very
		// fact this type records. The address is what makes the attempt
		// correlatable to a host, so it alone is demanded.
		if e.Address == "" && detail(e.Details, "address") == "" {
			return fmt.Errorf("%w: auth event %s requires an address per SPEC §3.5", ErrInvalidEvent, e.Type)
		}
	}
	return nil
}

// detail reads a string-ish value out of the free-form details map.
func detail(details map[string]interface{}, key string) string {
	if details == nil || details[key] == nil {
		return ""
	}
	return fmt.Sprint(details[key])
}

// NewGrantRevokedEvent turns a revocation reported by the state store into the journal
// entry §3.5 expects. This is the seam between the two packages: state cannot import
// events (events imports state), so the store records the fact and the caller, holding
// both, writes it here.
func NewGrantRevokedEvent(rev state.Revocation, at state.ZonedTime) Event {
	details := map[string]interface{}{
		"reason":      string(rev.Reason),
		"person":      rev.Person,
		"machine":     rev.Machine,
		"pinnedKeyFp": rev.PinnedKeyFP,
	}
	if rev.CurrentKeyFP != "" {
		details["currentKeyFp"] = rev.CurrentKeyFP
	}
	if len(rev.Caps) > 0 {
		details["caps"] = rev.Caps
	}
	return Event{
		Time:        at,
		Type:        EventGrantRevoke,
		Actor:       "gateway",
		Object:      rev.Person + " -> " + rev.Machine,
		Result:      string(rev.Reason),
		Fingerprint: rev.PinnedKeyFP,
		Details:     details,
	}
}

// Filter specifies criteria for querying event logs.
type Filter struct {
	Since  *time.Time
	Until  *time.Time
	Types  []EventType
	Actor  string
	Object string
	Result string
}

// Matches returns true if the event satisfies all active filter conditions.
func (f Filter) Matches(e Event) bool {
	if f.Since != nil && e.Time.Before(*f.Since) {
		return false
	}
	if f.Until != nil && e.Time.After(*f.Until) {
		return false
	}
	if len(f.Types) > 0 {
		matched := false
		for _, t := range f.Types {
			if e.Type == t {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if f.Actor != "" && e.Actor != f.Actor {
		return false
	}
	if f.Object != "" && e.Object != f.Object {
		return false
	}
	if f.Result != "" && e.Result != f.Result {
		return false
	}
	return true
}
