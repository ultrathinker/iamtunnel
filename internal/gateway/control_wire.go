package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// control_wire.go defines the JSON envelope carried by the iamtunnel-control
// channel (PROTOCOL §5.1).
//
// internal/proto - the package meant to own the exec/control JSON envelope -
// exists only as a doc.go stub with no marshaling code. Rather than add code
// to that stub, the runtime defines the minimal envelope it needs here,
// scoped to this package. It is not the frozen wire format of PROTOCOL.md and
// makes no claim to be; it exists so the door automaton can be driven over a
// real channel in-process, per SPEC §8's in-process e2e testing.

type controlDoor struct {
	ID           string `json:"id"`
	PubKey       string `json:"pubkey"`
	Opened       string `json:"opened"`
	IdleDeadline string `json:"idleDeadline"`
	HardDeadline string `json:"hardDeadline"`
}

type controlRequest struct {
	Proto  int          `json:"proto"`
	Caps   []string     `json:"caps"`
	ID     string       `json:"id"`
	Op     string       `json:"op"`
	Door   *controlDoor `json:"door,omitempty"`
	DoorID string       `json:"doorId,omitempty"`
	Reason string       `json:"reason,omitempty"`
}

type controlErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type controlResponse struct {
	Proto  int               `json:"proto"`
	Caps   []string          `json:"caps"`
	ID     string            `json:"id"`
	OK     bool              `json:"ok"`
	Result json.RawMessage   `json:"result,omitempty"`
	Error  *controlErrorBody `json:"error,omitempty"`
}

type doorOpenResult struct {
	DoorID               string `json:"doorId"`
	Installed            bool   `json:"installed"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint"`
}

type doorCloseResult struct {
	DoorID  string `json:"doorId"`
	Removed bool   `json:"removed"`
}

type doorStatusResult struct {
	Installed            bool   `json:"installed"`
	DoorID               string `json:"doorId,omitempty"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint,omitempty"`
}

// sanitizeResult mirrors the machine-side sanitizeResult (server/wire.go):
// the gateway reads Removed so the door.sanitize journal entry can record
// how many lines of admin access were wiped. Sanitized is the bare
// PROTOCOL §5.1 success signal and stays in the wire result alongside the
// count.
type sanitizeResult struct {
	Sanitized bool `json:"sanitized"`
	Removed   int  `json:"removed"`
}

// newRequestID mints a uuid-shaped, per-connection-unique correlation id
// (PROTOCOL §5.1: the id is unique across the whole tunnelEpoch).
func newRequestID() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	s := hex.EncodeToString(raw)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
