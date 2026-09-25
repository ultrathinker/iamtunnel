package server

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// decodeBase64Strict decodes standard base64 with padding, refusing
// anything StdEncoding itself would refuse (bad alphabet, bad padding,
// trailing garbage) — no fallback to a more permissive variant.
func decodeBase64Strict(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// wire.go: the JSON envelope carried by iamtunnel-control, decoded on the
// machine side of the wire that internal/gateway/control_wire.go defines on
// the gateway side (see that file's own doc comment: internal/proto is a
// doc.go stub with no marshaling code, so both ends of this in-process
// prototype define their own copy of the same shape — this file's field
// names and JSON tags are kept identical to control_wire.go's so the two
// halves speak the same bytes).
//
// This file is also where the central risk is handled: a privileged
// process on Windows parses what came from the network, and every
// parse mistake becomes a remote reachability. Every message on this
// channel is bounded in length, bounded in JSON nesting depth, rejects any
// field outside the known shape, and never panics no matter what bytes
// arrive — see decodeControlRequest and its fuzz-style test.

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

type sanitizeResult struct {
	Sanitized bool `json:"sanitized"`
	// Removed is the number of door lines the sweep took from the key file
	// (PROTOCOL §5.1: door.sanitize removes every marked line). The gateway
	// uses this number in the door.sanitize journal entry so the journal
	// says how many lines of admin access were just wiped. Zero is a
	// legitimate value: a sweep of an already-clean file is not an error.
	Removed int `json:"removed"`
}

// invalidControlEnvelopeError marks a syntactically valid JSON object whose
// compulsory control-envelope fields are absent or unusable. serveControl
// logs it separately: this is a protocol violation at the privileged network
// boundary, not an internal door-operation failure.
type invalidControlEnvelopeError struct{ reason string }

func (e *invalidControlEnvelopeError) Error() string {
	return "server: invalid control envelope: " + e.reason
}

// errLineTooLong and errLineTruncated are framing failures: the whole
// control channel is torn down on either, the same posture
// internal/gateway/machine_conn.go's readLoop already takes on any decode
// error from its side of this same channel ("mc.teardown(\"control-read-
// error\")") — a message that does not even frame is not something either
// side can recover a specific request id from.
var (
	errLineTooLong    = errors.New("server: control line exceeds the configured limit")
	errLineTruncated  = errors.New("server: control channel closed mid-line")
	errJSONTooDeep    = errors.New("server: control JSON nests deeper than allowed")
	errJSONDupKey     = errors.New("server: control JSON has a duplicate object key")
	errJSONNotObject  = errors.New("server: control JSON top level is not one object")
	errJSONUnbalanced = errors.New("server: control JSON brackets do not balance")
)

// readControlLine reads one LF-terminated line from r, refusing to buffer
// more than max bytes. bufio.Reader.ReadSlice¹ is used instead of
// ReadString/ReadBytes specifically because it reports bufio.ErrBufferFull
// without ever growing its internal buffer past the size it was
// constructed with — an attacker holding the line open with no '\n' cannot
// make this allocate unbounded memory.
//
// ¹ https://pkg.go.dev/bufio#Reader.ReadSlice
func readControlLine(r *bufio.Reader, max int) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errLineTooLong
		}
		if errors.Is(err, io.EOF) {
			if len(line) > 0 {
				return nil, errLineTruncated
			}
			return nil, io.EOF
		}
		return nil, err
	}
	// ReadSlice's returned slice aliases the reader's internal buffer and
	// is only valid until the next read; copy it out before it moves on.
	out := make([]byte, len(line)-1) // drop the trailing '\n'
	copy(out, line[:len(line)-1])
	return out, nil
}

// jsonFrame tracks one level of {}/[] nesting while checkJSONShape walks
// the token stream. seen is allocated lazily and only for object frames,
// since only object keys can duplicate.
type jsonFrame struct {
	isObject  bool
	expectKey bool
	seen      map[string]bool
}

// checkJSONShape streams data through json.Decoder.Token — which never
// panics and reports every malformation as an error, by the documented
// contract of encoding/json — and independently enforces three things
// PROTOCOL.md §1.3/§5.1 requires and encoding/json does not check on its
// own: the top level is exactly one JSON object, nesting never exceeds
// maxDepth, and no object anywhere in the document repeats a key (Go's
// stdlib silently keeps the last value of a duplicate key; PROTOCOL.md
// calls that E_JSON_INVALID). This runs before the value is ever
// unmarshaled into a Go struct, so a message that fails here never reaches
// door-opening logic at all.
func checkJSONShape(data []byte, maxDepth int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []*jsonFrame
	sawTop := false

	atKeyPosition := func() bool {
		if len(stack) == 0 {
			return false
		}
		top := stack[len(stack)-1]
		return top.isObject && top.expectKey
	}
	afterValue := func() {
		if len(stack) == 0 {
			return
		}
		top := stack[len(stack)-1]
		if top.isObject {
			top.expectKey = true
		}
	}

	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if len(stack) == 0 {
					if sawTop {
						return errJSONNotObject
					}
					if v != '{' {
						return errJSONNotObject
					}
					sawTop = true
				}
				stack = append(stack, &jsonFrame{isObject: v == '{', expectKey: v == '{'})
				if len(stack) > maxDepth {
					return errJSONTooDeep
				}
			case '}', ']':
				if len(stack) == 0 {
					return errJSONUnbalanced
				}
				stack = stack[:len(stack)-1]
				afterValue()
			}
		case string:
			if atKeyPosition() {
				top := stack[len(stack)-1]
				if top.seen == nil {
					top.seen = make(map[string]bool)
				}
				if top.seen[v] {
					return errJSONDupKey
				}
				top.seen[v] = true
				top.expectKey = false
				continue
			}
			afterValue()
		default:
			// number, bool, nil literal in value position.
			afterValue()
		}
	}
	if len(stack) != 0 {
		return errJSONUnbalanced
	}
	if !sawTop {
		return errJSONNotObject
	}
	return nil
}

// decodeControlRequest turns one already length-bounded line into a
// controlRequest. It never panics: checkJSONShape and json.Unmarshal both
// report malformed input as an error value, by their documented contracts,
// and this function does nothing besides call them and inspect the
// result — see wire_fuzz_test.go, which throws a large corpus of
// adversarial byte strings at exactly this function and asserts only that
// it returns (zero value, non-nil error) and never panics.
//
// DisallowUnknownFields is PROTOCOL §1.3's "any field not in this
// message's shape yields E_JSON_FIELD_UNKNOWN: silent-ignore is not
// allowed" — a machine that silently ignored an unrecognised field in
// a door.open sent by a compromised or newer-than-us gateway would be
// guessing at meaning instead of refusing.
func decodeControlRequest(line []byte, maxDepth int) (controlRequest, error) {
	if err := checkJSONShape(line, maxDepth); err != nil {
		return controlRequest{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var req controlRequest
	if err := dec.Decode(&req); err != nil {
		return controlRequest{}, err
	}
	if dec.More() {
		return controlRequest{}, errors.New("server: control line carries more than one JSON value")
	}
	if err := validateControlEnvelope(req); err != nil {
		return controlRequest{}, err
	}
	return req, nil
}

// validateControlEnvelope runs after the byte-level JSON checks but before
// anything reaches dispatch. encoding/json otherwise turns a missing int or
// string into its zero value and a missing array into nil. Version 1 has one
// wire version and no control capabilities, so proto:1 and caps:[] are the
// only accepted envelope values.
func validateControlEnvelope(req controlRequest) error {
	if req.Proto != 1 {
		return &invalidControlEnvelopeError{reason: "proto must be 1"}
	}
	if req.Caps == nil {
		return &invalidControlEnvelopeError{reason: "caps is required and must be an array"}
	}
	if len(req.Caps) != 0 {
		return &invalidControlEnvelopeError{reason: "caps must be empty in protocol version 1"}
	}
	if !validControlRequestID(req.ID) {
		return &invalidControlEnvelopeError{reason: "id is required and must be a lower-case RFC 4122 UUID"}
	}
	if req.Op == "" {
		return &invalidControlEnvelopeError{reason: "op is required"}
	}
	return nil
}

func encodeControlResponse(resp controlResponse) ([]byte, error) {
	raw, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func errorResponse(id, code, message string) controlResponse {
	return controlResponse{Proto: 1, Caps: []string{}, ID: id, OK: false,
		Error: &controlErrorBody{Code: code, Message: message}}
}

func okResponse(id string, result any) controlResponse {
	raw, err := json.Marshal(result)
	if err != nil {
		// Every result type above is a fixed struct of strings/bools;
		// Marshal only fails on unsupported types (channels, funcs,
		// cyclic maps), none of which appear here. Kept as a checked
		// error, not a panic path: no panic on anything from the
		// network, extended to no panic, period, in this package.
		return errorResponse(id, "E_INTERNAL", "internal: failed to encode result")
	}
	return controlResponse{Proto: 1, Caps: []string{}, ID: id, OK: true, Result: raw}
}

// ---- door.open semantic validation ---------------------------------------

var doorIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// pubKeyPattern matches PROTOCOL §5.1's exact required shape for the
// door.open pubkey field once surrounding whitespace is trimmed:
// "ssh-ed25519 SP <base64>", nothing else — no options, no comment, no
// second key. <base64> is the standard OpenSSH encoding of the SSH
// wire-format public-key blob (what ssh.MarshalAuthorizedKey produces),
// not merely the raw 32 key bytes.
var pubKeyPattern = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]+=*$`)

func validDoorID(id string) bool { return doorIDPattern.MatchString(id) }

func validControlRequestID(id string) bool { return doorIDPattern.MatchString(id) }

// decodeDoorPubKey validates a door.open pubkey field and returns both the
// base64 body to write into the key file (winkeys.FormatLine's pubKey
// argument) and the OpenSSH fingerprint of the key it names.
//
// The gateway's actual encoder (internal/gateway/core/door.go's
// defaultDoor) builds this field with ssh.MarshalAuthorizedKey, which
// appends a trailing newline; TrimSpace absorbs that formatting artefact
// before the shape is checked, so "no options or comment" is enforced on
// content, not on incidental whitespace a correct peer already sends.
//
// The base64 body must decode to a genuine SSH wire-format ed25519 public
// key — checked with ssh.ParsePublicKey, which never panics on malformed
// input and is the same parser OpenSSH-compatible code everywhere else in
// this repository trusts — not merely "some base64", which would let a
// malformed or oversized blob reach winkeys.Door.Install and be written
// into a privileged file verbatim.
func decodeDoorPubKey(pubkey string) (base64Body, fingerprint string, err error) {
	trimmed := strings.TrimSpace(pubkey)
	if !pubKeyPattern.MatchString(trimmed) {
		return "", "", errors.New("door pubkey must be exactly \"ssh-ed25519 <base64>\" with no options or comment")
	}
	parts := strings.Fields(trimmed)
	if len(parts) != 2 {
		return "", "", errors.New("door pubkey must have exactly two space-separated fields")
	}
	body := parts[1]
	blob, err := decodeBase64Strict(body)
	if err != nil {
		return "", "", fmt.Errorf("door pubkey base64 does not decode: %w", err)
	}
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return "", "", fmt.Errorf("door pubkey blob does not parse as an SSH public key: %w", err)
	}
	if pk.Type() != "ssh-ed25519" {
		return "", "", fmt.Errorf("door pubkey type is %q, want ssh-ed25519", pk.Type())
	}
	return body, ssh.FingerprintSHA256(pk), nil
}

// parseDoorDeadlines parses and orders-checks the three RFC3339 timestamps
// of a door.open request (PROTOCOL §5.1: "opened < idleDeadline <
// hardDeadline"). time.RFC3339 accepts an optional fractional-second tail
// on parse even though the layout string does not show one, which is what
// control_wire.go's rfc3339() (RFC3339Nano) actually produces.
func parseDoorDeadlines(opened, idle, hard string) (o, i, h time.Time, err error) {
	o, err = time.Parse(time.RFC3339, opened)
	if err != nil {
		return o, i, h, fmt.Errorf("door.opened does not parse as RFC3339: %w", err)
	}
	i, err = time.Parse(time.RFC3339, idle)
	if err != nil {
		return o, i, h, fmt.Errorf("door.idleDeadline does not parse as RFC3339: %w", err)
	}
	h, err = time.Parse(time.RFC3339, hard)
	if err != nil {
		return o, i, h, fmt.Errorf("door.hardDeadline does not parse as RFC3339: %w", err)
	}
	if !o.Before(i) {
		return o, i, h, errors.New("door.opened must be before door.idleDeadline")
	}
	if !i.Before(h) {
		return o, i, h, errors.New("door.idleDeadline must be before door.hardDeadline")
	}
	return o, i, h, nil
}
