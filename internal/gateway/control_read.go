package gateway

// control_read.go - how the gateway reads what a machine writes on its
// control channel (IAMT-443).
//
// PROTOCOL §5.1 bounds a control line to 16 KiB, one JSON object per
// LF-terminated line, and calls an unknown field, a wrong type, a
// duplicate key or an object without its LF a protocol violation. The
// machine has held the gateway to that from the first day
// (internal/server/wire.go: readControlLine, checkJSONShape,
// decodeControlRequest) and tears the tunnel down on the first line that
// breaks it. The gateway held the machine to none of it: readLoop ran a
// json.Decoder straight over the channel, which buffers a value of any
// size while it waits for its end, keeps the last of two duplicate keys,
// ignores fields it does not know and reads two objects on one line as
// two messages. A machine - the party whose key can be lifted off a
// laptop - could make the gateway buffer without limit.
//
// This is the gateway's half of the same rule, and it answers a breach
// the way the machine does: the line cannot be trusted to say which
// request it belongs to, so the tunnel goes. The machine's reader is
// mirrored here rather than imported, because internal/server is the
// machine's program and the gateway does not link it.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const (
	// controlLineMax is PROTOCOL §5.1's bound on one control line - the
	// number the machine holds the gateway to (server.DefaultControlLineMax).
	controlLineMax = 16 * 1024

	// controlJSONDepth bounds how deep a machine's line may nest, as
	// server.DefaultControlJSONDepth does in the other direction.
	controlJSONDepth = 16

	// maxMachineRequestsInFlight is how many of one machine's own requests
	// (sessions.tail, sessions.mine) the gateway works on at once. The
	// read loop waits for a free slot before it reads on: a machine that
	// asks faster than it is answered is slowed down by its own channel,
	// and cannot park one goroutine per line on the gateway. A window
	// asks one question at a time, so a handful covers every window a
	// person can have open on one machine.
	maxMachineRequestsInFlight = 4
)

var (
	errControlLineTooLong   = errors.New("gateway: control line exceeds 16 KiB")
	errControlLineTruncated = errors.New("gateway: control channel closed mid-line")
	errControlNotOneObject  = errors.New("gateway: control line is not exactly one JSON object")
	errControlTooDeep       = errors.New("gateway: control JSON nests deeper than allowed")
	errControlDuplicateKey  = errors.New("gateway: control JSON repeats an object key")
	errControlUnbalanced    = errors.New("gateway: control JSON brackets do not balance")
	errControlEnvelope      = errors.New("gateway: control envelope is not proto 1, caps [] and a uuid id")
)

// controlIDPattern is §5.1's `id`: a lower-case uuid, the shape both ends
// mint (newRequestID here, newControlRequestID on the machine).
var controlIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// readControlLine reads one LF-terminated line, refusing to hold more than
// max bytes of it. ReadSlice reports bufio.ErrBufferFull instead of growing
// its buffer past the size it was made with, so a machine that never sends
// the LF cannot make this allocate: r must be made with a buffer of max+1.
func readControlLine(r *bufio.Reader, max int) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errControlLineTooLong
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return nil, errControlLineTruncated
		}
		return nil, err
	}
	if len(line)-1 > max {
		return nil, errControlLineTooLong
	}
	// ReadSlice's slice is the reader's own buffer until the next read.
	out := make([]byte, len(line)-1)
	copy(out, line[:len(line)-1])
	return out, nil
}

// decodeControlInbound turns one bounded line into a controlInbound, or
// says why it may not: the line is exactly one JSON object, nests no
// deeper than controlJSONDepth, repeats no key, carries no field the
// envelope does not have, and its envelope is proto 1, caps [] and a uuid
// id - the only envelope version 1 has.
func decodeControlInbound(line []byte) (controlInbound, error) {
	if err := checkControlJSONShape(line, controlJSONDepth); err != nil {
		return controlInbound{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var in controlInbound
	if err := dec.Decode(&in); err != nil {
		return controlInbound{}, err
	}
	if dec.More() {
		return controlInbound{}, errControlNotOneObject
	}
	if in.Proto != 1 || in.Caps == nil || len(in.Caps) != 0 || !controlIDPattern.MatchString(in.ID) {
		return controlInbound{}, errControlEnvelope
	}
	return in, nil
}

// checkControlJSONShape walks data token by token - json.Decoder.Token
// reports every malformation as an error and never panics - and enforces
// what encoding/json does not check by itself: one top-level object,
// nesting no deeper than maxDepth, and no object repeating a key (Go keeps
// the last of two silently; §5.1 calls it a protocol violation).
func checkControlJSONShape(data []byte, maxDepth int) error {
	type frame struct {
		isObject  bool
		expectKey bool
		seen      map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []*frame
	sawTop := false
	afterValue := func() {
		if n := len(stack); n > 0 && stack[n-1].isObject {
			stack[n-1].expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if len(stack) == 0 {
					if sawTop || v != '{' {
						return errControlNotOneObject
					}
					sawTop = true
				}
				stack = append(stack, &frame{isObject: v == '{', expectKey: v == '{'})
				if len(stack) > maxDepth {
					return errControlTooDeep
				}
			case '}', ']':
				if len(stack) == 0 {
					return errControlUnbalanced
				}
				stack = stack[:len(stack)-1]
				afterValue()
			}
		case string:
			if n := len(stack); n > 0 && stack[n-1].isObject && stack[n-1].expectKey {
				top := stack[n-1]
				if top.seen == nil {
					top.seen = make(map[string]bool)
				}
				if top.seen[v] {
					return errControlDuplicateKey
				}
				top.seen[v] = true
				top.expectKey = false
				continue
			}
			if len(stack) == 0 {
				return errControlNotOneObject
			}
			afterValue()
		default:
			if len(stack) == 0 {
				return errControlNotOneObject
			}
			afterValue()
		}
	}
	if len(stack) != 0 {
		return errControlUnbalanced
	}
	if !sawTop {
		return errControlNotOneObject
	}
	return nil
}
