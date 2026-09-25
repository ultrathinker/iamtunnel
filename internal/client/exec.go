package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// maxExecResponse caps how many bytes of an exec response this package
// will ever buffer in memory. PROTOCOL §1.2 does not itself bound a
// generic exec response the way it bounds the control channel (16 KiB,
// §5.1) or a recordings.fetch chunk (1 MiB, §6), so this is this
// package's own decision: large enough for any answer this build's
// commands actually need, small enough that a misbehaving or hostile
// gateway cannot make the client allocate an unbounded amount of
// memory — long input gets a clear refusal, never a panic.
const maxExecResponse = 1 << 20 // 1 MiB

// execError mirrors the PROTOCOL §1.2 error object.
type execError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// execEnvelope mirrors the PROTOCOL §1.2 common response shape. Result is
// left raw so each command can decode its own result type strictly,
// instead of this package guessing a shape that fits every command.
type execEnvelope struct {
	Proto    int             `json:"proto"`
	Caps     []string        `json:"caps"`
	OK       bool            `json:"ok"`
	Result   json.RawMessage `json:"result"`
	Error    *execError      `json:"error"`
	MinProto int             `json:"minProto"`
}

// execCommand runs one exec-channel command (PROTOCOL §1.2/§6) over an
// already-authenticated client: open a "session" channel, request "exec"
// with the command name, write the JSON request to its stdin, read the
// JSON response from its stdout, and decode it strictly. It never panics
// on a malformed answer: every failure mode (truncated body, garbage
// bytes, an oversized body, unknown envelope shape) becomes a returned
// error.
func execCommand(ctx context.Context, client *ssh.Client, timeout time.Duration, command string, req interface{}) (execEnvelope, error) {
	var zero execEnvelope
	ch, reqs, err := openSession(ctx, client, timeout)
	if err != nil {
		return zero, err
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	ok, err := ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command}))
	if err != nil || !ok {
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("gateway refused command %q", command)}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return zero, fmt.Errorf("client: marshal %s request: %w", command, err)
	}
	if _, err := ch.Write(body); err != nil {
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("cannot send %q request: %v", command, err)}
	}
	_ = ch.CloseWrite()

	limited := io.LimitReader(ch, maxExecResponse+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("cannot read %q response: %v", command, err)}
	}
	if len(data) > maxExecResponse {
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("gateway response to %q exceeds %d bytes — refusing to buffer it", command, maxExecResponse)}
	}

	env, err := decodeEnvelope(data)
	if err != nil {
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("gateway response to %q is not a valid iamtunnel response: %v", command, err)}
	}
	if !env.OK {
		msg := "command refused"
		if env.Error != nil && env.Error.Message != "" {
			msg = env.Error.Message
		}
		return zero, &config.Error{Class: config.ClassUser, Msg: msg}
	}
	return env, nil
}

// preflight runs whoami, the version preflight PROTOCOL §1.1 puts before
// the first application command on a command-login connection (R2-CX
// F-06), and goes no further with a gateway that refuses it or answers in
// a protocol this client does not speak. machines.mine used to go first,
// alone.
func preflight(ctx context.Context, client *ssh.Client, timeout time.Duration) error {
	env, err := execCommand(ctx, client, timeout, "whoami", map[string]int{"proto": 1})
	if err != nil {
		return err
	}
	if env.Proto != 1 {
		return &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("the gateway speaks protocol %d and this client only 1 - update whichever of the two is older", env.Proto)}
	}
	return nil
}

// decodeEnvelope parses one PROTOCOL §1.2 response object strictly: an
// unknown field, a wrong-typed field, a truncated body, or bytes left
// over after the object all become a plain error — never a panic and
// never a silently accepted partial value.
func decodeEnvelope(data []byte) (execEnvelope, error) {
	var env execEnvelope
	if len(bytes.TrimSpace(data)) == 0 {
		return env, errors.New("empty response")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return env, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return env, errors.New("trailing data after the JSON response")
	}
	if env.Proto == 0 {
		return env, errors.New("response is missing \"proto\"")
	}
	return env, nil
}
