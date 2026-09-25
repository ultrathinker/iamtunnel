package client

// execrun.go: "iamtunnel client exec" — the only way an exec-only grant
// (SPEC §6.5, PROTOCOL §4.1/§5.1) can be used at all. It is a wholly
// different shape from an interactive session and from exec.go's own
// execCommand/execEnvelope (that file's exec channel carries a JSON
// admin/recordings command; this one carries the human's own command
// line, byte for byte, over the very same "exec" SSH channel request).
// The two never collide: this file's Exec/ExecOptions/ExecOutcome are
// the only exported names here.

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// ExecOptions carries everything one exec-grant command run needs. It
// deliberately has no In/Stdin field: under an exec grant the gateway
// closes the machine's stdin right after the command and refuses bytes the
// person writes (SPEC §6.5, R4 F-03), so there is nothing to send, and the
// type itself cannot be handed a stream to lose.
type ExecOptions struct {
	Conn           config.ConnString
	Machine        string
	Command        string // exactly as the person typed it; no shell wrapper is added
	Signer         ssh.Signer
	KnownHostsPath string

	Stdout io.Writer // channel stream "0" — the command's own stdout
	Stderr io.Writer // extended data, stream "1" — the machine's stderr AND the gateway's own words (the recording banner, a risk warning, E_COMMAND_BLOCKED or E_APPROVAL_REQUIRED)

	DialTimeout       time.Duration
	KeepaliveInterval time.Duration
}

// ExecOutcome is the observable result of one exec request.
type ExecOutcome struct {
	// Started reports whether the gateway accepted the "exec" channel
	// request itself (RFC 4254 §6.5's own success/failure reply — a
	// wire-level fact distinct from whether the command then ran: a red
	// command still gets Started=true, then ExitStatus 126, because the
	// gateway accepts the request before it classifies the command,
	// PROTOCOL §4.1's `exec` table row).
	Started bool
	// ExitStatus is the machine's own exit code, forwarded byte for byte
	// (PROTOCOL §4.1), or 126 when the gateway's risk policy stopped the
	// command before it reached the machine at all. nil means the
	// session ended without ever sending one — a transport that died
	// mid-command, not a clean end.
	ExitStatus *uint32
	// Refusal carries whatever text arrived describing why the request
	// itself failed at the wire level. RFC 4254 channel-request failures
	// carry no message on the wire, so today's gateway (which always
	// replies true to "exec" and explains a block over Stderr instead,
	// A2) never populates this; it exists so a future or non-conforming
	// peer's failure is not simply indistinguishable from "started but
	// gave nothing back".
	Refusal string
}

// Exec runs exactly one command on Machine over an exec grant (SPEC §6.5,
// PROTOCOL §4.1/§5.1): it sends "exec" and nothing else that could open an
// interactive program — never "pty-req", never "shell". This is the one
// difference from Connect; everything about reaching the gateway (dial,
// host-key pinning, keepalive) is the shared sessionDial both build on —
// one entry point: the connection-dialing code shared with Connect is
// reused, not copied.
//
// stdout (channel stream "0") and stderr (extended data, stream "1") are
// copied to separate destinations so a person — or a script piping this
// command's stdout — never has to pick the machine's own output out of
// the gateway's warnings by hand.
func Exec(ctx context.Context, opts ExecOptions) (ExecOutcome, error) {
	var zero ExecOutcome
	client, stop, err := sessionDial(ctx, opts.Conn, opts.Machine, opts.Signer, opts.KnownHostsPath, opts.DialTimeout, opts.KeepaliveInterval)
	if err != nil {
		return zero, err
	}
	defer stop()

	ch, reqs, err := openSession(ctx, client, opts.DialTimeout)
	if err != nil {
		return zero, err
	}
	defer ch.Close()

	exitCh := make(chan uint32, 1)
	// reqsDone closes when the request stream is over — see connect.go's
	// own field of the same name for why a channel, not a WaitGroup.
	reqsDone := make(chan struct{})
	go func() {
		defer close(reqsDone)
		for r := range reqs {
			if r.Type == "exit-status" {
				if e, perr := sshx.ParseExitStatus(r.Payload); perr == nil {
					select {
					case exitCh <- e.Status:
					default:
					}
				}
			}
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()

	started, err := ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: opts.Command}))
	if err != nil {
		// The gateway can refuse before this request even lands - the
		// session preconditions (grant, machine state) run ahead of any
		// channel request - and a refusal writes its line into the channel
		// and closes it. That read as bare "EOF" told the person the wire
		// died when the gateway had actually said why (IAMT-383); the
		// refusal line beats the close on the wire, so read it back.
		if said := refusalText(ch); said != "" {
			return zero, &config.Error{Class: config.ClassEnv, Msg: said}
		}
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("cannot send the command to the gateway: %v", err)}
	}
	if !started {
		// See ExecOutcome.Refusal's own comment: nothing on the wire names
		// a reason here, so this call reports only the fact of the
		// refusal, not a manufactured explanation for it.
		_ = ch.Close()
		<-reqsDone
		return ExecOutcome{Started: false}, nil
	}

	// No stdin is ever written (SPEC §6.5); close the write side
	// immediately so a machine-side program that reads until EOF on its
	// own stdin does not hang waiting for input this grant never sends.
	_ = ch.CloseWrite()

	var copyWG sync.WaitGroup
	copyWG.Add(2)
	go func() {
		defer copyWG.Done()
		_, _ = io.Copy(opts.Stdout, ch)
	}()
	go func() {
		defer copyWG.Done()
		_, _ = io.Copy(opts.Stderr, ch.Stderr())
	}()
	copyWG.Wait()

	// Wait for the final exit-status, but never past exitStatusGrace — see
	// connect.go's own comment on the constant for why the wait exists at
	// all and why it must be bounded.
	timer := time.NewTimer(exitStatusGrace)
	select {
	case <-reqsDone:
		timer.Stop()
	case <-timer.C:
	}
	_ = ch.Close()

	var status *uint32
	select {
	case v := <-exitCh:
		status = &v
	default:
	}

	return ExecOutcome{Started: true, ExitStatus: status}, nil
}

// refusalDrainTimeout bounds refusalText's reads. The channel that failed
// SendRequest is closed or closing, so they end on their own; the timer
// only covers a peer that fails the request without ever closing anything.
const refusalDrainTimeout = 2 * time.Second

// refusalText reads what the gateway said on a channel it closed under
// this request (IAMT-383). Both streams are read — the pre-exec
// refusals write the plain channel, the interactive-setup one writes
// extended data — and what was said, not how the transport died, is
// what the person needs. "" when nothing was said.
func refusalText(ch ssh.Channel) string {
	timer := time.AfterFunc(refusalDrainTimeout, func() { _ = ch.Close() })
	defer timer.Stop()
	said := make([]string, 2)
	var wg sync.WaitGroup
	for i, r := range [2]io.Reader{ch, ch.Stderr()} {
		wg.Add(1)
		go func(i int, r io.Reader) {
			defer wg.Done()
			b, _ := io.ReadAll(r)
			said[i] = strings.TrimSpace(string(b))
		}(i, r)
	}
	wg.Wait()
	parts := said[:0]
	for _, s := range said {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}
