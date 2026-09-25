package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// errControlTimeout marks a control-channel operation that got no reply
// within its PROTOCOL §1.5 deadline.
var errControlTimeout = errors.New("gateway: control operation timed out")

// sanitizeErrorText renders the machine's refusal as a single short string
// for the door.sanitize journal entry's Details["err"] (Result:"refused").
// It pulls the protocol error code first and falls back to the message,
// keeping the entry small and readable on the runbook's "tail the events"
// path.
func sanitizeErrorText(err error, resp controlResponse) string {
	if err != nil {
		return err.Error()
	}
	if resp.Error != nil {
		if resp.Error.Code != "" {
			return resp.Error.Code
		}
		return resp.Error.Message
	}
	return "ok:false without error body"
}

// errControlClosed marks a control-channel operation abandoned because the
// tunnel is already gone; the caller must not feed a second event into the
// door automaton for it - teardown already applied TransportLost once.
var errControlClosed = errors.New("gateway: control channel closed")

// beforeSendCommandFn, when non-nil, runs immediately before every
// sendCommand - the last instant before a control request goes on the
// wire. It is a test-only seam, nil in production (same rule as
// journalAppendFn and afterKeyCheckFn): the F-23 test parks a goroutine
// here to hold exactly the window it is about - an Apply that has already
// produced a command and the write of that command.
//
// It is an atomic, like journalAppendFn, and for the reason the -race gate
// found (round 3): a machine's drive loop reads the seam on every command
// it sends, for as long as the machine stays connected - which is longer
// than any one test - while the test that swapped it restores it in its
// cleanup. A plain variable made that write race the read.
var beforeSendCommandFn atomic.Pointer[func(mc *machineConn, cmd core.Command)]

// reservationTicket lets a human's goroutine block on the specific outcome of
// its own reservation, rather than polling core.Machine.Snapshot(): polling
// global state cannot tell "my reservation failed" from "a later, unrelated
// open cycle for someone else succeeded".
type reservationTicket struct {
	outcome chan doorOutcome
}

type doorOutcome struct {
	ok     bool
	reason string
}

// machineConn is the live connection of one registered machine: its
// transport, its control channel, and the core.Machine door automaton that
// owns its policy. The runtime turns wire events into core.Input and executes
// exactly the core.Command values Apply returns - see driveOne.
type machineConn struct {
	id    string
	sconn *ssh.ServerConn
	epoch uint64
	g     *Gateway

	doorMachine *core.Machine

	// driveMu serializes this connection's door wire cycles: one
	// Apply -> sendCommand -> reply -> Apply at a time (F-23, round-1
	// review 24.09.2026). core.Machine's own mutex makes each transition
	// atomic, but the command a transition returns is written to the
	// control channel by whoever holds it, so two entry points driving at
	// once could order the wire differently than the automaton ordered its
	// transitions: reserve's door.open could sit unwritten while a
	// ForceClose's door.close goes out, the machine installs the late
	// open's key after answering the close, and the reply lands on an
	// automaton that is already Closed - the key stays on the machine and
	// the ticket dies of old age. The entry points below take this lock
	// around their whole cycle; drive, driveOne, driveOneUntil and
	// sendCommand never take it themselves (they run under it), and
	// teardown deliberately does not either - its transport close is what
	// unblocks a cycle stuck on a machine that has stopped answering.
	// Lock order: driveMu, then mc.mu.
	driveMu sync.Mutex

	ctrlCh  ssh.Channel
	writeMu sync.Mutex

	mu      sync.Mutex
	pending map[string]chan controlResponse

	// watched remembers which sessions this machine has already been
	// told to have started watching, so session.watch is written once
	// per session and not once per poll (IAMT-343). It is keyed by
	// session id and lives with the connection: a machine that
	// reconnects is a new channel, a new identity check and honestly a
	// new act of watching.
	watched map[string]bool
	// watchMu serialises a first session.watch record across the control
	// requests that ask together (R4 review N-09; noteWatching).
	watchMu sync.Mutex
	// unknownOps remembers which control ops this machine asked for that
	// this gateway does not know, so each one is written to the journal
	// once per connection and not once per request (F-04, round-1 review
	// 24.09.2026) - the same rule and the same reasoning as watched
	// above, for a machine whose version skew makes it ask in a loop.
	// Bounded by maxUnknownOpsPerConn.
	unknownOps map[string]bool
	// retired records a door.open whose wire deadline elapsed.  The target
	// may still apply that request and reply later, so forgetting its id at
	// timeout would turn a real, installed key into an unaddressable door.
	// The first reconciliation status decides whether it already found the
	// key; only an unresolved late success is fed back as core.LateReply.
	retired map[string]*retiredOpen
	tickets []*reservationTicket
	closed  bool
	doneCh  chan struct{}
	probeMu sync.Mutex

	// torn is closed when teardown has run to its end, its journal line
	// written. A second teardown waits for it rather than return at once:
	// Gateway.Close tears every machine down, and it must not come back
	// while a teardown some other goroutine began is still writing
	// (IAMT-471).
	torn chan struct{}

	// statusMisses counts door.status requests in a row that got no answer
	// at all (IAMT-457, statusPause). Any answer resets it.
	statusMisses int

	// doorKey/doorKeyID cache the signer of the door most recently opened
	// for this machine. core.Machine.Snapshot() deliberately exposes only
	// HasPrivateKey (a bool), never the key itself; the key travels once,
	// inside the core.Command a door.open Apply() returns (core/door.go:
	// startOpen sets Command.Door = d, the full Door including
	// PrivateKey). Capturing it here, at the one place that command is
	// driven, is how the nested SSH handshake to the target gets a signer
	// without core exporting the key any wider than that.
	doorKey   ssh.Signer
	doorKeyID string

	stopProbe func()

	// ctx is cancelled exactly once, by teardown. core.Bridge needs EOF (or
	// a cancelled context) on BOTH directions to fully close a session:
	// when the machine's transport dies, only the target side of a live
	// human bridge breaks - the human side stays blocked reading from a
	// human who is still there and has sent nothing. Closing mc.sconn alone
	// does not unblock that Read; every human session bridged through this
	// machine is started with this context so teardown can force it closed
	// (SPEC §3.2: when the connection drops, do not pretend the machine is there - a stuck
	// bridge is exactly that pretence).
	ctx    context.Context
	cancel context.CancelFunc
}

// retiredOpen is kept under machineConn.mu.  A reply may arrive while the
// timeout path is still driving its mandatory door.status, hence response is
// retained until reconciliation says whether that status already cleaned it.
type retiredOpen struct {
	response          *controlResponse
	reconcileComplete bool
}

// currentDoorSigner returns the signer of the door this machine currently has
// open, if any. A caller must only trust the result after observing
// Snapshot().State == core.Open for the matching door id.
func (mc *machineConn) currentDoorSigner() (ssh.Signer, string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return mc.doorKey, mc.doorKeyID
}

// IsOnline reports whether the door automaton currently considers the
// machine online (PROTOCOL §5.2: online:true is allowed only after the
// control channel has been opened successfully, the initial door.status,
// and, if that one found a line, its confirmed cleanup). Used by e2e tests that
// drive the enrol wire path and need to assert "the machine is online
// now" without poking unexported fields.
func (mc *machineConn) IsOnline() bool {
	return mc.doorMachine.Snapshot().Online
}

func newMachineConn(g *Gateway, id string, sconn *ssh.ServerConn, epoch uint64) (*machineConn, error) {
	dm, err := core.NewMachine(core.Config{
		Now:      g.cfg.Now,
		DoorIdle: g.cfg.DoorIdle,
		DoorHard: g.cfg.DoorHard,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &machineConn{
		id:          id,
		sconn:       sconn,
		epoch:       epoch,
		g:           g,
		doorMachine: dm,
		pending:     make(map[string]chan controlResponse),
		retired:     make(map[string]*retiredOpen),
		doneCh:      make(chan struct{}),
		torn:        make(chan struct{}),
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// attachControl starts the read loop for the accepted iamtunnel-control
// channel. Global requests inside it are drained and refused (PROTOCOL §5.1
// carries no global requests of its own on this channel).
func (mc *machineConn) attachControl(ch ssh.Channel, reqs <-chan *ssh.Request) {
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		_ = ch.Close()
		return
	}
	mc.ctrlCh = ch
	mc.mu.Unlock()
	go func() {
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	// Counted in g.wg, which Close waits for (IAMT-471): the reader is the
	// one that tears the connection down when the machine drops, and its
	// machine.disconnected reached the journal after Close had returned.
	// The Add is safe here: handleMachine runs inside handleConn, whose own
	// count keeps g.wg above zero.
	mc.g.wg.Add(1)
	go mc.readLoop(ch)
}

func (mc *machineConn) readLoop(ch ssh.Channel) {
	defer mc.g.wg.Done()
	// One line at a time, never more than controlLineMax of it, each
	// held to §5.1's shape before anything acts on it (IAMT-443,
	// control_read.go). A line that breaks the rule cannot be trusted to
	// name the request it belongs to, so it ends the tunnel - the answer
	// the machine gives the gateway for the same fault.
	r := bufio.NewReaderSize(ch, controlLineMax+1)
	inflight := make(chan struct{}, maxMachineRequestsInFlight)
	for {
		// IAMT-338: the channel carries two kinds of line now. A
		// response answers something the gateway asked; a REQUEST is the
		// machine asking of its own accord (control_inbound.go), and it
		// is told apart by carrying an op. Before this the second kind
		// was decoded as a malformed response and dropped in silence,
		// which turned every machine-initiated request into a timeout
		// and every gateway refusal into one too.
		line, err := readControlLine(r, controlLineMax)
		if err != nil {
			if errors.Is(err, errControlLineTooLong) || errors.Is(err, errControlLineTruncated) {
				mc.teardown("control-framing")
			} else {
				mc.teardown("control-read-error")
			}
			return
		}
		in, err := decodeControlInbound(line)
		if err != nil {
			mc.teardown("control-protocol")
			return
		}
		if in.Op != "" {
			// Bounded (IAMT-443): the read waits for a free slot, so a
			// machine asking faster than it is answered is held back by
			// its own channel instead of parking a goroutine per line.
			select {
			case inflight <- struct{}{}:
			case <-mc.doneCh:
				return
			}
			// A request can journal (session.watch): counted like the
			// reader itself, which holds g.wg above zero for this Add.
			mc.g.wg.Add(1)
			go func() {
				defer mc.g.wg.Done()
				defer func() { <-inflight }()
				mc.handleMachineRequest(in)
			}()
			continue
		}
		resp := in.asResponse()
		mc.mu.Lock()
		c, ok := mc.pending[resp.ID]
		if ok {
			delete(mc.pending, resp.ID)
		}
		var late *controlResponse
		if !ok {
			if retired, found := mc.retired[resp.ID]; found {
				retired.response = &resp
				if retired.reconcileComplete {
					delete(mc.retired, resp.ID)
					late = &resp
				}
			}
		}
		mc.mu.Unlock()
		if ok {
			c <- resp
		}
		if late != nil {
			// IAMT-161: same WaitGroup bookkeeping as handleMachine's
			// sshd probe — driveRetiredOpen drives door.close commands
			// that write events.jsonl through the door automaton.
			mc.g.probesWG.Add(1)
			mc.g.probesInFlight.Add(1)
			go func() {
				defer mc.g.probesWG.Done()
				defer mc.g.probesInFlight.Add(-1)
				mc.driveRetiredOpen(*late)
			}()
		}
	}
}

// sendCommand serializes one control-channel round trip. The machine
// processes door.* strictly in the order received (PROTOCOL §5.1); the
// automaton's own mutex already guarantees at most one in-flight door.open
// per machine, so the only extra thing this needs to protect is the raw
// channel write.
func (mc *machineConn) sendCommand(cmd core.Command, timeout time.Duration) (controlResponse, error) {
	req := controlRequest{Proto: 1, Caps: []string{}, ID: newRequestID(), Op: cmd.Op}
	switch cmd.Op {
	case "door.open":
		req.Door = &controlDoor{
			ID:           cmd.Door.ID,
			PubKey:       cmd.Door.PublicKey,
			Opened:       rfc3339(cmd.Door.Opened),
			IdleDeadline: rfc3339(cmd.Door.IdleDeadline),
			HardDeadline: rfc3339(cmd.Door.HardDeadline),
		}
	case "door.close":
		req.DoorID = cmd.DoorID
		req.Reason = cmd.Reason
	case "door.sanitize":
		req.Reason = cmd.Reason
	}

	replyCh := make(chan controlResponse, 1)
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return controlResponse{}, errControlClosed
	}
	ch := mc.ctrlCh
	if ch == nil {
		mc.mu.Unlock()
		return controlResponse{}, errControlClosed
	}
	mc.pending[req.ID] = replyCh
	mc.mu.Unlock()

	raw, err := json.Marshal(req)
	if err != nil {
		mc.mu.Lock()
		delete(mc.pending, req.ID)
		mc.mu.Unlock()
		return controlResponse{}, err
	}
	raw = append(raw, '\n')

	mc.writeMu.Lock()
	_, werr := ch.Write(raw)
	mc.writeMu.Unlock()
	if werr != nil {
		mc.mu.Lock()
		delete(mc.pending, req.ID)
		mc.mu.Unlock()
		mc.teardown("control-write-error")
		return controlResponse{}, errControlClosed
	}

	select {
	case resp := <-replyCh:
		return resp, nil
	case <-time.After(timeout):
		mc.mu.Lock()
		delete(mc.pending, req.ID)
		if cmd.Op == "door.open" {
			if mc.retired == nil {
				mc.retired = make(map[string]*retiredOpen)
			}
			mc.retired[req.ID] = &retiredOpen{}
		}
		mc.mu.Unlock()
		return controlResponse{}, errControlTimeout
	case <-mc.doneCh:
		return controlResponse{}, errControlClosed
	}
}

// driveOne executes exactly one core.Command: send it, translate the wire
// outcome into a core.Input, and feed it back to the automaton. Any commands
// that Apply returns as a consequence are driven in turn (drive), which is
// how a chained transition (e.g. a late reply followed by its cleanup close)
// plays out without the runtime ever deciding door policy itself.
func (mc *machineConn) driveOne(cmd core.Command) {
	mc.drive([]core.Command{cmd})
}

// driveOneSync is driveOne under driveMu, for callers outside the
// serialized entry points (F-23) - the connect sweep's first door.status,
// which applies its answer to the automaton and must not interleave with a
// cycle some other goroutine is running on this connection.
func (mc *machineConn) driveOneSync(cmd core.Command) {
	mc.driveMu.Lock()
	defer mc.driveMu.Unlock()
	mc.driveOne(cmd)
}

// driveBudget is drive for a caller with a budget: the commands THIS caller
// hands over are awaited for at most what is left of ctx's deadline, on top
// of their ordinary per-op timeout, and a door.open among them is not written
// at all if that budget is already gone (IAMT-304). Commands the automaton
// chains off them — the door.status reconciliation openingTimeout emits, the
// door.close that follows — are driven by driveOne's own tail with their
// ordinary timeouts on purpose: a spent budget must not also silence the
// cleanup that has to run after it. Without a deadline in ctx this is exactly
// drive.
func (mc *machineConn) driveBudget(cmds []core.Command, ctx context.Context) {
	deadline, bounded := ctx.Deadline()
	for _, c := range cmds {
		mc.drive(mc.driveOneUntil(c, deadline, bounded))
	}
}

// driveOneUntil is driveOne with an optional ceiling on the wire wait. With
// bounded set, a door.open is awaited for at most the time left until deadline
// and is not written at all once that time is gone; every other command keeps
// its configured timeout, because a ceiling that could silence a close would
// trade a late door for a leaked one.
//
// The refusal to write is decided here, next to sendCommand, rather than at
// the caller's entry (IAMT-304, review round 9). A caller cannot check the
// deadline and then send atomically: `reserve`'s own pre-check left a window
// between the check and the write, and sendCommand registers the pending entry
// and writes the request BEFORE it starts waiting — so a deadline that passed
// in that window still put door.open on the wire, and the machine installed a
// temporary door for a probe that had already given up. Consulting the
// deadline immediately before the send is the last moment at which "the budget
// was still alive" is still true of the write itself.
//
// A door.open that is not written is still fed to the automaton as
// core.Timeout: the Opening row's timeout cell is what runs the mandatory
// reconciliation (door.status, and the close of anything that status finds),
// and the automaton, not this function, decides whether a line has to be
// cleaned up. Resolving the reservation as a failure without that event would
// skip the reconciliation entirely.
//
// It returns the commands the automaton chained off this one rather than
// driving them itself (IAMT-457): drive runs them as a loop. Driven from
// here, a reconciliation that never got an answer nested one more call per
// unanswered door.status, for as long as the machine kept its tunnel.
func (mc *machineConn) driveOneUntil(cmd core.Command, deadline time.Time, bounded bool) []core.Command {
	timeout := mc.g.cfg.DoorCloseTimeout
	switch cmd.Op {
	case "door.open":
		timeout = mc.g.cfg.DoorOpenTimeout
	case "door.status":
		timeout = mc.g.cfg.DoorStatusTimeout
	}
	notSent := false
	if bounded && cmd.Op == "door.open" {
		if left := time.Until(deadline); left <= 0 {
			notSent = true
		} else if left < timeout {
			timeout = left
		}
	}
	// before feeds the §5.2 terminal-cell check below: the runtime must see
	// the transition itself, not a flag the machine happened to carry
	// before it (the sweep close of a reconnect runs while the machine is
	// still offline - a was-online flip would miss exactly that refusal).
	before := mc.doorMachine.Snapshot()
	var ownAtIssue bool
	if cmd.Op == "door.close" {
		ownAtIssue = before.HasPrivateKey
	}
	if cmd.Op == "door.open" && !notSent {
		// Only a door.open that actually went out names the door most
		// recently opened for this machine: a request that was never written
		// leaves no line, and core forgets that door in the very transition
		// below (openingTimeout), so caching its key would keep a signer for
		// a door id the machine was never asked to install.
		mc.mu.Lock()
		mc.doorKey, mc.doorKeyID = cmd.Door.PrivateKey, cmd.Door.ID
		mc.mu.Unlock()
	}

	var resp controlResponse
	var err error
	if notSent {
		err = errControlTimeout
	} else {
		if fn := beforeSendCommandFn.Load(); fn != nil {
			(*fn)(mc, cmd)
		}
		resp, err = mc.sendCommand(cmd, timeout)
	}
	if errors.Is(err, errControlClosed) {
		// teardown already applied TransportLost and resolved every ticket;
		// feeding a second event here would be the runtime inventing a
		// second opinion about door policy instead of the automaton's.
		return nil
	}
	if cmd.Op == "door.status" {
		// Any answer, even a refusal, is a machine that is listening; only
		// silence counts towards giving up on it (statusPause).
		mc.mu.Lock()
		if errors.Is(err, errControlTimeout) {
			mc.statusMisses++
		} else {
			mc.statusMisses = 0
		}
		mc.mu.Unlock()
	}

	var in core.Input
	switch {
	case errors.Is(err, errControlTimeout):
		in = core.Input{Event: core.Timeout}
	case err != nil, !resp.OK:
		in = core.Input{Event: core.Failure}
	default:
		switch cmd.Op {
		case "door.open":
			var r doorOpenResult
			_ = json.Unmarshal(resp.Result, &r)
			in = core.Input{Event: core.Success, DoorID: r.DoorID}
		case "door.close":
			var r doorCloseResult
			_ = json.Unmarshal(resp.Result, &r)
			in = core.Input{Event: core.Success, DoorID: r.DoorID, Own: ownAtIssue}
		case "door.status":
			var r doorStatusResult
			_ = json.Unmarshal(resp.Result, &r)
			in = core.Input{Event: core.Status, Installed: r.Installed, DoorID: r.DoorID}
		case "door.sanitize":
			// door.sanitize sweeps every door-line on the machine rather than
			// naming one id (§5.1), so a success reply carries nothing the
			// automaton needs to check - it always plays as the "not this
			// epoch's own door" branch of closingSuccess (Own left false).
			in = core.Input{Event: core.Success}
		}
	}

	// door.sanitize is the only control-channel operation that removes every
	// marked line from administrators_authorized_keys without naming one id -
	// it wipes admin access blind (IAMT-103). The journal must speak about it
	// in every outcome. Outcome lives in the Event.Result field ("ok",
	// "timeout", "refused"), not in a separate event type: that matches the
	// convention the rest of the dictionary already follows for auth.failure
	// and session.drop, and the IAMT-104 decision for door.*. A successful
	// sanitize records the count it took (a zero-count success is still
	// recorded, because "the gateway swept and found nothing" is a separate
	// fact from "the gateway never swept"); a refused sanitize records the
	// errCode in Details["err"]; a timed-out one has no err — the deadline
	// itself is the verdict.
	if cmd.Op == "door.sanitize" {
		switch {
		case errors.Is(err, errControlTimeout):
			mc.g.appendEvent(events.Event{
				Type:   events.EventDoorSanitize,
				Actor:  "gateway",
				Object: mc.id,
				Result: "timeout",
				Details: map[string]interface{}{
					"epoch":  mc.epoch,
					"reason": cmd.Reason,
				},
			})
		case err != nil, !resp.OK:
			mc.g.appendEvent(events.Event{
				Type:   events.EventDoorSanitize,
				Actor:  "gateway",
				Object: mc.id,
				Result: "refused",
				Details: map[string]interface{}{
					"epoch":  mc.epoch,
					"reason": cmd.Reason,
					"err":    sanitizeErrorText(err, resp),
				},
			})
		default:
			var r sanitizeResult
			_ = json.Unmarshal(resp.Result, &r)
			mc.g.appendEvent(events.Event{
				Type:   events.EventDoorSanitize,
				Actor:  "gateway",
				Object: mc.id,
				Result: "ok",
				Details: map[string]interface{}{
					"epoch":   mc.epoch,
					"reason":  cmd.Reason,
					"removed": r.Removed,
				},
			})
		}
	}

	if cmd.Op == "door.open" {
		switch {
		case errors.Is(err, errControlTimeout):
			details := map[string]interface{}{
				"epoch":  mc.epoch,
				"doorId": cmd.Door.ID,
				"reason": cmd.Reason,
			}
			if notSent {
				// "timeout" is the verdict either way, but a journal that
				// cannot tell "we asked and gave up" from "the budget was
				// already spent, so nothing was ever asked" hides the
				// difference between a late door and no door at all.
				details["notSent"] = true
			}
			mc.g.appendEvent(events.Event{
				Type:    events.EventDoorOpen,
				Actor:   "gateway",
				Object:  mc.id,
				Result:  "timeout",
				Details: details,
			})
		case err != nil, !resp.OK:
			mc.g.appendEvent(events.Event{
				Type:   events.EventDoorOpen,
				Actor:  "gateway",
				Object: mc.id,
				Result: "refused",
				Details: map[string]interface{}{
					"epoch":  mc.epoch,
					"doorId": cmd.Door.ID,
					"reason": cmd.Reason,
					"err":    sanitizeErrorText(err, resp),
				},
			})
		default:
			var r doorOpenResult
			_ = json.Unmarshal(resp.Result, &r)
			doorID := r.DoorID
			if doorID == "" {
				doorID = cmd.Door.ID
			}
			mc.g.appendEvent(events.Event{
				Type:   events.EventDoorOpen,
				Actor:  "gateway",
				Object: mc.id,
				Result: "ok",
				Details: map[string]interface{}{
					"epoch":     mc.epoch,
					"doorId":    doorID,
					"installed": r.Installed,
					"reason":    cmd.Reason,
				},
			})
		}
	}

	if cmd.Op == "door.close" && err == nil && resp.OK {
		var r doorCloseResult
		_ = json.Unmarshal(resp.Result, &r)
		doorID := r.DoorID
		if doorID == "" {
			doorID = cmd.DoorID
		}
		mc.g.appendEvent(events.Event{
			Type:   events.EventDoorClose,
			Actor:  "gateway",
			Object: mc.id,
			Result: "ok",
			Details: map[string]interface{}{
				"epoch":   mc.epoch,
				"doorId":  doorID,
				"removed": r.Removed,
				"reason":  cmd.Reason,
			},
		})
	}

	next, aerr := mc.doorMachine.Apply(in)
	if aerr != nil {
		return nil
	}
	cur := mc.doorMachine.Snapshot()
	switch {
	case cmd.Op == "door.open" && cur.State == core.Open:
		mc.resolveTickets(true, "")
	case cmd.Op == "door.open" && cur.State == core.Closed:
		reason := "door did not open"
		if notSent {
			// The caller's budget, not the machine, ended this wait: the
			// reservation must not report a wire outcome for a request that
			// never went out.
			reason = "the reservation budget was already spent"
		}
		mc.resolveTickets(false, reason)
	case cmd.Op == "door.close" && cur.State == core.Closed && (in.Event == core.Failure || in.Event == core.Timeout):
		mc.resolveTickets(false, "door close failed")
	}
	// PROTOCOL §5.2, "closing" row, terminal cell (a refused close/sanitize,
	// or the second timeout of either): close the transport and wait for a
	// new epoch. The transition itself is the verdict - the Closing row ends
	// in Closed on Failure/second-Timeout and nowhere else - so executing
	// the cut here is not a second policy, it is this cell's prescribed
	// action. The epoch ends - unregistered, transport closed - and only
	// the machine's reconnect (a new tunnelEpoch that passes the initial
	// door.status sweep, §5.3 race 3) makes the gateway call the machine
	// alive again. One refusal therefore cannot leave the machine offline
	// forever (IAMT-69), and a genuinely stuck line still never admits
	// anyone: every later epoch repeats the sweep and the close until the
	// line is actually gone (TestRepeatedDoorCloseFailureStillDenies-
	// Everyone).
	terminalCut := before.State == core.Closing &&
		(in.Event == core.Failure || in.Event == core.Timeout) &&
		cur.State == core.Closed
	if terminalCut {
		mc.g.appendEvent(events.Event{
			Type:   events.EventDoorClose,
			Actor:  "gateway",
			Object: mc.id,
			Result: "failed",
			Details: map[string]interface{}{
				"epoch":   mc.epoch,
				"verdict": "new-epoch-required",
				"why":     "door.close refused or unanswered twice (PROTOCOL §5.2, closing row)",
			},
		})
		mc.teardown("door-close-failed")
	}
	// openingTimeout always asks the machine for door.status before another
	// reservation may create a door.  If that status saw an installed line,
	// its ordinary reconciliation close owns cleanup; otherwise a stored late
	// door.open success must become LateReply and make the automaton close it.
	if cmd.Op == "door.status" && before.ReconcilePending {
		mc.completeRetiredOpenReconciliation(in.Event == core.Status && in.Installed)
	}
	return next
}

// completeRetiredOpenReconciliation releases late successes only after the
// status generated by openingTimeout has completed.  A positive status has
// already produced core's reconnect close, so the matching retired reply is
// deliberately discarded rather than issuing a duplicate close.
func (mc *machineConn) completeRetiredOpenReconciliation(statusInstalled bool) {
	var late []controlResponse
	mc.mu.Lock()
	for id, retired := range mc.retired {
		if statusInstalled {
			delete(mc.retired, id)
			continue
		}
		retired.reconcileComplete = true
		if retired.response != nil {
			late = append(late, *retired.response)
			delete(mc.retired, id)
		}
	}
	mc.mu.Unlock()
	for _, resp := range late {
		// IAMT-161: same WaitGroup bookkeeping as handleMachine's sshd
		// probe — see readLoop above for the matching increment.
		mc.g.probesWG.Add(1)
		mc.g.probesInFlight.Add(1)
		go func(resp controlResponse) {
			defer mc.g.probesWG.Done()
			defer mc.g.probesInFlight.Add(-1)
			mc.driveRetiredOpen(resp)
		}(resp)
	}
}

// driveRetiredOpen translates only a successful late door.open response.  It
// delegates the cleanup decision to core's Closed+LateReply cell; the runtime
// never manufactures a close of its own. The LateReply transition and the
// close it produces are one wire cycle under driveMu (F-23), taken here
// because this runs in goroutines of its own (readLoop and
// completeRetiredOpenReconciliation spawn it) - never under a caller's lock.
func (mc *machineConn) driveRetiredOpen(resp controlResponse) {
	if !resp.OK {
		return
	}
	var result doorOpenResult
	_ = json.Unmarshal(resp.Result, &result)
	mc.driveMu.Lock()
	defer mc.driveMu.Unlock()
	cmds, err := mc.doorMachine.Apply(core.Input{
		Event:   core.LateReply,
		DoorID:  result.DoorID,
		Retired: true,
	})
	if err == nil {
		mc.drive(cmds)
	}
}

// drive runs cmds and everything the automaton chains off them, in the order
// the chain would have run depth first, as one loop (IAMT-457): a chained
// command goes to the front of the queue, before the rest of what its parent
// was part of.
//
// Every door.status first waits out statusPause. That is where the §5.2 rule
// lives -- a Timeout/error of this status only repeats the background check
// with backoff -- and where a machine that answers nothing on its control
// channel is finally let go of.
func (mc *machineConn) drive(cmds []core.Command) {
	queue := append([]core.Command(nil), cmds...)
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		if c.Op == "door.status" && !mc.statusPause() {
			return
		}
		queue = append(mc.driveOneUntil(c, time.Time{}, false), queue...)
	}
}

// doorStatusBackoffCap bounds the pause between two door.status to a machine
// that has not answered the last ones.
const doorStatusBackoffCap = 30 * time.Second

// statusPause is the wait before a door.status that follows unanswered ones:
// DoorStatusBackoff after the first miss, doubling after each further one, up
// to doorStatusBackoffCap. After DoorStatusMaxMisses in a row the machine is
// let go of - its epoch is torn down (control-unresponsive), which frees the
// registry for the machine's own reconnect, the one thing that can bring a
// stuck control handler back. Not while a session is live on it, though:
// those sessions are working through their own channels, and a door that
// cannot be reconciled is no reason to cut them; the retries then go on at
// the capped pause. It returns false when there is nothing left to send to:
// the machine was let go of here, or went away during the pause.
func (mc *machineConn) statusPause() bool {
	mc.mu.Lock()
	misses := mc.statusMisses
	mc.mu.Unlock()
	if misses == 0 {
		return true
	}
	if misses >= mc.g.cfg.DoorStatusMaxMisses && mc.doorMachine.Snapshot().Sessions == 0 {
		mc.teardown("control-unresponsive")
		return false
	}
	pause := doorStatusBackoffCap
	if shift := misses - 1; shift < 16 {
		if p := mc.g.cfg.DoorStatusBackoff << shift; p < pause {
			pause = p
		}
	}
	t := time.NewTimer(pause)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-mc.doneCh:
		return false
	}
}

func (mc *machineConn) resolveTickets(ok bool, reason string) {
	mc.mu.Lock()
	tickets := mc.tickets
	mc.tickets = nil
	mc.mu.Unlock()
	for _, t := range tickets {
		t.outcome <- doorOutcome{ok: ok, reason: reason}
	}
}

// reserve registers one human's reservation and blocks until the door is
// open for it, the reservation fails, ctx is done, or the machine goes away.
// It never decides door policy: every outcome it reports is either an
// immediate read of Snapshot().State == Open (state the automaton already
// reached) or a resolution driveOne computed from a wire reply.
//
// ctx is a budget, not just a cancellation channel (IAMT-304). Both halves of
// that budget are enforced where they bind, not here:
//
//   - a spent budget must not put door.open on the wire, so no temporary door
//     is installed for a caller that has already given up (for an sshd probe
//     that would be a line on the machine nobody is waiting for). That check
//     lives in driveOneUntil, immediately before sendCommand, because a check
//     at this function's entry cannot bind the write: the deadline can pass
//     between the two, and sendCommand writes the request before it starts
//     waiting for the reply (review round 9).
//   - the synchronous door.open wait is bounded by what is left of ctx, not by
//     DoorOpenTimeout alone. A probe that announced a 20s deadline must stop
//     waiting for the reply at that deadline rather than 10s later, and the
//     machine's late reply is then the automaton's late-reply cell to close,
//     not the runtime's assumption.
//
// A spent budget therefore still feeds core.Reservation and the door.open
// timeout cell: the automaton runs the reconciliation §5.2 owes after an
// opening that did not complete, and the reservation resolves as a timeout
// rather than as a wire failure. The select below keeps its ctx.Done branch
// for the other case — a request that did go out and whose transition left the
// ticket unresolved.
func (mc *machineConn) reserve(ctx context.Context) (bool, string) {
	t, opened, reason := mc.reserveWire(ctx)
	if t == nil {
		return opened, reason
	}
	select {
	case out := <-t.outcome:
		return out.ok, out.reason
	case <-ctx.Done():
		mc.cancelTicket(t)
		return false, "session setup timeout"
	case <-mc.doneCh:
		return false, "machine disconnected"
	}
}

// reserveWire is reserve's wire half, under driveMu (F-23): the Reservation
// transition and the door.open it produced are one serialized cycle, so no
// other entry point can put a door.close on the wire between the automaton
// deciding to open and the open itself being written. It returns a non-nil
// ticket when the caller is to wait for the door on it (the wire work is
// done; the ticket wait needs no lock), and a nil ticket with the final
// answer otherwise.
func (mc *machineConn) reserveWire(ctx context.Context) (*reservationTicket, bool, string) {
	mc.driveMu.Lock()
	defer mc.driveMu.Unlock()
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return nil, false, "machine disconnected"
	}
	cmds, err := mc.doorMachine.Apply(core.Input{Event: core.Reservation})
	if err != nil {
		mc.mu.Unlock()
		return nil, false, "door protocol error"
	}
	snap := mc.doorMachine.Snapshot()
	if snap.State == core.Open {
		mc.mu.Unlock()
		mc.driveBudget(cmds, ctx)
		return nil, true, ""
	}
	t := &reservationTicket{outcome: make(chan doorOutcome, 1)}
	mc.tickets = append(mc.tickets, t)
	mc.mu.Unlock()

	mc.driveBudget(cmds, ctx)
	return t, false, ""
}

func (mc *machineConn) cancelTicket(t *reservationTicket) {
	// Under driveMu (F-23): the CancelReservation transition and the
	// door.close it may produce are one wire cycle, like any other.
	mc.driveMu.Lock()
	defer mc.driveMu.Unlock()
	mc.mu.Lock()
	for i, x := range mc.tickets {
		if x == t {
			mc.tickets = append(mc.tickets[:i], mc.tickets[i+1:]...)
			break
		}
	}
	mc.mu.Unlock()
	cmds, err := mc.doorMachine.Apply(core.Input{Event: core.CancelReservation})
	if err == nil {
		mc.drive(cmds)
	}
}

// nestedHandshakeSucceeded/nestedHandshakeFailed report the outcome of the
// nested SSH handshake to sshd through iamtunnel-target (PROTOCOL §5.2): a
// reservation the door already granted either becomes a counted session or
// is released, exactly the Success/NestedFailure cells of the Open row.
// Both are wire cycles under driveMu (F-23) like every other transition:
// the release's door.close must not be overtaken by - or overtake - a
// cycle another entry point is running.
func (mc *machineConn) nestedHandshakeSucceeded() {
	mc.driveMu.Lock()
	defer mc.driveMu.Unlock()
	cmds, err := mc.doorMachine.Apply(core.Input{Event: core.Success})
	if err == nil {
		mc.drive(cmds)
	}
}

func (mc *machineConn) nestedHandshakeFailed() {
	mc.driveMu.Lock()
	defer mc.driveMu.Unlock()
	cmds, err := mc.doorMachine.Apply(core.Input{Event: core.NestedFailure})
	if err == nil {
		mc.drive(cmds)
	}
}

// doorRecheck is what recheckDoor found out about a door sshd had just
// refused the key of (IAMT-461).
type doorRecheck uint8

const (
	// doorStillInstalled: the machine holds that door, so the refusal is
	// sshd's own - or the question went unanswered and nothing is known
	// better than before. The caller's reservation is still held; the
	// caller releases it as the nested failure it is.
	doorStillInstalled doorRecheck = iota
	// doorReopened: the machine had closed that door itself, and a new one
	// is open now. The caller's reservation is still held; the caller tries
	// the handshake once more, with the door's current key.
	doorReopened
	// doorUnavailable: no new door could be had. The automaton has already
	// released the caller's reservation (a failed open, a lost transport or
	// the caller's own spent budget), and the caller must not release it a
	// second time.
	doorUnavailable
)

// recheckDoor asks the machine, through the automaton's open-row status cell,
// whether door doorID is still installed after sshd refused its key
// (IAMT-461), and when it is not, waits for the new door the automaton opens
// at once for the reservations still waiting - the caller's among them.
//
// The status is sent here rather than through driveOne: an unanswered or
// refused question changes nothing in the automaton (the door was not asked
// to do anything), whereas driveOne would feed that timeout to the open row
// as a failed nested handshake, and to a door closing meanwhile as a failed
// close. Only a real answer is applied.
func (mc *machineConn) recheckDoor(ctx context.Context, doorID string) doorRecheck {
	t, verdict := mc.recheckDoorWire(ctx, doorID)
	if t == nil {
		return verdict
	}
	select {
	case out := <-t.outcome:
		if out.ok {
			return doorReopened
		}
		return doorUnavailable
	case <-ctx.Done():
		mc.cancelTicket(t)
		return doorUnavailable
	case <-mc.doneCh:
		return doorUnavailable
	}
}

// recheckDoorWire is recheckDoor's wire half, under driveMu (F-23): the
// Recheck question, every answer applied to the automaton and the reopen
// drive are one serialized cycle, so no other entry point can interleave a
// transition of its own between them. It returns a non-nil ticket when the
// caller is to wait for the reopened door on it (the wire work is done; the
// wait needs no lock - the outcome comes from a cycle that will take its
// own turn), and a nil ticket with the final verdict otherwise.
func (mc *machineConn) recheckDoorWire(ctx context.Context, doorID string) (*reservationTicket, doorRecheck) {
	mc.driveMu.Lock()
	defer mc.driveMu.Unlock()
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return nil, doorUnavailable
	}
	cmds := mc.doorMachine.Recheck(doorID)
	if snap := mc.doorMachine.Snapshot(); len(cmds) == 0 && snap.State == core.Open {
		// Another caller has already found the door gone and replaced it.
		mc.mu.Unlock()
		return nil, doorReopened
	}
	t := &reservationTicket{outcome: make(chan doorOutcome, 1)}
	mc.tickets = append(mc.tickets, t)
	mc.mu.Unlock()

	for _, cmd := range cmds {
		timeout := mc.g.cfg.DoorStatusTimeout
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
			timeout = time.Until(deadline)
		}
		if timeout <= 0 {
			mc.dropTicket(t)
			return nil, doorStillInstalled
		}
		resp, err := mc.sendCommand(cmd, timeout)
		if errors.Is(err, errControlClosed) {
			// teardown released every reservation and resolved every ticket.
			return nil, doorUnavailable
		}
		if err != nil || !resp.OK {
			mc.dropTicket(t)
			return nil, doorStillInstalled
		}
		var r doorStatusResult
		_ = json.Unmarshal(resp.Result, &r)
		next, aerr := mc.doorMachine.Apply(core.Input{Event: core.Status, Installed: r.Installed, DoorID: r.DoorID})
		if aerr != nil {
			// The door moved on while the question was on the wire (it is
			// closing or opening now): wait for the outcome below.
			break
		}
		if snap := mc.doorMachine.Snapshot(); snap.State == core.Open && snap.DoorID == doorID {
			mc.dropTicket(t)
			return nil, doorStillInstalled
		}
		mc.g.appendEvent(events.Event{
			Type:   events.EventDoorClose,
			Actor:  mc.id,
			Object: mc.id,
			Result: "gone",
			Details: map[string]interface{}{
				"epoch":  mc.epoch,
				"doorId": doorID,
				"why":    "the machine had closed the door itself (its own idle or hard timer); found by door.status after sshd refused the door key",
			},
		})
		mc.driveBudget(next, ctx)
	}

	return t, doorUnavailable
}

// dropTicket takes a ticket off the list without touching the automaton: the
// reservation it waited for is still the caller's to release.
func (mc *machineConn) dropTicket(t *reservationTicket) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	for i, x := range mc.tickets {
		if x == t {
			mc.tickets = append(mc.tickets[:i], mc.tickets[i+1:]...)
			return
		}
	}
}

// enforceHardDeadline closes the door once its hard deadline has passed on
// the gateway's own clock (core.Machine.HardDeadline, IAMT-461). The expiry
// sweep calls it every tick; the close is driven off that loop, counted in
// probesWG like every other background door operation, so a machine slow to
// answer does not hold up the next tick for anyone else. The transition and
// its close are applied inside the goroutine, under driveMu (F-23) - a hard
// deadline close is a wire cycle like any other, and the sweep's tick must
// not race one that a session is running.
func (mc *machineConn) enforceHardDeadline(now time.Time) {
	mc.g.probesWG.Add(1)
	mc.g.probesInFlight.Add(1)
	go func() {
		defer mc.g.probesWG.Done()
		defer mc.g.probesInFlight.Add(-1)
		mc.driveMu.Lock()
		defer mc.driveMu.Unlock()
		cmds := mc.doorMachine.HardDeadline(now)
		if len(cmds) == 0 {
			return
		}
		mc.drive(cmds)
	}()
}

// releaseProbeReservation releases the temporary-door reservation used by an
// sshd probe. A probe proves public-key authentication but intentionally never
// opens a nested session, so its terminal event is NestedFailure rather than
// FinishSession. Unlike the general nested-handshake wrapper, its error is
// returned: a probe must not hide a rejected door-automaton transition.
// Serialized under driveMu like every wire cycle (F-23).
func (mc *machineConn) releaseProbeReservation() error {
	mc.driveMu.Lock()
	defer mc.driveMu.Unlock()
	cmds, err := mc.doorMachine.Apply(core.Input{Event: core.NestedFailure})
	if err != nil {
		return err
	}
	mc.drive(cmds)
	return nil
}

// finishSession releases one completed session's door slot (core.Machine.
// FinishSession) and drives whatever idle-close it produces. Serialized
// under driveMu like every wire cycle (F-23).
func (mc *machineConn) finishSession() {
	mc.driveMu.Lock()
	defer mc.driveMu.Unlock()
	cmds, err := mc.doorMachine.FinishSession()
	if err == nil {
		mc.drive(cmds)
	}
}

// closeForOSUserChange removes a live door before a different requested OS
// user can be probed. ForceClose uses the same closing transition and control
// path as every other door close, including its retry and epoch-cut rules.
// Why the door was stopped is the admin.op machines.set-user line the caller
// writes next; the close itself says "stop" (IAMT-469). Serialized under
// driveMu (F-23): the ForceClose transition and the door.close it returns
// are one wire cycle, and a reserve parked between its own transition and
// its write must not let this close overtake it on the wire.
func (mc *machineConn) closeForOSUserChange() {
	mc.driveMu.Lock()
	defer mc.driveMu.Unlock()
	cmds, err := mc.doorMachine.ForceClose()
	if err == nil {
		mc.drive(cmds)
	}
}

// teardown is the one path for "this machine's transport is gone": lost
// control channel, keepalive timeout, or eviction by a reconnect. It applies
// TransportLost exactly once, which is the automaton's own "everything about
// this epoch is dead" transition (core/door.go: lost), fails every
// outstanding reservation ticket, and unregisters the connection. It never
// decides to close the door itself - core.core's `lost` transition already
// did that by clearing the state the machine is trusted to reconcile on its
// next connect.
func (mc *machineConn) teardown(reason string) {
	mc.teardownWith(reason, nil)
}

// teardownWith is teardown with facts about the death that only the caller
// knows, for the machine.disconnected line this writes. The keepalive
// probe is the first caller (F-06, round-1 review 24.09.2026): the reason
// alone says a machine went silent, and an operator investigating "it
// drops every minute" needs the window the gateway watched as well.
func (mc *machineConn) teardownWith(reason string, details map[string]interface{}) {
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		<-mc.torn
		return
	}
	mc.closed = true
	stopProbe := mc.stopProbe
	ctrlCh := mc.ctrlCh
	mc.mu.Unlock()
	defer close(mc.torn)

	_, _ = mc.doorMachine.Apply(core.Input{Event: core.TransportLost})
	mc.resolveTickets(false, reason)
	mc.cancel()
	close(mc.doneCh)
	if stopProbe != nil {
		stopProbe()
	}
	if ctrlCh != nil {
		_ = ctrlCh.Close()
	}
	_ = mc.sconn.Close()
	mc.g.reg.remove(mc)
	line := map[string]interface{}{"tunnelEpoch": mc.epoch}
	for k, v := range details {
		line[k] = v
	}
	mc.g.appendEvent(events.Event{
		Type:    events.EventMachineDisconnected,
		Actor:   mc.id,
		Object:  mc.id,
		Result:  reason,
		Details: line,
	})
}

// setStopProbe publishes the keepalive stopper under the same lock teardown
// uses to take ownership of runtime resources. If teardown won the race while
// Probe was being created, stop the newly-created probe immediately instead of
// leaving it alive without an owner.
func (mc *machineConn) setStopProbe(stop func()) {
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		stop()
		return
	}
	mc.stopProbe = stop
	mc.mu.Unlock()
}
