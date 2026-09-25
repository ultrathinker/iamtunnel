package gateway

// harness_test.go: a fake machine and a fake human on the same SSH library
// (golang.org/x/crypto/ssh), the way internal/sshx's end-to-end tests already
// do it (see internal/sshx/endtoend_helpers_test.go) - extended here with the
// iamtunnel-control wire protocol this package defines (control_wire.go) and
// a fake target sshd that only accepts the door key the fake machine
// currently has "installed" in its simulated authorized_keys.
//
// Nothing here reaches the real ssh folder, a real sshd, the registry, or any
// system service: every listener is 127.0.0.1:0, every key is generated
// in-process, and all state lives in a t.TempDir().

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/proto"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// ---- key helpers -----------------------------------------------------------

func genSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func authorizedLine(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func fingerprintOf(t *testing.T, pub ssh.PublicKey) string {
	t.Helper()
	fp, err := state.ComputeFingerprint(authorizedLine(pub))
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	return fp
}

// ---- deterministic fixture shutdown (IAMT-314) ------------------------------

// connSet is the set of live connections one fixture has accepted or dialled.
// Closing the set cuts them all and refuses new registrations, so a fixture's
// cleanup can unblock its own goroutines instead of waiting for the far side
// to do it: a "range chans" or "range reqs" loop lives exactly as long as the
// transport under it. Without that, "wait for my goroutines" becomes "hang on
// them". Same helper as in internal/sshx and internal/server; test files of
// one package are not visible to another.
type connSet struct {
	mu     sync.Mutex
	closed bool
	conns  map[io.Closer]struct{}
}

func newConnSet() *connSet { return &connSet{conns: map[io.Closer]struct{}{}} }

// add registers c and returns false if the set is already closed, in which
// case c is closed here and the calling goroutine must return at once -
// otherwise it would be uncounted after closeAll.
func (cs *connSet) add(c io.Closer) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.closed {
		_ = c.Close()
		return false
	}
	cs.conns[c] = struct{}{}
	return true
}

func (cs *connSet) remove(c io.Closer) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.conns, c)
}

func (cs *connSet) closeAll() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.closed = true
	for c := range cs.conns {
		_ = c.Close()
	}
	cs.conns = map[io.Closer]struct{}{}
}

// ---- fake target sshd -------------------------------------------------------

// fakeTargetSSHD is the machine's own sshd (SPEC §5.2: "127.0.0.1:22"): it
// accepts a session, echoes bytes, and authenticates callers only against
// whatever door key keyAllowed currently reports as installed - modelling
// administrators_authorized_keys without ever touching a real file.
type fakeTargetSSHD struct {
	listener   net.Listener
	signer     ssh.Signer
	keyAllowed func(blob []byte) bool
	mu         sync.Mutex
	lastUser   string
	// cfgMod, if set, is applied to this fake sshd's own ssh.ServerConfig
	// before it starts accepting - IAMT-173's policy tests use it to pin
	// the target side to a single algorithm so the real nested-handshake
	// wire negotiation, not just a struct field, proves the gateway's
	// PROTOCOL §5.2 policy.
	cfgMod func(*ssh.ServerConfig)
	// onWindowChange, if set, is called with the cols/rows of every
	// "window-change" channel request this fake sshd's session receives -
	// IAMT-216's canary uses it to prove the resize wire-forward reaches
	// the machine side, not just the gateway's own recording.
	onWindowChange func(cols, rows int)
	// onPTYReq, if set, is called with the cols/rows of every "pty-req"
	// channel request this fake sshd's session receives - IAMT-217's canary
	// uses it to prove the machine gets the same size substituted for a
	// 0x0 pty-req that ends up in the .cast header, not the raw 0x0.
	onPTYReq func(cols, rows int)
	// onExecImmediate, if set, replaces the generic echo loop for an "exec"
	// channel request: it alone is responsible for writing output, sending
	// exit-status/exit-signal and closing ch. IAMT-306's live repro is a
	// real command that produces its output and exits entirely on its own,
	// regardless of whether the human side ever writes or closes anything -
	// serveEchoSession's default loop instead waits to echo back whatever
	// the human sent, which models an interactive terminal, not a one-shot
	// command.
	onExecImmediate func(ch ssh.Channel)
	// silent makes the sshd accept a connection and never send a byte of
	// the protocol; hangSessionOpen makes it finish the handshake and then
	// leave every session channel-open unanswered (IAMT-450: a hung sshd,
	// before and after the handshake).
	silent          bool
	hangSessionOpen bool

	// Shutdown (IAMT-314): quit wakes a session handler that is still
	// waiting to be started, conns cuts the accepted transports so every
	// "range chans"/"range reqs" ends, and wg counts every goroutine this
	// fixture starts so close() can wait for them.
	quit     chan struct{}
	quitOnce sync.Once
	wg       sync.WaitGroup
	conns    *connSet
}

func newFakeTargetSSHD(t *testing.T, keyAllowed func([]byte) bool) *fakeTargetSSHD {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeTargetSSHD{listener: ln, signer: genSigner(t), keyAllowed: keyAllowed, quit: make(chan struct{}), conns: newConnSet()}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.accept()
	}()
	t.Cleanup(s.close)
	return s
}

func (s *fakeTargetSSHD) addr() string { return s.listener.Addr().String() }

// close tears this fixture down deterministically (IAMT-314): lift every
// block first - quit, the listener, the accepted transports - and only then
// wait. The reverse order would hang on exactly the loops it is waiting for,
// and closing the listener alone was never enough: it does not touch a
// connection that has already been accepted.
func (s *fakeTargetSSHD) close() {
	s.quitOnce.Do(func() { close(s.quit) })
	_ = s.listener.Close()
	s.conns.closeAll()
	s.wg.Wait()
}

func (s *fakeTargetSSHD) accept() {
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			return
		}
		if !s.conns.add(raw) {
			continue
		}
		// wg.Add runs inside a goroutine that is itself already counted, so
		// the counter cannot reach zero between this Add and close()'s
		// Wait: there is no forbidden Add/Wait race here.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.conn(raw)
		}()
	}
}

func (s *fakeTargetSSHD) conn(raw net.Conn) {
	defer raw.Close()
	defer s.conns.remove(raw)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.Lock()
			s.lastUser = meta.User()
			keyAllowed := s.keyAllowed
			s.mu.Unlock()
			if keyAllowed(key.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("fake sshd: key not in authorized_keys")
		},
	}
	s.mu.Lock()
	cfgMod := s.cfgMod
	signer := s.signer
	onWindowChange := s.onWindowChange
	onPTYReq := s.onPTYReq
	onExecImmediate := s.onExecImmediate
	silent, hangSessionOpen := s.silent, s.hangSessionOpen
	s.mu.Unlock()
	if silent {
		_, _ = io.Copy(io.Discard, raw)
		return
	}
	if cfgMod != nil {
		cfgMod(cfg)
	}
	cfg.AddHostKey(signer)
	sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ssh.DiscardRequests(reqs)
	}()
	for n := range chans {
		if n.ChannelType() != "session" {
			_ = n.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		if hangSessionOpen {
			continue
		}
		ch, rr, err := n.Accept()
		if err != nil {
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveEchoSession(ch, rr, onWindowChange, onPTYReq, onExecImmediate)
		}()
	}
}

func (s *fakeTargetSSHD) userAuthenticatedByPublicKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastUser
}

func (s *fakeTargetSSHD) setKeyAllowed(keyAllowed func([]byte) bool) {
	s.mu.Lock()
	s.keyAllowed = keyAllowed
	s.mu.Unlock()
}

// setSigner swaps the host key this fake sshd presents on connections accepted
// from this point on. The hostkey.mismatch tests change it while the sshd is
// already accepting connections, so it goes through the same lock conn() reads
// the field under (IAMT-274): a direct assignment raced the background
// accept/conn goroutine.
func (s *fakeTargetSSHD) setSigner(signer ssh.Signer) {
	s.mu.Lock()
	s.signer = signer
	s.mu.Unlock()
}

// setCfgMod pins this fake sshd's own ssh.ServerConfig (e.g. to a single
// KEX algorithm) for connections accepted from this point on.
func (s *fakeTargetSSHD) setCfgMod(cfgMod func(*ssh.ServerConfig)) {
	s.mu.Lock()
	s.cfgMod = cfgMod
	s.mu.Unlock()
}

func (s *fakeTargetSSHD) setOnWindowChange(onWindowChange func(cols, rows int)) {
	s.mu.Lock()
	s.onWindowChange = onWindowChange
	s.mu.Unlock()
}

func (s *fakeTargetSSHD) setOnPTYReq(onPTYReq func(cols, rows int)) {
	s.mu.Lock()
	s.onPTYReq = onPTYReq
	s.mu.Unlock()
}

func (s *fakeTargetSSHD) setOnExecImmediate(fn func(ch ssh.Channel)) {
	s.mu.Lock()
	s.onExecImmediate = fn
	s.mu.Unlock()
}

func (s *fakeTargetSSHD) setSilent(silent bool) {
	s.mu.Lock()
	s.silent = silent
	s.mu.Unlock()
}

func (s *fakeTargetSSHD) setHangSessionOpen(hang bool) {
	s.mu.Lock()
	s.hangSessionOpen = hang
	s.mu.Unlock()
}

func (s *fakeTargetSSHD) serveEchoSession(ch ssh.Channel, reqs <-chan *ssh.Request, onWindowChange func(cols, rows int), onPTYReq func(cols, rows int), onExecImmediate func(ch ssh.Channel)) {
	defer ch.Close()
	started := make(chan struct{})
	reqsDone := make(chan struct{})
	var once sync.Once
	isExec := false
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(reqsDone)
		for r := range reqs {
			switch r.Type {
			case "pty-req", "shell", "window-change", "env":
				if r.Type == "window-change" && onWindowChange != nil {
					if w, err := sshx.ParseWindow(r.Payload); err == nil {
						onWindowChange(int(w.Columns), int(w.Rows))
					}
				}
				if r.Type == "pty-req" && onPTYReq != nil {
					if p, err := sshx.ParsePTY(r.Payload); err == nil {
						onPTYReq(int(p.Columns), int(p.Rows))
					}
				}
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
				if r.Type == "shell" {
					once.Do(func() { close(started) })
				}
			case "exec":
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
				isExec = true
				once.Do(func() { close(started) })
			default:
				if r.WantReply {
					_ = r.Reply(false, nil)
				}
			}
		}
	}()
	// IAMT-314: a bare "<-started" has no exit at all when neither shell
	// nor exec ever arrives, and the gateway opens this nested session as
	// soon as a human opens his channel - before any shell. That is the
	// shape goleak caught in internal/sshx, where a test really does open a
	// session and never start it. The product's own version of this wait,
	// awaitSessionStart in human_role.go, leaves on three conditions: the
	// start request, a closed request stream, and a timeout. reqsDone
	// closes strictly after the loop above has drained everything that
	// arrived, so a shell that did arrive always wins the race.
	select {
	case <-started:
	case <-reqsDone:
	case <-s.quit:
	}
	// select picks among ready cases at random, so the verdict is taken
	// from started and from nothing else.
	select {
	case <-started:
	default:
		// Never started: no echo loop and no exit-status.
		return
	}
	if isExec && onExecImmediate != nil {
		onExecImmediate(ch)
		return
	}

	buf := make([]byte, 32*1024)
	for {
		n, err := ch.Read(buf)
		if n > 0 {
			_, _ = ch.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
}

// ---- fake machine -----------------------------------------------------------

// fakeMachineBehavior lets a single test bend the fake machine's responses
// (refuse an open, go silent, etc.) without touching gateway product code -
// exactly the "inject through a constructor" seam; this
// struct configures a *test double*, not the gateway.
type fakeMachineBehavior struct {
	refuseOpen bool
	hangOpen   bool
	hangStatus bool
	// delayOpenInstall models a control request that reaches the machine but
	// finishes after the gateway's wire deadline.  The control loop continues
	// serving door.status while that delayed operation is pending.
	delayOpenInstall time.Duration
	// holdOpenInstall, if set, makes door.open's install+reply wait for a
	// receive on this channel, in addition to delayOpenInstall's fixed
	// sleep if both are set (IAMT-304 round 6). A test releases it once it
	// has independently confirmed, through fakeMachine.waitDoorOpenReceived
	// and its own short deterministic wait, that the gateway's own
	// DoorOpenTimeout has already fired - instead of guessing a sleep
	// duration long enough to outlast phase one's real, uncontrolled
	// handshake time (review round13, F-304-1).
	holdOpenInstall <-chan struct{}
	silentKeepalive bool
	// failClose makes every door.close reply ok:false and leave the
	// installed line in place - the machine whose door line cannot be
	// confirmed removed, the IAMT-69 case.
	failClose bool
	// preInstalledDoorID makes door.status report that id as already
	// installed (a line left over from an earlier epoch), with no key blob
	// behind it - the foreign-line cell of PROTOCOL §5.2 ("closed" row).
	preInstalledDoorID string
	// reportSanitizeRemoved makes door.sanitize reply with the given count
	// in its sanitizeResult.Removed payload. The default of 0 still
	// produces a well-formed reply (sanitize of a clean file).
	reportSanitizeRemoved int
	// failSanitize makes every door.sanitize reply ok:false with
	// E_CONTROL_INTERNAL — the refused sanitize path IAMT-103 asks the
	// journal to record.
	failSanitize bool
	// hangControlOpen / hangTargetOpen leave the gateway's channel-open of
	// that type unanswered - neither accepted nor refused - for as long as
	// the transport lives (IAMT-450).
	hangControlOpen bool
	hangTargetOpen  bool
	// hangSanitize makes every door.sanitize request hang with no reply
	// — exercises the gateway-side timeout branch of door.sanitize in
	// combination with a tight DoorCloseTimeout.
	hangSanitize bool
	// nackKeepalive makes the machine answer every keepalive@iamtunnel
	// probe with an explicit request failure instead of forwarding it to
	// the real success responder or dropping it silently. PROTOCOL §5
	// (unlike §4.2's human probe) does not change: failure is a protocol
	// violation there too, and this behavior proves the gateway still
	// counts it as a miss (IAMT-220 test (c) — §5 is untouched by the
	// §4.2 fix).
	nackKeepalive bool
}

type fakeMachine struct {
	t        *testing.T
	id       string
	signer   ssh.Signer
	sshdAddr string
	behavior fakeMachineBehavior

	conn ssh.Conn
	raw  net.Conn

	writeMu       sync.Mutex
	mu            sync.Mutex
	installedBlob []byte
	installedID   string
	// silent, when set, makes the machine stop answering keepalive
	// probes. It is deliberately a runtime flag and not only a
	// constructor option: a machine that is mute from its first
	// millisecond is doomed before the test has established anything,
	// so the assertion then races the very setup it depends on.
	silent bool
	// nack, when set, makes the machine answer every keepalive@iamtunnel
	// probe with an explicit request failure instead of forwarding it to
	// the real success responder. Same runtime-flag reasoning as silent:
	// a test flips it only after the session it wants to watch die is
	// already established (IAMT-220 test (c)).
	nack bool
	// everOpened is sticky (set, never cleared) so a test can tell "the door
	// was opened and then correctly closed again" from "the door was never
	// touched at all" - doorInstalled() alone answers only the current
	// instant and would miss a door that opened and closed again within a
	// polling window.
	everOpened bool
	// doorEvents reports every simulated authorized_keys transition.  Tests
	// wait for these transitions rather than assuming that a fixed sleep has
	// allowed an asynchronous close to finish.
	doorEvents chan bool
	// statusReqs counts the door.status requests that reached this machine.
	// The gateway's §5.2 reconciliation is a status round trip, so a test can
	// see that the automaton ran it even when no door was ever installed
	// (IAMT-304: a reservation whose budget was spent writes no door.open, but
	// it must still feed the Opening row's timeout cell - the cell whose whole
	// action is that status). The initial connect sweep is counted too, so
	// callers compare before and after rather than asserting an absolute.
	statusReqs int
	// openReqs counts the door.open requests that reached this machine,
	// whether or not they were allowed to install anything (hangOpen/
	// refuseOpen still count: the gateway wrote the request). IAMT-304
	// round 4 added it so a test needing to prove a temporary door's wire
	// write happened could do so directly instead of inferring it from a
	// later install - the install is asynchronous and the probe may have
	// given up in between. openReceived (round 6, below) replaced the poll
	// loop that used to read this counter (IAMT-304 round 12: that poll
	// accessor, doorOpenRequests, was removed as dead code - staticcheck
	// U1000 - once nothing called it any more); openReqs itself is kept,
	// incremented on every door.open exactly as before, for whichever
	// future test needs a plain count rather than an event wait.
	openReqs int
	// openReceived closes exactly once, the instant this machine's control
	// loop decodes a door.open request - before the hangOpen/refuseOpen/
	// delayOpenInstall branches, before anything that could take real
	// time. IAMT-304 round 6 (review, F-304-1): the deterministic
	// barrier a test blocks on instead of polling openReqs above for a
	// nonzero count, so "the open reached the wire" is an event a test can
	// wait on directly rather than a value a poll loop might not observe
	// for however long an unrelated real SSH handshake (phase one) happens
	// to take first.
	openReceived     chan struct{}
	openReceivedOnce sync.Once

	// controlOpLog records every control request this machine has decoded,
	// in wire arrival order (F-23, round-1 review 24.09.2026). The finding
	// is about the ORDER of door.* on the control channel disagreeing with
	// the order of the automaton's transitions, and no final state alone
	// tells "close then open" from "open then close" when both end Closed -
	// the order itself is the fact a test asserts.
	controlOpLog []string

	// reconcileStatusReplied closes exactly once, right after this machine
	// has WRITTEN the reply to the first door.status it receives following
	// a door.open (openingTimeout's mandatory reconciliation, PROTOCOL
	// §5.2). IAMT-304 round 7 (review round13, F-304-1 continued):
	// a late-reply scenario's holdOpenInstall must not be released on a
	// guessed wall-clock delay - under sibling load the gateway's own
	// goroutine that sends this reconciliation status can be scheduled
	// tens of milliseconds late, and a fixed sleep that assumes it already
	// ran can release the held install BEFORE the reconciliation status
	// reaches this machine. When that happens this machine truthfully
	// reports installed:true (because the release already ran), and the
	// automaton takes the (correct, spec'd) closedStatus/"reconnect" cell
	// instead of the late-reply cell the test wants to exercise -
	// completeRetiredOpenReconciliation then deliberately discards the
	// retired reply rather than double-closing. That is not a product bug;
	// it is this barrier's job to make the release wait for the fact that
	// this machine already answered "not installed" before any install can
	// happen, which pins the ordering the wire itself will deliver to the
	// gateway (both replies go through the same writeMu-guarded stream in
	// the order they are written) instead of leaving it to the scheduler.
	reconcileStatusReplied     chan struct{}
	reconcileStatusRepliedOnce sync.Once

	stopProbe func()
	closeOnce sync.Once

	// ctrl is the accepted iamtunnel-control channel, so a test can put
	// raw bytes on it with writeControlRaw (IAMT-443): lines the real
	// machine would never write, to see what the gateway does with them.
	ctrl ssh.Channel
	// ctrlStall, once closed by stallControlReader, stops serveControl
	// reading its channel: the gateway's writes then back up in the SSH
	// window exactly as they would towards a machine that stopped
	// reading (IAMT-443). stopped is closed by close() so a stalled
	// reader still leaves and wg.Wait returns.
	ctrlStall     chan struct{}
	ctrlStallOnce sync.Once
	stopped       chan struct{}

	// Shutdown (IAMT-314), same shape as fakeTargetSSHD above. conns here
	// holds the TCP connections spliceTarget dials to the fake sshd: without
	// cutting them, the copy that reads from the target waits for the target
	// to close first, and close() would hang on its own wg.Wait().
	wg    sync.WaitGroup
	conns *connSet
}

// pipeKeepalive forwards keepalive probes to the real responder while the
// machine is answering, and swallows them once it has gone silent. The
// gateway sees exactly what a mute peer looks like: the transport stays
// up and the probe simply never comes back.
func (fm *fakeMachine) pipeKeepalive(reqs <-chan *ssh.Request) {
	forward := make(chan *ssh.Request)
	fm.wg.Add(1)
	go func() {
		defer fm.wg.Done()
		sshx.Keepalive{}.Respond(forward)
	}()
	defer close(forward)
	for r := range reqs {
		if fm.isSilent() {
			continue
		}
		if fm.isNack() {
			// §5 (unlike §4.2) never treats this as alive: an explicit
			// request failure from the machine is a protocol violation,
			// not proof of life, and must still count as a miss.
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
			continue
		}
		forward <- r
	}
}

// goSilent stops the machine answering keepalive probes from this moment
// on. A test calls it after everything it wants to watch die is actually
// alive, so the teardown it asserts cannot instead race the setup.
func (fm *fakeMachine) goSilent() {
	fm.mu.Lock()
	fm.silent = true
	fm.mu.Unlock()
}

func (fm *fakeMachine) isSilent() bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.silent
}

// goNack switches the machine to answering every keepalive@iamtunnel probe
// with an explicit request failure, from this moment on (same
// after-setup-is-established reasoning as goSilent).
func (fm *fakeMachine) goNack() {
	fm.mu.Lock()
	fm.nack = true
	fm.mu.Unlock()
}

func (fm *fakeMachine) isNack() bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.nack
}

func newFakeMachine(t *testing.T, addr, id string, signer ssh.Signer, sshdAddr string, behavior fakeMachineBehavior) *fakeMachine {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("machine dial: %v", err)
	}
	cfg := &ssh.ClientConfig{
		User:            "machine:" + id,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("machine handshake: %v", err)
	}
	fm := &fakeMachine{t: t, id: id, signer: signer, sshdAddr: sshdAddr, behavior: behavior, conn: conn, raw: raw, doorEvents: make(chan bool, 8), openReceived: make(chan struct{}), reconcileStatusReplied: make(chan struct{}), conns: newConnSet(),
		ctrlStall: make(chan struct{}), stopped: make(chan struct{})}
	if behavior.preInstalledDoorID != "" {
		// A line left over from an earlier epoch: it sits in the simulated
		// authorized_keys exactly like a real one - door.status reports it,
		// a confirmed door.close removes it, a refused one leaves it.
		fm.installedID = behavior.preInstalledDoorID
	}
	// One pipe serves both cases, so going silent later exercises the same
	// code path as starting silent. Draining without ever replying is the
	// "molchashchiy peer" case sshx.Keepalive-s own doc comment calls the
	// main one, and what scenario 8 needs to exercise.
	fm.silent = behavior.silentKeepalive
	fm.nack = behavior.nackKeepalive
	fm.wg.Add(1)
	go func() {
		defer fm.wg.Done()
		fm.pipeKeepalive(reqs)
	}()
	fm.wg.Add(1)
	go func() {
		defer fm.wg.Done()
		fm.acceptChannels(chans)
	}()
	t.Cleanup(fm.close)
	return fm
}

// close cuts the machine's transports and its splices to the fake sshd, then
// waits for every goroutine this fixture started (IAMT-314). The probe is
// stopped after the transport is cut, not before: Keepalive.Probe's own doc
// comment says stop() does not wait for the goroutine of a last unanswered
// probe, which is parked in conn.SendRequest and leaves when the connection
// closes.
func (fm *fakeMachine) close() {
	fm.closeOnce.Do(func() {
		close(fm.stopped)
		_ = fm.conn.Close()
		_ = fm.raw.Close()
		fm.conns.closeAll()
		if fm.stopProbe != nil {
			fm.stopProbe()
		}
		fm.wg.Wait()
	})
}

func (fm *fakeMachine) acceptChannels(chans <-chan ssh.NewChannel) {
	for n := range chans {
		switch n.ChannelType() {
		case "iamtunnel-control":
			if fm.behavior.hangControlOpen {
				continue
			}
			ch, reqs, err := n.Accept()
			if err != nil {
				continue
			}
			fm.mu.Lock()
			fm.ctrl = ch
			fm.mu.Unlock()
			fm.wg.Add(2)
			go func() {
				defer fm.wg.Done()
				discardSSHRequests(reqs)
			}()
			go func() {
				defer fm.wg.Done()
				fm.serveControl(ch)
			}()
		case "iamtunnel-target":
			if fm.behavior.hangTargetOpen {
				continue
			}
			ch, reqs, err := n.Accept()
			if err != nil {
				continue
			}
			fm.wg.Add(2)
			go func() {
				defer fm.wg.Done()
				discardSSHRequests(reqs)
			}()
			go func() {
				defer fm.wg.Done()
				fm.spliceTarget(ch)
			}()
		default:
			_ = n.Reject(ssh.UnknownChannelType, "unexpected channel")
		}
	}
}

func discardSSHRequests(reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
	}
}

func (fm *fakeMachine) spliceTarget(ch ssh.Channel) {
	defer ch.Close()
	d, err := net.DialTimeout("tcp", fm.sshdAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer d.Close()
	// IAMT-314: registering the TCP connection is what lets close() cut it;
	// otherwise the copy reading from the target below waits for the target
	// to close first.
	if !fm.conns.add(d) {
		return
	}
	defer fm.conns.remove(d)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				if _, werr := d.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if tc, ok := d.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := d.Read(buf)
			if n > 0 {
				if _, werr := ch.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = ch.CloseWrite()
	}()
	wg.Wait()
}

func mustResult(v interface{}) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}

func (fm *fakeMachine) serveControl(ch ssh.Channel) {
	dec := json.NewDecoder(ch)
	reply := func(resp controlResponse) {
		raw, err := json.Marshal(resp)
		if err != nil {
			return
		}
		raw = append(raw, '\n')
		fm.writeMu.Lock()
		_, _ = ch.Write(raw)
		fm.writeMu.Unlock()
	}
	for {
		select {
		case <-fm.ctrlStall:
			<-fm.stopped
			return
		default:
		}
		var req controlRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		fm.mu.Lock()
		fm.controlOpLog = append(fm.controlOpLog, req.Op)
		fm.mu.Unlock()
		switch req.Op {
		case "door.open":
			// Counted before the behaviour branches: a hung or refused open is
			// still a request the gateway put on the wire, and that is what
			// this counter is for (IAMT-304 round 4: a test whose scenario
			// needs a temporary door can prove the wire write happened
			// instead of reporting a mystery when it did not).
			fm.mu.Lock()
			fm.openReqs++
			fm.mu.Unlock()
			fm.openReceivedOnce.Do(func() { close(fm.openReceived) })
			if fm.behavior.hangOpen {
				continue
			}
			if fm.behavior.refuseOpen {
				reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
					Error: &controlErrorBody{Code: "E_CONTROL_DOOR_CONFLICT", Message: "refused by test"}})
				continue
			}
			open := func() {
				blob, err := state.DecodeKeyBlob(req.Door.PubKey)
				if err != nil {
					reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
						Error: &controlErrorBody{Code: "E_CONTROL_PROTOCOL", Message: err.Error()}})
					return
				}
				fm.mu.Lock()
				fm.installedBlob = blob
				fm.installedID = req.Door.ID
				fm.everOpened = true
				fm.mu.Unlock()
				fm.signalDoorEvent(true)
				fp, _ := state.ComputeFingerprint(req.Door.PubKey)
				reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true,
					Result: mustResult(doorOpenResult{DoorID: req.Door.ID, Installed: true, PublicKeyFingerprint: fp})})
			}
			delay, hold := fm.behavior.delayOpenInstall, fm.behavior.holdOpenInstall
			if delay > 0 || hold != nil {
				go func() {
					if delay > 0 {
						time.Sleep(delay)
					}
					if hold != nil {
						<-hold
					}
					open()
				}()
				continue
			}
			open()
		case "door.close":
			if !proto.ValidDoorCloseReason(req.Reason) {
				// What the real machine refuses, this one refuses too
				// (IAMT-469): it took any reason, and a word only the
				// gateway knew went unnoticed until a real machine.
				reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
					Error: &controlErrorBody{Code: "E_CONTROL_PROTOCOL", Message: fmt.Sprintf("invalid door.close reason %q", req.Reason)}})
				continue
			}
			if fm.behavior.failClose {
				reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
					Error: &controlErrorBody{Code: "E_CONTROL_DOOR_MISMATCH", Message: "close refused by test"}})
				continue
			}
			fm.mu.Lock()
			if fm.installedID == req.DoorID {
				fm.installedBlob = nil
				fm.installedID = ""
			}
			installed := fm.installedID != ""
			fm.mu.Unlock()
			fm.signalDoorEvent(installed)
			reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true,
				Result: mustResult(doorCloseResult{DoorID: req.DoorID, Removed: true})})
		case "door.status":
			fm.mu.Lock()
			fm.statusReqs++
			fm.mu.Unlock()
			if fm.behavior.hangStatus {
				continue
			}
			fm.mu.Lock()
			installed, id := fm.installedID != "", fm.installedID
			fm.mu.Unlock()
			reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true,
				Result: mustResult(doorStatusResult{Installed: installed, DoorID: id})})
			select {
			case <-fm.openReceived:
				fm.reconcileStatusRepliedOnce.Do(func() { close(fm.reconcileStatusReplied) })
			default:
			}
		case "door.sanitize":
			if fm.behavior.hangSanitize {
				// Never reply: the gateway-side timeout must trip
				// and write door.sanitize with Result: "timeout".
				continue
			}
			if fm.behavior.failSanitize {
				reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
					Error: &controlErrorBody{Code: "E_CONTROL_INTERNAL", Message: "sweep refused by test"}})
				continue
			}
			removed := fm.behavior.reportSanitizeRemoved
			reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true,
				Result: mustResult(sanitizeResult{Sanitized: true, Removed: removed})})
		default:
			reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
				Error: &controlErrorBody{Code: "E_CONTROL_PROTOCOL", Message: "unknown op"}})
		}
	}
}

// writeControlRaw puts b on the machine's control channel as it is, under
// the same lock the machine's own replies take.
func (fm *fakeMachine) writeControlRaw(b []byte) error {
	fm.mu.Lock()
	ch := fm.ctrl
	fm.mu.Unlock()
	if ch == nil {
		return fmt.Errorf("fake machine: no control channel yet")
	}
	fm.writeMu.Lock()
	defer fm.writeMu.Unlock()
	_, err := ch.Write(b)
	return err
}

// stallControlReader makes the machine stop reading its control channel
// after whatever message it is reading now.
func (fm *fakeMachine) stallControlReader() {
	fm.ctrlStallOnce.Do(func() { close(fm.ctrlStall) })
}

func (fm *fakeMachine) doorInstalled() (bool, string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.installedID != "", fm.installedID
}

// controlOps is a copy of the ops of every control request this machine
// has received, in wire arrival order (see controlOpLog).
func (fm *fakeMachine) controlOps() []string {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return append([]string(nil), fm.controlOpLog...)
}

// doorStatusRequests is the number of door.status requests this machine has
// answered (or been asked, when the behaviour hangs them). See statusReqs.
func (fm *fakeMachine) doorStatusRequests() int {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.statusReqs
}

// waitDoorOpenReceived blocks until this machine's control loop has
// decoded a door.open request, or guard elapses. Unlike polling openReqs
// (IAMT-304 round 4's counter, for "did a door.open ever arrive" rather
// than "when"), this is a genuine event wait - openReceived closes the
// instant the decode happens, with no dependency on how long anything
// before that (a real SSH handshake in phase one, for example) took to
// get there (IAMT-304 round 6).
func (fm *fakeMachine) waitDoorOpenReceived(t *testing.T, guard time.Duration) {
	t.Helper()
	select {
	case <-fm.openReceived:
	case <-time.After(guard):
		t.Fatal("door.open never reached the machine within the guard - see openReceived's own doc comment")
	}
}

// waitReconcileStatusReplied blocks until this machine has written the
// reply to openingTimeout's mandatory post-open door.status, or guard
// elapses. See reconcileStatusReplied's own doc comment for why a
// late-reply scenario must wait for this event rather than a wall-clock
// guess before releasing a held door.open install (IAMT-304 round 7).
func (fm *fakeMachine) waitReconcileStatusReplied(t *testing.T, guard time.Duration) {
	t.Helper()
	select {
	case <-fm.reconcileStatusReplied:
	case <-time.After(guard):
		t.Fatal("the reconciliation door.status was never answered within the guard - see reconcileStatusReplied's own doc comment")
	}
}

func (fm *fakeMachine) signalDoorEvent(installed bool) {
	select {
	case fm.doorEvents <- installed:
	default:
	}
}

// waitDoorCycleClosed waits for the observable installed -> removed cycle.  A
// deadline is only a hung-test guard; completion is the machine's close event,
// not elapsed time.
//
// The guard is doorCycleHungGuard (10 s), the same number and for the same
// reason as waitUntil's: the cycle is a chain of asynchronous goroutine
// handoffs (the delayed install, the control reply, the automaton's close, the
// machine's removal), and under -race on a loaded host any one of them can be
// descheduled for longer than a tight budget would allow. With 2 s this test
// family failed about once in fifty runs on a 4-core VM while the product was
// doing exactly the right thing (IAMT-304 round 4). A green test never waits
// for the guard; a genuinely stuck one still fails, just later.
func (fm *fakeMachine) waitDoorCycleClosed(t *testing.T) {
	t.Helper()
	seenInstalled := false
	timeout := time.NewTimer(doorCycleHungGuard)
	defer timeout.Stop()
	for {
		installed, _ := fm.doorInstalled()
		if installed {
			seenInstalled = true
		}
		if seenInstalled && !installed {
			return
		}
		select {
		case installed := <-fm.doorEvents:
			if installed {
				seenInstalled = true
			} else if seenInstalled {
				return
			}
		case <-timeout.C:
			t.Fatal("temporary probe door did not complete an installed-to-closed cycle")
		}
	}
}

// doorCycleHungGuard is how long waitDoorCycleClosed is willing to wait before
// declaring the cycle stuck. See its comment: it is a hung-test guard, not the
// budget the cycle is expected to fit into.
const doorCycleHungGuard = 10 * time.Second

// probeTestBudget is the SSHDProbeTimeout a probe test uses when the deadline
// is not what the test is about. It has to outlast phase one (the target
// handshake), because phase one spends the same absolute budget PROTOCOL §7
// gives the whole probe: a probe whose budget is gone correctly refuses to
// write door.open, so a budget a starved phase one can spend turns every
// assertion about a temporary door into "no door was ever installed" — a
// correct product behaviour and a broken fixture. Seconds-long stalls have been
// observed under -race on a 4-core VM (IAMT-304 round 4), which is why this is
// 30s rather than the 250ms-5s the tests used before; the fixture's machine
// keepalive window (60s) outlasts it, so a slow phase one cannot also be killed
// by a liveness lapse.
const probeTestBudget = 30 * time.Second

// lateReplyHungGuard bounds TestSSHDProbe_TimedOutOpenLateSuccessClosesDoor's
// wait for the late-reply door.close landing in the journal (IAMT-304 round
// 5): unlike doorCycleHungGuard's single hop (a delayed install answered on
// the SAME request, waited out at 10s), this path is openingTimeout's own
// mandatory door.status round trip, followed — only once that reconciliation
// completes (machine_conn.go's completeRetiredOpenReconciliation) — by a
// SECOND, independent door.close round trip core.LateReply drives
// (driveRetiredOpen). Each hop is its own goroutine handoff a starved
// scheduler can delay, the same reason doorCycleHungGuard's own doc comment
// gives for why 2s stopped being enough for one hop; a guard sized for one
// hop is not sized for three, so this is 4x that number rather than a
// number picked to make one observed run pass. The door.open precondition
// this test also waits on is bounded by probeTestBudget instead — phase one
// may legitimately still be running there, which is a different, already
// pre-existing budget, not a new one invented for this guard.
const lateReplyHungGuard = 4 * doorCycleHungGuard

// doorEverOpened reports whether door.open ever installed a key, even if it
// was since closed again - the sticky signal scenario 3 needs ("the door
// never opened at all", not "the door happens to be shut right now").
func (fm *fakeMachine) doorEverOpened() bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.everOpened
}

// ---- fake human --------------------------------------------------------------

// dropResultSource is the slice of a test fixture the IAMT-218 diagnostic
// in shell() needs: the Result of the most recent session.drop event for a
// given (person, machine). The identity belongs to the SESSION, not the
// fixture (IAMT-218 round 2): many people dial against one shared fixture
// whose own person/machine fields are just its defaults, and a lookup keyed
// by the fixture identity silently returned "" for everyone else — the
// canary connects as carol while the fixture is alice. *fixture and
// *spyFixture implement it; a caller without a journal (fakeHuman in
// iamt126) passes nil.
type dropResultSource interface {
	lastSessionDropResult(person, machine string) string
}

type humanSession struct {
	// who actually dialed this session (person:machine, SPEC §5.1),
	// parsed from the SSH username at openHumanSession; used only by the
	// IAMT-218 refusal diagnostic to filter the session.drop journal.
	person, machine string
	// drops implements the IAMT-218 diagnostic lookup; nil is allowed —
	// shell() then simply omits the session.drop part of the message.
	drops  dropResultSource
	client *ssh.Client
	ch     ssh.Channel
	reqs   <-chan *ssh.Request
	exits  chan uint32
}

// humanDialUser remembers which SSH username each fixture human dialed
// with (IAMT-218 round 2). x/crypto's ssh.Client has no User() accessor,
// so dialHumanClient — the single choke point every fixture human passes
// through — registers cfg.User here and openHumanSession parses it into
// the session's (person, machine). Gateway tests never run t.Parallel and
// both writer and reader run on the test goroutine, so the map needs no
// lock; entries live for the life of the test binary, which is fine for
// test code.
var humanDialUser = map[*ssh.Client]string{}

func dialHuman(t *testing.T, addr, person, machine string, signer ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            person + ":" + machine,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return dialHumanClient(addr, cfg)
}

// dialHumanClient connects like ssh.Dial but keeps the client protocol-
// compliant on the gateway's live probe (IAMT-218). ssh.Dial installs
// x/crypto's default handleGlobalRequests, which answers FALSE to every
// global request — under the pre-IAMT-220 reading of PROTOCOL §4.2 a
// false reply to keepalive@openssh.com was a miss, so the gateway's
// HumanKeepalive probe tore such a transport down after Interval ×
// MaxMisses (150 ms × 3 = ~300 ms in these fixtures). Since IAMT-220 a
// failure reply counts as alive (TestIAMT220_HumanFailureReplyIsNotAMiss
// pins that); answering success stays the protocol-compliant shape. Every fixture human therefore lived on a ~300 ms fuse that
// had nothing to do with what the tests exercise: under -race load the
// nested handshake to the machine stretched past it and the blocked
// SendRequest("pty-req") died with EOF. NewClientConn + NewClient let us
// swap the handler for the compliant Keepalive.Respond — the same wiring
// fakeHuman (iamt126) and fakeMachine already use. On the wire the swap
// changes exactly one name: keepalive@openssh.com now gets request
// success (PROTOCOL §4.1 table row); every other name keeps getting the
// failure reply ApplyDisposition sends for Drop/Reject.
func dialHumanClient(addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	raw, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	// NewClient would start x/crypto's default false-replier on whatever
	// channel we hand it, so hand it a separate one and serve the real
	// requests with the protocol's own responder.
	//
	// IAMT-314: that channel used to be created and never closed, on the
	// stated theory that the goroutine ssh.NewClient starts "parks there
	// harmlessly". It parks there permanently. handleGlobalRequests
	// (x/crypto/ssh/client.go:169) ranges over exactly this channel and
	// has no other exit, so closing the client and the connection does
	// nothing for it - and goleak found one per fixture human at the end
	// of the package. Closing noopReqs from the goroutine that drains the
	// REAL request stream ties the two lifetimes together: the transport
	// dies, the mux closes reqs, Respond returns, noopReqs closes and
	// x/crypto's handler leaves with everything else x/crypto owns. That
	// is the same shape internal/admin/client.go already uses in
	// production, where Conn.Close closes its own noopReqs.
	noopReqs := make(chan *ssh.Request)
	client := ssh.NewClient(conn, chans, noopReqs)
	go func() {
		defer close(noopReqs)
		sshx.Keepalive{}.Respond(reqs)
	}()
	humanDialUser[client] = cfg.User
	return client, nil
}

// openHumanSession opens a "session" channel against the gateway as the
// given client. drops is kept on the humanSession so shell() (which calls
// SendRequest("pty-req")) can attach diagnostic context to a failure —
// under load the gateway may have closed the channel before pty-req was
// answered (IAMT-218). Without it, the failure message would be
// "pty-req: ok=false err=EOF" with no hint of which refusal branch
// fired; with it, the message includes the refusal text already sent
// on the channel and the most recent session.drop Result from
// events.jsonl for THE SESSION'S OWN (person, machine) — parsed from the
// username dialHumanClient registered, not the fixture's defaults — so
// the next flake names its own cause. nil is allowed.
func openHumanSession(t *testing.T, client *ssh.Client, drops dropResultSource) *humanSession {
	t.Helper()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	h := &humanSession{drops: drops, client: client, ch: ch, reqs: reqs, exits: make(chan uint32, 1)}
	// IAMT-218 round 2: remember WHO dialed this session. The username is
	// "person:machine" (SPEC §5.1); an unregistered client (fakeHuman in
	// iamt126 builds its transports itself) or an unparseable username
	// leaves both empty, and lastSessionDropResult then returns "" rather
	// than guessing by the fixture identity or matching the whole journal.
	if user, ok := humanDialUser[client]; ok {
		if pn, err := auth.ParseUsername(user); err == nil {
			h.person, h.machine = pn.Person, pn.Machine
		}
	}
	go func() {
		for r := range reqs {
			if r.Type == "exit-status" {
				if e, err := sshx.ParseExitStatus(r.Payload); err == nil {
					select {
					case h.exits <- e.Status:
					default:
					}
				}
			}
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	return h
}

// readLeftoverText drains whatever the gateway already wrote on the
// human channel before closing it (the refusal message from
// writeAndClose), bounded by a short deadline so a healthy handshake
// that returns (true, nil) does not pay extra wall-clock — we only
// call this from the SendRequest failure path. The returned text is
// empty when the gateway either rejected silently or closed before
// any data left its send buffer.
func (h *humanSession) readLeftoverText(deadline time.Duration) string {
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := h.ch.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()
	select {
	case s := <-done:
		return s
	case <-time.After(deadline):
		return ""
	}
}

// lastSessionDropResult returns the Result field of the most recent
// session.drop event in the journal for (person, machine), or "" if none.
// This is the second half of the IAMT-218 diagnostic: every refusal branch
// in human_role.go writes a session.drop with a typed Result (e.g.
// "session setup timeout", "target rejected session start",
// DenyMachineOffline.String()), and the channel-level refusal text is
// identical for several of them — only the journal Result tells them
// apart. Both names must be non-empty: an empty Actor or Object in
// events.Filter means "no filter" (event.go), and an unfiltered lookup
// would happily report some unrelated session's drop. Each fixture type
// implements the one-line adapter: fixture.lastSessionDropResult /
// spyFixture.lastSessionDropResult.
func lastSessionDropResult(log *events.Log, person, machine string) string {
	if log == nil || person == "" || machine == "" {
		return ""
	}
	evs, _, err := log.Read(events.Filter{
		Types:  []events.EventType{events.EventSessionDrop},
		Actor:  person,
		Object: machine,
	})
	if err != nil || len(evs) == 0 {
		return ""
	}
	return evs[len(evs)-1].Result
}

func (f *fixture) lastSessionDropResult(person, machine string) string {
	if f == nil {
		return ""
	}
	return lastSessionDropResult(f.log, person, machine)
}

// refusalDiagnostic builds the message shell() dies with when the gateway
// closed the human channel without answering pty-req. Deliberately a pure
// formatter (no t.Fatalf inside): TestIAMT218_RefusalDiagnosticNamesTheRefusal
// calls it on a session the gateway refused for real and pins the message
// contents without failing the suite.
func (h *humanSession) refusalDiagnostic(ok bool, err error) string {
	leftover := h.readLeftoverText(50 * time.Millisecond)
	drop := ""
	if h.drops != nil {
		drop = h.drops.lastSessionDropResult(h.person, h.machine)
	}
	return fmt.Sprintf("pty-req: ok=%v err=%v refusalText=%q sessionDrop=%q (IAMT-218 diagnostic: refusalText starting with %q is one of the human_role.go refusal lines written before the close; empty refusalText and empty sessionDrop with err=EOF mean the transport was closed with no refusal branch — the prime suspect there is the human keepalive probe or a machine-side teardown, see the IAMT-218 report)",
		ok, err, leftover, drop, "Access to this machine is currently unavailable")
}

func (h *humanSession) shell(t *testing.T) {
	t.Helper()
	ok, err := h.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	if err != nil || !ok {
		t.Fatalf("%s", h.refusalDiagnostic(ok, err))
	}
	ok, err = h.ch.SendRequest("shell", true, nil)
	if err != nil || !ok {
		t.Fatalf("shell: ok=%v err=%v", ok, err)
	}
}

// ---- gateway fixture ---------------------------------------------------------

// fixture is one fully wired gateway: state store, event log, listener,
// registered person/machine/grant, and the fake sshd the machine's door
// unlocks access to. Nothing here is product-code configuration a test could
// not otherwise reach through Config.
type fixture struct {
	t         *testing.T
	gw        *Gateway
	ln        net.Listener
	addr      string
	store     *state.Store
	log       *events.Log
	logPath   string // absolute path to events.jsonl; set by newFixture for test-side readers
	sshd      *fakeTargetSSHD
	machineID string
	person    string

	personKey  ssh.Signer
	machineKey ssh.Signer
	clock      *fakeClock

	// sessionEndsSeen counts the terminal session events
	// (session.stop / session.drop for f.person/f.machineID) that have
	// landed in events.jsonl. waitSessionEnd advances it by one per
	// call, so two consecutive calls deterministically mean "two
	// different sessions have ended" — no off-by-one between two
	// adjacent waits. See IAMT-211.
	sessionEndsSeen int

	machMu  sync.Mutex
	current *fakeMachine
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newFixture builds a gateway with one verified machine and one grant that is
// valid at construction time. cfgMod, if non-nil, is applied to the Config
// before New() - the constructor seam every test uses to vary timeouts,
// limits or the recording constructor.
func newFixture(t *testing.T, cfgMod func(*Config)) *fixture {
	t.Helper()
	dir := t.TempDir()

	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	// Nothing may reach the journal once Gateway.Close has returned
	// (IAMT-471). Registered first, so it runs last - after the gateway,
	// the log and the store are closed - and reports whatever the other
	// cleanups let through.
	var journalAfterClose atomic.Bool
	var lateMu sync.Mutex
	var late []string
	t.Cleanup(func() {
		lateMu.Lock()
		defer lateMu.Unlock()
		if len(late) > 0 {
			t.Errorf("written to the journal after Gateway.Close returned (IAMT-471): %v", late)
		}
	})
	t.Cleanup(func() { _ = store.Close() })

	log, err := events.OpenLog(dir + "/events.jsonl")
	if err != nil {
		t.Fatalf("events.OpenLog: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	hostKey := genSigner(t)
	personKey := genSigner(t)
	machineKey := genSigner(t)

	// IAMT-211: the fixture's session-end signal is read from the journal
	// directly by waitSessionEnd (no gateway-side hook, no
	// Config.OnSessionEnd — production structs carry no test-only
	// fields). The counter f.sessionEndsSeen makes two
	// adjacent waits distinct: each wait advances it by one, so the
	// second call deterministically waits for "session 2 has ended"
	// rather than "any session has ended since startup".
	f := &fixture{t: t, store: store, log: log, logPath: dir + "/events.jsonl",
		person: "alice", machineID: "vm1", personKey: personKey, machineKey: machineKey}

	f.sshd = newFakeTargetSSHD(t, func(blob []byte) bool {
		return f.doorKeyBlobAllowed(blob)
	})

	sshdHostKeyLine := authorizedLine(f.sshd.signer.PublicKey())
	verifiedUser := `MACHINE\svc`
	clock := newFakeClock(time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC))
	f.clock = clock

	until := state.NewZonedTime(clock.Now().Add(time.Hour))
	err = store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: f.person, Role: "user",
			Keys: []state.Key{{Fingerprint: fingerprintOf(t, personKey.PublicKey()), Pub: authorizedLine(personKey.PublicKey()), Added: state.NewZonedTime(clock.Now())}},
		})
		st.Machines = append(st.Machines, state.Machine{
			ID: f.machineID, Name: f.machineID, State: "verified",
			MachineKey:      authorizedLine(machineKey.PublicKey()),
			SSHDHostKey:     &sshdHostKeyLine,
			OSUser:          verifiedUser,
			RequestedOSUser: verifiedUser,
			VerifiedOSUser:  &verifiedUser,
			OSUserStatus:    state.OSUserStatusVerified,
		})
		return st.GrantAccess(f.person, f.machineID, &until, "shell")
	})
	if err != nil {
		t.Fatalf("seed state: %v", err)
	}

	cfg := Config{
		Store:   store,
		Log:     log,
		HostKey: hostKey,
		Now:     clock.Now,

		AuthLimits: auth.AuthLimits{HandshakeTimeout: 3 * time.Second},
		ACLLimits:  acl.Limits{},
		RateConfig: auth.RateConfig{
			MaxKnownFailures:   10,
			MaxUnknownFailures: 10,
			Window:             time.Minute,
			PairBanDuration:    time.Minute,
			AddrBanDuration:    time.Minute,
		},

		DoorIdle: time.Minute,
		DoorHard: 2 * time.Minute,

		ControlAcceptTimeout: time.Second,
		DoorOpenTimeout:      2 * time.Second,
		DoorCloseTimeout:     2 * time.Second,
		DoorStatusTimeout:    2 * time.Second,
		SessionSetupTimeout:  3 * time.Second,

		// The machine's liveness probe. Its numbers are a test-speed choice,
		// and a lapse is a teardown (machine_role.go:47) — so the window has to
		// outlast anything a test is doing with the machine, or a starved
		// responder goroutine under -race turns into "the machine was torn down
		// mid-scenario". The two tests that WANT a lapse want it fast and set
		// their own numbers (iamt220: 60ms x 2; scenarios 8: 80ms x 2). The
		// window here (20s x 3 misses = 60s) also outlasts probeTestBudget
		// (30s), which is what the probe tests give phase one (IAMT-304 round 4:
		// at 150ms x 3 this fixture tore a machine down mid-probe about once in
		// fifty -race runs on a 4-core VM, and the probe then never wrote
		// door.open).
		Keepalive: sshx.Keepalive{Interval: 20 * time.Second, MaxMisses: 3},

		// HumanKeepalive defaults (set by setDefaults) use product
		// numbers (20 s / 3 misses / openssh.com); tighten here so
		// IAMT-126 tests finish in milliseconds, not seconds.
		// The canary tests override again to whatever they need.
		HumanKeepalive: sshx.Keepalive{Interval: 150 * time.Millisecond, MaxMisses: 3, Name: "keepalive@openssh.com"},

		RecordingBaseDir: dir + "/recordings",

		// The lifecycle commands (gateway.backup / gateway.rotate-hostkey,
		// IAMT-174) operate on the same directory the store and the event
		// log live in, exactly as the production wiring in
		// cmd/iamtunnel's gatewayRuntimeConfig does.
		DataDir: dir,
	}
	if cfgMod != nil {
		cfgMod(&cfg)
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	f.gw = gw

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	f.addr = ln.Addr().String()
	guard := func(e events.Event) error {
		if journalAfterClose.Load() {
			lateMu.Lock()
			late = append(late, string(e.Type)+" "+e.Result)
			lateMu.Unlock()
		}
		return log.Append(e)
	}
	gw.journalAppendFn.Store(&guard)
	go gw.Serve(ln)
	t.Cleanup(func() {
		_ = gw.Close()
		journalAfterClose.Store(true)
	})

	return f
}

// doorKeyBlobAllowed is the fake target sshd's PublicKeyCallback: it accepts
// exactly the key the fake machine currently has "installed" in its
// simulated authorized_keys, never the gateway's own idea of the door - that
// would test the gateway against itself instead of against what the machine
// actually did with the key it was handed.
func (f *fixture) doorKeyBlobAllowed(blob []byte) bool {
	f.machMu.Lock()
	fm := f.current
	f.machMu.Unlock()
	if fm == nil {
		return false
	}
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.installedBlob != nil && string(fm.installedBlob) == string(blob)
}

func (f *fixture) connectMachine(behavior fakeMachineBehavior) *fakeMachine {
	fm := newFakeMachine(f.t, f.addr, f.machineID, f.machineKey, f.sshd.addr(), behavior)
	f.machMu.Lock()
	f.current = fm
	f.machMu.Unlock()
	return fm
}

func (f *fixture) waitMachineOnline(t *testing.T) {
	t.Helper()
	waitUntil(t, "machine did not come online", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Online
	})
}

// waitSessionEnd blocks until the gateway has appended one more terminal
// session event (session.stop on a clean end, session.drop otherwise)
// for the fixture's (person, machine) pair than it had at the previous
// call, or fails the test on timeout. The signal is the journal entry
// itself — events.jsonl is the only audit source the gateway exposes
// to operators, and Append does fsync before returning, so a line that
// is visible to a Read is durable on disk and was written strictly
// after rec.Close / execRec.Finish ran on the gateway side
// (human_role.go's appendEvent is the last write before serveHumanSession
// returns — see the order in human_role.go:420-430).
//
// Why the counter (f.sessionEndsSeen) and not just "count >= 1": two
// adjacent calls to waitSessionEnd in the FromTo test mean "session 1
// has ended" then "session 2 has ended". Polling for "count >= 1" both
// times makes the second wait a no-op; the counter makes the second
// wait deterministic.
//
// Why this is faster than the previous recordings.list / WalkDir poll
// the IAMT-193 helper did: a single file read of a small append-only
// log (one line per session), not a WalkDir of a multi-session
// recordings/<machine>/<date>/ tree. Under -race -count=30 parallel
// runs (gate 11) the WalkDir was the bottleneck — each poll had to
// traverse the recordings tree, parse every .meta, and could land in
// record.WriteMeta's Remove-then-Rename window (IAMT-193). Reading
// events.jsonl is bounded by the log size, has no mid-write gap
// (Append does fsync), and is cheap enough that the test's poll
// budget of 2 ms per tick fits hundreds of polls into the 10 s window.
//
// Deadline is 10 s — the same budget as waitUntil, so a hung gateway
// still fails the test loudly.
func (f *fixture) waitSessionEnd(t *testing.T, msg string) {
	t.Helper()
	target := f.sessionEndsSeen + 1
	deadline := time.Now().Add(10 * time.Second)
	for {
		count := f.countSessionEnds()
		if count >= target {
			f.sessionEndsSeen = count
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: gateway did not append the %d-th terminal session event for (%q, %q) within 10s (currently %d in events.jsonl)",
				msg, target, f.person, f.machineID, count)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// countSessionEnds returns the number of session.stop / session.drop
// events in events.jsonl that match the fixture's (person, machine)
// pair. Reads the log via events.Log.Read with a type filter — one
// open + read per call, no parsing of records that are not of the
// requested types, no WalkDir.
func (f *fixture) countSessionEnds() int {
	evs, _, err := f.log.Read(events.Filter{
		Types:  []events.EventType{events.EventSessionStop, events.EventSessionDrop},
		Actor:  f.person,
		Object: f.machineID,
	})
	if err != nil {
		return 0
	}
	return len(evs)
}

func waitUntil(t *testing.T, msg string, cond func() bool) {
	t.Helper()
	// 10 s, not 3: a full run without -race (gate 11) under the load of all
	// packages at once did not fit the recording finalization into 3 s
	// (IAMT-169 FromTo, 14.09); a green test never waits out the deadline,
	// a red one simply falls later.
	waitUntilFor(t, 10*time.Second, msg, cond)
}

// waitUntilFor is waitUntil with an explicit hang-guard instead of the
// shared 10s default. It exists for waits whose own dependency chain is
// longer than the single asynchronous hop the 10s number was calibrated
// against (see TestSSHDProbe_TimedOutOpenLateSuccessClosesDoor's use): the
// guard is still only a "this is definitely stuck" backstop, never the
// budget the wait is expected to fit into — a green run never comes close
// to it, and a genuinely stuck one just fails later instead of looking
// like a lost event.
func waitUntilFor(t *testing.T, guard time.Duration, msg string, cond func() bool) {
	t.Helper()
	waitUntilEvery(t, guard, 2*time.Millisecond, msg, cond)
}

// waitUntilEvery is waitUntilFor with an explicit poll interval instead of
// the shared 2ms default. A long guard (tens of seconds, IAMT-304 round 6)
// at a 2ms interval means tens of thousands of polls, and a poll here is
// not free when cond reads the journal: events.Log.Read takes the SAME
// mutex Log.Append does (internal/gateway/events/log.go), so a poll loop
// spinning every 2ms for 40s worth of ticks competes for that lock, and
// for whatever CPU a constrained GOMAXPROCS leaves over, against the very
// writer the test is waiting on - self-inflicted contention that gets
// worse exactly when the machine is already loaded, which is exactly when
// this guard needs the room. A coarser interval for a long guard costs
// nothing a green run would notice (it still returns the instant cond is
// true) and stops the wait itself from being part of what it is waiting
// out.
func waitUntilEvery(t *testing.T, guard, interval time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(guard)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatal(msg)
}
