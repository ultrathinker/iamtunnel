package gateway

// accept_independent_test.go - an INDEPENDENT acceptance test of the runtime
// (gateway.go, machine_conn.go, machine_role.go, human_role.go, lookup.go,
// control_wire.go, config.go). Written independently of the
// implementation: its claims are not taken from the code's own
// documentation.
//
// Four attackable claims:
//  A1. All door policy lives in the automaton (core.Machine); the runtime
//      only turns network events into core.Input and executes exactly the
//      commands Apply returned. The runtime NEVER decides on its own to open
//      or close the door (T1, T3, T4, T8).
//  A2. A person without a grant cannot reach the machine by ANY path (T1, T2, T11).
//  A3. The death of the control channel mid-session removes everything: the
//      session, the enrolment, the counters; the machine stops counting as connected (T5, T9, T10).
//  A4. Bytes from the machine land in the recording BEFORE the person sees
//      them: a recording failure cannot leave the recording without what was shown (T6, T7).
//
// The tests T1-T11 hit each claim from the side from which the runtime
// itself could break it -- not the automaton and not already accepted
// packets. Each sensitivity is proven by mutating the production code (it
// turns red). No switches: no setters, no env, no build
// tags -- only the existing injection seams of Config (Now, NewRecording, timeouts).

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/proto"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// ---- the spy machine: a real SSH side + a journal of every control operation

// spyBehavior - variations of the spy's behavior (this is a test double of
// the machine, not a switch in production code: injection only through its own dialer).
type spyBehavior struct {
	hangOpen       bool          // never answer door.open at all
	hangStatus     bool          // never answer door.status at all
	delayFirstOpen time.Duration // answer only the FIRST door.open, with a delay
}

// spyOp - one operation the machine saw on the control channel.
type spyOp struct {
	Op     string
	DoorID string
	Reason string
}

func (o spyOp) String() string {
	if o.Reason != "" {
		return fmt.Sprintf("%s(%s, reason=%q)", o.Op, o.DoorID, o.Reason)
	}
	return fmt.Sprintf("%s(%s)", o.Op, o.DoorID)
}

// spyMachine - like fakeMachine from harness_test.go, but: (a) it journals
// EVERY control-channel operation -- the only way to check, black-box,
// that the runtime does not invent door.open/door.close; (b) it can die
// on the control channel only, leaving the transport alive; (c) it can
// answer door.open late. The machine handles requests in parallel
// (a real machine need not answer strictly in turn) and installs the key
// at the moment of RECEIVING door.open, before any answer -- like a real
// authorized_keys entry.
type spyMachine struct {
	t        *testing.T
	id       string
	signer   ssh.Signer
	sshdAddr string
	behavior spyBehavior

	conn ssh.Conn
	raw  net.Conn

	writeMu sync.Mutex

	mu            sync.Mutex
	ops           []spyOp
	installedBlob []byte
	installedID   string
	everOpened    bool
	ctrlCh        ssh.Channel

	closeOnce sync.Once

	// Shutdown (IAMT-314), same shape as fakeMachine in harness_test.go.
	// handleOp is counted too: delayFirstOpen makes it sleep for seconds,
	// and a test that ends while one of those is still sleeping would leave
	// a goroutine behind.
	wg    sync.WaitGroup
	conns *connSet
}

func newSpyMachine(t *testing.T, addr, id string, signer ssh.Signer, sshdAddr string, behavior spyBehavior) *spyMachine {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("spy dial: %v", err)
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
		t.Fatalf("spy handshake: %v", err)
	}
	s := &spyMachine{t: t, id: id, signer: signer, sshdAddr: sshdAddr, behavior: behavior, conn: conn, raw: raw, conns: newConnSet()}
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		sshx.Keepalive{}.Respond(reqs)
	}()
	go func() {
		defer s.wg.Done()
		s.acceptChannels(chans)
	}()
	t.Cleanup(s.close)
	return s
}

// close cuts this machine's transports and its splices to the fake sshd,
// then waits for every goroutine it started (IAMT-314). Cutting first and
// waiting second is the only order that cannot hang: every loop below lives
// exactly as long as the transport under it.
func (s *spyMachine) close() {
	s.closeOnce.Do(func() {
		_ = s.conn.Close()
		_ = s.raw.Close()
		s.conns.closeAll()
		s.wg.Wait()
	})
}

// closeControlOnly drops ONLY the control channel; the transport stays alive.
func (s *spyMachine) closeControlOnly() {
	s.mu.Lock()
	ch := s.ctrlCh
	s.mu.Unlock()
	if ch != nil {
		_ = ch.Close()
	}
}

func (s *spyMachine) acceptChannels(chans <-chan ssh.NewChannel) {
	for n := range chans {
		switch n.ChannelType() {
		case "iamtunnel-control":
			ch, reqs, err := n.Accept()
			if err != nil {
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				discardSSHRequests(reqs)
			}()
			s.mu.Lock()
			s.ctrlCh = ch
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serveControl(ch)
			}()
		case "iamtunnel-target":
			ch, reqs, err := n.Accept()
			if err != nil {
				continue
			}
			s.wg.Add(2)
			go func() {
				defer s.wg.Done()
				discardSSHRequests(reqs)
			}()
			go func() {
				defer s.wg.Done()
				s.spliceTarget(ch)
			}()
		default:
			_ = n.Reject(ssh.UnknownChannelType, "unexpected channel")
		}
	}
}

func (s *spyMachine) spliceTarget(ch ssh.Channel) {
	defer ch.Close()
	d, err := net.DialTimeout("tcp", s.sshdAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer d.Close()
	// IAMT-314: registering the TCP connection is what lets close() cut it.
	// This splice deliberately returns after only ONE of its two copies has
	// finished, so the other one has to be counted in s.wg rather than left
	// to finish on its own.
	if !s.conns.add(d) {
		return
	}
	defer s.conns.remove(d)
	done := make(chan struct{}, 2)
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		_, _ = io.Copy(d, ch)
		if tc, ok := d.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		defer s.wg.Done()
		_, _ = io.Copy(ch, d)
		_ = ch.CloseWrite()
		done <- struct{}{}
	}()
	<-done
}

func (s *spyMachine) serveControl(ch ssh.Channel) {
	dec := json.NewDecoder(ch)
	for {
		var req controlRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleOp(ch, req)
		}()
	}
}

func (s *spyMachine) handleOp(ch ssh.Channel, req controlRequest) {
	doorID := req.DoorID
	if req.Door != nil {
		doorID = req.Door.ID
	}
	s.mu.Lock()
	s.ops = append(s.ops, spyOp{Op: req.Op, DoorID: doorID, Reason: req.Reason})
	s.mu.Unlock()

	reply := func(resp controlResponse) {
		raw, err := json.Marshal(resp)
		if err != nil {
			return
		}
		raw = append(raw, '\n')
		s.writeMu.Lock()
		_, _ = ch.Write(raw)
		s.writeMu.Unlock()
	}
	base := controlResponse{Proto: 1, Caps: []string{}, ID: req.ID}

	switch req.Op {
	case "door.open":
		if s.behavior.hangOpen {
			return
		}
		blob, err := state.DecodeKeyBlob(req.Door.PubKey)
		if err != nil {
			reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
				Error: &controlErrorBody{Code: "E_CONTROL_PROTOCOL", Message: err.Error()}})
			return
		}
		// A real machine installs the key into authorized_keys at the moment of
		// accepting door.open, BEFORE the answer -- so the delayed answer still
		// leaves a working key at the target.
		s.mu.Lock()
		s.installedBlob = blob
		s.installedID = req.Door.ID
		s.everOpened = true
		d := s.behavior.delayFirstOpen
		s.behavior.delayFirstOpen = 0 // only the first open is late
		s.mu.Unlock()
		if d > 0 {
			time.Sleep(d)
		}
		fp, _ := state.ComputeFingerprint(req.Door.PubKey)
		base.OK = true
		base.Result = mustResult(doorOpenResult{DoorID: req.Door.ID, Installed: true, PublicKeyFingerprint: fp})
		reply(base)
	case "door.close":
		if !proto.ValidDoorCloseReason(req.Reason) {
			// The real machine's dictionary (IAMT-469).
			base.Error = &controlErrorBody{Code: "E_CONTROL_PROTOCOL", Message: fmt.Sprintf("invalid door.close reason %q", req.Reason)}
			reply(base)
			return
		}
		s.mu.Lock()
		if s.installedID == req.DoorID {
			s.installedBlob = nil
			s.installedID = ""
		}
		s.mu.Unlock()
		base.OK = true
		base.Result = mustResult(doorCloseResult{DoorID: req.DoorID, Removed: true})
		reply(base)
	case "door.status":
		if s.behavior.hangStatus {
			return
		}
		s.mu.Lock()
		installed, id := s.installedID != "", s.installedID
		s.mu.Unlock()
		base.OK = true
		base.Result = mustResult(doorStatusResult{Installed: installed, DoorID: id})
		reply(base)
	default:
		base.OK = false
		base.Error = &controlErrorBody{Code: "E_CONTROL_PROTOCOL", Message: "unknown op"}
		reply(base)
	}
}

func (s *spyMachine) opsSnapshot() []spyOp {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]spyOp, len(s.ops))
	copy(out, s.ops)
	return out
}

func (s *spyMachine) opCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ops)
}

func (s *spyMachine) currentInstalled() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.installedID
}

func (s *spyMachine) doorEverOpened() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.everOpened
}

// waitOpsQuiescent waits until the operation journal stops changing and
// returns a snapshot -- so that the "no operations" asserts do not race flying bytes.
func (s *spyMachine) waitOpsQuiescent(t *testing.T) []spyOp {
	t.Helper()
	last := -1
	stable := 0
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n := s.opCount()
		if n == last {
			stable++
			if stable >= 25 { // 25 * 20ms of silence
				return s.opsSnapshot()
			}
		} else {
			stable = 0
			last = n
		}
		time.Sleep(20 * time.Millisecond)
	}
	return s.opsSnapshot()
}

// ----Fixture------------------------------------------------------------------

// spyFixture - like fixture from harness_test.go, but with the spy machine.
type spyFixture struct {
	t         *testing.T
	gw        *Gateway
	addr      string
	store     *state.Store
	log       *events.Log
	logPath   string
	sshd      *fakeTargetSSHD
	machineID string
	person    string
	personKey ssh.Signer
	machineKy ssh.Signer
	clock     *fakeClock
	recDir    string

	machMu sync.Mutex
	spy    *spyMachine
}

func newSpyFixture(t *testing.T, cfgMod func(*Config)) *spyFixture {
	t.Helper()
	dir := t.TempDir()

	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	log, err := events.OpenLog(dir + "/events.jsonl")
	if err != nil {
		t.Fatalf("events.OpenLog: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	hostKey := genSigner(t)
	personKey := genSigner(t)
	machineKey := genSigner(t)

	f := &spyFixture{t: t, store: store, log: log, logPath: dir + "/events.jsonl", person: "alice",
		machineID: "vm1", personKey: personKey, machineKy: machineKey, recDir: dir + "/recordings"}

	f.sshd = newFakeTargetSSHD(t, func(blob []byte) bool {
		f.machMu.Lock()
		s := f.spy
		f.machMu.Unlock()
		if s == nil {
			return false
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.installedBlob != nil && string(s.installedBlob) == string(blob)
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
		Store: store, Log: log, HostKey: hostKey, Now: clock.Now,
		AuthLimits: auth.AuthLimits{HandshakeTimeout: 3 * time.Second},
		ACLLimits:  acl.Limits{},
		RateConfig: auth.RateConfig{MaxKnownFailures: 10, MaxUnknownFailures: 10,
			Window: time.Minute, PairBanDuration: time.Minute, AddrBanDuration: time.Minute},
		DoorIdle: time.Minute, DoorHard: 2 * time.Minute,
		ControlAcceptTimeout: time.Second,
		DoorOpenTimeout:      2 * time.Second,
		DoorCloseTimeout:     2 * time.Second,
		DoorStatusTimeout:    2 * time.Second,
		SessionSetupTimeout:  3 * time.Second,
		// Same reasoning as the main fixture's Keepalive (harness_test.go): a
		// lapse here is a teardown (machine_role.go:47), so the window must
		// outlast any scenario a test runs against this machine. The spy
		// scenarios are all shorter than this and none of them wants the
		// machine declared dead (IAMT-304 round 4).
		Keepalive:        sshx.Keepalive{Interval: 20 * time.Second, MaxMisses: 3},
		RecordingBaseDir: f.recDir,
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
	f.addr = ln.Addr().String()
	go gw.Serve(ln)
	t.Cleanup(func() { _ = gw.Close() })
	return f
}

func (f *spyFixture) connectSpy(behavior spyBehavior) *spyMachine {
	s := newSpyMachine(f.t, f.addr, f.machineID, f.machineKy, f.sshd.addr(), behavior)
	f.machMu.Lock()
	f.spy = s
	f.machMu.Unlock()
	return s
}

func (f *spyFixture) waitSpyOnline(t *testing.T) {
	t.Helper()
	waitUntil(t, "spy machine did not come online", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Online
	})
}

// ---- the probe recorder (claim A4) ------------------------------------------

// probeRec - a probe recorder: it can hold every Write until the gate opens
// (the "record first, then the person" order is checked by the person NOT
// getting the byte while the gate is closed) and fail on a chosen substring
// (a recording failure must not show the byte to the person).
type probeRec struct {
	mu      sync.Mutex
	gate    chan struct{}
	failOn  string
	writes  []string
	aborted string
	closed  bool
}

func (r *probeRec) Write(p []byte) (int, error) {
	r.mu.Lock()
	if r.failOn != "" && strings.Contains(string(p), r.failOn) {
		r.mu.Unlock()
		return 0, fmt.Errorf("probeRec: injected recording failure")
	}
	r.writes = append(r.writes, string(p))
	gate := r.gate
	r.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-time.After(5 * time.Second):
			return 0, fmt.Errorf("probeRec: gate wait timed out")
		}
	}
	return len(p), nil
}

func (r *probeRec) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *probeRec) Abort(reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.aborted == "" {
		r.aborted = reason
	}
	return nil
}

// AddBytesIn is the bytesIn counter hook added by IAMT-169. probeRec is
// only used to assert "record before showing" (T6) and "a recording failure
// does not show the byte" (T7); it deliberately ignores the input bytes.
// IAMT-336 phase 5 widened the argument from a count to the bytes that
// were just forwarded.
func (r *probeRec) AddBytesIn(p []byte) {}

func (r *probeRec) seen(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, w := range r.writes {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func (r *probeRec) abortedReason() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.aborted
}

// ---- helpers-----------------------------------------------------------------

// lastSessionDropResult implements dropResultSource for the IAMT-218
// diagnostic in humanSession.shell — same journal read as fixture's, over
// the spy fixture's own log handle. The (person, machine) come from the
// SESSION (IAMT-218 round 2), not from the spy fixture's defaults.
func (f *spyFixture) lastSessionDropResult(person, machine string) string {
	if f == nil {
		return ""
	}
	return lastSessionDropResult(f.log, person, machine)
}

func (f *spyFixture) dialAndShell(t *testing.T, person, machine string, key ssh.Signer) (*ssh.Client, *humanSession) {
	t.Helper()
	client, err := dialHuman(t, f.addr, person, machine, key)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	return client, hs
}

func eventsContain(t *testing.T, path, substr string) bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	return strings.Contains(string(b), substr)
}

// chanAccum - the single reader of the channel for the whole test: bytes
// accumulate in the accumulator, nothing is stolen from later checks, and
// no goroutine leaks (it ends on EOF, i.e. when the channel closes at the end).
type chanAccum struct {
	mu sync.Mutex
	sb strings.Builder
}

func drain(ch ssh.Channel) *chanAccum {
	a := &chanAccum{}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				a.mu.Lock()
				a.sb.Write(buf[:n])
				a.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return a
}

func (a *chanAccum) get() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sb.String()
}

// waitContains waits for a substring to appear, no longer than d.
func waitContains(t *testing.T, a *chanAccum, substr string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(a.get(), substr) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return strings.Contains(a.get(), substr)
}

// stayAbsent checks that the substring did NOT appear within d.
func stayAbsent(t *testing.T, a *chanAccum, substr string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(a.get(), substr) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
	return !strings.Contains(a.get(), substr)
}

func onceChan() (chan struct{}, func()) {
	gate := make(chan struct{})
	var once sync.Once
	return gate, func() { once.Do(func() { close(gate) }) }
}

// ---- T1 (A1+A2): a person without a grant triggers NOT A SINGLE control op ----

func TestAccT1_DeniedHumanCausesZeroControlOps(t *testing.T) {
	f := newSpyFixture(t, nil)
	spy := f.connectSpy(spyBehavior{})
	f.waitSpyOnline(t)

	baseline := spy.opCount()

	strangerKey := genSigner(t)
	if err := f.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "mallory", Role: "user",
			Keys: []state.Key{{Fingerprint: fingerprintOf(t, strangerKey.PublicKey()), Pub: authorizedLine(strangerKey.PublicKey()), Added: state.NewZonedTime(f.clock.Now())}},
		})
		return nil
	}); err != nil {
		t.Fatalf("add stranger: %v", err)
	}

	client, err := dialHuman(t, f.addr, "mallory", f.machineID, strangerKey)
	if err != nil {
		t.Fatalf("mallory dial: %v", err)
	}
	defer client.Close()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("mallory open session: %v", err)
	}
	go discardSSHRequests(reqs)
	acc := drain(ch)

	if !waitContains(t, acc, "Access to this machine is currently unavailable", 2*time.Second) {
		t.Fatalf("mallory must get the generic denial line, got %q", acc.get())
	}

	ops := spy.waitOpsQuiescent(t)
	if got := ops[baseline:]; len(got) != 0 {
		t.Fatalf("denied human caused control ops %v - the runtime consulted the door without a grant", got)
	}
	if spy.doorEverOpened() {
		t.Fatal("door was opened for a person with no grant")
	}
}

// ---- T2 (A2): an expired grant is not let in, the door is untouched ----------

func TestAccT2_ExpiredGrantNeverOpensDoor(t *testing.T) {
	f := newSpyFixture(t, nil)
	spy := f.connectSpy(spyBehavior{})
	f.waitSpyOnline(t)
	baseline := spy.opCount()

	// The grant runs until 11:00 by the factory clock; move the gateway's clock to 12:00.
	f.clock.Advance(2 * time.Hour)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go discardSSHRequests(reqs)
	acc := drain(ch)

	if !waitContains(t, acc, "Access to this machine is currently unavailable", 2*time.Second) {
		t.Fatalf("expired grant must be denied, got %q", acc.get())
	}

	ops := spy.waitOpsQuiescent(t)
	if got := ops[baseline:]; len(got) != 0 {
		t.Fatalf("expired grant caused control ops %v", got)
	}
	if spy.doorEverOpened() {
		t.Fatal("door was opened on an expired grant")
	}
}

// ---- T3 (A1): a door.open timeout does not invent a door.close --------------

func TestAccT3_OpenTimeoutInventsNoClose(t *testing.T) {
	f := newSpyFixture(t, func(cfg *Config) { cfg.DoorOpenTimeout = 700 * time.Millisecond })
	spy := f.connectSpy(spyBehavior{hangOpen: true})
	f.waitSpyOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go discardSSHRequests(reqs)
	acc := drain(ch)

	if !waitContains(t, acc, "Access to this machine is currently unavailable", 3*time.Second) {
		t.Fatalf("human must be told the machine is unavailable, got %q", acc.get())
	}

	ops := spy.waitOpsQuiescent(t)
	var closes []spyOp
	opens := 0
	for _, op := range ops {
		switch op.Op {
		case "door.open":
			opens++
		case "door.close":
			closes = append(closes, op)
		}
	}
	if opens != 1 {
		t.Fatalf("expected exactly one door.open attempt, ops: %v", ops)
	}
	if len(closes) != 0 {
		t.Fatalf("runtime invented door.close on a door that never opened: %v", closes)
	}
	if spy.doorEverOpened() {
		t.Fatal("hanging machine must never report the key installed")
	}
	if id := spy.currentInstalled(); id != "" {
		t.Fatalf("key installed on a machine that never accepted the open: %q", id)
	}
	f.waitSpyOnline(t) // the reconcile after the timeout must leave the machine online
	mc, ok := f.gw.reg.get(f.machineID)
	if !ok || mc.doorMachine.Snapshot().State != core.Closed {
		t.Fatalf("door must settle Closed after open timeout, got ok=%v state=%v", ok, mc)
	}
}

// ---- T4 (A1+A2): a late answer to door.open does not open access to the person

func TestAccT4_TimedOutOpenNeverGrantsAccess(t *testing.T) {
	f := newSpyFixture(t, func(cfg *Config) {
		cfg.DoorOpenTimeout = 700 * time.Millisecond
		cfg.DoorStatusTimeout = 1500 * time.Millisecond
	})
	// The machine installs the key right on receiving door.open but answers
	// 2.5s later, long after the gateway timeout. The answer is late, yet the key at the target is ALREADY working.
	spy := f.connectSpy(spyBehavior{delayFirstOpen: 2500 * time.Millisecond})
	f.waitSpyOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go discardSSHRequests(reqs)
	acc := drain(ch)

	if !waitContains(t, acc, "Access to this machine is currently unavailable", 3*time.Second) {
		t.Fatalf("human must be denied while the open is timing out, got %q", acc.get())
	}
	if strings.Contains(acc.get(), "recorded") {
		t.Fatal("human reached the machine through a door whose open timed out")
	}

	ops := spy.waitOpsQuiescent(t)
	if len(ops) != 5 {
		t.Fatalf("expected [status open status close status], got %v", ops)
	}
	if ops[1].Op != "door.open" {
		t.Fatalf("ops[1] must be the door.open, got %v", ops)
	}
	if ops[3].Op != "door.close" || ops[3].Reason != "reconnect" {
		t.Fatalf("stale installed key must be reconciled by the automaton's close, got %v", ops)
	}
	if id := spy.currentInstalled(); id != "" {
		t.Fatalf("stale door key left installed on the machine: %q", id)
	}
	f.waitSpyOnline(t)

	// The person who comes next works normally through the NEW door.
	client2, hs2 := f.dialAndShell(t, f.person, f.machineID, f.personKey)
	defer client2.Close()
	const marker = "acc-t4-second-human"
	if _, err := hs2.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readUntil(t, hs2.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("second human must get a fresh working door, echo: %q", got)
	}
}

// ---- T5 (A3): the death of one control channel removes everything -----------

func TestAccT5_ControlChannelDeathAloneCleansUp(t *testing.T) {
	f := newSpyFixture(t, nil)
	spy := f.connectSpy(spyBehavior{})
	f.waitSpyOnline(t)

	client, hs := f.dialAndShell(t, f.person, f.machineID, f.personKey)
	defer client.Close()
	waitUntil(t, "session did not become active", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	spy.closeControlOnly() // the transport is alive, only iamtunnel-control died

	waitUntil(t, "machine stayed registered after control channel death", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return !ok
	})
	waitUntil(t, "machine still counts as online after control channel death", func() bool {
		return !f.gw.view.MachineOnline(f.machineID)
	})
	waitUntil(t, "human session survived control channel death", func() bool {
		_, err := hs.ch.SendRequest("window-change", true, sshx0())
		return err != nil
	})
	waitUntil(t, "acl session was not released after control channel death", func() bool {
		_, perMachine := f.gw.aclE.SessionCounts()
		return len(perMachine) == 0
	})

	// Full recovery: a new machine connects and serves a session.
	f.connectSpy(spyBehavior{})
	f.waitSpyOnline(t)
	client2, hs2 := f.dialAndShell(t, f.person, f.machineID, f.personKey)
	defer client2.Close()
	const marker = "acc-t5-recovery"
	if _, err := hs2.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readUntil(t, hs2.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("no echo after reconnect: %q", got)
	}
	// The transcript is appended at recording finalization -- close the session.
	_ = hs2.ch.Close()
	waitUntil(t, "post-reconnect session did not wind down", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})
	txt := waitForTranscript(t, f.recDir)
	if !strings.Contains(txt, marker) {
		t.Fatalf("post-reconnect transcript missing marker: %q", txt)
	}
}

// ---- T6 (A4): a byte from the machine lands in the recording BEFORE being shown to the person

func TestAccT6_RecordingCompletesBeforeHumanSeesByte(t *testing.T) {
	gate, openGate := onceChan()
	rec := &probeRec{gate: gate}
	var recMu sync.Mutex
	f := newSpyFixture(t, func(cfg *Config) {
		cfg.NewRecording = func(si SessionInfo) (core.Recording, error) {
			recMu.Lock()
			defer recMu.Unlock()
			return rec, nil
		}
	})
	f.connectSpy(spyBehavior{})
	f.waitSpyOnline(t)

	client, hs := f.dialAndShell(t, f.person, f.machineID, f.personKey)
	defer client.Close()
	t.Cleanup(openGate) // even on test failure, do not leave io.Copy blocked
	acc := drain(hs.ch)

	const marker = "acc-t6-order-marker"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// While the recording of the very first byte is held by the gate, the person
	// CANNOT see it: a broken order would have shown the marker here.
	if !stayAbsent(t, acc, marker, 600*time.Millisecond) {
		t.Fatal("human saw machine bytes before they were committed to the recording")
	}

	openGate()
	if !waitContains(t, acc, marker, 3*time.Second) {
		t.Fatalf("marker never reached the human after the gate opened: %q", acc.get())
	}
	if !rec.seen(marker) {
		t.Fatal("recording does not contain the byte the human was shown")
	}
}

// ---- T7 (A4): a recording failure does not show the byte to the person and tears down the session

func TestAccT7_RecorderFaultHidesByteFromHuman(t *testing.T) {
	rec := &probeRec{failOn: "DOSMARKER"}
	f := newSpyFixture(t, func(cfg *Config) {
		cfg.NewRecording = func(si SessionInfo) (core.Recording, error) {
			return rec, nil
		}
	})
	f.connectSpy(spyBehavior{})
	f.waitSpyOnline(t)

	client, hs := f.dialAndShell(t, f.person, f.machineID, f.personKey)
	defer client.Close()
	acc := drain(hs.ch)

	const okMark = "acc-t7-unomarker"
	if _, err := hs.ch.Write([]byte(okMark + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !waitContains(t, acc, okMark, 3*time.Second) {
		t.Fatalf("echo before the fault must pass: %q", acc.get())
	}
	if !rec.seen(okMark) {
		t.Fatal("shown byte missing from recording even before the fault")
	}

	const badMark = "acc-t7-DOSMARKER"
	if _, err := hs.ch.Write([]byte(badMark + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !stayAbsent(t, acc, badMark, 700*time.Millisecond) {
		t.Fatal("human was shown bytes the recorder failed to record")
	}
	waitUntil(t, "bridge did not tear the session down after recording fault", func() bool {
		_, err := hs.ch.SendRequest("window-change", true, sshx0())
		return err != nil
	})
	if reason := rec.abortedReason(); reason == "" {
		t.Fatal("recording was not aborted after the fault - silent unrecorded tail")
	}
	if rec.seen(badMark) {
		t.Fatal("failed chunk is recorded as written")
	}
	if !eventsContain(t, f.logPath, "session.drop") {
		t.Fatal("recording fault was not journaled as session.drop")
	}
}

// ---- T8 (A1): with no reservations the runtime does not touch the door at all

func TestAccT8_NoDoorActivityWithoutReservation(t *testing.T) {
	f := newSpyFixture(t, nil)
	spy := f.connectSpy(spyBehavior{})
	f.waitSpyOnline(t)
	baseline := spy.opCount()

	// A second and a half of the machine's life, eight keepalive rounds and a
	// half-hour clock jump: no human activity, no reason for the door.
	time.Sleep(1200 * time.Millisecond)
	f.clock.Advance(30 * time.Minute)

	ops := spy.waitOpsQuiescent(t)
	if got := ops[baseline:]; len(got) != 0 {
		t.Fatalf("runtime touched the door with no reservation pending: %v", got)
	}
	if spy.doorEverOpened() {
		t.Fatal("door opened spontaneously")
	}
	f.waitSpyOnline(t)
}

// ---- T9 (A3): eviction on reconnect does not throw out the new machine ------

func TestAccT9_ReconnectEvictionKeepsNewConnUsable(t *testing.T) {
	f := newSpyFixture(t, nil)
	spy1 := f.connectSpy(spyBehavior{})
	f.waitSpyOnline(t)
	mc1, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("first conn not registered")
	}
	epoch1 := mc1.epoch

	spy1.close()
	waitUntil(t, "old connection was not removed after transport loss", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return !ok
	})
	spy2 := f.connectSpy(spyBehavior{})
	// Wait for the NEW epoch and its online specifically: a bare waitSpyOnline
	// would lie here while the registry still shows the old conn.
	waitUntil(t, "new conn did not take over the registry slot", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.epoch > epoch1 && mc.doorMachine.Snapshot().Online
	})

	// The old transport is indeed dead...
	waitUntil(t, "evicted transport is still alive", func() bool {
		_, _, err := spy1.conn.SendRequest("keepalive@iamtunnel", true, nil)
		return err != nil
	})
	// ...but its teardown must not have thrown the NEW machine out of the registry.
	if !f.gw.view.MachineOnline(f.machineID) {
		t.Fatal("stale teardown evicted the newer connection - machine wrongly offline")
	}
	if _, ok := f.gw.reg.get(f.machineID); !ok {
		t.Fatal("newer connection missing from registry after old conn teardown")
	}
	if spy2.opCount() == 0 {
		t.Fatal("new connection never spoke on the control channel")
	}

	client, hs := f.dialAndShell(t, f.person, f.machineID, f.personKey)
	defer client.Close()
	const marker = "acc-t9-post-eviction"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := readUntil(t, hs.ch, marker); !strings.Contains(got, marker) {
		t.Fatalf("session through the surviving conn broken: %q", got)
	}
}

// ---- T10 (A3, -race): the race of the control death with session setup ------

func TestAccT10_Race_ControlDeathVsSessionSetup(t *testing.T) {
	f := newSpyFixture(t, nil)
	for i := 0; i < 4; i++ {
		spy := f.connectSpy(spyBehavior{})
		f.waitSpyOnline(t)

		humanDone := make(chan struct{})
		go func() {
			defer close(humanDone)
			cfg := &ssh.ClientConfig{
				User:            f.person + ":" + f.machineID,
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(f.personKey)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         3 * time.Second,
			}
			c, err := ssh.Dial("tcp", f.addr, cfg)
			if err != nil {
				return
			}
			defer c.Close()
			ch, reqs, err := c.OpenChannel("session", nil)
			if err != nil {
				return
			}
			go discardSSHRequests(reqs)
			_, _ = ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
			_, _ = ch.SendRequest("shell", true, nil)
			_, _ = ch.Write([]byte("acc-t10\n"))
			_ = ch.Close()
		}()

		time.Sleep(time.Duration(i%5) * 7 * time.Millisecond)
		spy.closeControlOnly()

		waitUntil(t, "machine never cleaned up after racing control death", func() bool {
			_, ok := f.gw.reg.get(f.machineID)
			return !ok && !f.gw.view.MachineOnline(f.machineID)
		})
		select {
		case <-humanDone:
		case <-time.After(3 * time.Second):
			t.Fatalf("iteration %d: human goroutine stuck", i)
		}
	}
}

// ---- T11 (A2): swapping the role/owner of the key does not pass at all ------

func TestAccT11_CrossRoleAndOwnerImpersonationDenied(t *testing.T) {
	f := newSpyFixture(t, nil)
	spy := f.connectSpy(spyBehavior{})
	f.waitSpyOnline(t)

	strangerKey := genSigner(t)
	if err := f.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "mallory", Role: "user",
			Keys: []state.Key{{Fingerprint: fingerprintOf(t, strangerKey.PublicKey()), Pub: authorizedLine(strangerKey.PublicKey()), Added: state.NewZonedTime(f.clock.Now())}},
		})
		return nil
	}); err != nil {
		t.Fatalf("add stranger: %v", err)
	}

	// (1) someone else's key + someone else's username posing as the grant owner;
	// (2) the person's key + the machine's username;
	// (3) the machine's key + the person's username.
	attempts := []struct {
		user string
		key  ssh.Signer
	}{
		{f.person + ":" + f.machineID, strangerKey},
		{"machine:" + f.machineID, f.personKey},
		{f.person + ":" + f.machineID, f.machineKy},
	}
	for i, a := range attempts {
		cfg := &ssh.ClientConfig{
			User:            a.user,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(a.key)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         3 * time.Second,
		}
		if c, err := ssh.Dial("tcp", f.addr, cfg); err == nil {
			_ = c.Close()
			t.Fatalf("attempt %d (%s): impersonation dial succeeded", i, a.user)
		}
	}
	if spy.doorEverOpened() {
		t.Fatal("door was opened for an impersonation attempt")
	}
	if got := spy.waitOpsQuiescent(t)[1:]; len(got) != 0 {
		t.Fatalf("impersonation caused control ops: %v", got)
	}
}
