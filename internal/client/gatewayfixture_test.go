package client_test

// gatewayfixture_test.go spins up a real internal/gateway.Gateway — the
// accepted package itself, through its exported Config/New — plus a fake
// machine and a fake target sshd, the same shape internal/gateway's own
// harness_test.go uses (fake peers on golang.org/x/crypto/ssh, nothing
// touching a real ssh folder or a real sshd). It exists so
// internal/client's Connect can be exercised end to end for the
// denied-machine, recording-banner and mid-session-transport-loss cases
// against the real, accepted gateway logic rather than only against a
// hand-rolled double.
//
// internal/gateway's own control-channel JSON envelope
// (internal/gateway/control_wire.go) is unexported and scoped to that
// package on purpose (its own doc comment says so); the types below are
// this test's own minimal copy of the same shape, not a dependency on
// gateway internals.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway"
	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// syncBuffer is a bytes.Buffer safe for concurrent Write/String: Connect
// writes to Out from its own goroutines while a test reads it from the
// main one to watch for the recording banner.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func genEDSigner(t *testing.T) ssh.Signer {
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

// ---- fake target sshd (the machine's own local sshd, SPEC §5.2) ----------

type fakeTargetSSHD struct {
	listener   net.Listener
	signer     ssh.Signer
	keyAllowed func([]byte) bool
}

func newFakeTargetSSHD(t *testing.T, keyAllowed func([]byte) bool) *fakeTargetSSHD {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeTargetSSHD{listener: ln, signer: genEDSigner(t), keyAllowed: keyAllowed}
	go s.accept()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeTargetSSHD) addr() string { return s.listener.Addr().String() }

func (s *fakeTargetSSHD) accept() {
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.conn(raw)
	}
}

func (s *fakeTargetSSHD) conn(raw net.Conn) {
	defer raw.Close()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if s.keyAllowed(key.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("fake sshd: key not in authorized_keys")
		},
	}
	cfg.AddHostKey(s.signer)
	sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for n := range chans {
		if n.ChannelType() != "session" {
			_ = n.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, rr, err := n.Accept()
		if err != nil {
			continue
		}
		go serveEchoSession(ch, rr)
	}
}

func serveEchoSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	started := make(chan struct{})
	var once sync.Once
	go func() {
		for r := range reqs {
			switch r.Type {
			case "pty-req", "shell", "window-change", "env":
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
				// A distinct, recognizable line on each of the two
				// streams — stdout vs stderr (extended data) — so a
				// client-side test can prove the two are not merged
				// anywhere on their way back: stdout and stderr are
				// kept separate.
				if exec, perr := sshx.ParseExec(r.Payload); perr == nil {
					_, _ = ch.Write([]byte("exec-stdout:" + exec.Command + "\n"))
					_, _ = ch.Stderr().Write([]byte("exec-stderr:" + exec.Command + "\n"))
				}
				once.Do(func() { close(started) })
			default:
				if r.WantReply {
					_ = r.Reply(false, nil)
				}
			}
		}
	}()
	<-started
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
	_ = ch.Close()
}

// ---- fake machine (the control-channel peer, PROTOCOL §5.1) --------------

type ctlDoor struct {
	ID           string `json:"id"`
	PubKey       string `json:"pubkey"`
	Opened       string `json:"opened"`
	IdleDeadline string `json:"idleDeadline"`
	HardDeadline string `json:"hardDeadline"`
}
type ctlRequest struct {
	Proto  int      `json:"proto"`
	Caps   []string `json:"caps"`
	ID     string   `json:"id"`
	Op     string   `json:"op"`
	Door   *ctlDoor `json:"door,omitempty"`
	DoorID string   `json:"doorId,omitempty"`
	Reason string   `json:"reason,omitempty"`
}
type ctlErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type ctlResponse struct {
	Proto  int             `json:"proto"`
	Caps   []string        `json:"caps"`
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *ctlErrorBody   `json:"error,omitempty"`
}
type ctlDoorOpenResult struct {
	DoorID               string `json:"doorId"`
	Installed            bool   `json:"installed"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint"`
}
type ctlDoorCloseResult struct {
	DoorID  string `json:"doorId"`
	Removed bool   `json:"removed"`
}
type ctlDoorStatusResult struct {
	Installed bool   `json:"installed"`
	DoorID    string `json:"doorId,omitempty"`
}

type fakeMachine struct {
	t        *testing.T
	id       string
	sshdAddr string

	conn ssh.Conn
	raw  net.Conn

	writeMu sync.Mutex
	mu      sync.Mutex
	blob    []byte
	doorID  string
	everSet bool // sticky: a door was installed at least once, even if since removed

	closeOnce sync.Once
}

func newFakeMachine(t *testing.T, addr, id string, signer ssh.Signer, sshdAddr string) *fakeMachine {
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
	fm := &fakeMachine{t: t, id: id, sshdAddr: sshdAddr, conn: conn, raw: raw}
	go sshx.Keepalive{}.Respond(reqs)
	go fm.acceptChannels(chans)
	t.Cleanup(fm.close)
	return fm
}

func (fm *fakeMachine) close() {
	fm.closeOnce.Do(func() {
		_ = fm.conn.Close()
		_ = fm.raw.Close()
	})
}

func (fm *fakeMachine) acceptChannels(chans <-chan ssh.NewChannel) {
	for n := range chans {
		switch n.ChannelType() {
		case "iamtunnel-control":
			ch, reqs, err := n.Accept()
			if err != nil {
				continue
			}
			go discardReqs(reqs)
			go fm.serveControl(ch)
		case "iamtunnel-target":
			ch, reqs, err := n.Accept()
			if err != nil {
				continue
			}
			go discardReqs(reqs)
			go fm.spliceTarget(ch)
		default:
			_ = n.Reject(ssh.UnknownChannelType, "unexpected channel")
		}
	}
}

func discardReqs(reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
	}
}

func (fm *fakeMachine) spliceTarget(ch ssh.Channel) {
	d, err := net.DialTimeout("tcp", fm.sshdAddr, 5*time.Second)
	if err != nil {
		_ = ch.Close()
		return
	}
	defer d.Close()
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
	_ = ch.Close()
}

func (fm *fakeMachine) serveControl(ch ssh.Channel) {
	dec := json.NewDecoder(ch)
	reply := func(resp ctlResponse) {
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
		var req ctlRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		switch req.Op {
		case "door.open":
			blob, err := state.DecodeKeyBlob(req.Door.PubKey)
			if err != nil {
				reply(ctlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false, Error: &ctlErrorBody{Code: "E_CONTROL_PROTOCOL", Message: err.Error()}})
				continue
			}
			fm.mu.Lock()
			fm.blob = blob
			fm.doorID = req.Door.ID
			fm.everSet = true
			fm.mu.Unlock()
			fp, _ := state.ComputeFingerprint(req.Door.PubKey)
			var res ctlDoorOpenResult
			res = ctlDoorOpenResult{DoorID: req.Door.ID, Installed: true, PublicKeyFingerprint: fp}
			b, _ := json.Marshal(res)
			reply(ctlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true, Result: b})
		case "door.close":
			fm.mu.Lock()
			if fm.doorID == req.DoorID {
				fm.blob = nil
				fm.doorID = ""
			}
			fm.mu.Unlock()
			b, _ := json.Marshal(ctlDoorCloseResult{DoorID: req.DoorID, Removed: true})
			reply(ctlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true, Result: b})
		case "door.status":
			fm.mu.Lock()
			installed, id := fm.doorID != "", fm.doorID
			fm.mu.Unlock()
			b, _ := json.Marshal(ctlDoorStatusResult{Installed: installed, DoorID: id})
			reply(ctlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true, Result: b})
		default:
			b, _ := json.Marshal(struct{}{})
			_ = b
			reply(ctlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false, Error: &ctlErrorBody{Code: "E_CONTROL_PROTOCOL", Message: "unknown op"}})
		}
	}
}

// ---- gateway fixture -------------------------------------------------------

type gwFixture struct {
	t         *testing.T
	gw        *gateway.Gateway
	addr      string
	store     *state.Store
	log       *events.Log
	dir       string
	machineID string
	hostKey   ssh.Signer
	machKey   ssh.Signer

	sshd *fakeTargetSSHD

	machMu  sync.Mutex
	current *fakeMachine
}

// newGWFixture only prepares the state store and the fake target sshd —
// it deliberately does not start the gateway yet. Config.Store's grants
// are loaded into the ACL engine exactly once, inside gateway.New: every
// persisted grant is wired in before the gateway accepts a connection.
// A grant added to cfg.Store directly after New has already run would
// not be picked up that way — the running gateway's own admin exec
// commands (grants.add and friends) call acl.Engine.AddGrant directly
// instead, which is how they reach a live gateway, not a choice this
// test double can route around. So every test seeds all the people and
// grants it needs first, and only then calls start().
func newGWFixture(t *testing.T) *gwFixture {
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

	f := &gwFixture{t: t, store: store, log: log, dir: dir, machineID: "win01", hostKey: genEDSigner(t), machKey: genEDSigner(t)}
	f.sshd = newFakeTargetSSHD(t, func(blob []byte) bool { return f.doorKeyAllowed(blob) })

	sshdHostKeyLine := authorizedLine(f.sshd.signer.PublicKey())
	verifiedUser := `MACHINE\svc`
	if err := store.Update(func(st *state.State) error {
		st.Machines = append(st.Machines, state.Machine{
			ID: f.machineID, Name: f.machineID, State: "verified",
			MachineKey:      authorizedLine(f.machKey.PublicKey()),
			SSHDHostKey:     &sshdHostKeyLine,
			OSUser:          verifiedUser,
			RequestedOSUser: verifiedUser,
			VerifiedOSUser:  &verifiedUser,
			OSUserStatus:    state.OSUserStatusVerified,
		})
		return nil
	}); err != nil {
		t.Fatalf("seed machine: %v", err)
	}

	return f
}

// start builds and launches the gateway over everything seeded so far
// (machine, people, grants). Call it only after every addPerson this
// test needs.
func (f *gwFixture) start(t *testing.T) {
	t.Helper()
	cfg := gateway.Config{
		Store:   f.store,
		Log:     f.log,
		HostKey: f.hostKey,

		AuthLimits: auth.AuthLimits{HandshakeTimeout: 3 * time.Second},
		ACLLimits:  acl.Limits{},
		RateConfig: auth.RateConfig{
			MaxKnownFailures: 10, MaxUnknownFailures: 10,
			Window: time.Minute, PairBanDuration: time.Minute, AddrBanDuration: time.Minute,
		},

		DoorIdle: time.Minute, DoorHard: 2 * time.Minute,

		ControlAcceptTimeout: time.Second,
		DoorOpenTimeout:      2 * time.Second,
		DoorCloseTimeout:     2 * time.Second,
		DoorStatusTimeout:    2 * time.Second,
		SessionSetupTimeout:  3 * time.Second,

		Keepalive: sshx.Keepalive{Interval: 150 * time.Millisecond, MaxMisses: 3},

		RecordingBaseDir: f.dir + "/recordings",
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	f.gw = gw

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go gw.Serve(ln)
	t.Cleanup(func() { _ = gw.Close() })
	f.addr = ln.Addr().String()
}

func (f *gwFixture) fingerprint() string {
	return ssh.FingerprintSHA256(f.hostKey.PublicKey())
}

func (f *gwFixture) doorKeyAllowed(blob []byte) bool {
	f.machMu.Lock()
	fm := f.current
	f.machMu.Unlock()
	if fm == nil {
		return false
	}
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.blob != nil && string(fm.blob) == string(blob)
}

// addPerson registers person with signer's key and, if until is non-nil,
// grants them a "shell" access to this fixture's machine.
func (f *gwFixture) addPerson(t *testing.T, person string, signer ssh.Signer, until *time.Time) {
	t.Helper()
	f.addPersonWithCap(t, person, signer, until, "shell")
}

// addPersonWithCap is addPerson plus the grant's own capability ("exec"
// vs "shell", PROTOCOL §4.3), so a test can seed the exec-only grant
// the exec-mode tests need without duplicating the person/key bookkeeping.
func (f *gwFixture) addPersonWithCap(t *testing.T, person string, signer ssh.Signer, until *time.Time, cap string) {
	t.Helper()
	fp, err := state.ComputeFingerprint(authorizedLine(signer.PublicKey()))
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if err := f.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: person, Role: "user",
			Keys: []state.Key{{Fingerprint: fp, Pub: authorizedLine(signer.PublicKey()), Added: state.NewZonedTime(time.Now())}},
		})
		if until != nil {
			z := state.NewZonedTime(*until)
			return st.GrantAccess(person, f.machineID, &z, cap)
		}
		return nil
	}); err != nil {
		t.Fatalf("add person %s: %v", person, err)
	}
}

func (f *gwFixture) connString(person string) config.ConnString {
	host, port := splitAddr(f.addr)
	return config.ConnString{Host: host, Port: port, Person: person, Fingerprint: f.fingerprint()}
}

func (f *gwFixture) connectMachine(t *testing.T) *fakeMachine {
	t.Helper()
	fm := newFakeMachine(t, f.addr, f.machineID, f.machKey, f.sshd.addr())
	f.machMu.Lock()
	f.current = fm
	f.machMu.Unlock()
	// There is no exported way to observe "online" from outside the
	// gateway package, by design; connectRetrying in connect_test.go
	// absorbs the short, real window between the
	// machine's handshake finishing and the gateway's own control/status
	// round trip marking it online, instead of this fixture guessing at
	// a fixed sleep.
	return fm
}

func waitFor(t *testing.T, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}
