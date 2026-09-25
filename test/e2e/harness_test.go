package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// ---- Key Helpers -----------------------------------------------------------

// testUIDForDoor returns the uid/gid winkeys should treat as the
// door line's owner in this test binary. The e2e harness is special:
// unlike internal/{server,winkeys,gateway}'s unit tests, the fake
// machine is a real process role (the test's own goroutine path) and
// the keyFile is owned by the test process itself. Under non-root
// (the non-root uid-1000 lane) `os.Getuid()` returns the real
// uid, fchownIfRoot under non-root fstats, sees the owner already
// matches, and skips the chown — no syscall. Under root (the docker
// root lane `go test` runs through), `os.Getuid()` returns 0 and
// `os.Getgid()` returns 0 — and `DoorOptions{0, 0}` is the winkeys
// unset-owner sentinel: validateOptionsPlatform refuses it with
// "unset sentinel — resolve the OS user via elevate.VerifyOSUser
// (or os/user.Lookup)" before SweepStale ever runs, so the corrupted
// line the scenario plants in the seed file is never removed and the
// test reports "sanitize did not remove the corrupted line" — same
// external symptom as fix1/fix2's earlier DoorLockPath guard, with
// a different underlying guard-condition. The helper keeps the
// invariant "never hand the sentinel pair to winkeys": under root
// it returns a fixed non-zero pair (1000, mirroring the uid-1000
// lane for easy comparison) — and that pair still produces real
// production behaviour (the server under root MUST be able to
// chown the door to a non-root owner) without being a test seam:
// the file is inside `t.TempDir()` of the fake machine, the test
// deletes it on cleanup, no production code path is touched by the
// synthetic 1000.
func testUIDForDoor() (uid, gid int) {
	u := os.Getuid()
	g := os.Getgid()
	if u == 0 && g == 0 {
		return 1000, 1000
	}
	return u, g
}

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

// ---- Control Wire Types ----------------------------------------------------

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

// sanitizeResult mirrors internal/server/wire.go's sanitizeResult: the
// number of door lines the sweep took is part of the wire contract so the
// gateway's door.sanitize journal entry can carry it.
type sanitizeResult struct {
	Sanitized bool `json:"sanitized"`
	Removed   int  `json:"removed"`
}

// readDoorLineFromFile answers the "is there a door line, and if so what
// is its id" question the gateway asks through door.status. The first
// door line in the file wins; a file with only a corrupted marker
// (own marker signature but invalid id tail) reports installed=true
// with the literal marker-tail text — exactly the shape the gateway
// must NOT trust and that drives sanitize(reason:"corrupted").
//
// Used by the e2e harness when fakeMachineBehavior.keyFile is set,
// so the fake machine's status reflects the real file on disk after
// sanitize (scenario 20 needs the second status to be installed:false).
func readDoorLineFromFile(path string) (bool, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, "", nil
		}
		return false, "", err
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		if !strings.Contains(line, "iamtunnel-door=") {
			continue
		}
		idx := strings.Index(line, "iamtunnel-door=")
		id := strings.TrimSpace(line[idx+len("iamtunnel-door="):])
		return true, id, nil
	}
	return false, "", nil
}

func mustResult(v interface{}) json.RawMessage {
	raw, _ := json.Marshal(v)
	return raw
}

// ---- Fake Target SSHD -------------------------------------------------------

type fakeTargetSSHD struct {
	listener net.Listener
	// signer is fixed by the constructor and never reassigned: conn
	// goroutines read it while the accept loop keeps serving, so a test
	// that swapped the field after construction raced every such read
	// (IAMT-105: the write could also lose to a straggler connection
	// from an earlier fixture landing on the reused loopback port, in
	// which case scenario 08 read back the OLD key, the gateway had
	// nothing to reject, and the scenario passed without ever
	// exercising its assertion). A scenario that needs a different host
	// key passes it to newFakeTargetSSHDWithKey.
	signer     ssh.Signer
	keyAllowed func(blob []byte) bool

	userMu               sync.Mutex
	authenticatedUserLog []string
	startMu              sync.Mutex
	startRequests        []string
}

// newFakeTargetSSHDWithKey builds the fake sshd around the given host
// key. The key is installed BEFORE `go s.accept()` starts, so every
// conn goroutine — however early it runs — observes the same key, and
// presented-vs-pinned mismatches exist from the first connection on.
func newFakeTargetSSHDWithKey(t *testing.T, keyAllowed func([]byte) bool, signer ssh.Signer) *fakeTargetSSHD {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeTargetSSHD{listener: ln, signer: signer, keyAllowed: keyAllowed}
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
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if s.keyAllowed(key.Marshal()) {
				s.userMu.Lock()
				s.authenticatedUserLog = append(s.authenticatedUserLog, meta.User())
				s.userMu.Unlock()
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
		go s.serveEchoSession(ch, rr)
	}
}

// authenticatedUsers returns the usernames of nested SSH connections whose
// door key was accepted. Tests use it to distinguish the proved account from
// the merely requested account; the target SSHD itself has no reason to care.
func (s *fakeTargetSSHD) authenticatedUsers() []string {
	s.userMu.Lock()
	defer s.userMu.Unlock()
	return append([]string(nil), s.authenticatedUserLog...)
}

// startedRequests reports only process-start requests observed by the target.
// It deliberately excludes pty-req: a terminal allocation alone is not a
// command start, whereas shell and exec would violate a fail-closed recording
// refusal if they reached this fake.
func (s *fakeTargetSSHD) startedRequests() []string {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	return append([]string(nil), s.startRequests...)
}

func (s *fakeTargetSSHD) recordStartRequest(kind string) {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	s.startRequests = append(s.startRequests, kind)
}

func (s *fakeTargetSSHD) serveEchoSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
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
					s.recordStartRequest(r.Type)
					once.Do(func() { close(started) })
				}
			case "exec":
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
				s.recordStartRequest(r.Type)
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

// ---- Fake Machine -----------------------------------------------------------

type fakeMachineBehavior struct {
	refuseOpen        bool
	hangOpen          bool
	hangStatus        bool
	silentKeepalive   bool
	staleKeyOnConnect []byte
	reportForeignDoor string
	// reportSanitizeRemoved makes door.sanitize reply with the given count
	// in its sanitizeResult.Removed payload. Default of 0 still produces
	// a well-formed reply (sanitize of a clean file).
	reportSanitizeRemoved int
	// failSanitize makes every door.sanitize reply ok:false with
	// E_CONTROL_INTERNAL — the refused sanitize path IAMT-103 asks the
	// journal to record.
	failSanitize bool
	// hangSanitize makes every door.sanitize request hang with no reply
	// — exercises the gateway-side timeout branch of door.sanitize.
	hangSanitize bool
	// keyFile, when non-empty, makes door.sanitize drive a REAL winkeys
	// sweep on the given path instead of reporting a fixed count. The
	// count in the reply is the value winkeys.Door.SweepStale returned,
	// and the file on disk is the same bytes the gateway's journal
	// entry is about. Used by scenario 20 to exercise the byte-level
	// invariant "no foreign key loses a single byte".
	keyFile string
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
	everOpened    bool
	silent        bool
	openCount     int
	closeCount    int

	statusHandshakeDone chan struct{}
	statusOnce          sync.Once

	stopProbe func()
	closeOnce sync.Once
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
	fm := &fakeMachine{
		t:                   t,
		id:                  id,
		signer:              signer,
		sshdAddr:            sshdAddr,
		behavior:            behavior,
		conn:                conn,
		raw:                 raw,
		statusHandshakeDone: make(chan struct{}),
	}
	if behavior.staleKeyOnConnect != nil {
		fm.installedBlob = behavior.staleKeyOnConnect
		fm.installedID = "stale-door-id"
	}
	fm.silent = behavior.silentKeepalive
	go fm.pipeKeepalive(reqs)
	go fm.acceptChannels(chans)
	t.Cleanup(fm.close)
	return fm
}

// pipeKeepalive answers keepalive@iamtunnel for as long as the machine is not
// silent, and drops every request without a reply once it is - which is what
// the gateway's probe counts as a miss.
//
// The silence is a flag rather than a construction-time branch because
// scenario 12 has to make the machine go quiet *after* the human session
// exists. Started silent, the gateway's keepalive deadline (80ms x 2) races the
// human dial and session setup, and under the load of a full -race package run
// the deadline won: pty-req came back EOF because the machine was already gone
// (one failure in twenty repeats, IAMT-85). With the flip the assertion is
// causal - the session dies because the machine went quiet, not because the
// test was slow.
func (fm *fakeMachine) pipeKeepalive(reqs <-chan *ssh.Request) {
	forward := make(chan *ssh.Request)
	go sshx.Keepalive{}.Respond(forward)
	defer close(forward)
	for r := range reqs {
		if fm.isSilent() {
			continue
		}
		forward <- r
	}
}

// goSilent stops the answers from this moment on.
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

func (fm *fakeMachine) close() {
	fm.closeOnce.Do(func() {
		if fm.stopProbe != nil {
			fm.stopProbe()
		}
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
			go discardSSHRequests(reqs)
			go fm.serveControl(ch)
		case "iamtunnel-target":
			ch, reqs, err := n.Accept()
			if err != nil {
				continue
			}
			go discardSSHRequests(reqs)
			go fm.spliceTarget(ch)
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
		var req controlRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		switch req.Op {
		case "door.open":
			if fm.behavior.hangOpen {
				continue
			}
			if fm.behavior.refuseOpen {
				reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
					Error: &controlErrorBody{Code: "E_CONTROL_DOOR_CONFLICT", Message: "refused by test"}})
				continue
			}
			blob, err := state.DecodeKeyBlob(req.Door.PubKey)
			if err != nil {
				reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
					Error: &controlErrorBody{Code: "E_CONTROL_PROTOCOL", Message: err.Error()}})
				continue
			}
			fm.mu.Lock()
			fm.installedBlob = blob
			fm.installedID = req.Door.ID
			fm.everOpened = true
			fm.openCount++
			fm.mu.Unlock()
			fp, _ := state.ComputeFingerprint(req.Door.PubKey)
			reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true,
				Result: mustResult(doorOpenResult{DoorID: req.Door.ID, Installed: true, PublicKeyFingerprint: fp})})
		case "door.close":
			fm.mu.Lock()
			if fm.installedID == req.DoorID {
				fm.installedBlob = nil
				fm.installedID = ""
			}
			fm.closeCount++
			fm.mu.Unlock()
			reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true,
				Result: mustResult(doorCloseResult{DoorID: req.DoorID, Removed: true})})
		case "door.status":
			if fm.behavior.hangStatus {
				continue
			}
			fm.mu.Lock()
			installed, id := fm.installedID != "", fm.installedID
			if fm.behavior.reportForeignDoor != "" {
				installed = true
				id = fm.behavior.reportForeignDoor
			}
			fm.mu.Unlock()
			// When a real key file is wired, door.status answers from
			// the file itself so the second status after sanitize
			// reflects the actual post-sweep state. scenario 20 needs
			// this to assert "a second status without the line".
			if fm.behavior.keyFile != "" {
				switch installed, id, err := readDoorLineFromFile(fm.behavior.keyFile); {
				case err != nil:
					reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
						Error: &controlErrorBody{Code: "E_INTERNAL", Message: err.Error()}})
					continue
				default:
					reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true,
						Result: mustResult(doorStatusResult{Installed: installed, DoorID: id})})
					fm.statusOnce.Do(func() { close(fm.statusHandshakeDone) })
					continue
				}
			}
			reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true,
				Result: mustResult(doorStatusResult{Installed: installed, DoorID: id})})
			fm.statusOnce.Do(func() { close(fm.statusHandshakeDone) })
		case "door.sanitize":
			if fm.behavior.hangSanitize {
				continue
			}
			if fm.behavior.failSanitize {
				reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
					Error: &controlErrorBody{Code: "E_CONTROL_INTERNAL", Message: "sweep refused by test"}})
				continue
			}
			if fm.behavior.keyFile != "" {
				// Drive a REAL winkeys sweep so the bytes on disk
				// are the same bytes the gateway's journal entry is
				// about. scenario 20 reads the file afterwards and
				// asserts on the foreign line's byte-for-byte survival.
				//
				// LockPath has been mandatory on linux/darwin since
				// IAMT-246 fix1: NewDoor (without options) is now only
				// good for windows and for tests that do not need a
				// real write. In e2e scenario 20, the sweep must
				// actually erase the corrupted line from disk — which
				// means writeAtomicBytes, which means
				// writeAtomicBytesPlatform, which requires
				// opts.LockPath. We put the lock in the fake machine's
				// t.TempDir() — TestScenario20 is isolated and nobody
				// else needs the lock.
				//
				// OwnerUID/OwnerGID: unlike tests in
				// internal/{server,winkeys,gateway}, which plug in
				// testUIDForDoor() (a seam-provided non-zero value),
				// here this is NOT a seam — the fake machine runs
				// inside the real e2e test process itself, and keyFile
				// belongs to that very process. os.Getuid()/Getgid()
				// return the real owner under a non-root runner, and
				// fchownIfRoot sees a match and skips the actual
				// chown syscall. Under a root runner (`go test` runs in
				// Docker golang:1.27.0 with no `-u`), both would
				// return 0 and DoorOptions{0,0} would
				// again fall into winkeys' unset-sentinel — so instead
				// we go through the local testUIDForDoor(), the same
				// seam as in internal/gateway/testhelpers_test.go and
				// internal/server/testhelpers_test.go:39: non-root →
				// the real euid/egid pair, root → a fixed (1000,
				// 1000), which is valid for validateOptionsPlatform and
				// for fchownIfRoot. Under root, fchownIfRoot will
				// actually call chownFnFD on a file inside the fake
				// machine's t.TempDir() — ordinary product behavior
				// (a server running as root MUST be able to chown the
				// door), just with a synthetic target uid here rather
				// than the process's real euid.
				lockPath := filepath.Join(fm.t.TempDir(), "door.lock")
				uid, gid := testUIDForDoor()
				d, err := winkeys.NewDoorWithOptions(fm.behavior.keyFile, nil, winkeys.DoorOptions{
					LockPath: lockPath,
					OwnerUID: uid,
					OwnerGID: gid,
				})
				if err != nil {
					reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
						Error: &controlErrorBody{Code: "E_INTERNAL", Message: err.Error()}})
					continue
				}
				removed, err := d.SweepStale("")
				if err != nil {
					reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: false,
						Error: &controlErrorBody{Code: "E_INTERNAL", Message: err.Error()}})
					continue
				}
				reply(controlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true,
					Result: mustResult(sanitizeResult{Sanitized: true, Removed: removed})})
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

func (fm *fakeMachine) doorInstalled() (bool, string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.installedID != "", fm.installedID
}

func (fm *fakeMachine) doorEverOpened() bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.everOpened
}

// doorOpenCount returns the cumulative number of door.open commands the
// gateway has sent on the control channel to this fake machine. Unlike
// doorEverOpened (sticky boolean, "was a door opened at all"), this lets a
// test distinguish "the door opened once and closed" from "the door opened
// twice and closed twice" - the second-cycle leg of scenario IAMT-21 needs
// the latter to assert that the door can be reopened for a fresh session
// after it has auto-closed.
func (fm *fakeMachine) doorOpenCount() int {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.openCount
}

// doorCloseCount returns the cumulative number of door.close commands the
// gateway has sent. Scenario IAMT-21 uses it separately from doorInstalled():
// the absence of an installed key on the fake machine is consistent with
// either "sessions ended but door.close was never sent" or "sessions ended
// and door.close was sent and acknowledged", and only this counter proves
// the latter happened on the wire.
func (fm *fakeMachine) doorCloseCount() int {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.closeCount
}

func (fm *fakeMachine) waitOnline(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-fm.statusHandshakeDone:
		time.Sleep(15 * time.Millisecond) // Allow gateway goroutine to finish processing status response
	case <-time.After(timeout):
		t.Fatal("fake machine initial door.status handshake did not complete in time")
	}
}

// ---- Fake Human -------------------------------------------------------------

type humanSession struct {
	client *ssh.Client
	ch     ssh.Channel
	reqs   <-chan *ssh.Request
	exits  chan uint32
}

func dialHuman(t *testing.T, addr, person, machine string, signers ...ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            person + ":" + machine,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	return ssh.Dial("tcp", addr, cfg)
}

func openHumanSession(t *testing.T, client *ssh.Client) *humanSession {
	t.Helper()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	h := &humanSession{client: client, ch: ch, reqs: reqs, exits: make(chan uint32, 1)}
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

func (h *humanSession) shell(t *testing.T) {
	t.Helper()
	ok, err := h.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	if err != nil || !ok {
		t.Fatalf("pty-req: ok=%v err=%v", ok, err)
	}
	ok, err = h.ch.SendRequest("shell", true, nil)
	if err != nil || !ok {
		t.Fatalf("shell: ok=%v err=%v", ok, err)
	}
}

// ---- Fixture ----------------------------------------------------------------

type fixture struct {
	t         *testing.T
	gw        *gateway.Gateway
	ln        net.Listener
	addr      string
	dir       string
	store     *state.Store
	log       *events.Log
	sshd      *fakeTargetSSHD
	machineID string
	person    string

	personKey  ssh.Signer
	bob        string
	bobKey     ssh.Signer
	machineKey ssh.Signer
	hostKey    ssh.Signer
	clock      *fakeClock

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

// isolateEnv pins BOTH platform pairs of the environment variables the
// product resolves its data directories from (IAMT-106): the Windows
// pair LOCALAPPDATA/ProgramData and the Unix pair HOME/XDG_DATA_HOME.
// Every value is a dummy path inside the fixture's own t.TempDir(), so
// whatever a product path resolves from the process environment stays
// inside the test's scratch space on either platform, and nothing can
// leak into the real %LOCALAPPDATA%, %ProgramData%, $HOME or XDG data
// dir of the machine running the suite. t.Setenv restores the previous
// values when the test finishes.
func isolateEnv(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("LOCALAPPDATA", filepath.Join(dir, "localappdata"))
	t.Setenv("ProgramData", filepath.Join(dir, "programdata"))
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "xdgdata"))
}

// fixtureOpts is what a test may pick about the fixture BEFORE any of
// its goroutines start. Everything set here is wired in at
// construction; there is deliberately no way to bend a running
// fixture's plumbing after the fact.
type fixtureOpts struct {
	// SSHDPresentedKey is the host key the fake target sshd presents
	// from its very first connection. Nil (the default) means a fresh
	// key, which is also the key pinned in state.json — the happy path.
	// A deliberately different key is scenario 08's premise: state.json
	// then pins a separate, legitimate key while the target sshd
	// presents the wrong one, and the mismatch exists from birth instead
	// of being swapped in under a live accept loop.
	SSHDPresentedKey ssh.Signer
}

func newFixture(t *testing.T, cfgMod func(*gateway.Config)) *fixture {
	t.Helper()
	return newFixtureOpts(t, fixtureOpts{}, cfgMod)
}

func newFixtureOpts(t *testing.T, opts fixtureOpts, cfgMod func(*gateway.Config)) *fixture {
	t.Helper()
	dir := t.TempDir()

	isolateEnv(t, dir)

	pinnedSigner := genSigner(t)
	presentedSigner := opts.SSHDPresentedKey
	if presentedSigner == nil {
		presentedSigner = pinnedSigner
	}

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
	bobKey := genSigner(t)
	machineKey := genSigner(t)

	f := &fixture{
		t:          t,
		dir:        dir,
		store:      store,
		log:        log,
		person:     "alice",
		bob:        "bob",
		machineID:  "vm1",
		personKey:  personKey,
		bobKey:     bobKey,
		machineKey: machineKey,
		hostKey:    hostKey,
	}

	f.sshd = newFakeTargetSSHDWithKey(t, func(blob []byte) bool {
		return f.doorKeyBlobAllowed(blob)
	}, presentedSigner)

	sshdHostKeyLine := authorizedLine(pinnedSigner.PublicKey())
	verifiedUser := `MACHINE\svc`
	clock := newFakeClock(time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC))
	f.clock = clock

	until := state.NewZonedTime(clock.Now().Add(time.Hour))
	err = store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: f.person, Role: "user",
			Keys: []state.Key{{Fingerprint: fingerprintOf(t, personKey.PublicKey()), Pub: authorizedLine(personKey.PublicKey()), Added: state.NewZonedTime(clock.Now())}},
		})
		st.People = append(st.People, state.Person{
			Name: f.bob, Role: "user",
			Keys: []state.Key{{Fingerprint: fingerprintOf(t, bobKey.PublicKey()), Pub: authorizedLine(bobKey.PublicKey()), Added: state.NewZonedTime(clock.Now())}},
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
		if err := st.GrantAccess(f.person, f.machineID, &until, "shell"); err != nil {
			return err
		}
		return st.GrantAccess(f.bob, f.machineID, &until, "shell")
	})
	if err != nil {
		t.Fatalf("seed state: %v", err)
	}

	cfg := gateway.Config{
		Store:   store,
		Log:     log,
		HostKey: hostKey,
		Now:     clock.Now,

		// Default the public address to whatever the listener was bound
		// to. Tests that hand out enrol codes / connection strings
		// through the gateway itself need the resulting URL to be
		// dialable from the same process; 127.0.0.1:<port> is always
		// dialable from the test runner.
		PublicHost: "127.0.0.1",

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

		Keepalive: sshx.Keepalive{Interval: 150 * time.Millisecond, MaxMisses: 3},

		RecordingBaseDir: dir + "/recordings",
	}
	if cfgMod != nil {
		cfgMod(&cfg)
	}

	// Bind the listener FIRST so we know the port to advertise in any
	// enrol-code / connection-string URLs the gateway hands out. The
	// product code in production picks these from "gateway install"
	// CLI flags; a test cannot reasonably do that, so it infers them
	// from the listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	f.addr = ln.Addr().String()
	if _, portStr, perr := net.SplitHostPort(f.addr); perr == nil {
		if p, perr2 := strconv.Atoi(portStr); perr2 == nil {
			cfg.PublicPort = p
		}
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	f.gw = gw

	go gw.Serve(ln)
	t.Cleanup(func() { _ = gw.Close() })

	return f
}

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
	return f.connectMachineWithKey(behavior, f.machineKey)
}

// connectMachineWithKey connects the fake machine with an EXPLICIT
// machine key, so a test that enrolled a different long-term key does
// not have to reassign the fixture's f.machineKey field while the
// fixture's goroutines are already running (IAMT-105 sweep: the field
// swap in runFakeMachineAs was write-after-start by construction even
// though every current read of it sits on the test goroutine).
func (f *fixture) connectMachineWithKey(behavior fakeMachineBehavior, machineKey ssh.Signer) *fakeMachine {
	fm := newFakeMachine(f.t, f.addr, f.machineID, machineKey, f.sshd.addr(), behavior)
	f.machMu.Lock()
	f.current = fm
	f.machMu.Unlock()
	fm.waitOnline(f.t, 3*time.Second)
	return fm
}

func (f *fixture) recordingsDir() string {
	return f.dir + "/recordings"
}

// ---- Helpers ----------------------------------------------------------------

func waitUntil(t *testing.T, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

func readUntil(t *testing.T, r io.Reader, want string) string {
	t.Helper()
	buf := make([]byte, 4096)
	var acc strings.Builder
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, err := r.Read(buf)
		if n > 0 {
			acc.Write(buf[:n])
			if strings.Contains(acc.String(), want) {
				return acc.String()
			}
		}
		if err != nil {
			break
		}
	}
	return acc.String()
}

func readAll(t *testing.T, r io.Reader, wait time.Duration) string {
	t.Helper()
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		var acc strings.Builder
		for {
			n, err := r.Read(buf)
			if n > 0 {
				acc.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- acc.String()
	}()
	select {
	case s := <-done:
		return s
	case <-time.After(wait):
		return ""
	}
}

func waitForTranscript(t *testing.T, dir string) string {
	t.Helper()
	var found string
	waitUntil(t, "no .txt transcript appeared under "+dir, func() bool {
		var hit string
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".txt") {
				hit = path
			}
			return nil
		})
		if hit == "" {
			return false
		}
		b, err := os.ReadFile(hit)
		if err != nil {
			return false
		}
		found = string(b)
		return true
	})
	return found
}

func waitForCast(t *testing.T, dir string) string {
	t.Helper()
	var found string
	waitUntil(t, "no .cast recording appeared under "+dir, func() bool {
		var hit string
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".cast") {
				hit = path
			}
			return nil
		})
		if hit == "" {
			return false
		}
		b, err := os.ReadFile(hit)
		if err != nil {
			return false
		}
		found = string(b)
		return true
	})
	return found
}

func sshx0() []byte {
	return sshx.MarshalWindow(sshx.WindowChange{Columns: 80, Rows: 24})
}
