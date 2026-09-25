package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/elevate"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/proto"
	"github.com/ultrathinker/iamtunnel/internal/server"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// cmdServer is the machine-side role (SPEC §3.2): the tunnel and the
// door, plus the internal doorwatch child process of SPEC §6.3.
func cmdServer(s *streams, args []string) int {
	if len(args) == 0 {
		return fail(s, userErrf(`iamtunnel server: want exactly one of "start", "stop", "status", "install", "uninstall" or the internal "doorwatch" — see "iamtunnel server --help".`))
	}
	if helpWord(args[0]) {
		return helpTopic(s, "server")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "start":
		return cmdServerStart(s, rest)
	case "stop":
		return cmdServerStopStatus(s, "server stop", rest)
	case "status":
		return cmdServerStopStatus(s, "server status", rest)
	case "install":
		return cmdServerInstall(s, rest)
	case "uninstall":
		return cmdServerUninstall(s, rest)
	case "doorwatch":
		return cmdServerDoorwatch(s, rest)
	default:
		return fail(s, userErrf("iamtunnel server: unknown subcommand %q — want %q, %q, %q, %q, %q or the internal %q. See \"iamtunnel server --help\".",
			sub, "start", "stop", "status", "install", "uninstall", "doorwatch"))
	}
}

// ---- server start/stop/status IPC ---------------------------------------
//
// internal/server has no notion of "is another instance already running"
// or "ask a running instance to stop" — Run just drives one machine's
// tunnel until its context is cancelled. cmd/iamtunnel supplies that on
// top: "server start" opens a loopback TCP control listener on an
// OS-chosen port, writes its port and a random per-run token to
// control.json in the server role directory, and answers
// "status"/"stop" requests authenticated by that
// token. "server stop"/"server status" read control.json and dial the
// recorded port.
//
// Why loopback TCP rather than a named pipe or a lock file: it must
// work "when start is running in a different Windows session" —
// loopback TCP sockets are not session-scoped on Windows, unlike some
// named-pipe ACL configurations, and it needs no extra platform code to
// build on Linux too. The random token (not just "any local connection
// to this port is trusted") stops another local process that happens to
// guess or scan the ephemeral port from stopping someone else's tunnel.
// A missing or stale (nothing listening) control.json is always treated
// as "not running", never as an error — a leftover file from a crashed
// process must not block the next "server start".

const controlFileName = "control.json"

func controlFilePath(dir string) string { return filepath.Join(dir, controlFileName) }

type controlFileRecord struct {
	PID   int    `json:"pid"`
	Port  int    `json:"port"`
	Token string `json:"token"`
}

type controlRequestMsg struct {
	Token string `json:"token"`
	Cmd   string `json:"cmd"` // "status" | "stop" | "tail" | "sessions"

	// "tail" only (IAMT-340), and the same three fields the gateway's
	// sessions.tail carries (contract §1): the session id exactly as
	// sessions.active hands it out, the byte offset to continue from,
	// and how many raw bytes are wanted. They are named and typed here
	// the way §1 names and types them — the window asks its own server
	// the same question an admin asks the gateway directly.
	ID     string `json:"id,omitempty"`
	Offset uint64 `json:"offset,omitempty"`
	Limit  uint32 `json:"limit,omitempty"`
}

// tailReplyMsg is the "tail" answer. Its two fields are mutually
// exclusive and each one is the gateway's own bytes, unmoved:
//
//   - Result is §1's answer body ({id,offset,total,live,data}) exactly
//     as it came back over the control channel. Nothing on this side
//     parses `data`, recomputes `total` or re-reads `live`, so the window
//     sees the gateway's answer and not this program's retelling of it.
//   - Refusal is the gateway's own refusal, code and message, for the
//     same reason: "this session is not this machine's" is a verdict
//     only the gateway may state, and the machine has no standing to
//     restate it in its own words.
//
// The presence of this object is itself the signal that the GATEWAY
// answered. A "tail" that failed on this side — no tunnel, no control
// channel, no answer in time — carries no Tail at all and speaks only in
// the reply's Message, so a machine-side failure can never be mistaken
// for the gateway's refusal, and the other way round.
type tailReplyMsg struct {
	Result  json.RawMessage     `json:"result,omitempty"`
	Refusal *server.TailRefusal `json:"refusal,omitempty"`
}

type controlReplyMsg struct {
	OK      bool   `json:"ok"`
	Running bool   `json:"running"`
	PID     int    `json:"pid"`
	Message string `json:"message,omitempty"`

	// Tail answers "tail" only; nil on every other command and on a
	// "tail" whose question never reached the gateway.
	Tail *tailReplyMsg `json:"tail,omitempty"`

	// Sessions answers "sessions" only (IAMT-345): the live sessions on
	// THIS machine, as the gateway named them. An empty list and a nil
	// one are different answers: empty means the gateway said nobody is
	// here, nil means the question never got an answer, and the Message
	// then says whose fault that was.
	Sessions []proto.MineSession `json:"sessions,omitempty"`

	// SshdRunning answers "status" only (IAMT-358): whether the local
	// sshd is running and listening, asked by the SERVER PROCESS, which
	// is the only party in a position to know. Until 19.09.2026 the
	// window never learned it at all -- ui.ServerState.SshdRunning was
	// filled by nothing, so every window printed "sshd service: not
	// running -- the door cannot open" and a paragraph of advice about
	// starting it, on a machine whose sshd was Running/Automatic. A
	// confident false claim about whether the machine can be entered.
	SshdRunning bool `json:"sshdRunning"`

	// Connected and DoorOpen answer "status" only (IAMT-182): Connected
	// is true exactly while this instance's tunnel to the gateway is up
	// (server.Config.StatusSink reports a live *server.Machine — distinct
	// from Running, which is true the instant the control listener
	// itself is up, before the very first dial); DoorOpen is that live
	// Machine's own DoorOpen(), always false while Connected is false.
	// Neither field is ever set on "stop"'s reply — this is the live
	// window's read-only status question, not a lever over the door.
	Connected bool `json:"connected,omitempty"`
	DoorOpen  bool `json:"doorOpen,omitempty"`
}

// sendControl talks to whatever "server start" instance control.json
// names, if any. contacted is true only when a live process answered;
// everything else (no file, garbled file, nothing listening) reports
// contacted=false with a nil error — those are "not running", not
// failures — and cleans up a stale file so the next check does not pay
// the same dial timeout again.
func sendControl(dir, cmd string) (reply controlReplyMsg, contacted bool, err error) {
	reply, contacted, err = controlRoundTrip(dir, controlRequestMsg{Cmd: cmd}, 3*time.Second)
	if err != nil || !contacted {
		return reply, contacted, err
	}
	// A reply the running server itself marked not-ok is this side's
	// failure to report (a bad token, an unknown command), which is why
	// it comes back as an error here. A "tail" is different on purpose:
	// there the running server is answering with the GATEWAY's verdict,
	// and the caller must be able to read that verdict rather than
	// receive it as a transport failure — see sendControlTail.
	if !reply.OK {
		return reply, true, fmt.Errorf("%s", reply.Message)
	}
	return reply, true, nil
}

// controlRoundTrip is the whole of "read control.json, dial it, ask one
// request, read one reply", shared by every command of this socket. It
// deliberately turns "not running" into contacted=false with a nil
// error — no file, a garbled file, nothing listening, a reply that never
// arrives — because those are states of the world, not failures, and it
// cleans up a stale file so the next check does not pay the same dial
// timeout again.
//
// budget is the caller's own wire deadline. It is a parameter rather
// than one number for everyone because the commands differ in how long
// their answers legitimately take: "status"/"stop" are answered from
// memory, while a "tail" is answered by the gateway over the tunnel and
// may take seconds. The rule every caller follows is that this deadline
// must outlive the handler's own budget on the other end, so the reply
// is never cut off by a client that gave up first.
func controlRoundTrip(dir string, req controlRequestMsg, budget time.Duration) (reply controlReplyMsg, contacted bool, err error) {
	path := controlFilePath(dir)
	data, rerr := state.ReadDataFile(path)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return controlReplyMsg{}, false, nil
		}
		return controlReplyMsg{}, false, classifyPathErr(rerr, path)
	}
	var rec controlFileRecord
	if jerr := json.Unmarshal(data, &rec); jerr != nil || rec.Port == 0 {
		_ = os.Remove(path)
		return controlReplyMsg{}, false, nil
	}
	conn, derr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", rec.Port), 500*time.Millisecond)
	if derr != nil {
		_ = os.Remove(path)
		return controlReplyMsg{}, false, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(budget))
	req.Token = rec.Token
	if eerr := json.NewEncoder(conn).Encode(req); eerr != nil {
		return controlReplyMsg{}, false, fmt.Errorf("writing to the running server: %w", eerr)
	}
	if derr := json.NewDecoder(conn).Decode(&reply); derr != nil {
		_ = os.Remove(path)
		return controlReplyMsg{}, false, nil
	}
	return reply, true, nil
}

// sendControlTail is the client half of the socket's "tail" command
// (IAMT-340) — the call the owner's window makes to see what is happening
// on this machine right now.
//
// Its contract with the caller is the one thing that must not blur: a
// non-nil error means THE ANSWER IS NOT THE GATEWAY'S (this server is
// not running, the tunnel is down, the gateway did not answer in time).
// The gateway's own verdict, refusal included, always arrives as a
// returned reply, with Tail set — OK true and Tail.Result carrying §1's
// body, or OK false and Tail.Refusal carrying the gateway's code and
// message. So a caller can tell "the gateway said no" from "the machine
// never got to ask" without parsing prose, and neither statement is ever
// dressed up as the other.
func sendControlTail(dir string, req server.TailRequest) (reply controlReplyMsg, contacted bool, err error) {
	// server.TailTimeout is the running server's own budget for the
	// relay, and handleControlConn's own deadline on that same request
	// is the socket's. This one is larger than both: whoever gives up
	// last is the client, so an answer that was written is an answer
	// that was read.
	return controlRoundTrip(dir, controlRequestMsg{
		Cmd:    "tail",
		ID:     req.SessionID,
		Offset: req.Offset,
		Limit:  req.Limit,
	}, server.TailTimeout+2*time.Second)
}

// doorStatusFunc reports this instance's live door state for a "status"
// reply (IAMT-182): connected is whether the tunnel to the gateway is up
// right now, doorOpen is that connection's own door line — always false
// when connected is false. cmdServerStart supplies the real one, backed
// by the *server.Machine server.Config.StatusSink hands over; a fake in
// a test can report anything without a network or a window.
type doorStatusFunc func() (connected, doorOpen bool)

// tailFunc carries one "tail" from the local control socket to the live
// tunnel (IAMT-340) — the machine's own answer to its owner's window. It
// is a seam for the same reason doorStatusFunc is one: the real value
// reaches the running *server.Machine through server.Config.StatusSink,
// which no test wants to build, and a fake can then prove what the
// socket does with an answer without a gateway, a tunnel or a session.
//
// Its error means only "this machine could not ask" (no tunnel yet, the
// control channel is down, the gateway went quiet). A refusal by the
// gateway is not an error — it comes back inside the answer.
type tailFunc func(ctx context.Context, req server.TailRequest) (server.TailAnswer, error)

// mineFunc carries "which sessions are on me" from the local control
// socket to the live tunnel, the same way tailFunc carries a tail. It is
// separate rather than folded into tailFunc because the two questions
// have nothing in common but their route: one names a session, the other
// asks what the sessions are called.
type mineFunc func(ctx context.Context) ([]proto.MineSession, error)

// handleControlConn answers exactly one request per connection. "stop"
// removes control.json and replies before calling onStop, so a "server
// status" issued right after a successful "server stop" is guaranteed to
// see "not running" — there is no window where the file still exists
// after the caller has already been told the stop succeeded.
func handleControlConn(conn net.Conn, dir, token string, onStop func(), status doorStatusFunc, tail tailFunc, mine mineFunc, sshd sshdProbeFunc) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var req controlRequestMsg
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	if req.Token != token {
		_ = json.NewEncoder(conn).Encode(controlReplyMsg{OK: false, Message: "bad control token"})
		return
	}
	switch req.Cmd {
	case "status":
		connected, doorOpen := false, false
		if status != nil {
			connected, doorOpen = status()
		}
		_ = json.NewEncoder(conn).Encode(controlReplyMsg{
			OK: true, Running: true, PID: os.Getpid(),
			Connected: connected, DoorOpen: doorOpen,
			SshdRunning: sshd != nil && sshd(),
		})
	case "stop":
		_ = os.Remove(controlFilePath(dir))
		_ = json.NewEncoder(conn).Encode(controlReplyMsg{OK: true, Running: false, PID: os.Getpid()})
		onStop()
	case "tail":
		_ = json.NewEncoder(conn).Encode(handleTailCommand(req, tail))
	case "sessions":
		_ = json.NewEncoder(conn).Encode(handleSessionsCommand(mine))
	default:
		_ = json.NewEncoder(conn).Encode(controlReplyMsg{OK: false, Message: "unknown control command " + req.Cmd})
	}
}

// handleSessionsCommand asks the tunnel which sessions are live on this
// machine and hands the answer back (IAMT-345). Same two pieces of
// judgement as handleTailCommand, and for the same reason: a failure on
// this side is reported in this server's own voice, and the gateway's
// list is passed on as the gateway built it.
func handleSessionsCommand(mine mineFunc) controlReplyMsg {
	fail := func(message string) controlReplyMsg {
		return controlReplyMsg{OK: false, Running: true, PID: os.Getpid(), Message: message}
	}
	if mine == nil {
		return fail("this server cannot ask the gateway for its sessions")
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer cancel()
	sessions, err := mine(ctx)
	if err != nil {
		return fail("this machine's server could not get its session list from the gateway: " + err.Error())
	}
	// A machine with no guests answers with an empty list, and that is a
	// real answer: the window must be able to tell "nobody is working
	// here" from "nobody could be asked".
	if sessions == nil {
		sessions = []proto.MineSession{}
	}
	return controlReplyMsg{OK: true, Running: true, PID: os.Getpid(), Sessions: sessions}
}

// handleTailCommand is the running server's whole part in "watch this
// machine" (IAMT-340): hand the question to the tunnel and hand the
// tunnel's answer back, with nothing added in between.
//
// It is a pure translation of directions and nothing else — no filtering
// of the data, no deciding who may look at what (the gateway decides
// that from the identity of the control channel the question arrives on,
// never from a field in a body), no remembering of previous answers. Its
// only two pieces of judgement are both about honesty:
//
//   - a machine-side failure (tail==nil, no live tunnel, no answer in
//     time, the gateway's answer unreadable) is reported as this
//     server's own failure, in the reply's Message, with no Tail object
//     at all. It never borrows the gateway's voice to say "no";
//   - the gateway's verdict, success or refusal, is copied into Tail
//     as it arrived, so the window reads the gateway's bytes rather than
//     this program's retelling of them.
func handleTailCommand(req controlRequestMsg, tail tailFunc) controlReplyMsg {
	fail := func(message string) controlReplyMsg {
		return controlReplyMsg{OK: false, Running: true, PID: os.Getpid(), Message: message}
	}
	if tail == nil {
		return fail("this server cannot relay tail requests")
	}
	// server.Tail already bounds the relay on its own (server.TailTimeout),
	// and that bound is the one that decides. This context adds the
	// cancellation path a caller owns: it is cut to this connection's own
	// 5-second wire deadline (handleControlConn), so the relay stops
	// rather than working on an answer nobody is left to read.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer cancel()
	answer, err := tail(ctx, server.TailRequest{SessionID: req.ID, Offset: req.Offset, Limit: req.Limit})
	if err != nil {
		// The machine could not ask, or could not read what came back.
		// Say so in this server's own words: nothing here claims what
		// the gateway would have answered.
		return fail("this machine's server could not get an answer from the gateway: " + err.Error())
	}
	out := controlReplyMsg{OK: true, Running: true, PID: os.Getpid()}
	switch {
	case answer.Refusal != nil:
		out.OK = false
		out.Message = answer.Refusal.Message
		out.Tail = &tailReplyMsg{Refusal: answer.Refusal}
	case len(answer.Result) > 0:
		out.Tail = &tailReplyMsg{Result: answer.Result}
	default:
		// Neither a body nor a refusal: a shape server.Tail does not
		// produce. Refusing to guess which one it meant is the same
		// posture as everywhere else on this path.
		return fail("this machine's server got no usable answer from the gateway")
	}
	return out
}

// sshdProbeFunc is the seam through which the status reply learns
// whether sshd is up. A seam and not a direct call: the probe reaches the
// real Windows service manager, and this tree forbids a test binary from
// touching it (run_windows.go panics on sight). Production passes
// localSSHDRunning; a nil probe answers "not known to be running", which
// is what every test gets and what the field meant before it existed.
type sshdProbeFunc func() bool

// localSSHDRunning answers "can this machine be entered at all" for the
// status reply (IAMT-358). It is the same probe "server start" runs
// before it connects -- service state plus a dial of the listening port
// -- so the window and the pre-flight cannot disagree.
//
// A probe, not a cached flag: sshd can be stopped by hand at any moment,
// and a window that kept saying "running" because it was true once is
// the same class of lie as the one this replaces.
func localSSHDRunning() bool {
	return server.CheckSSHD(net.JoinHostPort("127.0.0.1", "22"), nil) == nil
}

func serveControl(ln net.Listener, dir, token string, onStop func(), status doorStatusFunc, tail tailFunc, mine mineFunc, sshd sshdProbeFunc) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleControlConn(conn, dir, token, onStop, status, tail, mine, sshd)
	}
}

// adminKeysFileName is the file Windows OpenSSH reads administrators'
// keys from, in %ProgramData%\ssh (the "Match Group administrators"
// block of the stock sshd_config).
const adminKeysFileName = "administrators_authorized_keys"

// userLookupFn is the seam serverKeyFile reaches for on Linux and
// Darwin: a fixed observation in tests (so a test binary never
// touches /etc/passwd / NSS / LDAP), os/user.Lookup in production.
// Tests install their own via init() in iamt248_*_test.go.
var userLookupFn = func(name string) (*user.User, error) {
	return user.Lookup(name)
}

// verifyOSUserFn is the seam enrol reaches for on Linux and
// Darwin: a fixed observation in tests, elevate.VerifyOSUser in
// production (which routes through userLookupFn on unix so the
// user-database seam covers both call sites).
var verifyOSUserFn = func(name string) error {
	return elevate.VerifyOSUser(name)
}

// serverKeyFile is the one place the door's key file path comes from
// (SPEC §3.2, §3.2.1, §6.3 layer 0; IAMT-156, IAMT-248). An explicit
// --key-file wins. Otherwise:
//
//   - Windows: %ProgramData%\ssh\administrators_authorized_keys,
//     computed from env (the CLI's streams.env, never os.Getenv, so
//     tests can substitute).
//   - Linux/Darwin (IAMT-248): the file sshd really reads for the
//     gateway-bound OS user, namely <osUser-home>/.ssh/authorized_keys.
//     The OS user comes from enrolment.json (the gateway bound the
//     user at enrol-code time; iamtunnel does not invent it). The
//     home directory is resolved through the userLookupFn seam
//     (default os/user.Lookup) so a test binary never touches
//     /etc/passwd.
//
// On Windows the env-supplied ProgramData must be absolute (see
// config.WindowsProgramData); on Linux the env supplies osUser
// instead — there is no ProgramData, only an osUser.
func serverKeyFile(goos string, env map[string]string, osUser string, flag string) (string, error) {
	const path = "server start"
	if flag != "" {
		if !filepath.IsAbs(flag) {
			return "", userErrf("iamtunnel %s: --key-file %q must be an absolute path (the authorized_keys file sshd reads administrators' keys from).", path, flag)
		}
		return flag, nil
	}
	if goos == "windows" {
		programData, err := config.WindowsProgramData(env)
		if err != nil {
			return "", envErrf("iamtunnel %s: cannot locate the OpenSSH administrators key file: %v — fix the environment or pass --key-file <path>.", path, err)
		}
		return filepath.Join(programData, "ssh", adminKeysFileName), nil
	}
	if goos == "linux" || goos == "darwin" {
		if osUser == "" {
			return "", envErrf("iamtunnel %s: cannot resolve the default door key file on %s without an osUser — pass --key-file <path>.", path, goos)
		}
		if strings.Contains(osUser, `\`) {
			return "", userErrf("iamtunnel %s: the gateway-bound OS user %q contains a backslash — Linux/Darwin use a bare username with no DOMAIN\\ prefix.", path, osUser)
		}
		u, err := userLookupFn(osUser)
		if err != nil || u == nil {
			return "", envErrf("iamtunnel %s: OS user %q does not exist on this machine — run \"iamtunnel enrol\" again or pick a different user with \"iamtunnel admin machines set-user\".", path, osUser)
		}
		home := u.HomeDir
		if home == "" {
			return "", envErrf("iamtunnel %s: OS user %q has no home directory recorded in the user database.", path, osUser)
		}
		if !filepath.IsAbs(home) {
			return "", envErrf("iamtunnel %s: OS user %q home directory %q is not absolute.", path, osUser, home)
		}
		return filepath.Join(home, ".ssh", "authorized_keys"), nil
	}
	return "", envErrf("iamtunnel %s: there is no default door key file on %s — pass --key-file <path> naming the authorized_keys file sshd reads.", path, goos)
}

// serverStartParams are the "server start" inputs already resolved from
// the flags and the role directory. record, when set, is the enrolment
// record the anchor check already vetted (R4 F-04): the config is built
// from that very value, not from a second read of the profile directory.
// Nil means "load it yourself", which is what every caller but
// cmdServerStart wants.
type serverStartParams struct {
	dataDir     string
	keyFileFlag string
	exe         string
	idleMinutes int
	maxHours    int
	record      *gatewayRecord
}

// serverStartConfig assembles the server.Config "server start" runs
// with: the enrolment record and machine key from the data directory,
// the door's key file from serverKeyFile. It only reads — the first write
// to the key file happens inside server.Run — so a test can build the
// production config from a substitute environment and inspect it.
//
// On Linux/Darwin (IAMT-248) the enrolment record also carries the
// gateway-bound OS user; serverStartConfig threads it into
// serverKeyFile (which resolves the user's home directory under
// the userLookupFn seam) and into server.Config{DoorLockPath,
// OwnerUID, OwnerGID} so the winkeys door layer's openat-based
// write knows where to create the lock file and who should own
// the new line.
func serverStartConfig(goos string, env map[string]string, p serverStartParams) (server.Config, error) {
	const path = "server start"
	rec, err := gatewayRecordForStart(p)
	if err != nil {
		if os.IsNotExist(err) {
			return server.Config{}, envErrf(`iamtunnel %s: this machine is not registered — run "iamtunnel enrol <code>" first.`, path)
		}
		return server.Config{}, err
	}
	dirs := config.Dirs{Server: p.dataDir}
	signer, err := loadSignerStrict(dirs.MachineKey())
	if err != nil {
		if os.IsNotExist(err) {
			return server.Config{}, envErrf(`iamtunnel %s: this machine is not registered — run "iamtunnel enrol <code>" first.`, path)
		}
		return server.Config{}, err
	}
	scfg := server.Config{
		GatewayAddr:        fmt.Sprintf("%s:%d", rec.Host, rec.Port),
		GatewayFingerprint: rec.Fingerprint,
		MachineID:          rec.MachineID,
		MachineKey:         signer,
		TargetAddr:         "127.0.0.1:22",
		DoorwatchExe:       p.exe,
		WatchdogJournal:    dirs.ServerEvents(),
		MaxDoorIdle:        time.Duration(p.idleMinutes) * time.Minute,
		MaxDoorHard:        time.Duration(p.maxHours) * time.Hour,
		Logger:             func(string) {},
	}
	// The key file is never derived from the data directory: sshd does
	// not read anything there (IAMT-156). On Linux/Darwin the gateway
	// bound an OS user at enrol-time; we resolve the home through the
	// userLookupFn seam (default os/user.Lookup, testable via init()).
	if scfg.KeyFile, err = serverKeyFile(goos, env, rec.OSUser, p.keyFileFlag); err != nil {
		return server.Config{}, err
	}
	// Linux/Darwin: thread the lock-file path, the file's owner,
	// and the OS-user binding through to the winkeys door so its
	// openat-based write knows where to put the lock (server data
	// dir, never the user's home), who should own the new line,
	// and which OS-user the sshd -T pre-flight must name.
	if goos == "linux" || goos == "darwin" {
		scfg.DoorLockPath = filepath.Join(p.dataDir, "door.lock")
		scfg.OSUser = rec.OSUser
		if u, lerr := lookupOwner(rec.OSUser); lerr == nil && u != nil {
			if uid, perr := strconv.Atoi(u.Uid); perr == nil {
				scfg.OwnerUID = uid
			}
			if gid, perr := strconv.Atoi(u.Gid); perr == nil {
				scfg.OwnerGID = gid
			}
		}
	}
	return scfg, nil
}

// gatewayRecordForStart is serverStartConfig's enrolment record: the one
// the caller vetted when it is there, a fresh read otherwise.
func gatewayRecordForStart(p serverStartParams) (gatewayRecord, error) {
	if p.record != nil {
		return *p.record, nil
	}
	return loadGatewayRecord(p.dataDir)
}

// lookupOwner is the small wrapper around userLookupFn that
// returns (nil, nil) for an unresolvable name rather than an
// error: serverStartConfig treats "no uid resolved" as "leave
// OwnerUID/GID zero so the door layer refuses", not as a fatal
// startup error — the door's own check surfaces the actionable
// refusal at the first Install. A nil error here is
// deliberate, not a missed check.
func lookupOwner(name string) (*user.User, error) {
	if name == "" {
		return nil, nil
	}
	return userLookupFn(name)
}

// requireServerElevation refuses before a server command reads enrolment or
// opens its control listener: both server start and its doorwatch child can
// write the protected OpenSSH administrators key file (Windows) or the
// user's ~/.ssh/authorized_keys (Linux). The production stream owns the
// real check; tests inject a result through streams.isElevated and therefore
// never invoke UAC / runas / sudo or require administrator rights.
//
// On Windows the failure mode is "this console is not elevated — re-run
// with Run as administrator". On Linux the failure mode is "this process
// does not have euid 0 — re-run with sudo". The two failure texts are
// kept distinct on purpose: the fix is a different command, and a copy
// of the Linux text on a Windows machine (or vice versa) would mislead
// the operator.
func requireServerElevation(s *streams, path string) error {
	check := s.isElevated
	if check == nil {
		check = elevate.IsElevated
	}
	elevated, err := check()
	if err != nil {
		if runtime.GOOS == "windows" {
			return deniedErrf("iamtunnel %s: cannot verify administrator privileges: %v — close this console and run it using \"Run as administrator\".", path, err)
		}
		return deniedErrf("iamtunnel %s: cannot verify root privileges: %v — invoke this command again with sudo.", path, err)
	}
	if !elevated {
		if runtime.GOOS == "windows" {
			return deniedErrf("iamtunnel %s: administrator privileges are required — close this console and run it using \"Run as administrator\".", path)
		}
		return deniedErrf("iamtunnel %s: root privileges are required — run it with sudo: sudo iamtunnel %s", path, path)
	}
	return nil
}

// macPermissionHint is the macOS advisory both `enrol` and `server start`
// print before they touch the OS (IAMT-264, SPEC §3.2.1's macOS half of
// the platform layer). macOS is the one platform where the daemon the
// pre-flight needs and the folder the door writes into are both behind
// operator-granted permissions, and neither failure looks like a
// permission problem from the inside: a switched-off daemon gives a
// connection refused, and a TCC refusal gives an EPERM that reads like an
// ordinary file error. Saying it up front, in the command whose job is to
// be refused if either is missing, is cheaper than decoding the failure.
//
// The two grants are exactly the two that can be needed:
//
//   - Remote Login (System Settings → General → Sharing → Remote Login;
//     `sudo systemsetup -setremotelogin on`) is the launchd job
//     com.openssh.sshd the pre-flight asks for (internal/server/run_darwin.go).
//   - Full Disk Access (System Settings → Privacy & Security → Full Disk
//     Access) is only needed when the door's key file lives in a
//     TCC-protected place — Desktop, Documents, Downloads, iCloud Drive,
//     in whichever home the OS user has. ~/.ssh itself is not protected,
//     so a plain setup needs no FDA; a key file pointed there with
//     --key-file is what makes the grant necessary. The grant must cover
//     THIS binary: the watchdog is a re-exec of the same path
//     (winkeys.SpawnWatchdog), so one grant covers the server and its
//     doorwatch child.
const macPermissionHint = `macOS: two permissions are yours to grant, and neither failure names itself:
  - Remote Login must be on — System Settings → General → Sharing → Remote Login (or "sudo systemsetup -setremotelogin on") — so sshd answers on 127.0.0.1:22.
  - If the door's key file sits in a protected folder (Desktop, Documents, Downloads, iCloud Drive), grant this binary Full Disk Access — System Settings → Privacy & Security → Full Disk Access — so the server and its doorwatch child may write it.`

// permissionHint returns the advisory to print before a machine command
// runs, or "" when this platform needs no such warning. It takes the GOOS
// as an argument rather than reading runtime.GOOS so the text and its
// gating are testable from any host — the darwin branches of this package
// cannot run in this repo's Linux CI, and a hint nobody can test is a
// hint nobody can keep true.
func permissionHint(goos string) string {
	if goos != "darwin" {
		return ""
	}
	return macPermissionHint
}

func cmdServerStart(s *streams, args []string) int {
	const path = "server start"
	fs := newFlagSet(path, "[--idle-minutes N] [--max-hours N] [--key-file <path>]")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	fs.valFlag("idle-minutes")
	fs.valFlag("max-hours")
	fs.valFlag("key-file")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	idleMinutes := 15
	if v := fs.val("idle-minutes"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10080 {
			return fail(s, userErrf("iamtunnel %s: --idle-minutes %q must be a whole number from 1 to 10080 (minutes with no tunnel traffic before the door closes).", path, v))
		}
		idleMinutes = n
	}
	maxHours := 8
	if v := fs.val("max-hours"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 720 {
			return fail(s, userErrf("iamtunnel %s: --max-hours %q must be a whole number from 1 to 720 (hours before the door closes regardless of traffic).", path, v))
		}
		maxHours = n
	}
	// IAMT-264: on macOS say up front what the operator may still have to
	// grant — the pre-flight and the door write are both behind
	// operator-granted permissions there, and neither refusal names them.
	// Printed before any I/O, so it is on screen (and in the LaunchDaemon
	// log) even when the start is refused a moment later.
	//
	// IAMT-297: "refused a moment later" is exactly what the root-gate below
	// does, so the hint now goes in front of it — otherwise the one refusal
	// an ordinary Mac account meets first (uid 501, no sudo) answered before
	// the hint and the sentence above was a promise the code did not keep.
	// The gate is not weakened: the hint is a constant string, only a stdout
	// write moved above it, and all real I/O still follows.
	if hint := permissionHint(runtime.GOOS); hint != "" {
		fmt.Fprintln(s.out, hint)
	}
	if err := requireServerElevation(s, path); err != nil {
		return fail(s, err)
	}
	_, dir, lerr := loadConfig(s, "server", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")})
	if lerr != nil {
		return fail(s, lerr)
	}

	// IAMT-213: before anything is read from or written into the
	// machine data directory, it and everything already inside it are
	// brought to the protected {SYSTEM, Administrators} DACL (no-op on
	// non-Windows) — a directory an older binary created with
	// inherited Users-read rights is healed here, without manual
	// steps. The command is already elevation-gated above, so the
	// lockdown cannot fail for lack of rights on a healthy machine; a
	// failure refuses the start rather than running with readable
	// machine material. The error arrives already classified
	// (denied + the "Run as administrator" hint on a permission
	// failure); %w keeps that class for fail().
	if err := hardenServerDir(dir, false); err != nil {
		return fail(s, fmt.Errorf("iamtunnel %s: could not lock down the machine data directory: %w", path, err))
	}

	// R4 F-04: the record this elevated start is about to act on is
	// checked against the enrolment anchor first, and the checked value
	// itself is what the config is built from. The profile directory the
	// record lives in can be moved aside and replaced by this account's
	// own unelevated processes; the anchor is where they cannot. On
	// non-Windows this is the plain record read.
	rec, verr := verifiedServerRecord(s.env, dir)
	if verr != nil {
		return fail(s, verr)
	}

	exe, eerr := os.Executable()
	if eerr != nil {
		return fail(s, envErrf("iamtunnel %s: could not resolve this program's own executable path: %v", path, eerr))
	}
	scfg, cerr := serverStartConfig(runtime.GOOS, s.env, serverStartParams{
		dataDir:     dir,
		keyFileFlag: fs.val("key-file"),
		exe:         exe,
		idleMinutes: idleMinutes,
		maxHours:    maxHours,
		record:      &rec,
	})
	if cerr != nil {
		return fail(s, cerr)
	}

	// IAMT-307: the server's own door open/close/sweep (SPEC §6.3 layers 0
	// and 2 — the server writes the key line and removes it on Stop/
	// door.close/keepalive loss) must land in the SAME machine-local
	// journal the watchdog's layer-3 cleanup already writes to
	// (scfg.WatchdogJournal, threaded to the doorwatch child a few lines
	// below via SpawnWatchdog) — RUNBOOK §1.7/§6 and THREATS both document
	// {"Op":"open"|"close"|"sweep",...} in this file as the machine's
	// complete local audit trail, not a watchdog-only one ("on the machine —
	// Op:"close"" for a plain Stop, RUNBOOK's own words). Before this fix
	// scfg.Sink was never set, so winkeys.NewDoorWithOptions fell back to
	// its noopSink and every server-driven open/close/sweep vanished — a
	// live run's journal held only the two lines a kill -9 produced.
	// winkeys.NewJournalSink opens O_APPEND specifically so this sink and
	// the watchdog's own (opened separately, in the child process) can
	// write the same file concurrently without tearing a record in half;
	// both processes run as root (the watchdog does not drop privileges -
	// see doorwatch_unix.go), so there is no ownership mismatch to
	// reconcile. It also rotates the file once it grows past
	// DefaultJournalMaxBytes and prunes old archives on its own (IAMT-307:
	// this journal has no other retention, and a machine that reconnects
	// for years never stops appending to it). OnError prints to this
	// process's own stderr rather than dropping a failed write/rotation
	// silently - under the systemd unit RUNBOOK installs, stderr reaches
	// the service's journal, which is exactly where an operator already
	// looks for a misbehaving iamtunnel-machine service.
	// Role: RotatorRole (the default; stated explicitly here so the two
	// sinks on this same path read as a deliberate pair - see the
	// doorwatch call sites' AppenderRole wiring): the server is this
	// journal's one rotator (IAMT-307 round 10, F-307-10).
	sink, serr := winkeys.NewJournalSink(scfg.WatchdogJournal, winkeys.JournalOptions{
		OnError: func(err error) { fmt.Fprintf(s.errs, "iamtunnel %s: local audit journal: %v\n", path, err) },
		Role:    winkeys.RotatorRole,
	})
	if serr != nil {
		return fail(s, envErrf("iamtunnel %s: could not open the machine's local audit journal %s: %v", path, scfg.WatchdogJournal, serr))
	}
	scfg.Sink = sink
	// Every path out of this function - an early refusal below (sshd
	// unreachable, control listener busy, ...) as much as the normal
	// stop sequence - must release the file. On the normal path this
	// still runs safely after server.Run's goroutine has returned: the
	// last statement before this function's own return is <-runDone.
	if c, ok := sink.(interface{ Close() error }); ok {
		defer c.Close()
	}

	if _, contacted, _ := sendControl(dir, "status"); contacted {
		return fail(s, userErrf("iamtunnel %s: a server is already running for this machine (data dir %s) — stop it first.", path, dir))
	}

	checkSSHD := s.checkSSHD
	if checkSSHD == nil {
		checkSSHD = func(addr string) error {
			return server.CheckSSHD(addr, nil)
		}
	}

	// Pre-flight (IAMT-248 fix1): on Linux, always run CheckSSHD
	// (systemctl + dial) and CheckSSHDConfig(sshd -T -C user=<osUser>)
	// before opening the control listener or starting the tunnel.
	// Both are no-ops on Windows — sshd reads the well-known
	// ProgramData\ssh\administrators_authorized_keys unconditionally
	// so the runtime config probe is moot there. Tests inject
	// checkSSHD / checkSSHDConfig via the streams struct (see
	// iamt138_server_start_sshd_test.go for the wiring); the
	// production code never branches on runtime.GOOS to skip the
	// check — that was the IAMT-248 regression the report flagged.
	if err := checkSSHD(scfg.TargetAddr); err != nil {
		return fail(s, envErrf("iamtunnel %s: %v", path, err))
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		checkSSHDConfig := s.checkSSHDConfig
		if checkSSHDConfig == nil {
			checkSSHDConfig = func(osUser string) error {
				return server.CheckSSHDConfig(osUser, nil)
			}
		}
		// scfg.OSUser came from enrolment.json; on Windows it is
		// empty (no equivalent binding). On Linux/Darwin it is
		// the gateway-bound POSIX user.
		osUser := scfg.OSUser
		if osUser == "" {
			return fail(s, envErrf("iamtunnel %s: OS user is empty — was this machine enrolled? re-run \"iamtunnel enrol <code>\"", path))
		}
		if err := checkSSHDConfig(osUser); err != nil {
			return fail(s, envErrf("iamtunnel %s: sshd -T pre-flight: %v", path, err))
		}
	}

	ln, lnerr := net.Listen("tcp", "127.0.0.1:0")
	if lnerr != nil {
		return fail(s, envErrf("iamtunnel %s: could not open the local control listener: %v", path, lnerr))
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		_ = ln.Close()
		return fail(s, envErrf("iamtunnel %s: could not generate a control token: %v", path, err))
	}
	token := hex.EncodeToString(tokenBytes)
	port := ln.Addr().(*net.TCPAddr).Port
	if err := atomicWriteMachineJSON(controlFilePath(dir), controlFileRecord{PID: os.Getpid(), Port: port, Token: token}); err != nil {
		_ = ln.Close()
		return fail(s, err)
	}

	// currentMachine mirrors the live *server.Machine for as long as the
	// tunnel is up (IAMT-182): nil before the first connect and again the
	// instant it drops, non-nil in between — server.Run's own contract
	// for Config.StatusSink. This is the ONLY way "server status"/the
	// live window learn the door's real state without a second copy of
	// the connect loop.
	var currentMachine atomic.Pointer[server.Machine]
	scfg.StatusSink = currentMachine.Store

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- server.Run(ctx, scfg) }()

	var stopOnce sync.Once
	stopCh := make(chan struct{})
	triggerStop := func() { stopOnce.Do(func() { close(stopCh) }) }

	doorStatus := func() (connected, doorOpen bool) {
		m := currentMachine.Load()
		if m == nil {
			return false, false
		}
		return true, m.DoorOpen()
	}
	// tail is the same seam reached from the other side (IAMT-340): the
	// window's question about a live session goes to whatever Machine is
	// connected at this instant, exactly as the status question does.
	// currentMachine is nil both before the first connect and again the
	// moment the tunnel drops, and that nil is answered honestly rather
	// than waited out — there is no channel to ask over, which is a fact
	// about this machine and not a verdict about the session.
	tail := func(ctx context.Context, req server.TailRequest) (server.TailAnswer, error) {
		m := currentMachine.Load()
		if m == nil {
			return server.TailAnswer{}, server.ErrNoControlChannel
		}
		return m.Tail(ctx, req)
	}
	// mine is the question that has to be answered before tail can be
	// asked at all (IAMT-345): the window learns from the gateway what
	// the sessions on this machine are called, because the machine
	// itself never sees an id go by.
	mine := func(ctx context.Context) ([]proto.MineSession, error) {
		m := currentMachine.Load()
		if m == nil {
			return nil, server.ErrNoControlChannel
		}
		return m.MineSessions(ctx)
	}
	go serveControl(ln, dir, token, triggerStop, doorStatus, tail, mine, localSSHDRunning)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			triggerStop()
		case <-stopCh:
		}
	}()

	<-stopCh
	signal.Stop(sigCh)
	cancel()
	_ = ln.Close()
	_ = os.Remove(controlFilePath(dir))
	<-runDone
	fmt.Fprintf(s.out, "iamtunnel %s: stopped.\n", path)
	return exitOK
}

func cmdServerStopStatus(s *streams, path string, args []string) int {
	fs := newFlagSet(path, "")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	// Root-gate (IAMT-248 fix1). server stop signals the running
	// process to close; a non-elevated caller must not be able to
	// stop a privileged server. server status reads the
	// control.json — a non-elevated caller must not be able to
	// inspect the privileged server's state either, even
	// read-only. Both paths are gated identically; status-only
	// exemptions are not in scope here (SPEC §3.2.1 names
	// "enrol, server start|stop|install|uninstall" — status is
	// not in the list, but review called it out too; we gate it
	// anyway because it touches the server data dir).
	if err := requireServerElevation(s, path); err != nil {
		return fail(s, err)
	}
	_, dir, lerr := loadConfig(s, "server", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")})
	if lerr != nil {
		return fail(s, lerr)
	}

	cmd := "status"
	if path == "server stop" {
		cmd = "stop"
	}
	reply, contacted, cerr := sendControl(dir, cmd)
	if cerr != nil {
		return fail(s, envErrf("iamtunnel %s: %v", path, cerr))
	}
	if !contacted {
		fmt.Fprintf(s.out, "iamtunnel %s: the server is not running.\n", path)
		return exitOK
	}
	if cmd == "stop" {
		fmt.Fprintf(s.out, "iamtunnel %s: the server (pid %d) was stopped.\n", path, reply.PID)
		return exitOK
	}
	fmt.Fprintf(s.out, "iamtunnel %s: the server is running (pid %d).\n", path, reply.PID)
	return exitOK
}

// --- systemd half of install/uninstall (IAMT-249, SPEC §3.2.1) -------------
//
// §3.2.1: "server install writes /etc/systemd/system/iamtunnel-machine.service
// (User=root, Restart=on-failure, KillMode=mixed ...), daemon-reload,
// enable --now; server uninstall is the reverse. The manual server start
// remains."
// The OS is reached exactly as the gateway's half reaches it (IAMT-177): one
// seam (systemdSetup, gateway.go) whose production value is linuxSystemd and
// whose test value is a recorder, so no test binary ever writes to /etc or
// talks to systemd. The three systemctl steps and the uninstall sequence are
// shared with the gateway role (systemdInstallTail / systemdUninstallTail) —
// only the unit and the words differ.

const (
	// machineUnitName is the unit SPEC §3.2.1 names; RUNBOOK §1.7 uses the
	// same name for the by-hand install.
	machineUnitName = "iamtunnel-machine.service"

	// systemServerDir is the machine-wide server directory the Unix ROOT
	// service uses, and the only place it is named since 1.4.
	//
	// The interactive default moved under the person's own profile that
	// release (internal/config/paths.go), because a registration belongs
	// to one person on one machine and two people on one machine are two
	// registrations. A root service has no person, so it cannot use that
	// default: install would otherwise write a unit that runs as root
	// against whichever user happened to type the command, which is
	// neither of the two things anybody meant.
	//
	// This is where the two platforms genuinely part, and it is not a
	// stopgap — it is what each one is for.
	//
	// On Windows, autostart is per person: `server install` registers a
	// logon task per registration (server_task.go), triggered by that
	// account's sign-in and running as that account against that
	// account's own directory. Several people share one box over Remote
	// Desktop, each signs in, each server starts, each audit line names
	// its own registration. There is no Windows machine service and
	// there should not be: a service has no person, and every line it
	// wrote would be attributed to the service.
	//
	// On Unix the machine role is the opposite shape. A Linux target is
	// normally headless — nobody signs in at all, so a per-session
	// autostart would never fire — and the role wants root anyway: it
	// writes the door line into the bound account's ~/.ssh and the
	// sshd pre-flight is a system probe. So the Unix install stays one
	// impersonal system unit, under one machine-wide directory named
	// here, carrying the machine's single registration. A Unix host that
	// should carry two registrations needs a per-user autostart of its
	// own (systemd --user, LaunchAgent) and an unprivileged `server
	// start` to go with it; neither exists yet, and the limit is stated
	// in SPEC §3.2.1 rather than hidden behind a path constant.
	systemServerDir = "/var/lib/iamtunnel-machine"
)

// machineUnitFile renders the machine's systemd unit (SPEC §3.2.1). A pure
// function on purpose, like gatewayUnitFile: a test asserts the directives
// without running anything, and an operator can diff it against the example
// in RUNBOOK.md §1.7 — the text below IS that example, parameterised by the
// binary path and the machine data directory.
//
// The three directives §3.2.1 names verbatim are here exactly as named:
//
//   - User=root — the machine role writes into another user's home (the door
//     line in <osUser>/.ssh/authorized_keys) and binds 127.0.0.1:22's side of
//     the nested handshake; it is not an unprivileged service.
//   - Restart=on-failure — `server stop` (and systemd's own SIGTERM) is a
//     CLEAN exit and must NOT be undone by a restart, or the machine would
//     race its own operator; a crash or a panic must be undone.
//   - KillMode=mixed — SIGTERM reaches only the server, which removes its own
//     door line and stops the watchdog, and SIGKILL goes to the whole cgroup
//     only after systemd's stop timeout. Sending SIGTERM to the whole group
//     at once would kill the one process whose job is to remove the line
//     after the server is gone (SPEC §6.3), and SIGKILL-only would leave the
//     line behind on every stop.
//
// The hardening block carries over the gateway's (SPEC §3.5) minus exactly
// one directive, ProtectHome:
//
//   - ProtectHome=yes cannot be used here. The door line lives in
//     <osUser-home>/.ssh/authorized_keys (§3.2.1); ProtectHome=yes makes
//     /home and /root inaccessible, so the door could never open — the unit
//     would start and then fail its only job.
//   - ProtectHome=read-only + ReadWritePaths=<home> would fix that, but it
//     would freeze ONE home path into the unit forever. osUser is not a
//     constant: enrolment binds it and `admin machines set-user` rebinds it
//     (§3.3, §3.4). After a rebind the old home would still be writable and
//     the new one read-only — a silent breakage of the product's only job,
//     which is exactly the class of defect IAMT-248 had to undo. The unit
//     therefore names no home at all.
//
// ProtectSystem=full rather than strict: strict mounts the entire hierarchy
// read-only (except /dev, /proc, /sys), which takes /run with it — and
// `server start` runs the §3.2.1 sshd pre-flight, whose service probe is
// `systemctl is-active`, which needs the systemd D-Bus socket under /run.
// Under strict that pre-flight would fail on exactly the hosts the unit
// exists for, and re-opening /run and the target home via ReadWritePaths
// would hand back most of what strict took away. full keeps /usr, /boot and
// /etc read-only — the trees a compromised machine role must not rewrite —
// while /var/lib (the machine data directory, §3.2.1) and the door's target
// stay writable without any per-host carve-out.
//
// NoNewPrivileges=yes, PrivateTmp=yes, AmbientCapabilities= (empty: for a
// root unit there is no capability to keep, the line is carried over so the
// two unit files stay diff-comparable) and LimitNOFILE=65536 come over
// unchanged from the gateway unit.
//
// After= names the three unit names §3.2.1's pre-flight accepts — ssh.service,
// sshd.service, ssh.socket — as ORDERING only, with no Wants/Requires: a host
// that runs sshd some other way is not dragged into a failed dependency, a
// name that does not exist is ignored, and a host that starts both gets the
// socket listening before `server start` dials it. Without that ordering a
// machine that boots faster than its sshd refuses the start, and with
// Restart=on-failure plus systemd's start rate limit it would land in
// "failed" instead of coming up on its own. time-sync is ordered for the same
// reason as on the gateway: the machine's own audit lines must not be stamped
// with a clock that has not been set yet.
func machineUnitFile(binPath, dataDir string) string {
	return fmt.Sprintf(`[Unit]
Description=iamtunnel machine server (door and tunnel to the gateway)
After=network-online.target time-sync.target ssh.service sshd.service ssh.socket
Wants=network-online.target time-sync.target

[Service]
Type=simple
User=root
ExecStart=%s server start --data-dir %s
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=on-failure
RestartSec=5
KillMode=mixed
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
AmbientCapabilities=
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, systemdExecWord(binPath), systemdExecWord(dataDir))
}

// setupMachineSystemd drives the machine's Linux install: write the rendered
// unit, then the shared systemd tail — daemon-reload, enable, start.
//
// Unlike the gateway's half there is no service user to create and nothing to
// chown: the unit runs as root (SPEC §3.2.1), which is also the account that
// created the data directory, so the userExists/createUser/chownDir steps of
// the seam are deliberately not called here — a test pins that they stay at
// zero calls, because a machine install that quietly started creating users
// would be a different product.
func setupMachineSystemd(setup systemdSetup, binPath, dataDir string) error {
	// String concatenation, not filepath.Join: a path on the TARGET
	// machine (Linux) must be assembled with forward slashes regardless
	// of the OS the test builds/runs on — the same argument as in
	// setupSystemd.
	unitPath := systemdUnitDir + "/" + machineUnitName
	// R1-CX F-21: refused before the unit is written; runServerInstall
	// asks this, and whether the path is absolute, before it creates the
	// data directory.
	if err := refuseSystemdUnitControl("server install", binPath, dataDir); err != nil {
		return err
	}
	if werr := setup.writeUnit(unitPath, machineUnitFile(binPath, dataDir)); werr != nil {
		return envErrf("server install: write the systemd unit %s: %v — write it by hand per RUNBOOK.md §1.7 and run \"systemctl daemon-reload && systemctl enable --now %s\".", unitPath, werr, machineUnitName)
	}
	return systemdInstallTail(setup, "server", machineUnitName)
}

// uninstallMachineSystemdUnit drives the machine's Linux uninstall: the same
// sequence the gateway's half runs (§3.2.1 "server uninstall is the reverse"),
// through the same shared tail. The machine data directory is never touched:
// machine.key and the enrolment record are what let this machine ever come
// back, and removing them stays an explicit operator action.
func uninstallMachineSystemdUnit(setup systemdSetup) (bool, error) {
	return systemdUninstallTail(setup, "server", systemdUnitDir+"/"+machineUnitName, machineUnitName)
}

// cmdServerInstall is the machine's start-on-boot (SPEC §3.2.1). It replaces
// nothing: "server start" keeps working by hand, from a console, or from an
// operator's own supervisor, exactly as before — install only adds the unit
// that makes the machine come up on its own after a reboot.
func cmdServerInstall(s *streams, args []string) int {
	const path = "server install"
	fs := newFlagSet(path, "")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	// §3.2.1: install writes /etc/systemd/system and starts a root unit —
	// same root gate as start/stop/status, same banner-free refusal text.
	if err := requireServerElevation(s, path); err != nil {
		return fail(s, err)
	}
	// Which directory this install is FOR is the one thing the two
	// platforms answer differently, and systemServerDir spells out why.
	// On Unix the root service gets the machine-wide directory rather
	// than the per-user default a person running this command would
	// otherwise resolve; on Windows the autostart IS per person, so the
	// person's own directory is exactly right. An explicit --data-dir
	// (or --config) still wins on either: an operator who names a
	// directory means that directory.
	dir := systemServerDir
	if runtime.GOOS == "windows" || fs.val("data-dir") != "" || fs.val("config") != "" {
		var lerr error
		_, dir, lerr = loadConfig(s, "server", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")})
		if lerr != nil {
			return fail(s, lerr)
		}
	}
	return runServerInstall(s, path, dir)
}

// runServerInstall does the local half (the data directory) and then the
// service half. The platform check comes first, before anything is created:
// on a host with no service integration this command must be a pure refusal
// that leaves the disk exactly as it found it.
func runServerInstall(s *streams, path, dir string) int {
	// The platform check comes first, before anything is created: on a host
	// with no autostart integration this command must be a pure refusal
	// that leaves the disk exactly as it found it. All three supported
	// platforms have one — a systemd unit on Linux, a LaunchDaemon on
	// macOS, a logon task on Windows (server_task.go) — and each names its
	// own in the text.
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return fail(s, envErrf("iamtunnel %s: the autostart half of install (systemd unit on Linux, LaunchDaemon on macOS, logon task on Windows — SPEC §3.2.1) supports Linux, macOS and Windows; this build is running on %s and has no integration for it. \"iamtunnel %s\" stays the entry point there; run \"server install\" on the machine itself.", path, runtime.GOOS, "server start"))
	}
	// On Windows the task is named after the REGISTRATION and runs as the
	// account that registration is bound to, so both must already exist:
	// there is no impersonal machine autostart to install ahead of an
	// enrolment the way there is on Unix. Refuse before creating anything,
	// and say which command comes first.
	var winSpec logonTaskSpec
	if runtime.GOOS == "windows" {
		var werr error
		winSpec, werr = logonTaskSpecFor(s, path, dir)
		if werr != nil {
			return fail(s, werr)
		}
		// IAMT-445: the task starts this very file with the highest
		// privileges at every sign-in, so only administrators may be able
		// to change it - checked, and in C:\iamtunnel locked, before
		// anything is created.
		if serr := secureLogonTaskExe(s, path, winSpec.ExePath); serr != nil {
			return fail(s, serr)
		}
		// R4 F-04: the logon task's elevated start checks the enrolment
		// record against the anchor before it acts on it. A registration
		// made before the anchor existed gets one laid down here, where
		// the operator is present and elevated - the one moment the
		// current profile record is taken at its word, and the output
		// says so; an anchor that already disagrees with the record
		// refuses instead of being quietly rewritten.
		_, anchorErr := readMachineEnrolmentAnchor(s.env)
		hadAnchor := anchorErr == nil
		if aerr := ensureMachineEnrolmentAnchor(s.env, dir); aerr != nil {
			return fail(s, aerr)
		}
		if !hadAnchor {
			if anchor, rerr := readMachineEnrolmentAnchor(s.env); rerr == nil {
				fmt.Fprintf(s.out, "  the enrolment anchor %s now holds gateway %s:%d (fingerprint %s, machine %s) — the elevated \"server start\" checks the profile record against it at every start.\n", enrolmentAnchorName, anchor.Host, anchor.Port, anchor.Fingerprint, anchor.MachineID)
			}
		}
	}
	// IAMT-445b: the unit (the LaunchDaemon on macOS) starts this file as
	// root at every boot, so only root may be able to change it or any
	// directory on the way to it - checked before anything is created. A
	// binary that cannot be located is reported by the install step below.
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		writers := linuxSystemd.exeWriters
		if runtime.GOOS == "darwin" {
			writers = darwinLaunchd.exeWriters
		}
		if bin, exeErr := os.Executable(); exeErr == nil {
			if serr := refuseChangeableServiceExe(path, bin, writers); serr != nil {
				return fail(s, serr)
			}
			// R1-CX F-21: and the unit must be able to carry the binary
			// and the directory at all.
			if runtime.GOOS == "linux" {
				if serr := refuseSystemdUnitPaths(path, bin, dir); serr != nil {
					return fail(s, serr)
				}
			}
		}
	}
	// §3.2.1: the server directory is owned by root, 0700. install runs
	// as root (requireServerElevation above), so the directory created
	// here is already owned by root; chmod fixes up a directory a
	// previous run created with wider permissions (the same technique
	// as in gateway install). On macOS the default directory is the
	// same — /var/lib/iamtunnel-machine (internal/config/paths.go) —
	// and the launchd job also runs as root.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(s, classifyPathErr(err, dir))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fail(s, classifyPathErr(err, dir))
	}

	switch runtime.GOOS {
	case "linux":
		bin, exeErr := os.Executable()
		if exeErr != nil {
			return fail(s, envErrf("iamtunnel %s: locate this binary for the systemd unit: %v", path, exeErr))
		}
		if err := setupMachineSystemd(linuxSystemd, bin, dir); err != nil {
			return fail(s, err)
		}
		fmt.Fprintf(s.out, "iamtunnel %s: systemd unit %s written (User=root, Restart=on-failure, KillMode=mixed), daemon reloaded, enabled and started.\n", path, systemdUnitDir+"/"+machineUnitName)
	case "darwin":
		bin, exeErr := os.Executable()
		if exeErr != nil {
			return fail(s, envErrf("iamtunnel %s: locate this binary for the LaunchDaemon plist: %v", path, exeErr))
		}
		if err := setupMachineLaunchd(darwinLaunchd, bin, dir); err != nil {
			return fail(s, err)
		}
		fmt.Fprintf(s.out, "iamtunnel %s: LaunchDaemon %s written (0644, root:wheel; root, Restart-on-failure), loaded and started; logs go to %s.\n", path, machinePlistPath, machineLogPath)
	case "windows":
		if err := setupMachineLogonTask(windowsTasks, winSpec); err != nil {
			return fail(s, err)
		}
		fmt.Fprintf(s.out, "iamtunnel %s: the logon task %s is registered for %s and started (it runs \"server start --data-dir %s\" with the highest privileges that account has, with no time limit and no stop on battery).\n", path, logonTaskName(winSpec.Machine), winSpec.User, winSpec.DataDir)
		fmt.Fprintf(s.out, "  it starts again every time %s signs in, including over Remote Desktop, and nobody else's registration on this machine is touched.\n", winSpec.User)
		// Windows refused above unless the machine is already
		// registered, so the not-registered note below cannot apply here.
		return exitOK
	}

	// The service starts `server start`, which refuses without an enrolment
	// record (§3.2.1: "this machine is not enrolled"). install is allowed
	// before enrol — the operator may legitimately set the service up first —
	// but then its first start fails and the platform's own restart policy
	// gives up (systemd's start rate limit; launchd's SuccessfulExit=false
	// does not retry a start that never succeeded). Say so here, while the
	// operator is still looking at install's own output, instead of leaving
	// a dead service unexplained. The restart command is the platform's.
	if !machineEnrolled(dir) {
		fmt.Fprintf(s.out, "  note: this machine is not registered yet, so the service's first start refuses (\"this machine is not registered\"): run \"iamtunnel enrol <code>\" with the code from the gateway admin, then %s (or just \"iamtunnel server start\").\n", machineServiceRestartHint())
	}
	return exitOK
}

// machineServiceRestartHint is the "make the service pick the enrolment up"
// command for this platform: the unit and the LaunchDaemon are started by
// different supervisors, and telling a macOS operator to run systemctl (or
// a Linux operator to kickstart a launchd job) would send them to a command
// that does not exist on their machine.
func machineServiceRestartHint() string {
	if runtime.GOOS == "darwin" {
		return "\"sudo launchctl kickstart -k system/" + machinePlistLabel + "\""
	}
	return "\"systemctl restart " + machineUnitName + "\""
}

// machineAutostartSubject names what install put in place on this
// platform, for the sentences that have to say it. Telling a Windows
// operator that "the machine service" is not installed would send him
// looking in services.msc for something this product never creates
// there — the autostart he has is a task (server_task.go).
func machineAutostartSubject() string {
	if runtime.GOOS == "windows" {
		return "the logon task"
	}
	return "the machine service"
}

// machineEnrolled reports whether this machine already carries a gateway
// enrolment record. Best-effort by design: install's outcome does not depend
// on it, only the extra sentence printed after a successful install.
func machineEnrolled(dir string) bool {
	_, err := loadGatewayRecord(dir)
	return err == nil
}

// cmdServerUninstall removes the unit install put in place (SPEC §3.2.1,
// "server uninstall is the reverse"). The machine data directory — machine key,
// enrolment record, local journal — is deliberately left alone, exactly as
// the gateway's uninstall leaves its own data behind: a later "server start"
// (or install) must revive the same machine identity. Idempotent: no unit on
// disk is "nothing to do", not an error.
func cmdServerUninstall(s *streams, args []string) int {
	const path = "server uninstall"
	fs := newFlagSet(path, "")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	if err := requireServerElevation(s, path); err != nil {
		return fail(s, err)
	}
	// The directory is only named in the "was not touched" line, so a config
	// problem must not block removing the unit: an explicitly given
	// --data-dir (or IAMTUNNEL_DATA_DIR) is used as typed, otherwise the
	// lookup is best-effort and the line degrades to the unnamed form. Same
	// reasoning and same order as the gateway's uninstall (IAMT-258).
	dir := fs.val("data-dir")
	if dir == "" {
		dir = s.env["IAMTUNNEL_DATA_DIR"]
	}
	dirFromEnv := dir != ""
	if _, _, lerr := loadConfig(s, "server", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")}); lerr != nil {
		if !dirFromEnv {
			dir = ""
		}
	}
	switch runtime.GOOS {
	case "linux":
		removed, err := uninstallMachineSystemdUnit(linuxSystemd)
		return reportServerUninstall(s, path, dir, removed, err)
	case "darwin":
		removed, err := uninstallMachineLaunchd(darwinLaunchd)
		return reportServerUninstall(s, path, dir, removed, err)
	case "windows":
		// The task is named after the registration, so uninstall has to
		// read the enrolment record to know what to remove — and unlike
		// the Unix halves it has no fixed name to fall back on. The
		// directory therefore matters here, and a best-effort lookup is
		// not enough: resolve it the way install did.
		lookIn := dir
		if lookIn == "" {
			var lerr error
			if _, lookIn, lerr = loadConfig(s, "server", cfgOpts{configPath: fs.val("config")}); lerr != nil {
				return fail(s, lerr)
			}
		}
		rec, rerr := loadGatewayRecord(lookIn)
		if rerr != nil {
			return fail(s, userErrf("iamtunnel %s: the logon task is named after this machine's registration, and the enrolment record in %s could not be read (%v) — so this command cannot tell which task is yours. Remove it in Task Scheduler under the %s folder, or with \"schtasks /Delete /TN \"%s\\<name>\" /F\".", path, lookIn, rerr, logonTaskFolder, logonTaskFolder))
		}
		removed, err := removeMachineLogonTask(windowsTasks, strings.TrimSpace(rec.MachineID))
		return reportServerUninstall(s, path, lookIn, removed, err)
	default:
		return fail(s, envErrf("iamtunnel %s: the autostart half of uninstall (systemd unit on Linux, LaunchDaemon on macOS, logon task on Windows — SPEC §3.2.1) supports Linux, macOS and Windows; this build is running on %s and has no integration for it.", path, runtime.GOOS))
	}
}

// reportServerUninstall prints the uninstall outcome; the data-directory line
// makes the promise visible in the operator's terminal — no server command
// ever destroys the machine's key or its enrolment. The twin of
// reportGatewayUninstall with the machine's own artifacts named in the line.
func reportServerUninstall(s *streams, path, dir string, removed bool, err error) int {
	if err != nil {
		return fail(s, err)
	}
	if !removed {
		fmt.Fprintf(s.out, "iamtunnel %s: %s is not installed; nothing to do.\n", path, machineAutostartSubject())
		return exitOK
	}
	if runtime.GOOS == "windows" {
		// Deliberately NOT the Unix wording. systemctl/launchctl stop the
		// service as part of disabling it, and that stop is a SIGTERM —
		// the server's own clean exit, which removes its door line on the
		// way out. Task Scheduler has no such thing: ending a task
		// terminates the process outright, and a server killed that way
		// leaves its door line for the watchdog to clean up instead of
		// closing it itself. So uninstall removes the autostart and
		// leaves a running server alone, and says which command ends it
		// properly.
		fmt.Fprintf(s.out, "iamtunnel %s: the logon task was removed; this machine no longer starts its server when that account signs in.\n", path)
		fmt.Fprintf(s.out, "  a server that is running right now keeps running — stop it with \"iamtunnel server stop\", which closes its door on the way out.\n")
	} else {
		fmt.Fprintf(s.out, "iamtunnel %s: the machine service was stopped and removed.\n", path)
	}
	if dir != "" {
		fmt.Fprintf(s.out, "  the data directory %s was not touched (machine key, enrolment record and local journal survive; remove it by hand if you really want a re-enrol).\n", dir)
	} else {
		fmt.Fprintln(s.out, "  the data directory was not touched (machine key, enrolment record and local journal survive; remove it by hand if you really want a re-enrol).")
	}
	return exitOK
}

// maxPID is the default process-id ceiling on both Windows and Linux.
const maxPID = 4194304

// cmdServerDoorwatch is the watchdog child process (SPEC §6.3, layer 3).
// It is internal: listed in the help so the process table explains
// itself, but not part of the day-to-day surface.
//
// The argv layout is OS-specific (IAMT-247):
//
//	Windows (<door-id> <parent-pid> <keyfile> <max-wait-ms> <journal-path>):
//	  5 positional arguments. Documented in internal/winkeys.ParseWatchdogArgs
//	  and built by internal/winkeys.SpawnWatchdog on the parent side.
//	  Pre-IAMT-247 layout, unchanged so existing Windows tests and
//	  fixtures keep working.
//
//	Linux and macOS (<door-id> <parent-pid> <keyfile> <max-wait-ms>
//	      <journal-path> <lock-path> <owner-uid> <owner-gid>):
//	  8 positional arguments. The three tail fields carry the unix-only
//	  DoorOptions (LockPath/OwnerUID/OwnerGID) that NewDoorWithOptions
//	  requires on linux/darwin; the doorwatch subprocess ends up
//	  calling NewDoorWithOptions on its end to clean up the line.
//	  Parsed by internal/winkeys.ParseWatchdogArgsUnix
//	  (doorwatch_unix.go); built by SpawnWatchdog's unix half. Linux
//	  and macOS share this layout on purpose: only the child's waiting
//	  mechanism differs (pidfd poll vs kqueue NOTE_EXIT), never the
//	  contract the parent and the child agree on.
//
// <max-wait-ms> is the safety cap on how long this process is
// willing to wait for the parent. It MUST come from the parent
// process's MaxDoorHard + WatchdogLifetimeSlack (see
// internal/server.Config.WatchdogLifetime), not from a hard-coded
// value: IAMT-130 found a 5-minute hard-coded cap that could
// expire while the door was still legally open.
//
// <journal-path> is the audit log this process writes its
// "remove-by-watcher" event into. An empty path means no journal —
// the cleanup event is dropped, the same as the previous
// sink=nil behaviour. In production the parent passes an explicit
// path under the machine data directory; tests pass an explicit
// path under t.TempDir() so they never touch real state.
func cmdServerDoorwatch(s *streams, args []string) int {
	// Linux and macOS share one argv layout (the unix DoorOptions tail,
	// IAMT-247 / IAMT-263); Windows keeps the pre-IAMT-247 five-field
	// one. The two parsers mirror the two SpawnWatchdog halves in
	// internal/winkeys.
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		return cmdServerDoorwatchUnix(s, args)
	}
	return cmdServerDoorwatchOther(s, args)
}

// watchdogAuditErrorReporter builds the OnError callback for the
// watchdog's own journal sink (IAMT-307 round 7, F-307-3). The watchdog
// exists specifically to keep running after the parent server process
// that started it is gone (SPEC §6.3), and SpawnWatchdog routes its
// stdout/stderr to /dev/null in production for exactly that reason —
// nothing is left to read them once the parent's own log handling has
// died with it. Writing a failed audit write to this process's own
// stderr, the way cmd/iamtunnel's "server start" does for the server
// role a few lines above, would therefore be silent again in the one
// case this journal matters most: the parent already dead.
//
// The one channel still guaranteed reachable at that point is the same
// filesystem the journal itself lives on, so a failed write is appended,
// one line per failure, to a plain-text file living right next to the
// journal - an operator who already knows to look at <journal>.jsonl for
// the audit trail finds <journal>.jsonl.watchdog.err beside it recording
// exactly when and why a write was lost. This is deliberately
// best-effort: if the filesystem is unwritable, so was the journal write
// this reports, and there is no third channel left to fall back to — see
// RUNBOOK's note on this file for what an operator does with it.
func watchdogAuditErrorReporter(journalPath string) func(error) {
	errPath := journalPath + ".watchdog.err"
	return func(werr error) {
		// The open obeys the machine data-file contract (IAMT-332
		// round seven): a symlink or FIFO planted at the error file's
		// name is refused, and the refusal is swallowed like any other
		// open failure — the channel is best-effort, and hanging on a
		// FIFO inside open(2) would be the one outcome worse than
		// silence.
		f, oerr := state.OpenAppendDataFile(errPath)
		if oerr != nil {
			return
		}
		defer f.Close()
		fmt.Fprintf(f, "%s watchdog audit journal error: %v\n", time.Now().UTC().Format(time.RFC3339Nano), werr)
	}
}

// cmdServerDoorwatchUnix is the Unix half of cmdServerDoorwatch
// (Linux since IAMT-247, macOS since IAMT-263).
// See cmdServerDoorwatch's doc comment for the full argv layout.
func cmdServerDoorwatchUnix(s *streams, args []string) int {
	const path = "server doorwatch"
	fs := newFlagSet(path, "<door-id> <parent-pid> <keyfile> <max-wait-ms> <journal-path> <lock-path> <owner-uid> <owner-gid>")
	fs.valFlag("config")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(8); err != nil {
		return fail(s, err)
	}
	if !config.ValidName(fs.pos[0]) {
		return fail(s, config.NameError("door id", fs.pos[0]))
	}
	pid, err := strconv.Atoi(fs.pos[1])
	if err != nil || pid < 1 || pid > maxPID {
		return fail(s, userErrf("iamtunnel %s: parent pid %q must be a number from 1 to %d — this command is started by the server itself, not by hand.", path, fs.pos[1], maxPID))
	}
	keyFile := strings.TrimSpace(fs.pos[2])
	if keyFile == "" {
		return fail(s, userErrf("iamtunnel %s: keyfile path must not be empty", path))
	}
	maxWaitMs, err := strconv.ParseInt(strings.TrimSpace(fs.pos[3]), 10, 64)
	if err != nil || maxWaitMs <= 0 {
		return fail(s, userErrf("iamtunnel %s: max-wait-ms %q must be a positive whole number of milliseconds — this command is started by the server itself, not by hand.", path, fs.pos[3]))
	}
	journalPath := strings.TrimSpace(fs.pos[4])
	lockPath := strings.TrimSpace(fs.pos[5])
	if lockPath == "" {
		return fail(s, userErrf("iamtunnel %s: lock-path must not be empty — the Unix doorwatch needs the cross-process lock file path to call NewDoorWithOptions.", path))
	}
	ownerUID, uidErr := strconv.Atoi(strings.TrimSpace(fs.pos[6]))
	if uidErr != nil || ownerUID < 0 {
		return fail(s, userErrf("iamtunnel %s: owner-uid %q must be a non-negative whole number — this command is started by the server itself, not by hand.", path, fs.pos[6]))
	}
	ownerGID, gidErr := strconv.Atoi(strings.TrimSpace(fs.pos[7]))
	if gidErr != nil || ownerGID < 0 {
		return fail(s, userErrf("iamtunnel %s: owner-gid %q must be a non-negative whole number — this command is started by the server itself, not by hand.", path, fs.pos[7]))
	}
	if err := requireServerElevation(s, path); err != nil {
		return fail(s, err)
	}
	// loadConfig is intentionally still called so the watchdog
	// participates in the same config-loading checks as every other
	// server subcommand; the result is unused for the watch path
	// itself beyond that.
	if _, _, lerr := loadConfig(s, "server", cfgOpts{configPath: fs.val("config")}); lerr != nil {
		return fail(s, lerr)
	}
	var sink winkeys.Sink
	if journalPath != "" {
		// AppenderRole (IAMT-307 round 10, F-307-10): the server, not
		// the watchdog, is this journal's rotator (see server.go's own
		// scfg.Sink construction below in cmdServer). Two independent
		// rotators on the same path - each with its own in-memory
		// pendingArchive that is lost the moment that process exits -
		// meant a truncate that kept failing was never resolved "exactly
		// once": every watchdog spawn published one more duplicate
		// archive of an ever-growing live file. The watchdog only ever
		// appends its own layer-3 cleanup line here.
		sinkFile, ferr := winkeys.NewJournalSink(journalPath, winkeys.JournalOptions{
			OnError: watchdogAuditErrorReporter(journalPath),
			Role:    winkeys.AppenderRole,
		})
		if ferr != nil {
			return fail(s, envErrf("iamtunnel %s: could not open the audit journal %s: %v", path, journalPath, ferr))
		}
		sink = sinkFile
	}
	if err := winkeys.RunWatchdog(pid, fs.pos[0], keyFile, sink, time.Duration(maxWaitMs)*time.Millisecond, lockPath, ownerUID, ownerGID); err != nil {
		return fail(s, err)
	}
	return exitOK
}

// cmdServerDoorwatchOther is the Windows (and any non-Unix) half of
// cmdServerDoorwatch — pre-IAMT-247 layout, unchanged. See
// cmdServerDoorwatch's doc comment.
func cmdServerDoorwatchOther(s *streams, args []string) int {
	const path = "server doorwatch"
	fs := newFlagSet(path, "<door-id> <parent-pid> <keyfile> <max-wait-ms> <journal-path>")
	fs.valFlag("config")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(5); err != nil {
		return fail(s, err)
	}
	if !config.ValidName(fs.pos[0]) {
		return fail(s, config.NameError("door id", fs.pos[0]))
	}
	pid, err := strconv.Atoi(fs.pos[1])
	if err != nil || pid < 1 || pid > maxPID {
		return fail(s, userErrf("iamtunnel %s: parent pid %q must be a number from 1 to %d — this command is started by the server itself, not by hand.", path, fs.pos[1], maxPID))
	}
	keyFile := strings.TrimSpace(fs.pos[2])
	if keyFile == "" {
		return fail(s, userErrf("iamtunnel %s: keyfile path must not be empty", path))
	}
	maxWaitMs, err := strconv.ParseInt(strings.TrimSpace(fs.pos[3]), 10, 64)
	if err != nil || maxWaitMs <= 0 {
		return fail(s, userErrf("iamtunnel %s: max-wait-ms %q must be a positive whole number of milliseconds — this command is started by the server itself, not by hand.", path, fs.pos[3]))
	}
	journalPath := strings.TrimSpace(fs.pos[4])
	if err := requireServerElevation(s, path); err != nil {
		return fail(s, err)
	}
	// loadConfig is intentionally still called so the watchdog
	// participates in the same config-loading checks as every other
	// server subcommand; the result is unused for the watch path
	// itself beyond that.
	if _, _, lerr := loadConfig(s, "server", cfgOpts{configPath: fs.val("config")}); lerr != nil {
		return fail(s, lerr)
	}
	var sink winkeys.Sink
	if journalPath != "" {
		// AppenderRole: see cmdServerDoorwatchUnix's identical wiring
		// and its comment for why (IAMT-307 round 10, F-307-10) - the
		// server, not the watchdog, is this journal's rotator.
		sinkFile, ferr := winkeys.NewJournalSink(journalPath, winkeys.JournalOptions{
			OnError: watchdogAuditErrorReporter(journalPath),
			Role:    winkeys.AppenderRole,
		})
		if ferr != nil {
			return fail(s, envErrf("iamtunnel %s: could not open the audit journal %s: %v", path, journalPath, ferr))
		}
		sink = sinkFile
	}
	if err := winkeys.RunWatchdog(pid, fs.pos[0], keyFile, sink, time.Duration(maxWaitMs)*time.Millisecond, "", 0, 0); err != nil {
		return fail(s, err)
	}
	return exitOK
}
