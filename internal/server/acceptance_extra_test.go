package server

// acceptance_extra_test.go — acceptance tests for an
// independent review of the machine role (IAMT-62, first pass). The
// package's author did not take part in writing these tests; each test
// is built to catch exactly one assertion from SPEC §3, and every
// assertion is proven by breaking the product code.
//
// File principles:
//   - all networking stays on 127.0.0.1 and t.TempDir();
//   - real key files, real winkeys operations;
//   - the watchdog is replaced with noopSpawnWatchdog, except where the
//     watchdog itself is the subject of the test (that is what
//     watchdog_integration_windows_test.go does).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// ---------------------------------------------------------------------------
// Helpers: a gateway with a controllable keepalive responder, and
// control-channel round trips.
// ---------------------------------------------------------------------------

// reviewGateway — a minimal SSH server playing the gateway role. Unlike
// fakeGateway from testhelpers_test.go, it ANSWERS keepalive@iamtunnel
// with success by default (fakeGateway's ssh.DiscardRequests answers
// with failure, which kills a live connection after three misses — that
// gets in the way of connection-death tests). The keepaliveOK flag
// turns off the replies: silence is the second way a connection dies
// (PROTOCOL §5: "missing replies"), which is what T6 uses.
type reviewGateway struct {
	ln          net.Listener
	hostKey     ssh.Signer
	keepaliveOK atomic.Bool

	ready chan struct{}
	conn  *ssh.ServerConn
	chans <-chan ssh.NewChannel

	// Teardown (IAMT-314), set up the same way as fakeGateway.
	wg    sync.WaitGroup
	conns *connSet
}

func newReviewGateway(t *testing.T) *reviewGateway {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gw := &reviewGateway{ln: ln, hostKey: mustSigner(t), ready: make(chan struct{}), conns: newConnSet()}
	gw.keepaliveOK.Store(true)
	t.Cleanup(gw.close)
	return gw
}

// close -- deterministic teardown (IAMT-314), same as fakeGateway.
func (gw *reviewGateway) close() {
	_ = gw.ln.Close()
	gw.conns.closeAll()
	gw.wg.Wait()
}

// startAccept runs acceptOne in a goroutine the fixture owns
// (IAMT-314).
func (gw *reviewGateway) startAccept() {
	gw.wg.Add(1)
	go func() {
		defer gw.wg.Done()
		gw.acceptOne()
	}()
}

func (gw *reviewGateway) addr() string        { return gw.ln.Addr().String() }
func (gw *reviewGateway) fingerprint() string { return ssh.FingerprintSHA256(gw.hostKey.PublicKey()) }

func (gw *reviewGateway) acceptOne() {
	raw, err := gw.ln.Accept()
	if err != nil {
		close(gw.ready)
		return
	}
	if !gw.conns.add(raw) {
		close(gw.ready)
		return
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(gw.hostKey)
	sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		_ = raw.Close()
		close(gw.ready)
		return
	}
	gw.conn = sconn
	gw.chans = chans
	gw.wg.Add(1)
	go func() {
		defer gw.wg.Done()
		for r := range reqs {
			if !r.WantReply {
				continue
			}
			if r.Type == "keepalive@iamtunnel" {
				if gw.keepaliveOK.Load() {
					_ = r.Reply(true, nil)
				}
				// silence when keepaliveOK=false — a "miss" per PROTOCOL §5
				continue
			}
			_ = r.Reply(false, nil)
		}
	}()
	close(gw.ready)
}

func (gw *reviewGateway) wait(t *testing.T) *ssh.ServerConn {
	t.Helper()
	select {
	case <-gw.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway never saw the machine connect")
	}
	if gw.conn == nil {
		t.Fatal("the machine's handshake with the fake gateway failed")
	}
	return gw.conn
}

// reviewStart runs a real Machine.Serve against the fake gateway and
// opens the single iamtunnel-control channel.
func reviewStart(t *testing.T, tweak func(*Config)) (*reviewGateway, ssh.Channel, *Config, context.CancelFunc) {
	t.Helper()
	machineKey := mustSigner(t)
	gw := newReviewGateway(t)
	gw.startAccept()

	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("administrators_authorized_keys")
	cfg := Config{
		GatewayAddr:        gw.addr(),
		GatewayFingerprint: gw.fingerprint(),
		MachineID:          "vm-review",
		MachineKey:         machineKey,
		KeyFile:            keyFile,
		DoorLockPath:       filepath.Join(tree.Home, "door.lock"),
		OwnerUID:           testUIDForDoor(),
		OwnerGID:           testGIDForDoor(),
		TargetAddr:         "127.0.0.1:1", // a port nobody needs; T8 swaps it for an echo
		SpawnWatchdog:      noopSpawnWatchdog,
		Keepalive:          sshx.Keepalive{Interval: 120 * time.Millisecond, MaxMisses: 3},
		DialTimeout:        5 * time.Second,
		HandshakeTimeout:   5 * time.Second,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	if err := cfg.setDefaults(); err != nil {
		t.Fatalf("setDefaults: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	serveInBackground(t, ctx, cancel, m)

	sc := gw.wait(t)
	ch, reqs, err := sc.OpenChannel("iamtunnel-control", nil)
	if err != nil {
		t.Fatalf("open iamtunnel-control: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	return gw, ch, &cfg, cancel
}

// reviewRoundTrip sends one request over control and reads one reply.
func reviewRoundTrip(t *testing.T, ch ssh.Channel, req controlRequest) controlResponse {
	t.Helper()
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if _, err := ch.Write(append(line, '\n')); err != nil {
		t.Fatalf("write request: %v", err)
	}
	buf := make([]byte, 64*1024)
	n, err := readWithDeadline(t, ch, buf, 5*time.Second)
	if err != nil {
		t.Fatalf("no answer to the control request: %v", err)
	}
	var resp controlResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		t.Fatalf("answer did not parse as a controlResponse (%q): %v", buf[:n], err)
	}
	return resp
}

// reviewDoorOpenRequest — a door.open with a fixed key (so the
// fingerprint can be checked against door.status); returns the request
// and the fingerprint.
func reviewDoorOpenRequest(t *testing.T, id string, idle, hard time.Duration) (controlRequest, string) {
	t.Helper()
	pub := validPubKeyLine(t)
	body := strings.Fields(pub)[1]
	blob, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	fp := ssh.FingerprintSHA256(pk)
	now := time.Now()
	req := controlRequest{
		Proto: 1, Caps: []string{}, ID: "11111111-1111-1111-1111-111111111111", Op: "door.open",
		Door: &controlDoor{
			ID:           id,
			PubKey:       pub,
			Opened:       now.Format(time.RFC3339Nano),
			IdleDeadline: now.Add(idle).Format(time.RFC3339Nano),
			HardDeadline: now.Add(hard).Format(time.RFC3339Nano),
		},
	}
	return req, fp
}

func reviewWaitUntil(t *testing.T, what string, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s: %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// T1. §3.1 — the review's own garbage corpus for decodeControlRequest.
// ---------------------------------------------------------------------------

func TestReviewJSONCorpus(t *testing.T) {
	const status = `{"proto":1,"caps":[],"id":"11111111-1111-1111-1111-111111111111","op":"door.status"}`
	cases := []struct {
		name    string
		line    string
		wantErr bool
		wantOp  string // checked only when wantErr==false
	}{
		// --- accepted and parsed exactly ---
		{"valid status", status, false, "door.status"},
		{"CR tail tolerated", status + "\r", false, "door.status"},
		{"empty object lacks the required envelope", `{}`, true, ""},
		{"missing proto/caps/id", `{"op":"door.close","doorId":"x"}`, true, ""},
		{"door null reaches semantic validation", `{"proto":1,"caps":[],"id":"11111111-1111-1111-1111-111111111111","op":"door.open","door":null}`, false, "door.open"},
		{"invalid utf-8 is replaced by U+FFFD (known deviation, see report)", "{\"proto\":1,\"caps\":[],\"id\":\"11111111-1111-1111-1111-111111111111\",\"op\":\"\xff\xfe\"}", false, "��"},
		{"escaped NUL within op reaches semantic validation (known deviation, see report)", "{\"proto\":1,\"caps\":[],\"id\":\"11111111-1111-1111-1111-111111111111\",\"op\":\"door.st\\u0000atus\"}", false, "door.st\u0000atus"},

		// --- top level ---
		{"empty", ``, true, ""},
		{"whitespace only", "  \r", true, ""},
		{"bare null", `null`, true, ""},
		{"bare true", `true`, true, ""},
		{"bare number", `42`, true, ""},
		{"bare -0", `-0`, true, ""},
		{"overflowing number 1e400", `{"proto":1e400}`, true, ""},
		{"huge integer for proto", `{"proto":123456789012345678901234567890}`, true, ""},
		{"bare string", `"str"`, true, ""},
		{"bare array", `[]`, true, ""},
		{"array of numbers", `[1,2,3]`, true, ""},
		{"single brace", `{`, true, ""},
		{"lone close", `}`, true, ""},
		{"unbalanced open", `{"a":1`, true, ""},
		{"unbalanced close", `{"a":1}}`, true, ""},
		{"two objects", `{}{}`, true, ""},
		{"trailing garbage", `{} garbage`, true, ""},
		{"two values", `{"a":1} {"b":2}`, true, ""},
		{"trailing NUL byte", status + string([]byte{0}), true, ""},
		{"BOM prefix", "\xef\xbb\xbf" + `{}`, true, ""},
		{"raw NUL inside string", "{\"proto\":1,\"caps\":[],\"id\":\"a" + string([]byte{0}) + "b\",\"op\":\"door.status\"}", true, ""},
		{"NaN literal", `{"proto":NaN}`, true, ""},
		{"Infinity literal", `{"proto":Infinity}`, true, ""},
		{"binary garbage", string([]byte{0xff, 0xfe, 0x00, 0x01, '{', '}'}), true, ""},

		// --- duplicate keys (including the escaped form) ---
		{"duplicate top-level key", `{"proto":1,"proto":2,"op":"door.status","id":"x","caps":[]}`, true, ""},
		{"duplicate via unicode escape of same key", `{"op":"a","op":"b","id":"x","caps":[]}`, true, ""},
		{"duplicate nested key in door", `{"proto":1,"op":"door.open","id":"x","caps":[],"door":{"id":"a","id":"b"}}`, true, ""},
		{"duplicate caps key", `{"proto":1,"caps":[],"caps":[],"id":"x","op":"door.status"}`, true, ""},

		// --- unknown fields ---
		{"unknown top-level field", `{"proto":1,"caps":[],"id":"x","op":"door.status","extra":1}`, true, ""},
		{"unknown field in door", `{"proto":1,"op":"door.open","id":"x","caps":[],"door":{"id":"a","evil":1}}`, true, ""},

		// --- wrong types ---
		{"proto as string", `{"proto":"1","caps":[],"id":"x","op":"door.status"}`, true, ""},
		{"caps as object", `{"proto":1,"caps":{},"id":"x","op":"door.status"}`, true, ""},
		{"caps with number element", `{"proto":1,"caps":[1],"id":"x","op":"door.status"}`, true, ""},
		{"door as string", `{"proto":1,"op":"door.open","id":"x","caps":[],"door":"obj"}`, true, ""},
		{"door.id as number", `{"proto":1,"op":"door.open","id":"x","caps":[],"door":{"id":5}}`, true, ""},
		{"op as number", `{"proto":1,"caps":[],"id":"x","op":7}`, true, ""},

		// --- depth ---
		{"depth over the limit of 16", `{"a":` + strings.Repeat(`[`, 16) + strings.Repeat(`]`, 16) + `}`, true, ""},
		{"deep object bomb 10k", strings.Repeat(`{"a":`, 10000) + `1` + strings.Repeat(`}`, 10000), true, ""},
		{"deep array bomb 10k", strings.Repeat(`[`, 10000) + strings.Repeat(`]`, 10000), true, ""},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on corpus entry %q: %v", c.line, r)
				}
			}()
			req, err := decodeControlRequest([]byte(c.line), DefaultControlJSONDepth)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected a refusal, parsed: %+v", req)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected success, got an error: %v", err)
			}
			if req.Op != c.wantOp {
				t.Fatalf("op = %q, want %q", req.Op, c.wantOp)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// T2. §3.1 — the control-channel line-length limit at the exact
// boundary, through a real SSH channel: 512 bytes of content gets an
// answer, 513 tears the tunnel down.
// ---------------------------------------------------------------------------

func TestReviewControlLineLimitExactBoundary(t *testing.T) {
	const limit = 512
	_, ch, _, _ := reviewStart(t, func(c *Config) { c.ControlLineMax = limit })

	build := func(pad int) string {
		prefix := `{"proto":1,"caps":[],"id":"11111111-1111-1111-1111-111111111111","op":"`
		suffix := `"}`
		return prefix + strings.Repeat("a", pad) + suffix
	}
	send := func(line string) (controlResponse, error) {
		if _, err := ch.Write([]byte(line + "\n")); err != nil {
			return controlResponse{}, err
		}
		buf := make([]byte, 64*1024)
		n, rerr := readWithDeadline(t, ch, buf, 5*time.Second)
		if rerr != nil {
			return controlResponse{}, rerr
		}
		var resp controlResponse
		if err := json.Unmarshal(buf[:n], &resp); err != nil {
			t.Fatalf("answer is not JSON: %v (%q)", err, buf[:n])
		}
		return resp, nil
	}

	fixed := len(build(0))
	resp, err := send(build(limit - fixed))
	if err != nil {
		t.Fatalf("a line of exactly %d bytes must be accepted, got: %v", limit, err)
	}
	if resp.OK {
		t.Fatal("an unknown op at the limit boundary must not execute successfully")
	}

	// One byte longer — a framing error: no answer, the channel closes.
	if _, err := ch.Write([]byte(build(limit-fixed+1) + "\n")); err != nil {
		t.Fatalf("write oversized: %v", err)
	}
	buf := make([]byte, 1024)
	if n, rerr := readWithDeadline(t, ch, buf, 5*time.Second); rerr == nil && n > 0 {
		t.Fatalf("a line of %d bytes must tear the channel down with no answer, got an answer: %q", limit+1, buf[:n])
	}
}

// ---------------------------------------------------------------------------
// T3. §3.2 — the watchdog starts BEFORE the line is written; on a
// garbage request it does not start at all.
// ---------------------------------------------------------------------------

func TestReviewWatchdogSpawnOrder(t *testing.T) {
	var spawns atomic.Int32
	dc, keyFile := newTestDoorController(t, func(exe, doorID, kf string, pid int, _ time.Duration, _, _ string, _, _ int) (*winkeys.Watchdog, error) {
		spawns.Add(1)
		if fileContains(t, kf, "iamtunnel-door="+doorID) {
			t.Fatal("watchdog started AFTER the door line was already in the file")
		}
		return nil, nil
	})

	now := time.Now()
	if r := dc.open(doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)); !r.OK {
		t.Fatalf("door.open refused: %+v", r.Error)
	}
	if spawns.Load() != 1 {
		t.Fatalf("expected exactly one watchdog spawn, got %d", spawns.Load())
	}
	if !fileContains(t, keyFile, "iamtunnel-door="+winkeysID(testDoorID)) {
		t.Fatal("no line in the file after a successful open")
	}

	// A garbage request: the watchdog does not start at all.
	dc2, keyFile2 := newTestDoorController(t, func(string, string, string, int, time.Duration, string, string, int, int) (*winkeys.Watchdog, error) {
		t.Fatal("watchdog started for a request that failed validation")
		return nil, nil
	})
	bad := doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)
	bad.Door.PubKey = "ssh-ed25519 not-base64!!!"
	if r := dc2.open(bad); r.OK {
		t.Fatal("garbage request was accepted")
	}
	if _, err := os.Stat(keyFile2); !os.IsNotExist(err) {
		t.Fatal("key file was created by a garbage request")
	}
}

// ---------------------------------------------------------------------------
// T4. §3.3 — ceilings: accepted exactly at the limit, one nanosecond
// over gets E_CONTROL_DOOR_LIMIT.
// ---------------------------------------------------------------------------

func TestReviewCeilingBoundary(t *testing.T) {
	const idleLimit = 5 * time.Minute
	const hardLimit = time.Hour
	mk := func() *doorController {
		tree := testsupport.NewSSHTree(t)
		keyFile := tree.KeyPath("keys")
		cfg := &Config{
			KeyFile: keyFile, DoorwatchExe: "unused",
			DoorLockPath: filepath.Join(tree.Home, "door.lock"),
			OwnerUID:     testUIDForDoor(), OwnerGID: testGIDForDoor(),
			MaxDoorIdle: idleLimit, MaxDoorHard: hardLimit,
			SpawnWatchdog: noopSpawnWatchdog,
		}
		dc, err := newDoorController(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return dc
	}
	now := time.Now()

	if r := mk().open(doorOpenRequest(t, testDoorID, now, idleLimit, hardLimit)); !r.OK {
		t.Fatalf("a request at exactly both limits must be accepted, refused: %+v", r.Error)
	}
	r := mk().open(doorOpenRequest(t, testDoorID, now, idleLimit+time.Nanosecond, hardLimit))
	if r.OK || r.Error == nil || r.Error.Code != "E_CONTROL_DOOR_LIMIT" {
		t.Fatalf("idle 1ns over the limit must yield E_CONTROL_DOOR_LIMIT, got %+v", r)
	}
	r = mk().open(doorOpenRequest(t, testDoorID, now, idleLimit, hardLimit+time.Nanosecond))
	if r.OK || r.Error == nil || r.Error.Code != "E_CONTROL_DOOR_LIMIT" {
		t.Fatalf("hard 1ns over the limit must yield E_CONTROL_DOOR_LIMIT, got %+v", r)
	}
}

// T4b. §3.3 — timers are monotonic and measured from when the request
// was received, not from the gateway's clock: a request with opened in
// the future and in the past (a day of skew each way) must be closed
// by the machine on its OWN windows. Plus: activity feeds the idle
// timer but does not save the door from hard.
func TestReviewTimersMonotonicReceiptRelative(t *testing.T) {
	const idleWindow = 900 * time.Millisecond
	const hardWindow = 2 * time.Second

	run := func(t *testing.T, name string, openedAt time.Time) {
		t.Run(name, func(t *testing.T) {
			tree := testsupport.NewSSHTree(t)
			keyFile := tree.KeyPath("keys")
			cfg := &Config{
				KeyFile: keyFile, DoorwatchExe: "unused",
				DoorLockPath: filepath.Join(tree.Home, "door.lock"),
				OwnerUID:     testUIDForDoor(), OwnerGID: testGIDForDoor(),
				MaxDoorIdle: 2 * time.Second, MaxDoorHard: 10 * time.Second,
				SpawnWatchdog: noopSpawnWatchdog,
			}
			dc, err := newDoorController(cfg)
			if err != nil {
				t.Fatal(err)
			}
			req := controlRequest{
				Proto: 1, Caps: []string{}, ID: "t", Op: "door.open",
				Door: &controlDoor{
					ID:           testDoorID,
					PubKey:       validPubKeyLine(t),
					Opened:       openedAt.Format(time.RFC3339Nano),
					IdleDeadline: openedAt.Add(idleWindow).Format(time.RFC3339Nano),
					HardDeadline: openedAt.Add(hardWindow).Format(time.RFC3339Nano),
				},
			}
			if r := dc.open(req); !r.OK {
				t.Fatalf("door.open with a skewed gateway clock was refused: %+v", r.Error)
			}

			// Feed the idle timer with activity (the way tunnel bytes do
			// it in spliceTarget): every 100 ms.
			stop := make(chan struct{})
			go func() {
				for {
					select {
					case <-stop:
						return
					case <-time.After(100 * time.Millisecond):
						dc.touch()
					}
				}
			}()
			defer close(stop)

			time.Sleep(1500 * time.Millisecond)
			if !fileContains(t, keyFile, "iamtunnel-door=") {
				t.Fatal("the door closed before the hard limit despite continuous activity")
			}
			reviewWaitUntil(t, "the hard timer closed the door despite activity and clock skew",
				func() bool { return !fileContains(t, keyFile, "iamtunnel-door=") }, 4*time.Second)
		})
	}

	run(t, "opened a day in the future (gateway clock ran ahead)", time.Now().Add(24*time.Hour))
	run(t, "opened a day in the past (gateway clock fell behind)", time.Now().Add(-24*time.Hour))
}

// T4c. With no activity, the idle timer closes the door on its own.
func TestReviewIdleTimerClosesQuietDoor(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)
	now := time.Now()
	if r := dc.open(doorOpenRequest(t, testDoorID, now, 300*time.Millisecond, time.Hour)); !r.OK {
		t.Fatalf("open refused: %+v", r.Error)
	}
	reviewWaitUntil(t, "the idle timer closed the quiet door",
		func() bool { return !fileContains(t, keyFile, "iamtunnel-door=") }, 3*time.Second)
}

// ---------------------------------------------------------------------------
// T5. §3.4 — foreign keys are untouched: a foreign line, and a foreign
// line that LOOKS LIKE OURS (the marker inside a comment). Genuinely
// foreign lines are preserved byte-for-byte in their original order
// across open, close, SweepStale and sanitize.
//
// A corrupted line of ours (damagedOurs), before the IAMT-94 fix, was
// considered foreign because of its non-base64 key; now (corrupt: true)
// it is ours. By the IAMT-94 decision, only door.sanitize and
// SweepStale are required to remove it (PROTOCOL.md:246, IAMT-94);
// door.open does NOT — §5.1 (PROTOCOL.md:243,248) requires open to only
// ADD one line and preserve everything else byte-for-byte, including
// our corrupted line.
// ---------------------------------------------------------------------------

func TestReviewForeignLinesUntouchedByteForByte(t *testing.T) {
	foreign := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdminKeyDoNotTouch111111111 admin@corp`
	lookalike := `command="backup" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIForeignAdminKey2222222222 iamtunnel-door=deadbeefdeadbeefdeadbeefdeadbeef`
	damagedOurs := `restrict,pty,from="127.0.0.1" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7fakeProductKeyForTestsOnlyDoNotUseAnywhere iamtunnel-door=zzzz`

	dc, keyFile := newTestDoorController(t, nil)
	original := strings.Join([]string{foreign, lookalike, damagedOurs}, "\r\n") + "\r\n"
	if err := os.WriteFile(keyFile, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	firstTwoUnchanged := func(stage string, wantCount int) {
		t.Helper()
		b, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatalf("%s: read: %v", stage, err)
		}
		lines := strings.Split(strings.TrimRight(string(b), "\r\n"), "\r\n")
		if len(lines) != wantCount {
			t.Fatalf("%s: the file has %d lines left (expected %d): %q", stage, len(lines), wantCount, string(b))
		}
		for i, want := range []string{foreign, lookalike} {
			if lines[i] != want {
				t.Fatalf("%s: foreign line %d changed:\n want %q\n got  %q\nfile: %q", stage, i, want, lines[i], string(b))
			}
		}
	}

	now := time.Now()
	if r := dc.open(doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)); !r.OK {
		t.Fatalf("open refused: %+v", r.Error)
	}
	// After door.open: genuinely foreign lines (foreign, lookalike) are
	// preserved byte-for-byte at the start of the file; our corrupted
	// line (damagedOurs) is ALSO preserved — door.open does NOT touch
	// it (§5.1, PROTOCOL.md:248 "only the line with the exact
	// iamtunnel-marker"); a new valid door line is appended at the
	// end. 4 lines total.
	firstTwoUnchanged("after door.open", 4)
	if !fileContains(t, keyFile, "iamtunnel-door="+winkeysID(testDoorID)) {
		t.Fatal("our line was not added")
	}
	if !fileContains(t, keyFile, damagedOurs) {
		t.Fatalf("our corrupted line (damagedOurs) should only be removed by sanitize/SweepStale (§5.1 PROTOCOL.md:246), door.open must leave it untouched: %q", damagedOurs)
	}

	if r := dc.close(controlRequest{ID: "c", Op: "door.close", DoorID: testDoorID, Reason: "stop"}); !r.OK {
		t.Fatalf("close refused: %+v", r.Error)
	}
	// After door.close: the valid door line was removed by doorId
	// (§5.1 PROTOCOL.md:244), damagedOurs remains. 3 lines total.
	firstTwoUnchanged("after door.close", 3)
	if fileContains(t, keyFile, "iamtunnel-door="+winkeysID(testDoorID)) {
		t.Fatal("our line was not removed by close")
	}
	if !fileContains(t, keyFile, damagedOurs) {
		t.Fatal("damagedOurs should have survived door.close — only sweep/sanitize remove it")
	}

	if _, err := dc.sweepStale(); err != nil {
		t.Fatalf("SweepStale: %v", err)
	}
	// After SweepStale: damagedOurs is removed (§5.1); genuinely
	// foreign lines (including the lookalike) remain untouched in
	// their original order.
	firstTwoUnchanged("after SweepStale (as before every Start/reconnect)", 2)
	if fileContains(t, keyFile, damagedOurs) {
		t.Fatal("SweepStale must remove our corrupted line, and did not")
	}

	// door.sanitize: foreign lines (including the lookalike) must be
	// preserved byte-for-byte in their original order (2 lines). By
	// this point damagedOurs was already removed by SweepStale above;
	// even if we had preserved it, sanitize would still be required
	// to remove it.
	if r := dc.sanitize(controlRequest{ID: "z", Op: "door.sanitize", Reason: "corrupted"}); !r.OK {
		t.Fatalf("sanitize refused: %+v", r.Error)
	}
	firstTwoUnchanged("after door.sanitize", 2)
}

// ---------------------------------------------------------------------------
// T6. §3.5 — three ways a connection dies while a door is live and
// open; in each one the line must disappear from the REAL file, by
// the machine's own effort.
// ---------------------------------------------------------------------------

func TestReviewTransportDeathRemovesDoorLine(t *testing.T) {
	cases := []struct {
		name  string
		onRun func(t *testing.T, gw *reviewGateway, cancel context.CancelFunc)
	}{
		{"clean transport close by the gateway", func(t *testing.T, gw *reviewGateway, _ context.CancelFunc) {
			if err := gw.conn.Close(); err != nil {
				t.Fatalf("close transport: %v", err)
			}
		}},
		{"gateway falls silent on keepalive", func(t *testing.T, gw *reviewGateway, _ context.CancelFunc) {
			gw.keepaliveOK.Store(false) // three 120ms misses and the machine tears it down itself
		}},
		{"stopped via context (Stop/window close)", func(t *testing.T, _ *reviewGateway, cancel context.CancelFunc) {
			cancel()
		}},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			gw, ch, cfg, cancel := reviewStart(t, nil)
			req, _ := reviewDoorOpenRequest(t, testDoorID, 10*time.Minute, time.Hour)
			if resp := reviewRoundTrip(t, ch, req); !resp.OK {
				t.Fatalf("door.open refused: %+v", resp.Error)
			}
			reviewWaitUntil(t, "the door line appeared in the file",
				func() bool { return fileContains(t, cfg.KeyFile, "iamtunnel-door=") }, 5*time.Second)

			c.onRun(t, gw, cancel)

			reviewWaitUntil(t, "the machine removed its own line after the connection died",
				func() bool { return !fileContains(t, cfg.KeyFile, "iamtunnel-door=") }, 6*time.Second)
		})
	}
}

// ---------------------------------------------------------------------------
// T7. §3.6 — the machine accepts only iamtunnel-control and
// iamtunnel-target; everything else is rejected; the first control is
// not replaced by a second one.
// ---------------------------------------------------------------------------

func TestReviewForeignChannelTypesRejected(t *testing.T) {
	gw, ch, _, _ := reviewStart(t, nil)
	sc := gw.wait(t)

	for _, typ := range []string{"session", "direct-tcpip", "tcpip-forward", "chaff"} {
		if other, _, err := sc.OpenChannel(typ, nil); err == nil {
			_ = other.Close()
			t.Fatalf("channel of type %q was accepted, must be rejected", typ)
		}
	}

	// A second control is rejected; the first one keeps working.
	if second, _, err := sc.OpenChannel("iamtunnel-control", nil); err == nil {
		_ = second.Close()
		t.Fatal("a second iamtunnel-control was accepted")
	}
	if resp := reviewRoundTrip(t, ch, controlRequest{Proto: 1, Caps: []string{}, ID: "11111111-1111-1111-1111-111111111112", Op: "door.status"}); !resp.OK {
		t.Fatalf("the first control channel stopped answering: %+v", resp.Error)
	}
}

// ---------------------------------------------------------------------------
// T8. §3.6 — iamtunnel-target is a pure byte pipe: garbage (including
// syntactically valid door.open JSON and an SSH banner) is relayed to
// the target byte-for-byte and is NOT executed and NOT parsed by the
// machine.
// ---------------------------------------------------------------------------

func TestReviewTargetChannelIsPureBytePipe(t *testing.T) {
	// The target is an ordinary TCP echo server, no SSH at all. If the
	// machine parses anything at all on the target channel, the echo
	// will not match byte-for-byte.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = echoLn.Close() })
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for {
					n, rerr := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if rerr != nil {
						return
					}
				}
			}(c)
		}
	}()

	gw, _, cfg, _ := reviewStart(t, func(c *Config) { c.TargetAddr = echoLn.Addr().String() })

	// A syntactically valid door.open, the kind an attacker might slip
	// into the target channel: the machine has no right to execute it.
	openReq, _ := reviewDoorOpenRequest(t, testDoorID, time.Minute, time.Hour)
	openLine, err := json.Marshal(openReq)
	if err != nil {
		t.Fatal(err)
	}

	sc := gw.wait(t)
	target, reqs, err := sc.OpenChannel("iamtunnel-target", nil)
	if err != nil {
		t.Fatalf("open iamtunnel-target: %v", err)
	}
	go ssh.DiscardRequests(reqs)

	payload := bytes.Join([][]byte{
		[]byte("SSH-2.0-NotReallySSH\r\n"),
		{0x00, 0x01, 0x02, 0xff, 0xfe, 0x0a, 0x0d},
		openLine,
		[]byte("\n"),
		bytes.Repeat([]byte{0xA5, 0x5A}, 2048),
	}, nil)

	if _, err := target.Write(payload); err != nil {
		t.Fatalf("write target: %v", err)
	}

	got := make([]byte, len(payload))
	total := 0
	for total < len(payload) {
		n, rerr := readWithDeadline(t, target, got[total:], 5*time.Second)
		if rerr != nil && n == 0 {
			t.Fatalf("echo broke off at %d/%d bytes: %v", total, len(payload), rerr)
		}
		total += n
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("target channel corrupted the bytes: got %d bytes, got[0:16]=% x want[0:16]=% x",
			total, got[:16], payload[:16])
	}

	// The door from the "door.open" that arrived over target must stay closed.
	time.Sleep(500 * time.Millisecond)
	if fileContains(t, cfg.KeyFile, "iamtunnel-door=") {
		t.Fatal("a door.open that arrived over iamtunnel-target opened the door — the target channel is being parsed by the machine")
	}
}

// ---------------------------------------------------------------------------
// T9. §5.1 — door.status must report the actual state: exact
// installed/doorId/publicKeyFingerprint (the package's existing test
// only checks OK, see finding #1 in the report).
// ---------------------------------------------------------------------------

func TestReviewStatusReportsExactFields(t *testing.T) {
	dc, _ := newTestDoorController(t, nil)
	decode := func(t *testing.T, resp controlResponse) doorStatusResult {
		t.Helper()
		var res doorStatusResult
		if !resp.OK {
			t.Fatalf("door.status errored: %+v", resp.Error)
		}
		if err := json.Unmarshal(resp.Result, &res); err != nil {
			t.Fatalf("result did not parse: %v", err)
		}
		return res
	}

	s0 := decode(t, dc.status(controlRequest{ID: "s0", Op: "door.status"}))
	if s0.Installed {
		t.Fatalf("installed must be false before open, got %+v", s0)
	}

	req, fp := reviewDoorOpenRequest(t, testDoorID, time.Minute, time.Hour)
	if r := dc.open(req); !r.OK {
		t.Fatalf("open refused: %+v", r.Error)
	}
	s1 := decode(t, dc.status(controlRequest{ID: "s1", Op: "door.status"}))
	if !s1.Installed {
		t.Fatal("after a successful open, door.status reports installed:false — the gateway would consider the door closed")
	}
	if s1.DoorID != testDoorID {
		t.Fatalf("door.status reports doorId %q, want %q", s1.DoorID, testDoorID)
	}
	if s1.PublicKeyFingerprint != fp {
		t.Fatalf("door.status reports fingerprint %q, want %q", s1.PublicKeyFingerprint, fp)
	}
}

// ---------------------------------------------------------------------------
// §3.3/§6.2 — a fingerprint mismatch: Run must exit immediately with
// ErrFingerprintMismatch and not retry.
// ---------------------------------------------------------------------------

func TestReviewRunStopsOnFingerprintMismatch(t *testing.T) {
	machineKey := mustSigner(t)
	gw := newReviewGateway(t)
	gw.startAccept()

	tree := testsupport.NewSSHTree(t)
	cfg := Config{
		GatewayAddr:        gw.addr(),
		GatewayFingerprint: "SHA256:0000000000000000000000000000000000000000A",
		MachineID:          "vm-review",
		MachineKey:         machineKey,
		KeyFile:            tree.KeyPath("keys"),
		DoorLockPath:       filepath.Join(tree.Home, "door.lock"),
		OwnerUID:           testUIDForDoor(),
		OwnerGID:           testGIDForDoor(),
		TargetAddr:         "127.0.0.1:1",
		SpawnWatchdog:      noopSpawnWatchdog,
		BackoffBase:        50 * time.Millisecond,
		BackoffMax:         200 * time.Millisecond,
		Keepalive:          sshx.Keepalive{Interval: 100 * time.Millisecond, MaxMisses: 2},
	}
	if err := cfg.setDefaults(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	err := Run(ctx, cfg)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Run returned with no error on a wrong fingerprint")
	}
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("wanted ErrFingerprintMismatch, got: %v", err)
	}
	// Must not retry: with a 50ms backoff, an endless loop would live
	// out the whole context (5s).
	if elapsed >= 4*time.Second {
		t.Fatalf("Run retried after a fingerprint mismatch for %s — must exit immediately", elapsed)
	}
}
