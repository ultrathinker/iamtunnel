package server

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

func testConfig(t *testing.T, gw *fakeGateway, machineKey ssh.Signer, targetAddr string) Config {
	t.Helper()
	tree := testsupport.NewSSHTree(t)
	cfg := Config{
		GatewayAddr:        gw.addr(),
		GatewayFingerprint: gw.fingerprint(),
		MachineID:          "vm1",
		MachineKey:         machineKey,
		KeyFile:            tree.KeyPath("administrators_authorized_keys"),
		DoorLockPath:       filepath.Join(tree.Home, "door.lock"),
		OwnerUID:           testUIDForDoor(),
		OwnerGID:           testGIDForDoor(),
		TargetAddr:         targetAddr,
		SpawnWatchdog:      noopSpawnWatchdog,
		DialTimeout:        5 * time.Second,
		HandshakeTimeout:   5 * time.Second,
		Keepalive:          sshx.Keepalive{Interval: 200 * time.Millisecond, MaxMisses: 3},
	}
	// Dial() calls setDefaults() on its own local copy; tests that also
	// build a doorController directly from this Config (bypassing Dial)
	// need the defaults applied here too, or MaxDoorIdle/MaxDoorHard stay
	// zero and refuse every door.open.
	if err := cfg.setDefaults(); err != nil {
		t.Fatalf("setDefaults: %v", err)
	}
	return cfg
}

// ---- item 1 & 2: fingerprint check on first contact ----------------------

func TestDial_FingerprintMatch_Succeeds(t *testing.T) {
	machineKey := mustSigner(t)
	gw := newFakeGateway(t, func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(machineKey.PublicKey().Marshal()) })
	gw.startAccept()

	cfg := testConfig(t, gw, machineKey, "127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer m.conn.Close()
}

func TestDial_FingerprintMismatch_RefusesWithoutRetry(t *testing.T) {
	machineKey := mustSigner(t)
	gw := newFakeGateway(t, func(k ssh.PublicKey) bool { return true })
	gw.startAccept()

	cfg := testConfig(t, gw, machineKey, "127.0.0.1:1")
	cfg.GatewayFingerprint = "SHA256:0000000000000000000000000000000000000000A" // 43 chars, deliberately wrong

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := Dial(ctx, cfg)
	if err == nil {
		_ = m.conn.Close()
		t.Fatal("expected fingerprint mismatch to be refused")
	}
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("got err=%v, want ErrFingerprintMismatch", err)
	}
	if m != nil {
		t.Fatal("a refused Dial must not return a usable Machine")
	}
}

// ---- item 9: iamtunnel-target is a pure byte splice to TargetAddr,
// carrying a real nested SSH session end-to-end, the way the gateway's
// human_role.go actually drives it. --------------------------------------

func TestServe_TargetChannelCarriesNestedSSHEndToEnd(t *testing.T) {
	machineKey := mustSigner(t)
	humanLikeKey := mustSigner(t) // stands in for the gateway's ephemeral door-key signer
	sshd := newFakeSSHD(t, func([]byte) bool { return true })

	gw := newFakeGateway(t, func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(machineKey.PublicKey().Marshal()) })
	gw.startAccept()

	cfg := testConfig(t, gw, machineKey, sshd.addr())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- m.Serve(ctx) }()

	sc := gw.wait(t)
	targetCh, targetReqs, err := sc.OpenChannel("iamtunnel-target", nil)
	if err != nil {
		t.Fatalf("open iamtunnel-target: %v", err)
	}
	go ssh.DiscardRequests(targetReqs)

	nestedConn, nestedChans, nestedReqs, err := ssh.NewClientConn(sshx.NewChannelConn(targetCh), "target", &ssh.ClientConfig{
		User:            "whoever",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(humanLikeKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("nested ssh handshake through iamtunnel-target failed: %v", err)
	}
	defer nestedConn.Close()
	go ssh.DiscardRequests(nestedReqs)
	go func() {
		for c := range nestedChans {
			_ = c.Reject(ssh.UnknownChannelType, "unexpected")
		}
	}()

	// Open the session channel directly (the same low-level style
	// internal/gateway/human_role.go uses, not the high-level ssh.Client
	// API) and drive shell + a byte round trip through fakeSSHD's echo —
	// this is the actual proof that a human's bytes reach the target sshd
	// through the machine's splice and come back unmodified.
	sessCh, sessReqs, err := nestedConn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open nested session channel: %v", err)
	}
	defer sessCh.Close()
	go ssh.DiscardRequests(sessReqs)

	ok, err := sessCh.SendRequest("shell", true, nil)
	if err != nil || !ok {
		t.Fatalf("shell request: ok=%v err=%v", ok, err)
	}
	const marker = "hello-through-the-splice"
	if _, err := sessCh.Write([]byte(marker)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(marker))
	if _, err := readFullWithDeadline(t, sessCh, buf, 5*time.Second); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != marker {
		t.Fatalf("got %q back, want %q — bytes were altered in transit", buf, marker)
	}

	cancel()
	<-serveErrCh
}

// ---- item 8: garbage on the control channel never panics and leaves the
// door file in a clean, reusable state. -------------------------------------

func TestServe_ControlChannelGarbage_NoPanicAndCleanRecovery(t *testing.T) {
	cases := []struct {
		name             string
		garbage          []byte
		tolerateWriteErr bool
	}{
		{name: "not-json", garbage: []byte("not json at all\n")},
		{name: "malformed-door-open", garbage: []byte(`{"proto":1,"op":"door.open","id":"x","caps":[],"door":{"id":"bad"}}` + "\n")},
		// Oversized line: the machine may close the connection before
		// this large a write finishes, which surfaces here as a write
		// error rather than a clean EOF — that IS the line-length limit
		// working, not a test failure.
		{name: "oversized-line", garbage: []byte(`{"proto":1,"op":"door.status","id":"` + strings.Repeat("a", 200000) + `"}` + "\n"), tolerateWriteErr: true},
		{name: "duplicate-key", garbage: []byte(`{"proto":1,"proto":2,"op":"door.status","id":"x","caps":[]}` + "\n")},
	}

	for _, c := range cases {
		garbage := c.garbage
		t.Run(c.name, func(t *testing.T) {
			machineKey := mustSigner(t)
			gw := newFakeGateway(t, func(k ssh.PublicKey) bool { return true })
			gw.startAccept()

			cfg := testConfig(t, gw, machineKey, "127.0.0.1:1")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			m, err := Dial(ctx, cfg)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			serveErrCh := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Machine.Serve panicked on garbage input: %v", r)
					}
				}()
				serveErrCh <- m.Serve(ctx)
			}()

			ctrl := gw.openControl(t)
			if _, err := ctrl.Write(garbage); err != nil {
				if !c.tolerateWriteErr {
					t.Fatalf("write garbage: %v", err)
				}
				t.Logf("write garbage returned an error (acceptable for this case): %v", err)
			}

			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Serve did not return after garbage + context cancellation")
			}

			// The key file must still be usable for a legitimate open
			// afterwards — garbage on one connection must not corrupt
			// state that survives into the next one.
			dc, err := newDoorController(&cfg)
			if err != nil {
				t.Fatalf("newDoorController after garbage: %v", err)
			}
			resp := dc.open(doorOpenRequest(t, testDoorID, time.Now(), time.Minute, time.Hour))
			if !resp.OK {
				t.Fatalf("door.open after a garbage connection was refused: %+v", resp.Error)
			}
		})
	}
}

func TestServe_DuplicateControlChannelRejectedFirstStaysAlive(t *testing.T) {
	machineKey := mustSigner(t)
	gw := newFakeGateway(t, func(k ssh.PublicKey) bool { return true })
	gw.startAccept()

	cfg := testConfig(t, gw, machineKey, "127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	serveInBackground(t, ctx, cancel, m)

	sc := gw.wait(t)

	first, firstReqs, err := sc.OpenChannel("iamtunnel-control", nil)
	if err != nil {
		t.Fatalf("open first control channel: %v", err)
	}
	go ssh.DiscardRequests(firstReqs)

	second, secondReqs, err := sc.OpenChannel("iamtunnel-control", nil)
	if err == nil {
		go ssh.DiscardRequests(secondReqs)
		_ = second.Close()
		t.Fatal("second iamtunnel-control channel must be rejected")
	}

	// First channel must still work: send a legitimate door.status.
	if _, err := first.Write([]byte(`{"proto":1,"caps":[],"id":"11111111-1111-1111-1111-111111111111","op":"door.status"}` + "\n")); err != nil {
		t.Fatalf("write to first control channel after duplicate rejection: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := readWithDeadline(t, first, buf, 3*time.Second)
	if err != nil {
		t.Fatalf("first control channel did not answer after duplicate rejection: %v", err)
	}
	if n == 0 {
		t.Fatal("empty response from first control channel")
	}
}

func TestServe_InitialPayloadRejectedTunnelStaysUsableAndLegalOpensPass(t *testing.T) {
	machineKey := mustSigner(t)
	gw := newFakeGateway(t, func(ssh.PublicKey) bool { return true })
	gw.startAccept()

	cfg := testConfig(t, gw, machineKey, "127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	serveInBackground(t, ctx, cancel, m)
	sc := gw.wait(t)

	// ExtraData is opaque raw bytes. Neither a run of NUL bytes nor the
	// wire encoding of an empty SSH string means "no payload".
	for _, tc := range []struct {
		name    string
		channel string
		payload []byte
	}{
		{"control with text", "iamtunnel-control", []byte("attacker-controlled-bytes")},
		{"target with text", "iamtunnel-target", []byte("attacker-controlled-bytes")},
		{"control with four NUL bytes", "iamtunnel-control", []byte{0, 0, 0, 0}},
		{"target with encoded empty SSH string", "iamtunnel-target", []byte{0, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ch, _, err := sc.OpenChannel(tc.channel, tc.payload); err == nil {
				_ = ch.Close()
				t.Fatalf("%s with %d initial payload bytes was accepted", tc.channel, len(tc.payload))
			}
		})
	}

	control, controlReqs, err := sc.OpenChannel("iamtunnel-control", nil)
	if err != nil {
		t.Fatalf("legal control after rejected opens: %v", err)
	}
	defer control.Close()
	go ssh.DiscardRequests(controlReqs)
	if _, err := control.Write([]byte(`{"proto":1,"caps":[],"id":"11111111-1111-1111-1111-111111111111","op":"door.status"}` + "\n")); err != nil {
		t.Fatalf("write legal status after rejected opens: %v", err)
	}
	buf := make([]byte, 4096)
	if n, err := readWithDeadline(t, control, buf, 3*time.Second); err != nil || n == 0 {
		t.Fatalf("legal control did not answer after rejected opens: n=%d err=%v", n, err)
	}

	for n := 1; n <= 2; n++ {
		target, targetReqs, err := sc.OpenChannel("iamtunnel-target", nil)
		if err != nil {
			t.Fatalf("legal target #%d after rejected opens: %v", n, err)
		}
		go ssh.DiscardRequests(targetReqs)
		_ = target.Close()
	}
}

func readFullWithDeadline(t *testing.T, ch ssh.Channel, buf []byte, timeout time.Duration) (int, error) {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		n, err := io.ReadFull(ch, buf)
		resCh <- result{n, err}
	}()
	select {
	case r := <-resCh:
		return r.n, r.err
	case <-time.After(timeout):
		return 0, os.ErrDeadlineExceeded
	}
}

func readWithDeadline(t *testing.T, ch ssh.Channel, buf []byte, timeout time.Duration) (int, error) {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		n, err := ch.Read(buf)
		resCh <- result{n, err}
	}()
	select {
	case r := <-resCh:
		return r.n, r.err
	case <-time.After(timeout):
		return 0, os.ErrDeadlineExceeded
	}
}
