package server

// iamt194_sweep_before_first_dial_test.go — end-to-end wiring for SPEC
// §6.3 (the "BSOD/power loss" line, RUNBOOK §6 item 9): an orphaned
// door line left over from a process's "past life" (a power-loss
// crash) must be removed from the key file BEFORE the very first
// Dial, not only on reconnect. The mechanism (winkeys.Door.SweepStale)
// is covered by its own tests in internal/winkeys/doors_test.go; this
// test covers the wiring in Run — the call to sweepBeforeConnect before
// every Dial, including the first (internal/server/run.go:62).
//
// Everything runs on 127.0.0.1 and in t.TempDir(): the "gateway" is a
// raw TCP listener, the keys are a file in a temp directory; the test
// never touches a real sshd, the registry, or keys outside TempDir.

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func TestIAMT194_RunSweepsStaleDoorBeforeFirstDial(t *testing.T) {
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("administrators_authorized_keys")

	// A "past life" door line: a full, legitimate door line of ours
	// (our options prefix, a valid key, a marker with a 32-hex id) —
	// exactly what remains on disk after a BSOD/power loss with an
	// open door. The foreign line is an ordinary admin key with no
	// prefix of ours; SweepStale has no right to touch it or its bytes.
	staleDoorID := "0123456789abcdef0123456789abcdef"
	staleLine := winkeys.FormatLine(staleDoorID, winkeys.TestKey)
	foreignLine := "ssh-ed25519 " + winkeys.TestKey + " admin@corp.example"
	tree.WriteKeyFile(t, "administrators_authorized_keys", []byte(staleLine+"\n"+foreignLine+"\n"))

	// Fake gateway: a raw TCP listener. The moment of the first
	// accepted connection IS "the first Dial" (Run does the sweep
	// strictly before Dial, in the same goroutine, so by the time
	// accept fires the sweep has already finished). On the first
	// accept, the listener snapshots the key file (observed exactly at
	// the moment of the first connection, with no race against
	// retries), then closes the connection: the SSH handshake fails,
	// and Run goes into its ordinary retry with a tiny backoff, until
	// the test cancels the context.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start the fake gateway: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var (
		mu          sync.Mutex
		atFirstDial []byte
		readErr     error
		firstDial   = make(chan struct{})
		once        sync.Once
	)
	go func() {
		for {
			raw, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			once.Do(func() {
				b, rerr := os.ReadFile(keyFile)
				mu.Lock()
				atFirstDial, readErr = b, rerr
				mu.Unlock()
				close(firstDial)
			})
			_ = raw.Close()
		}
	}()

	cfg := Config{
		GatewayAddr: ln.Addr().String(),
		// A handshake against a raw TCP listener never reaches the
		// fingerprint check; the field is only here so setDefaults
		// accepts the config.
		GatewayFingerprint: "SHA256:0000000000000000000000000000000000000000A",
		MachineID:          "vm-194",
		MachineKey:         mustSigner(t),
		KeyFile:            keyFile,
		// Without DoorLockPath the sweep before the first Dial fails
		// on its own on linux/darwin ("LockPath is required") and the
		// "past life" line would remain — the test's main assertion
		// would then pass vacuously.
		DoorLockPath:     filepath.Join(tree.Home, "door.lock"),
		OwnerUID:         testUIDForDoor(),
		OwnerGID:         testGIDForDoor(),
		TargetAddr:       "127.0.0.1:1",
		SpawnWatchdog:    noopSpawnWatchdog,
		BackoffBase:      10 * time.Millisecond,
		BackoffMax:       50 * time.Millisecond,
		DialTimeout:      2 * time.Second,
		HandshakeTimeout: 500 * time.Millisecond,
	}

	// Run does not treat a sweep failure as fatal: it logs it via
	// cfg.logf and continues — by design, the sweep is retried on
	// every iteration, a transient failure heals itself, and failing
	// hard over it would mean never connecting at all (see
	// run.go:100). But with Logger == nil, logf silently does
	// nothing, and that is exactly why the "line not removed" cause
	// used to be invisible: the test had no sweep message, not even a
	// hint of one — only its own assertion about the file's contents
	// (IAMT-288: on macOS this turned out to be the same fixture
	// failure as IAMT-284 — "home directory … owned by uid 501,
	// expected uid 1000" — but logged rather than shown). Now Run's
	// log is collected and included in the failure message, so the
	// next live acceptance names the cause itself.
	var (
		logMu  sync.Mutex
		runLog []string
	)
	cfg.Logger = func(s string) {
		logMu.Lock()
		runLog = append(runLog, s)
		logMu.Unlock()
	}
	logText := func() string {
		logMu.Lock()
		defer logMu.Unlock()
		if len(runLog) == 0 {
			return "(empty)"
		}
		return strings.Join(runLog, "\n")
	}
	sweepFailure := func() string {
		logMu.Lock()
		defer logMu.Unlock()
		for _, s := range runLog {
			if strings.Contains(s, "SweepStale before connect failed") {
				return s
			}
		}
		return ""
	}

	if err := cfg.setDefaults(); err != nil {
		t.Fatalf("setDefaults: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- Run(ctx, cfg) }()

	select {
	case <-firstDial:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("the fake gateway never saw a first connection: Run never reached Dial")
	}
	mu.Lock()
	got, rerr := atFirstDial, readErr
	mu.Unlock()
	if rerr != nil {
		t.Fatalf("read the key file at the moment of the first Dial: %v", rerr)
	}
	// Main assertion: by the time of the first Dial, the orphaned door
	// line is already gone from the file, and the foreign line is
	// intact byte-for-byte. If the sweep did in fact fail, name its
	// error first — that is the actual cause, and "line not removed"
	// is only the consequence.
	if line := sweepFailure(); line != "" {
		t.Fatalf("the sweep before the first Dial failed: %s\nkey file at that moment = %q; full Run log:\n%s", line, got, logText())
	}
	want := foreignLine + "\n"
	if string(got) != want {
		t.Fatalf("at the moment of the first Dial the key file = %q, want exactly %q (the orphaned door line %q was not removed before the first connection); Run log:\n%s",
			got, want, staleLine, logText())
	}

	// Teardown: Run must exit on context cancellation (retries are
	// bounded by ctx, not by a counter).
	cancel()
	select {
	case rerr := <-runDone:
		if rerr == nil {
			t.Fatal("Run returned with no error after the context was cancelled")
		}
		if !errors.Is(rerr, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", rerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not finish within 5s of the context being cancelled")
	}
	// Run's log — into the test output (visible under -v and on a
	// green run): it explains exactly what the machine did before the
	// first Dial.
	t.Logf("Run log:\n%s", logText())
}
