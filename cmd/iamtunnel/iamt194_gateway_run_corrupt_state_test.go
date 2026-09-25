package main

// iamt194_gateway_run_corrupt_state_test.go — the end-to-end wiring of
// the maintainer's IAMT-179 decision (SPEC §3.5/§8): "gateway run" with
// a corrupted state.json refuses to start ENTIRELY — no half-service
// with amnesia. The mechanism (parseStateBytes/CorruptStateError) is
// covered by internal/gateway/state tests; this test holds the
// cmd-level wiring through the same path "gateway run" takes: run() →
// cmdGatewayRun → runGatewayServe → gatewayServeWithSettings
// (cmd/iamtunnel/gateway.go, state.Open's refusal branch).
//
// Assertions: the exit code is the env class (3, not the user class 2
// "state lock"), stderr carries the verbatim text of
// state.CorruptStateError, the port listener is not up, state.json is
// not rewritten (the bytes are the same), and state.lock is free after
// the refusal — reacquiring it with the package's own primitive passes
// (round 2: the refusal path must not leak the descriptor/lock).
// The data directory is t.TempDir(); no real port (an ephemeral one,
// checked by a failed dial) and no files outside the TempDir are ever
// touched.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestIAMT194_GatewayRunRefusesCorruptState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, state.StateFileName)

	// An empty state.json is a realistic corruption (a write torn by a
	// power loss) with a FULLY deterministic error text: parseStateBytes
	// (the "empty file" branch) produces it without the json parser, so
	// the expected CorruptStateError text does not depend on the
	// encoding/json version.
	if err := os.WriteFile(statePath, nil, 0o600); err != nil {
		t.Fatalf("prepare empty state.json: %v", err)
	}
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state.json before the run: %v", err)
	}

	// A free port: if the refusal branch worked, no listener must appear
	// on it.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("grab the probe port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	// drive() is synchronous: "gateway run" in a working refusal branch
	// returns right away. The observation is bounded below in time so
	// that the canary "the branch was replaced with a read-only
	// continuation" turns red with this test's own clear line, not with
	// the package-wide timeout.
	type driveResult struct {
		out, errs string
		code      int
	}
	done := make(chan driveResult, 1)
	go func() {
		out, errs, code := drive(t, "gateway", "run", "--data-dir", dir, "--port", strconv.Itoa(port), "--public-host", "gw.example.test")
		done <- driveResult{out: out, errs: errs, code: code}
	}()
	var res driveResult
	select {
	case res = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("gateway run did not return within 30s on a corrupted state.json: the refusal branch did not fire (the gateway kept running instead of refusing)")
	}
	if res.code != exitEnv {
		t.Fatalf("exit code = %d, out=%q errs=%q, want exitEnv (%d): a corrupted state.json is environment/data, not a usage error and not \"already running\"", res.code, res.out, res.errs, exitEnv)
	}

	// The verbatim CorruptStateError text
	// (internal/gateway/state/errors.go:51) exactly as the type itself
	// assembles it; the "gateway run: " prefix is the
	// gatewayServeWithSettings wrapper.
	wantErr := (&state.CorruptStateError{
		Path:    statePath,
		Snippet: "(empty file)",
		Err:     errors.New("state file is empty (unexpected EOF)"),
	}).Error()
	want := "gateway run: " + wantErr
	if !strings.Contains(res.errs, want) {
		t.Fatalf("stderr does not contain the verbatim CorruptStateError text:\nwant: %s\ngot: %s", want, res.errs)
	}
	if strings.Contains(res.errs, "already holds the state lock") {
		t.Fatalf("the refusal went down the \"state lock\" branch instead of \"corrupted state\": %q", res.errs)
	}

	// state.json must remain untouched byte-for-byte: the refusal branch
	// repairs nothing and rewrites nothing.
	after, rerr := os.ReadFile(statePath)
	if rerr != nil {
		t.Fatalf("read state.json after the refusal: %v", rerr)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("state.json was rewritten during the refused start: was %d bytes, now %d", len(before), len(after))
	}

	// Lock/descriptor leak on the refusal path (IAMT-194, round 2): on
	// corruption state.Open returns, along with the error, a read-only
	// Store already holding state.lock; the refusal branch must close
	// it. After gateway run returns, reacquiring the lock with the same
	// package primitive must pass. It turns red on BOTH platforms: flock
	// is bound to the open file descriptor (a second flock from the same
	// process gets EWOULDBLOCK), LockFileEx even more so; where Linux
	// would silently survive the deletion of an open file, this
	// acquisition still refuses.
	leakProbe, lerr := state.AcquireFileLock(filepath.Join(dir, state.LockFileName))
	if lerr != nil {
		t.Fatalf("state.lock remained held after the gateway run refusal: %v — the lock/descriptor leaked on the refusal path", lerr)
	}
	if leakProbe != nil {
		_ = leakProbe.Unlock()
	}

	// The listener is not up: nobody is listening on the chosen port.
	conn, derr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if derr == nil {
		_ = conn.Close()
		t.Fatalf("port %d was accepted by someone: the gateway raised a listener although it had to refuse because of the corrupted state.json", port)
	}
}
