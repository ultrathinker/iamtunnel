package core

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// IAMT-441, the second line. The recording runs inside the bridge's copy
// goroutines: machine -> human hands every chunk to rec.Write, which parses
// it the way a terminal would, and human -> machine hands every chunk to
// rec.AddBytesIn. A panic in either went through io.Copy to the top of a
// goroutine nobody recovered, and a Go program with an unrecovered panic in
// any goroutine exits: the gateway went down, and every session on it with
// it, for a fault in one.
//
// A panic in another goroutine cannot be caught from the test's own, so
// the bridge runs in a child process and this test looks at how the child
// ended: that is the only way the test can fail on its own line, and not
// merely crash, while the fault still takes the process down.

const iamt441ChildEnv = "IAMT441_BRIDGE_CHILD"

// panickingRecording is a Recording whose own code panics, standing in
// for any fault inside the real one.
type panickingRecording struct {
	onWrite, onAddBytesIn bool

	mu          sync.Mutex
	closed      bool
	aborted     bool
	abortReason string
}

func (r *panickingRecording) Write(p []byte) (int, error) {
	if r.onWrite {
		panic("recorder fault on machine output")
	}
	return len(p), nil
}

func (r *panickingRecording) AddBytesIn(p []byte) {
	if r.onAddBytesIn {
		panic("recorder fault on human input")
	}
}

func (r *panickingRecording) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *panickingRecording) Abort(reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aborted = true
	r.abortReason = reason
	return nil
}

func TestIAMT441_BridgePanicEndsTheSessionNotTheProcess(t *testing.T) {
	if os.Getenv(iamt441ChildEnv) == "1" {
		iamt441BridgeChild(t)
		return
	}
	cmd := exec.Command(os.Args[0],
		"-test.run=^TestIAMT441_BridgePanicEndsTheSessionNotTheProcess$",
		"-test.count=1", "-test.v", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), iamt441ChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("a panic inside the recording ended the whole process instead of one session (%v):\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: TestIAMT441_BridgePanicEndsTheSessionNotTheProcess") {
		t.Fatalf("the child process did not run the bridge checks:\n%s", out)
	}
}

func iamt441BridgeChild(t *testing.T) {
	cases := []struct {
		name       string
		rec        *panickingRecording
		fromHuman  []byte
		fromTarget []byte
	}{
		{"machine output", &panickingRecording{onWrite: true}, nil, []byte("A\x1b[9223372036854775807CX")},
		{"human input", &panickingRecording{onAddBytesIn: true}, []byte("ls\r"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			human, target := newFakeStream(), newFakeStream()
			if tc.fromHuman != nil {
				human.readCh <- tc.fromHuman
			}
			if tc.fromTarget != nil {
				target.readCh <- tc.fromTarget
			}
			drained := make(chan struct{})
			done := make(chan error, 1)
			go func() { done <- Bridge(context.Background(), human, target, tc.rec, drained) }()

			var err error
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Bridge did not return after the recording panicked")
			}
			if err == nil || !strings.Contains(err.Error(), "panicked") {
				t.Errorf("Bridge returned %v, want the panic as this session's error", err)
			}
			if !human.isClosed() || !target.isClosed() {
				t.Errorf("both streams must be closed after a panic: human closed=%v, target closed=%v", human.isClosed(), target.isClosed())
			}
			tc.rec.mu.Lock()
			aborted, closed, reason := tc.rec.aborted, tc.rec.closed, tc.rec.abortReason
			tc.rec.mu.Unlock()
			if !aborted || closed {
				t.Errorf("the recording must be aborted, not closed cleanly: aborted=%v closed=%v", aborted, closed)
			}
			if !strings.Contains(reason, "recorder fault") {
				t.Errorf("the abort reason %q does not say what failed", reason)
			}
			select {
			case <-drained:
			default:
				t.Errorf("targetDrained was never closed: a caller waiting on it would wait forever")
			}
		})
	}
}
