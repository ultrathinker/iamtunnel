package gateway

// shutdown_test.go covers IAMT-68: Close must return. Every wait in the
// runtime - a control round trip, a handshake, a human bridge, a pending
// channel-open - ends when the peer transport dies, so Close cuts the
// transports and the handlers finish their own teardown paths.
//
// The tests here never hang with the code they test: every Close call runs
// in its own goroutine against a timeout guarded by select/t.Fatal, so a
// regression turns into a red test in seconds instead of a wedged CI
// machine (IAMT-68, item 1).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// closeWithin runs g.Close in a goroutine and fails the test by its OWN
// timeout if it does not return within limit. This is what makes these
// tests usable: if Close wedges, the test goes red at `limit`, it does not
// wedge with the product code.
func closeWithin(t *testing.T, f *fixture, limit time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f.gw.Close() }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatal("Gateway.Close did not return within " + limit.String())
		return nil
	}
}

// machineGoneAndTransportDead asserts the shutdown actually ended the
// machine's epoch: it is out of the registry and its transport is dead.
func machineGoneAndTransportDead(t *testing.T, f *fixture, fm *fakeMachine) {
	t.Helper()
	waitUntil(t, "machine was still registered after Close", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return !ok
	})
	waitUntil(t, "machine transport survived Close", func() bool {
		_, _, err := fm.conn.SendRequest("keepalive@iamtunnel", true, nil)
		return err != nil
	})
}

// ---- item 1: the load-bearing assertion -------------------------------------
//
// A machine that connects, keeps its tunnel and never answers door.status
// drives the §5.2 reconciliation retry loop forever; Close must still
// return. On the pre-IAMT-68 runtime this test goes red at its own
// timeout, because the handler goroutine spinning the reconciliation loop
// holds the WaitGroup forever.

func TestCloseReturnsWhileMachineSilentlyIgnoresDoorStatus(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		// A short status deadline makes the reconciliation loop spin fast
		// (~10 turns/s): the hang must not depend on the production 5s
		// numbers to reproduce.
		cfg.DoorStatusTimeout = 100 * time.Millisecond
	})
	f.connectMachine(fakeMachineBehavior{hangStatus: true})

	// The machine registered and its handler is stuck in the initial
	// door.status reconciliation loop before Close is attempted.
	waitUntil(t, "silent machine was not registered", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return ok
	})
	time.Sleep(300 * time.Millisecond)

	if err := closeWithin(t, f, 10*time.Second); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fm := f.current
	machineGoneAndTransportDead(t, f, fm)
}

// ---- item 2: Close returns in every other live state, exhaustively ---------
//
// Each subtest is one state the gateway can be in when Stop arrives. The
// live-human-session subtest is also item 3's proof: the decision is "cut
// the session immediately and finalize its recording" - the transcript
// must be complete on disk by the time Close returns.

func TestCloseReturnsInEveryLiveState(t *testing.T) {
	t.Run("01-no-connections", func(t *testing.T) {
		f := newFixture(t, nil)
		if err := closeWithin(t, f, 5*time.Second); err != nil {
			t.Fatalf("Close with no peers: %v", err)
		}
	})

	t.Run("02-live-answering-machine", func(t *testing.T) {
		f := newFixture(t, nil)
		fm := f.connectMachine(fakeMachineBehavior{})
		f.waitMachineOnline(t)
		if err := closeWithin(t, f, 10*time.Second); err != nil {
			t.Fatalf("Close with a live machine: %v", err)
		}
		machineGoneAndTransportDead(t, f, fm)
	})

	t.Run("03-machine-mid-door-open", func(t *testing.T) {
		f := newFixture(t, nil)
		f.connectMachine(fakeMachineBehavior{hangOpen: true})
		f.waitMachineOnline(t)

		client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
		if err != nil {
			t.Fatalf("human dial: %v", err)
		}
		defer client.Close()
		hs := openHumanSession(t, client, f)

		// The reservation is in: the automaton sent door.open and the
		// machine never answers it - the machine handler is parked mid-
		// command, the human handler mid-reservation. (No pty/shell here:
		// those are only proxied once the door is open, which is exactly
		// the state this subtest freezes.)
		waitUntil(t, "door never reached the opening state", func() bool {
			mc, ok := f.gw.reg.get(f.machineID)
			return ok && mc.doorMachine.Snapshot().State == core.Opening
		})

		if err := closeWithin(t, f, 10*time.Second); err != nil {
			t.Fatalf("Close mid door.open: %v", err)
		}
		// The parked reservation must have been failed, not forgotten: the
		// setup path is gone and nothing of the half-open session survives.
		waitUntil(t, "human channel survived Close mid-reservation", func() bool {
			_, err := hs.ch.SendRequest("window-change", true, sshx0())
			return err != nil
		})
		waitUntil(t, "machine was still registered after Close", func() bool {
			_, ok := f.gw.reg.get(f.machineID)
			return !ok
		})
	})

	t.Run("04-live-human-session", func(t *testing.T) {
		f := newFixture(t, nil)
		f.connectMachine(fakeMachineBehavior{})
		f.waitMachineOnline(t)

		client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
		if err != nil {
			t.Fatalf("human dial: %v", err)
		}
		defer client.Close()
		hs := openHumanSession(t, client, f)
		hs.shell(t)

		const marker = "byte-before-shutdown"
		if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		got := readUntil(t, hs.ch, marker)
		if !strings.Contains(got, marker) {
			t.Fatalf("echo did not contain marker: %q", got)
		}
		waitUntil(t, "session did not become active before Close", func() bool {
			mc, ok := f.gw.reg.get(f.machineID)
			return ok && mc.doorMachine.Snapshot().Sessions == 1
		})

		if err := closeWithin(t, f, 10*time.Second); err != nil {
			t.Fatalf("Close with a live human session: %v", err)
		}

		// Item 3's decision, stated as behavior: the session is cut, and
		// its recording is finalized (status aborted, transcript complete)
		// BEFORE Close returns. A record without .txt/.meta is a disputed
		// session - the whole thing a graceful stop exists to prevent.
		txt := waitForTranscript(t, f.recordingsDir())
		if !strings.Contains(txt, marker) {
			t.Fatalf("transcript finalized at Close does not contain %q; got %q", marker, txt)
		}
		metas := findFiles(t, f.recordingsDir(), ".meta")
		if len(metas) == 0 {
			t.Fatal("no .meta was finalized for the session cut by Close")
		}
		raw := readOne(t, metas[0])
		if !strings.Contains(raw, "aborted") {
			t.Fatalf("finalized meta does not record the abort: %s", raw)
		}
	})
}

// ---- item 4: double Close is safe -------------------------------------------

func TestDoubleCloseIsSafe(t *testing.T) {
	t.Run("twice-with-live-machine", func(t *testing.T) {
		f := newFixture(t, func(cfg *Config) {
			cfg.DoorStatusTimeout = 100 * time.Millisecond
		})
		f.connectMachine(fakeMachineBehavior{hangStatus: true})
		waitUntil(t, "silent machine was not registered", func() bool {
			_, ok := f.gw.reg.get(f.machineID)
			return ok
		})

		if err := closeWithin(t, f, 10*time.Second); err != nil {
			t.Fatalf("first Close: %v", err)
		}
		// The second Close must answer at once: same flag check as the
		// first, nothing left to wait for, and - above all - no panic.
		done := make(chan error, 1)
		go func() { done <- f.gw.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("second Close: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("second Close did not return within 2s")
		}
	})

	t.Run("close-before-serve", func(t *testing.T) {
		dir := t.TempDir()
		store, log, hostKey := bareStoreAndLog(t, dir)
		gw, err := New(Config{Store: store, Log: log, HostKey: hostKey})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		// Close without Serve: ln is nil, the registry is empty - the
		// shutdown path must survive its own simplest case.
		done := make(chan error, 1)
		go func() { done <- gw.Close() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Close before Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Close before Serve did not return within 2s")
		}
	})
}

// ---- shared small helpers ----------------------------------------------------

// bareStoreAndLog builds the minimum Config inputs for a gateway that no
// peer ever dials. It touches nothing outside t.TempDir().
func bareStoreAndLog(t *testing.T, dir string) (*state.Store, *events.Log, ssh.Signer) {
	t.Helper()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("events.OpenLog: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return store, log, genSigner(t)
}

func findFiles(t *testing.T, root, suffix string) []string {
	t.Helper()
	var hits []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, suffix) {
			hits = append(hits, path)
		}
		return nil
	})
	return hits
}

func readOne(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
