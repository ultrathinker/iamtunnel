package gateway

// IAMT-466: stopping the gateway - an update, a restart of the service -
// cut every live session at once and without a word, exactly like a
// network fault; SPEC §3.5 promised a drain. Now a stop first drains:
// nothing new is taken, every live session is told the gateway is
// restarting, and the gateway waits up to its drain timeout for them to
// leave before it cuts what is left. gateway.status says draining, and
// the version and the disk it runs on.

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// iamt466ReadWithin reads r until want shows up or d passes, whichever is
// first; a Read that never returns does not hold the test.
func iamt466ReadWithin(r io.Reader, want string, d time.Duration) (string, bool) {
	found := make(chan string, 1)
	go func() {
		var acc strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			acc.Write(buf[:n])
			if strings.Contains(acc.String(), want) || err != nil {
				found <- acc.String()
				return
			}
		}
	}()
	select {
	case s := <-found:
		return s, strings.Contains(s, want)
	case <-time.After(d):
		return "", false
	}
}

func TestIAMT466_ADrainTellsTheLiveSessionAndWaitsForIt(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "the session did not start", func() bool { return len(f.gw.aclE.Sessions()) == 1 })

	drained := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		f.gw.Drain(10 * time.Second)
		drained <- time.Since(start)
	}()

	if got, ok := iamt466ReadWithin(hs.ch.Stderr(), "gateway is restarting", 5*time.Second); !ok {
		t.Fatalf("the live session was not told the gateway is restarting (stderr: %q)", got)
	}

	// Still a working session while the drain waits for it.
	const marker = "iamt-466-still-working"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write during the drain: %v", err)
	}
	readUntil(t, hs.ch, marker)
	select {
	case <-drained:
		t.Fatal("the drain did not wait for the live session")
	default:
	}

	_ = hs.ch.Close()
	select {
	case d := <-drained:
		if d > 8*time.Second {
			t.Errorf("the drain took %s after the last session left", d)
		}
	case <-time.After(9 * time.Second):
		t.Fatal("the drain did not end when the last session left")
	}
}

func TestIAMT466_NothingNewIsTakenWhileDraining(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	first, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer first.Close()
	hs := openHumanSession(t, first, f)
	hs.shell(t)
	waitUntil(t, "the session did not start", func() bool { return len(f.gw.aclE.Sessions()) == 1 })
	// A login that got in before the stop, and asks for its session after.
	late, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer late.Close()

	go f.gw.Drain(5 * time.Second)
	waitUntil(t, "the drain did not begin", func() bool { return f.gw.draining.Load() })

	// A new login is not taken...
	if c, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey); err == nil {
		_ = c.Close()
		t.Fatal("a new login was taken while the gateway was draining")
	}
	// ...nor a new session, even on a connection that was already in.
	second := openHumanSession(t, late, f)
	ok, err := second.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	if err == nil && ok {
		t.Fatal("a new session was opened while the gateway was draining")
	}
	if text := second.readLeftoverText(time.Second); !strings.Contains(text, "restarting") {
		t.Errorf("the refused session was not told why: %q", text)
	}
	_ = hs.ch.Close()
}

func TestIAMT466_ADrainGivesUpAtItsTimeout(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "the session did not start", func() bool { return len(f.gw.aclE.Sessions()) == 1 })

	start := time.Now()
	f.gw.Drain(300 * time.Millisecond)
	if d := time.Since(start); d < 250*time.Millisecond || d > 5*time.Second {
		t.Fatalf("a drain with a session that stays took %s, want about its 300ms timeout", d)
	}
}

func TestIAMT466_GatewayStatusSaysVersionDiskAndDraining(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.Version = "1.14-iamt466" })
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	status := func() map[string]any {
		t.Helper()
		raw, err := root.Exec("gateway.status", map[string]any{"proto": 1})
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	st := status()
	if st["version"] != "1.14-iamt466" {
		t.Errorf("gateway.status version = %v, want the running build's", st["version"])
	}
	if p, ok := st["diskPercent"].(float64); !ok || p < 0 || p > 100 {
		t.Errorf("gateway.status diskPercent = %v, want the used percent of the recordings disk", st["diskPercent"])
	}
	if st["draining"] != false {
		t.Errorf("gateway.status draining = %v before any stop, want false", st["draining"])
	}

	go f.gw.Drain(2 * time.Second)
	waitUntil(t, "the drain did not begin", func() bool { return f.gw.draining.Load() })
	if st := status(); st["draining"] != true {
		t.Errorf("gateway.status draining = %v while draining, want true (asked over a connection already in)", st["draining"])
	}
}
