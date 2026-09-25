package gateway

// scenarios_test.go covers the eight minimum scenarios, one test
// function per scenario. Every test drives the real Gateway through a real TCP
// listener; the only fakes are the remote peers (harness_test.go).

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// ---- 1: machine connects, names itself, control channel stays alive -------

func TestScenario1_MachineConnectsAndStaysOnline(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("machine not registered after connect")
	}
	snap := mc.doorMachine.Snapshot()
	if !snap.Online {
		t.Fatalf("machine registered but not online: %+v", snap)
	}
	if installed, _ := fm.doorInstalled(); installed {
		t.Fatal("a freshly connected machine must not already have a door installed")
	}
}

// ---- 2: full happy path, bytes reach the recording -------------------------

func TestScenario2_GrantedHumanReachesMachineAndIsRecorded(t *testing.T) {
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

	const marker = "hello-from-scenario-2"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readUntil(t, hs.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("echo did not contain marker: %q", got)
	}
	_ = hs.ch.Close()

	waitUntil(t, "session did not close on the machine side", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	txt := waitForTranscript(t, f.recordingsDir())
	if !strings.Contains(txt, marker) {
		t.Fatalf("recording transcript does not contain %q; got: %q", marker, txt)
	}
}

// ---- 3: no grant -> refused, door never touched -----------------------------

func TestScenario3_UngrantedHumanIsDeniedAndDoorNeverOpens(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	strangerKey := genSigner(t)
	if err := f.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "mallory", Role: "user",
			Keys: []state.Key{{Fingerprint: fingerprintOf(t, strangerKey.PublicKey()), Pub: authorizedLine(strangerKey.PublicKey()), Added: state.NewZonedTime(f.clock.Now())}},
		})
		return nil
	}); err != nil {
		t.Fatalf("add stranger: %v", err)
	}

	client, err := dialHuman(t, f.addr, "mallory", f.machineID, strangerKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()

	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go discardSSHRequests(reqs)

	line := readAll(t, ch, 2*time.Second)
	if !strings.Contains(line, "Access to this machine is currently unavailable") {
		t.Fatalf("expected the single generic denial line, got %q", line)
	}

	// readAll already blocked until the channel closed (or 2s), so any
	// mistaken door.open a wrongly-ordered implementation might have sent
	// has already happened by now. doorEverOpened is sticky: it catches a
	// door that opened and was then correctly closed again just as surely
	// as one still open, which a plain doorInstalled() check right here
	// would not - the whole point of "the door must never be touched at
	// all" (gate 3).
	if fm.doorEverOpened() {
		t.Fatal("door was opened at any point for a denied person")
	}
}

// ---- 4: two humans share one door, it closes after the last ---------------

func TestScenario4_TwoHumansShareOneDoorClosedAfterLast(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	dial := func() (*ssh.Client, *humanSession) {
		c, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		hs := openHumanSession(t, c, f)
		hs.shell(t)
		return c, hs
	}

	c1, hs1 := dial()
	defer c1.Close()
	c2, hs2 := dial()
	defer c2.Close()

	waitUntil(t, "both sessions did not become active", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 2
	})
	if mc, _ := f.gw.reg.get(f.machineID); mc.doorMachine.Snapshot().State != core.Open {
		t.Fatalf("door state with two live sessions = %v, want open", mc.doorMachine.Snapshot().State)
	}

	_ = hs1.ch.Close()
	waitUntil(t, "first close did not drop session count to 1", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})
	if mc, _ := f.gw.reg.get(f.machineID); mc.doorMachine.Snapshot().State != core.Open {
		t.Fatal("door closed while a session was still live")
	}

	_ = hs2.ch.Close()
	waitUntil(t, "door did not close after the last session ended", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().State == core.Closed
	})
}

// ---- 5: revoke mid-session ends the session and closes the door ----------

func TestScenario5_RevokeDuringSessionEndsItAndClosesDoor(t *testing.T) {
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

	waitUntil(t, "session did not become active before revoke", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	if _, err := f.gw.aclE.Revoke(f.person, f.machineID, f.clock.Now()); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	text := readAll(t, hs.ch, 2*time.Second)
	if !strings.Contains(text, "grant was revoked") && !strings.Contains(text, "grant expired") {
		t.Fatalf("human was not told the session ended by revoke, got %q", text)
	}

	waitUntil(t, "door did not close after revoke ended the only session", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().State == core.Closed
	})
}

// ---- 6: control channel drops mid-session -> everything cleaned up --------

func TestScenario6_ControlChannelDropMidSessionCleansEverything(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)

	waitUntil(t, "session did not become active before the drop", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	fm.close() // simulate the tunnel dying outright, not a clean door.close

	waitUntil(t, "human session was not torn down after transport loss", func() bool {
		_, err := hs.ch.SendRequest("window-change", true, sshx0())
		return err != nil
	})

	waitUntil(t, "machine was still considered online after transport loss", func() bool {
		return !f.gw.view.MachineOnline(f.machineID)
	})
	// IAMT-109: the registry removal runs at the END of teardown
	// (machine_conn.go:475, after the context cancel and the socket
	// close), while MachineOnline flips at the BEGINNING (Apply
	// (TransportLost)). The product never promised that these two
	// observable effects land in any particular order — reserve() is
	// race-safe under the closed flag, so a new reservation against a
	// still-registered mc that is already closed is rejected by the
	// same mutex teardown took — and this test's flaky ~1-in-6 failures
	// came from racing those two events. Wait for the second effect
	// the same way we waited for the first.
	waitUntil(t, "stale connection still in registry after transport loss", func() bool {
		_, stillRegistered := f.gw.reg.get(f.machineID)
		return !stillRegistered
	})
}

// ---- 7: machine reconnects, old connection evicted not duplicated ---------

func TestScenario7_MachineReconnectEvictsOldConnection(t *testing.T) {
	f := newFixture(t, nil)
	fm1 := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	mc1, _ := f.gw.reg.get(f.machineID)
	epoch1 := mc1.epoch

	fm1.close()
	waitUntil(t, "old connection was not removed after transport loss", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return !ok
	})
	fm2 := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	waitUntil(t, "old connection was not evicted", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.epoch != epoch1
	})
	mc2, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("no machine registered after reconnect")
	}
	if mc2 == mc1 {
		t.Fatal("registry still holds the pre-reconnect connection")
	}
	if mc2.epoch <= epoch1 {
		t.Fatalf("new epoch %d did not advance past old epoch %d", mc2.epoch, epoch1)
	}

	// The evicted connection's transport must actually be dead, not merely
	// forgotten by the registry (§5.2: reconnect "closes its sessions").
	waitUntil(t, "old machine transport was not actually closed", func() bool {
		_, _, err := fm1.conn.SendRequest("keepalive@iamtunnel", true, nil)
		return err != nil
	})
	_ = fm2
}

// ---- 8: keepalive failure closes the session and the door ------------------

func TestScenario8_KeepaliveFailureClosesSessionAndDoor(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.Keepalive = sshx.Keepalive{Interval: 80 * time.Millisecond, MaxMisses: 2}
	})
	// The machine answers keepalive normally while the session is being
	// established, and only then goes mute. Starting mute made the
	// assertion race its own setup: with Interval 80ms and MaxMisses 2
	// the gateway may tear the transport down before pty-req is even
	// sent, and the test then fails at pty-req with EOF instead of
	// proving anything about keepalive. Observed under load in gate 5.
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)

	waitUntil(t, "session did not become active before keepalive should fail", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	fm.goSilent()

	waitUntil(t, "keepalive failure did not tear the session down", func() bool {
		_, err := hs.ch.SendRequest("window-change", true, sshx0())
		return err != nil
	})
	waitUntil(t, "keepalive failure did not remove the machine from the registry", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return !ok
	})
}

// ---- shared helpers ----------------------------------------------------------

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

func (f *fixture) recordingsDir() string {
	return f.gw.cfg.RecordingBaseDir
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

// sshx0 is a well-formed "window-change" payload, used only as a cheap probe
// request to detect whether a channel/connection is still alive.
func sshx0() []byte {
	return sshx.MarshalWindow(sshx.WindowChange{Columns: 80, Rows: 24})
}
