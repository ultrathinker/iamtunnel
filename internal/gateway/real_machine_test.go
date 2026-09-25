//go:build windows

package gateway

// real_machine_test.go plugs the real machine role (internal/server) into
// the exact same fixture harness_test.go/scenarios_test.go already build
// for the fake machine — same real Gateway, same real door automaton, same
// real ACL/state/events — swapping only the peer that plays the machine
// side of the wire. The nine minimum scenarios must be checked against
// the gateway that is "already working", built on
// harness_test.go rather than duplicating it; this file is that seam,
// added as new code rather than any edit to the two files it builds on.
//
// The real machine spawns a REAL doorwatch subprocess (winkeys.
// SpawnWatchdog against a freshly built iamtunnel.exe) and writes to a
// REAL temp file with the REAL winkeys ACL/lock code — nothing about the
// door mechanics here is faked; only the "sshd on 127.0.0.1:22" the
// gateway's nested handshake talks to is a loopback fake, exactly as
// the minimum-scenario list requires (only the machine's sshd may
// remain fake).

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/server"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

var (
	buildIamtunnelOnce sync.Once
	iamtunnelExePath   string
	iamtunnelBuildErr  error
)

// buildIamtunnelExe compiles the real cmd/iamtunnel binary once per test
// binary run, the same way internal/winkeys/doorwatch_test.go's build()
// helper does for its own watchdog tests — this is not a fake stand-in,
// it is the actual "iamtunnel server doorwatch" subcommand (cmd/iamtunnel/
// server.go's cmdServerDoorwatch, wired to winkeys.RunWatchdog).
func buildIamtunnelExe(t *testing.T) string {
	t.Helper()
	buildIamtunnelOnce.Do(func() {
		dir, err := os.MkdirTemp("", "iamtunnel-real-machine-build")
		if err != nil {
			iamtunnelBuildErr = err
			return
		}
		name := "iamtunnel"
		if runtime.GOOS == "windows" {
			name = "iamtunnel.exe"
		}
		dst := filepath.Join(dir, name)
		root, err := os.Getwd()
		if err != nil {
			iamtunnelBuildErr = err
			return
		}
		cmd := exec.Command("go", "build", "-o", dst, "github.com/ultrathinker/iamtunnel/cmd/iamtunnel")
		cmd.Dir = root
		cmd.Env = testsupport.IamtunnelBuildEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			iamtunnelBuildErr = errWithOutput(err, out)
			return
		}
		iamtunnelExePath = dst
	})
	if iamtunnelBuildErr != nil {
		t.Fatalf("build iamtunnel.exe for real-machine tests: %v", iamtunnelBuildErr)
	}
	return iamtunnelExePath
}

type buildOutputError struct {
	err error
	out []byte
}

func (e *buildOutputError) Error() string       { return e.err.Error() + "\n" + string(e.out) }
func errWithOutput(err error, out []byte) error { return &buildOutputError{err: err, out: out} }

// realMachine is one running server.Run loop wired to a fixture, plus the
// fake sshd it splices to and the key file it writes.
type realMachine struct {
	keyFile string
	sshd    *fakeTargetSSHD
	cancel  context.CancelFunc
	done    chan struct{}
}

// startRealMachine points the fixture's machine record at a fresh fake
// sshd (so the nested handshake's pinned host key matches this test's own
// target, not any other test's) and starts a real server.Run loop against
// the fixture's gateway.
func startRealMachine(t *testing.T, f *fixture) *realMachine {
	return startRealMachineMode(t, f, nil, true)
}

func startRealMachineOnce(t *testing.T, f *fixture, initialKeyFile []byte) *realMachine {
	return startRealMachineMode(t, f, initialKeyFile, false)
}

func startRealMachineMode(t *testing.T, f *fixture, initialKeyFile []byte, reconnect bool) *realMachine {
	t.Helper()
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("administrators_authorized_keys")
	if initialKeyFile != nil {
		tree.WriteKeyFile(t, "administrators_authorized_keys", initialKeyFile)
	}

	sshd := newFakeTargetSSHD(t, func(blob []byte) bool {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return false
		}
		return strings.Contains(string(b), base64.StdEncoding.EncodeToString(blob))
	})

	sshdHostKeyLine := authorizedLine(sshd.signer.PublicKey())
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID == f.machineID {
				st.Machines[i].SSHDHostKey = &sshdHostKeyLine
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("point fixture machine at this test's fake sshd: %v", err)
	}

	exe := buildIamtunnelExe(t)
	cfg := server.Config{
		GatewayAddr:        f.addr,
		GatewayFingerprint: ssh.FingerprintSHA256(f.gw.cfg.HostKey.PublicKey()),
		MachineID:          f.machineID,
		MachineKey:         f.machineKey,
		KeyFile:            keyFile,
		DoorLockPath:       filepath.Join(tree.Home, "door.lock"),
		OwnerUID:           testUIDForDoor(),
		OwnerGID:           testGIDForDoor(),
		TargetAddr:         sshd.addr(),
		DoorwatchExe:       exe,
		Keepalive:          sshx.Keepalive{Interval: 150 * time.Millisecond, MaxMisses: 3},
		BackoffBase:        50 * time.Millisecond,
		BackoffMax:         500 * time.Millisecond,
		Logger:             func(s string) { t.Logf("server: %s", s) },
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if reconnect {
			_ = server.Run(ctx, cfg)
			return
		}
		m, err := server.Dial(ctx, cfg)
		if err != nil {
			t.Logf("single-lifetime server dial: %v", err)
			return
		}
		_ = m.Serve(ctx)
	}()

	rm := &realMachine{keyFile: keyFile, sshd: sshd, cancel: cancel, done: done}
	t.Cleanup(func() {
		rm.cancel()
		select {
		case <-rm.done:
		case <-time.After(5 * time.Second):
		}
	})
	return rm
}

// fileHasDoorLine is a polling predicate (every caller wraps it in
// waitUntil), so a transient Windows sharing violation while the real
// winkeys writer is mid-rename (writeAtomic's tmp-file swap) must not
// abort the test outright — it is retried a few times here, and any
// caller's own waitUntil timeout is what actually catches a genuinely
// stuck file.
func (rm *realMachine) fileHasDoorLine(t *testing.T) bool {
	t.Helper()
	var b []byte
	var err error
	for i := 0; i < 20; i++ {
		b, err = os.ReadFile(rm.keyFile)
		if err == nil {
			return strings.Contains(string(b), "iamtunnel-door=")
		}
		if os.IsNotExist(err) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("read key file: %v", err)
	return false
}

// fileEquals is a polling predicate because winkeys replaces the file
// atomically and Windows can briefly deny a concurrent read.  Success is a
// byte-for-byte comparison, not merely a check that some foreign line exists.
func (rm *realMachine) fileEquals(t *testing.T, want []byte) bool {
	t.Helper()
	var b []byte
	var err error
	for i := 0; i < 20; i++ {
		b, err = os.ReadFile(rm.keyFile)
		if err == nil {
			return bytes.Equal(b, want)
		}
		if os.IsNotExist(err) {
			return len(want) == 0
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("read key file for byte-for-byte comparison: %v", err)
	return false
}

func foreignKeyFile(t *testing.T) []byte {
	t.Helper()
	return []byte(authorizedLine(genSigner(t).PublicKey()) + "\r\n")
}

// ---- item 1: the real machine connects, the fingerprint pins, control
// stays alive, and it comes online with no door touched. --------------------

func TestRealMachine_ConnectsAndComesOnline(t *testing.T) {
	f := newFixture(t, nil)
	rm := startRealMachine(t, f)
	f.waitMachineOnline(t)

	if rm.fileHasDoorLine(t) {
		t.Fatal("a freshly connected machine must not already have a door installed")
	}
}

// ---- items 3 & 9: a granted human's session opens a real door line on a
// real file (watchdog spawned via a real subprocess), reaches the fake
// sshd through a real nested SSH handshake over the real splice, and the
// gateway records the bytes. ------------------------------------------------

func TestRealMachine_GrantedHumanOpensRealDoorAndReachesSSHD(t *testing.T) {
	f := newFixture(t, nil)
	rm := startRealMachine(t, f)
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()

	hs := openHumanSession(t, client, f)
	hs.shell(t)

	const marker = "hello-from-real-machine-test"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readUntil(t, hs.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("echo did not contain marker: %q", got)
	}

	if !rm.fileHasDoorLine(t) {
		t.Fatal("expected a real door line to be installed in the real key file while the session is live")
	}

	_ = hs.ch.Close()

	// ---- item 6: after the session ends, the gateway drives door.close
	// and the real winkeys line disappears from the real file. -------------
	waitUntil(t, "door line was not removed from the real key file after close", func() bool {
		return !rm.fileHasDoorLine(t)
	})
}

// ---- item 7: killing the transport out from under the real machine makes
// it remove its own door line under lock, without the gateway's help. ------

func TestRealMachine_TransportLossRemovesOwnDoorLine(t *testing.T) {
	f := newFixture(t, nil)
	foreign := foreignKeyFile(t)
	rm := startRealMachineOnce(t, f, foreign)
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)

	waitUntil(t, "door line never appeared", func() bool { return rm.fileHasDoorLine(t) })

	// Sever the machine's own connection to the gateway (not the gateway's
	// side): the live server must notice on its own and clean up, the same
	// invariant PROTOCOL §5.2 layer 2 states for Stop/keepalive loss.
	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("machine not registered")
	}
	_ = mc.sconn.Close()

	waitUntil(t, "real machine did not remove its own door line after transport loss", func() bool {
		return !rm.fileHasDoorLine(t)
	})
	waitUntil(t, "transport cleanup altered the foreign key", func() bool {
		return rm.fileEquals(t, foreign)
	})
}

func TestRealMachine_ForeignKeySurvivesTransportReconnectAndCleanup(t *testing.T) {
	f := newFixture(t, nil)
	foreign := foreignKeyFile(t)
	rm := startRealMachineMode(t, f, foreign, true)
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "door line never appeared", func() bool { return rm.fileHasDoorLine(t) })

	old, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("machine not registered")
	}
	_ = old.sconn.Close()

	waitUntil(t, "machine did not reconnect after transport loss", func() bool {
		current, ok := f.gw.reg.get(f.machineID)
		return ok && current != old && current.doorMachine.Snapshot().Online
	})
	waitUntil(t, "reconnect/sweep altered the foreign key", func() bool {
		return rm.fileEquals(t, foreign)
	})

	rm.cancel()
	select {
	case <-rm.done:
	case <-time.After(5 * time.Second):
		t.Fatal("real machine did not stop after cancellation")
	}
	if !rm.fileEquals(t, foreign) {
		t.Fatal("local cleanup altered the foreign key")
	}
}
