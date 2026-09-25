package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// gateway_status_live_test.go proves the live half of "gateway status"
// (IAMT-89): when the gateway's state lock is genuinely held, the command
// must answer "running" with the real counts — never "not running". The
// lock IS the liveness signal runGatewayStatus listens to (gateway.go):
// state.Open returns state.ErrLockHeld when somebody already holds
// state.lock. The two real ways to hold it are exercised here:
//
//   - a real gateway: this package's own gatewayServe (the exact function
//     "gateway run" calls), which also mints the host key — so the status
//     answer must carry that key's true fingerprint;
//   - a bare state.Open (the review's "at least holds the same file
//     lock") in a data dir where no host key was ever generated — so the
//     same "running" answer must say "not generated yet".
//
// The seeded counts are deliberately all different (2 people, 3 machines,
// 1 grant) and asserted as one literal line: zero matches zero too
// easily, and with 2/3/1 any permutation or zeroing of the printed
// counts fails the test.
//
// Nothing here writes outside its own temporary directories: the data
// dir is an explicit --data-dir into a t.TempDir(), and every drive*
// call pins LOCALAPPDATA and ProgramData (driveFull does it for each
// run), so config.DirsFor can never fall through to the real
// %ProgramData%\iamtunnel.
//
// Lock discipline (the review's leak question): the seed store is closed
// before the gateway starts, the gateway is stopped and joined through
// t.Cleanup, and the bare-lock store is released through t.Cleanup — a
// leaked lock would poison every later test that opens the same
// directory, and there is no later test sharing it, but the release is
// still unconditional.

// seedLiveStatusState fills dir with 2 people, 3 machines and 1 grant
// through the same state.Store the gateway itself uses, then releases
// the store's lock so a gateway (or a bare lock holder) can take it.
func seedLiveStatusState(t *testing.T, dir string) {
	t.Helper()
	machineKeys := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		_, _, signer := genTestKey(t)
		machineKeys = append(machineKeys, authorizedKeyLine(signer.PublicKey()))
	}
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	updateErr := store.Update(func(st *state.State) error {
		for _, name := range []string{"alice", "bob"} {
			st.People = append(st.People, state.Person{Name: name, Role: "user"})
		}
		for i, key := range machineKeys {
			id := fmt.Sprintf("vm%d", i+1)
			st.Machines = append(st.Machines, state.Machine{
				ID: id, Name: id, State: "verified",
				MachineKey: key,
				OSUser:     `MACHINE\svc`,
			})
		}
		return st.GrantAccess("bob", "vm2", nil, "shell")
	})
	closeErr := store.Close()
	if updateErr != nil {
		t.Fatalf("seed state: %v", updateErr)
	}
	if closeErr != nil {
		t.Fatalf("close the seed store: %v", closeErr)
	}
}

// liveGateway is one real gatewayServe instance kept running for a
// status probe, with everything the product call does: state lock held,
// event log open, host key minted, listener serving.
type liveGateway struct {
	dir  string
	addr net.Addr
	stop chan struct{}
	done chan error
	once sync.Once
}

// startLiveGatewayForStatus raises gatewayServe on dir with port 0
// (ephemeral, loopback-only clients in the test) and fails the test
// loudly if it dies before reporting ready instead of hanging on the
// ready channel.
func startLiveGatewayForStatus(t *testing.T, dir string) *liveGateway {
	t.Helper()
	ready := make(chan net.Addr, 1)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := gatewayServe(dir, 0, func(a net.Addr) { ready <- a }, stop)
		done <- err
	}()
	lg := &liveGateway{dir: dir, stop: stop, done: done}
	select {
	case lg.addr = <-ready:
	case err := <-done:
		t.Fatalf("gatewayServe failed before reporting ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("gatewayServe did not report ready within 10s")
	}
	t.Cleanup(func() {
		lg.stopAndWait()
	})
	return lg
}

// stopAndWait shuts the gateway down and waits for a full return: only
// after gatewayServe has come back is the state lock really released
// (its own store.Close runs on its return path). The Once covers the
// wait as well as the close — the test body and the cleanup both call
// this, and a second <-done on the drained channel would hang forever.
func (lg *liveGateway) stopAndWait() {
	lg.once.Do(func() {
		close(lg.stop)
		<-lg.done
	})
}

// hostkeyFingerprintOnDisk derives the fingerprint from the host key
// file itself. It deliberately does not call readHostkeyFingerprint or
// fingerprintOfSigner: the expectation of a test must not be produced by
// the code under test.
func hostkeyFingerprintOnDisk(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(hostkeyPath(dir))
	if err != nil {
		t.Fatalf("read the host key file: %v", err)
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		t.Fatalf("parse the host key file: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		t.Fatalf("signer from the host key file: %v", err)
	}
	sum := sha256.Sum256(signer.PublicKey().Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// TestGatewayStatusLiveGatewayReportsRunningWithTrueCounts is the
// carrying assertion of IAMT-89: against a real, running gateway the
// command says "running", prints the true seeded counts (2/3/1) and the
// true host key fingerprint; after the same gateway stops, the very same
// command in the very same directory says "not running" again — the
// other half of runGatewayStatus must not break (it is what
// TestConfigPlumbingPrecedenceEndToEnd and
// TestGatewaySurfaceMatrix/status_backup already pin).
func TestGatewayStatusLiveGatewayReportsRunningWithTrueCounts(t *testing.T) {
	dir := t.TempDir()
	seedLiveStatusState(t, dir)
	lg := startLiveGatewayForStatus(t, dir)

	out, errs, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("gateway status against a live gateway: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, "iamtunnel gateway status: running (data dir ") {
		t.Fatalf("a live gateway must be reported as \"running\", got:\n%s", out)
	}
	if strings.Contains(out, "not running") {
		t.Fatalf("nothing in a live-gateway answer may say \"not running\", got:\n%s", out)
	}
	if !strings.Contains(out, "people=2 machines=3 grants=1") {
		t.Fatalf("the counts must be the seeded reality (2 people, 3 machines, 1 grant), got:\n%s", out)
	}
	if strings.Contains(out, "not generated yet") {
		t.Fatalf("gatewayServe minted a host key, so \"not generated yet\" is wrong, got:\n%s", out)
	}
	wantFP := hostkeyFingerprintOnDisk(t, dir)
	if !strings.Contains(out, "host key fingerprint: "+wantFP) {
		t.Fatalf("the printed fingerprint must be the real key's %s, got:\n%s", wantFP, out)
	}

	lg.stopAndWait()
	out2, errs2, code2 := drive(t, "gateway", "status", "--data-dir", dir)
	if code2 != exitOK {
		t.Fatalf("gateway status after stop: code=%d out=%q errs=%q", code2, out2, errs2)
	}
	if !strings.Contains(out2, "not running") {
		t.Fatalf("after the gateway stopped the command must say \"not running\" again, got:\n%s", out2)
	}
	if !strings.Contains(out2, "people=2 machines=3 grants=1") {
		t.Fatalf("the stopped-gateway answer must still carry the real counts, got:\n%s", out2)
	}
}

// TestGatewayStatusLiveLockWithoutHostkeyReportsNotGeneratedYet holds
// the very same state.lock a live gateway holds — with a plain
// state.Open and nothing else — in a data dir that never had a host
// key. The lock is liveness, so the answer must still say "running",
// and the second host key state must show in the same answer: "not
// generated yet".
func TestGatewayStatusLiveLockWithoutHostkeyReportsNotGeneratedYet(t *testing.T) {
	dir := t.TempDir()
	seedLiveStatusState(t, dir)

	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open (take the lock): %v", err)
	}
	t.Cleanup(func() {
		// Release the lock no matter how the test ends: a leaked lock on
		// this directory would fail whichever test opens it next — the
		// classic way a flaky defect is left behind.
		if cerr := store.Close(); cerr != nil {
			t.Errorf("release the state lock: %v", cerr)
		}
	})

	out, errs, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("gateway status against a held lock: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, "iamtunnel gateway status: running (data dir ") {
		t.Fatalf("a held state lock IS a live gateway for status, want \"running\", got:\n%s", out)
	}
	if strings.Contains(out, "not running") {
		t.Fatalf("a held state lock must never produce \"not running\", got:\n%s", out)
	}
	if !strings.Contains(out, "host key: not generated yet") {
		t.Fatalf("no host key exists in this data dir, want \"not generated yet\", got:\n%s", out)
	}
	if !strings.Contains(out, "people=2 machines=3 grants=1") {
		t.Fatalf("the running branch reads its counts from state.json on disk; want the seeded counts, got:\n%s", out)
	}
}
