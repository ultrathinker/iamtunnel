//go:build windows

package gateway

// IAMT-444: two people's registrations on one Windows machine, and one of
// them has a door open. Since 1.4 each person runs a server of his own on
// a shared machine, and on Windows both write their door lines into the
// one file sshd reads for administrators; the owner tag
// (iamtunnel-owner=<registration>) says whose line is whose, and every
// sweep leaves another registration's line alone.
//
// door.status did not. parseDiskDoorStatus reported the first door line
// in the file, whoever's it was, and did not even read the 1.4 tail: the
// owner tag after the id failed its "only blanks after 32 hex" check, so
// the id came back empty. For the gateway, installed with no id is a
// corrupted line, and it answers that with door.sanitize; the machine's
// sweep rightly left the other person's line where it was; the gateway,
// told the sweep succeeded, asked door.status again - and saw the same
// line. The second registration never came online, and the journal grew
// by a door.sanitize entry per round trip for as long as the first
// person's door stayed open.
//
// This drives both registrations for real: two real servers on one real
// key file, a person really inside through the first, and the second
// started while that door is open.

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/server"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// iamt444Registration starts a real server.Run for one registration on a
// key file it may share with another, with a fake sshd of its own that
// admits exactly the keys that file holds.
func iamt444Registration(t *testing.T, f *fixture, id string, key ssh.Signer, keyFile, lockPath string) {
	t.Helper()
	sshd := newFakeTargetSSHD(t, func(blob []byte) bool {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return false
		}
		return strings.Contains(string(b), base64.StdEncoding.EncodeToString(blob))
	})
	hostKeyLine := authorizedLine(sshd.signer.PublicKey())
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID == id {
				st.Machines[i].SSHDHostKey = &hostKeyLine
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("point %s at its fake sshd: %v", id, err)
	}

	cfg := server.Config{
		GatewayAddr:        f.addr,
		GatewayFingerprint: ssh.FingerprintSHA256(f.gw.cfg.HostKey.PublicKey()),
		MachineID:          id,
		MachineKey:         key,
		KeyFile:            keyFile,
		DoorLockPath:       lockPath,
		OwnerUID:           testUIDForDoor(),
		OwnerGID:           testGIDForDoor(),
		TargetAddr:         sshd.addr(),
		DoorwatchExe:       buildIamtunnelExe(t),
		Keepalive:          sshx.Keepalive{Interval: 150 * time.Millisecond, MaxMisses: 3},
		BackoffBase:        50 * time.Millisecond,
		BackoffMax:         500 * time.Millisecond,
		Logger:             func(s string) { t.Logf("server %s: %s", id, s) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Run(ctx, cfg)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
}

// iamt444DoorLine returns the door line of registration owner in the key
// file, or "" when it holds none.
func iamt444DoorLine(t *testing.T, keyFile, owner string) string {
	t.Helper()
	var b []byte
	var err error
	for i := 0; i < 20; i++ {
		// winkeys swaps the file atomically; Windows can refuse a read
		// for the instant of the rename.
		if b, err = os.ReadFile(keyFile); err == nil || os.IsNotExist(err) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.Contains(line, "iamtunnel-door=") && strings.HasSuffix(line, " iamtunnel-owner="+owner) {
			return line
		}
	}
	return ""
}

func iamt444Journal(f *fixture, typ events.EventType, machine string) int {
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{typ}, Object: machine})
	if err != nil {
		return 0
	}
	return len(evs)
}

func TestIAMT444_ASecondRegistrationComesOnlineBesideAnOpenDoor(t *testing.T) {
	f := newFixture(t, nil)
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("administrators_authorized_keys")
	lockPath := filepath.Join(tree.Home, "door.lock")

	// The second registration: another person's server on the same
	// machine, known to the gateway exactly like the first.
	const second = "vm2"
	secondKey := genSigner(t)
	if err := f.store.Update(func(st *state.State) error {
		var first state.Machine
		for _, m := range st.Machines {
			if m.ID == f.machineID {
				first = m
			}
		}
		m := first
		m.ID, m.Name = second, second
		m.MachineKey = authorizedLine(secondKey.PublicKey())
		st.Machines = append(st.Machines, m)
		return nil
	}); err != nil {
		t.Fatalf("register the second machine: %v", err)
	}

	// The first registration comes up and a person goes in through it:
	// its door line, tagged with its own name, is now live in the file.
	iamt444Registration(t, f, f.machineID, f.machineKey, keyFile, lockPath)
	f.waitMachineOnline(t)
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	if got := iamt444Echo(t, hs, "before"); !strings.Contains(got, "before") {
		t.Fatalf("precondition: the first registration's session does not echo: %q", got)
	}
	liveLine := iamt444DoorLine(t, keyFile, f.machineID)
	if liveLine == "" {
		t.Fatalf("precondition: no door line of %s in the shared key file while its session is live", f.machineID)
	}

	// The second registration starts while that door is open.
	iamt444Registration(t, f, second, secondKey, keyFile, lockPath)
	online := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if mc, ok := f.gw.reg.get(second); ok && mc.doorMachine.Snapshot().Online {
			online = true
			break
		}
	}
	if !online {
		t.Fatalf("the second registration never came online beside the first one's open door; the journal holds %d door.sanitize and %d door.close entries for it",
			iamt444Journal(f, events.EventDoorSanitize, second), iamt444Journal(f, events.EventDoorClose, second))
	}
	if n := iamt444Journal(f, events.EventDoorSanitize, second) + iamt444Journal(f, events.EventDoorClose, second); n != 0 {
		t.Errorf("the second registration's gateway ran %d door.sanitize/door.close operations over a line that is not its own", n)
	}

	// The first person's door and session are exactly as they were.
	if got := iamt444DoorLine(t, keyFile, f.machineID); got != liveLine {
		t.Errorf("the open door's line changed under it:\nbefore: %q\nafter:  %q", liveLine, got)
	}
	if got := iamt444Echo(t, hs, "after"); !strings.Contains(got, "after") {
		t.Errorf("the first registration's session stopped answering: %q", got)
	}

	// And it still ends the ordinary way: the first registration closes
	// its own door, the second stays online throughout.
	_ = hs.ch.Close()
	waitUntil(t, "the first registration's door line was not removed after its session ended", func() bool {
		return iamt444DoorLine(t, keyFile, f.machineID) == ""
	})
	if mc, ok := f.gw.reg.get(second); !ok || !mc.doorMachine.Snapshot().Online {
		t.Errorf("the second registration went offline when the first one's door closed")
	}
}

// iamt444Echo writes s into the session and returns what came back up to it.
func iamt444Echo(t *testing.T, hs *humanSession, s string) string {
	t.Helper()
	if _, err := hs.ch.Write([]byte(s + "\n")); err != nil {
		t.Fatalf("write %q: %v", s, err)
	}
	return readUntil(t, hs.ch, s)
}
