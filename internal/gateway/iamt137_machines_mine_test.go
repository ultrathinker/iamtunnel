package gateway

// iamt137_machines_mine_test.go — IAMT-137:
//
//   "machines.mine exists on the client and is missing from the gateway".
//
// PROTOCOL §6:
//   | machines.mine | person; {proto} | {machines:[{id,name,until,online,state,sshdListening,doorOpen}]} |
//
// The access-decision requirement:
//   "The list of machines available to a person is an access decision.
//    It must answer exactly what the ACL says at the moment of a real
//    connection... A single source of truth, not a second parallel
//    calculation of rights."

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestMachinesMine_Isolation proves that an ordinary user ("alice") sees only
// machines she is granted access to, and does NOT see machines granted to
// another user ("bob").
//
// Canary 1:
//
//	In internal/gateway/admin_role.go, change cmdMachinesMine to query all
//	machines from state.Store (or ignore person filter in GrantsFor).
//	The test will fail on line:
//	  t.Fatalf("machines.mine isolation breach: alice saw foreign machine %q in response", m.ID)
func TestMachinesMine_Isolation(t *testing.T) {
	f := newFixture(t, nil)
	// Alice is f.person ("alice", role "user"), already granted f.machineID ("vm1")

	// Add second person "bob" (role "user")
	bobKey := genSigner(t)
	addPerson(t, f, "bob", "user", bobKey)

	// Add second machine "vm2"
	vm2Key := genSigner(t)
	vm2HostKey := genSigner(t)
	hostKeyLine := authorizedLine(vm2HostKey.PublicKey())
	verifiedUser := `CORP\Administrator`
	if err := f.store.Update(func(st *state.State) error {
		st.Machines = append(st.Machines, state.Machine{
			ID: "vm2", Name: "vm2", State: "verified",
			MachineKey:      authorizedLine(vm2Key.PublicKey()),
			SSHDHostKey:     &hostKeyLine,
			OSUser:          verifiedUser,
			RequestedOSUser: verifiedUser,
			VerifiedOSUser:  &verifiedUser,
			OSUserStatus:    state.OSUserStatusVerified,
		})
		until := state.NewZonedTime(f.clock.Now().Add(2 * time.Hour))
		return st.GrantAccess("bob", "vm2", &until, "shell")
	}); err != nil {
		t.Fatalf("add vm2 and bob grant: %v", err)
	}

	// Also activate bob's grant in acl.Engine so ACL is synchronized
	untilBob := f.clock.Now().Add(2 * time.Hour)
	if err := f.gw.aclE.AddGrant(acl.Grant{Person: "bob", Machine: "vm2", Until: &untilBob, Caps: []string{"shell"}}, f.clock.Now()); err != nil {
		t.Fatalf("AddGrant bob vm2: %v", err)
	}

	// Alice calls machines.mine
	aliceConn := dialAdmin(t, f, f.person, f.personKey)
	aliceMachines, err := aliceConn.MachinesMine()
	if err != nil {
		t.Fatalf("alice MachinesMine: %v", err)
	}

	foundAliceMachine := false
	for _, m := range aliceMachines {
		if m.ID == "vm2" {
			t.Fatalf("machines.mine isolation breach: alice saw foreign machine %q in response", m.ID)
		}
		if m.ID == f.machineID {
			foundAliceMachine = true
		}
	}
	if !foundAliceMachine {
		t.Fatalf("alice did not see her own machine %q; got %+v", f.machineID, aliceMachines)
	}
}

// TestMachinesMine_OrdinaryUserCanCall proves that an ordinary human with
// role "user" (not "admin") can execute machines.mine successfully.
//
// Canary 2:
//
//	In internal/gateway/admin_role.go, mark machines.mine as adminOnly: true.
//	The test will fail on line:
//	  t.Fatalf("ordinary user alice failed to run machines.mine: %v", err)
func TestMachinesMine_OrdinaryUserCanCall(t *testing.T) {
	f := newFixture(t, nil)
	// Alice has role "user" in fixture
	aliceConn := dialAdmin(t, f, f.person, f.personKey)
	machines, err := aliceConn.MachinesMine()
	if err != nil {
		t.Fatalf("ordinary user alice failed to run machines.mine: %v", err)
	}
	if len(machines) == 0 {
		t.Fatalf("alice expected at least 1 machine, got 0")
	}
}

// TestMachinesMine_BoundaryConditions tests edge cases:
// 1. A user without any grants gets an empty list and success, NOT an error.
// 2. An expired grant is omitted from the list.
// 3. A revoked grant is omitted immediately.
// 4. An indefinite grant (Until == nil) is returned with empty Until string.
func TestMachinesMine_BoundaryConditions(t *testing.T) {
	f := newFixture(t, nil)

	// User without grants
	charlieKey := genSigner(t)
	addPerson(t, f, "charlie", "user", charlieKey)
	charlieConn := dialAdmin(t, f, "charlie", charlieKey)
	charlieMachines, err := charlieConn.MachinesMine()
	if err != nil {
		t.Fatalf("charlie without grants: %v", err)
	}
	if len(charlieMachines) != 0 {
		t.Fatalf("charlie expected 0 machines, got %d", len(charlieMachines))
	}

	// Indefinite grant for david
	davidKey := genSigner(t)
	addPerson(t, f, "david", "user", davidKey)
	if err := f.store.Update(func(st *state.State) error {
		return st.GrantAccess("david", f.machineID, nil, "shell")
	}); err != nil {
		t.Fatalf("grant david: %v", err)
	}
	if err := f.gw.aclE.AddGrant(acl.Grant{Person: "david", Machine: f.machineID, Until: nil, Caps: []string{"shell"}}, f.clock.Now()); err != nil {
		t.Fatalf("AddGrant david: %v", err)
	}
	davidConn := dialAdmin(t, f, "david", davidKey)
	davidMachines, err := davidConn.MachinesMine()
	if err != nil {
		t.Fatalf("david MachinesMine: %v", err)
	}
	if len(davidMachines) != 1 || davidMachines[0].ID != f.machineID {
		t.Fatalf("david expected 1 machine %q, got %+v", f.machineID, davidMachines)
	}
	if davidMachines[0].Until != "" {
		t.Fatalf("david indefinite grant expected empty Until string, got %q", davidMachines[0].Until)
	}

	// Expired grant check: advance time past alice's grant deadline
	f.clock.Advance(2 * time.Hour)
	aliceConn := dialAdmin(t, f, f.person, f.personKey)
	aliceMachinesExpired, err := aliceConn.MachinesMine()
	if err != nil {
		t.Fatalf("alice MachinesMine after expiry: %v", err)
	}
	if len(aliceMachinesExpired) != 0 {
		t.Fatalf("alice expected 0 machines after grant expiry, got %d", len(aliceMachinesExpired))
	}
}

// TestMachinesMine_ClientPackageInteroperability tests calling client.Machines
// from the client package against the live running gateway.
func TestMachinesMine_ClientPackageInteroperability(t *testing.T) {
	f := newFixture(t, nil)
	clientDir := t.TempDir()

	// Write gateway host key into known_hosts
	knownHostsPath := client.KnownHostsPath(clientDir)
	_ = os.MkdirAll(filepath.Dir(knownHostsPath), 0o700)
	khLine := f.addr + " " + authorizedLine(f.gw.cfg.HostKey.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(khLine), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cs := config.ConnString{
		Host:        "127.0.0.1",
		Port:        f.ln.Addr().(*net.TCPAddr).Port,
		Person:      f.person,
		Fingerprint: gatewayFingerprint(f),
	}

	machines, err := client.Machines(context.Background(), clientDir, cs, f.personKey, 5*time.Second)
	if err != nil {
		t.Fatalf("client.Machines: %v", err)
	}
	if len(machines) != 1 || machines[0].ID != f.machineID {
		t.Fatalf("client.Machines = %+v, want 1 machine %q", machines, f.machineID)
	}
}

// TestMachinesMine_SSHDListening_ReflectsVerificationHistoryNotLiveProbe
// explicitly pins the architectural contract and limitation of machines.mine:
// SSHDListening reflects historical verification status and online tunnel state,
// NOT a real-time live TCP probe to the target machine's sshd port.
//
// If the target sshd dies while the machine server's tunnel is online,
// machines.mine returns SSHDListening: true. The failure is discovered
// when an actual human session dials the machine (giving DenyMachineSSHDUnreachable).
//
// Canary (Fix 2):
//
//	If machines.mine attempted a live probe to sshd and reported false when sshd
//	listener is closed, this test would fail on:
//	  t.Fatalf("machines.mine SSHDListening = %v; want true (reflects verification history, not live probe)", m.SSHDListening)
func TestMachinesMine_SSHDListening_ReflectsVerificationHistoryNotLiveProbe(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// Target sshd listener is closed
	_ = f.sshd.listener.Close()

	// Alice queries machines.mine
	aliceConn := dialAdmin(t, f, f.person, f.personKey)
	machines, err := aliceConn.MachinesMine()
	if err != nil {
		t.Fatalf("alice MachinesMine: %v", err)
	}
	if len(machines) != 1 {
		t.Fatalf("expected 1 machine, got %d", len(machines))
	}
	m := machines[0]
	if !m.Online {
		t.Fatalf("machine expected to be online, got online=%v", m.Online)
	}
	if !m.SSHDListening {
		t.Fatalf("machines.mine SSHDListening = %v; want true (reflects verification history, not live probe)", m.SSHDListening)
	}
}
