//go:build (windows || linux || darwin) && !nogui

package main

// gui_admin_lists_goal_test.go proves guiAdminLists actually fills in
// ui.Grant's Goal and RecentGoals (SPEC IAMT-402) once a goal has been
// declared for a grant — the half of review19 finding 2 that wiring
// AdminGrantGoal alone would not fix: gui_actions.go:682 built every
// ui.Grant with only Person/Machine/Until, so every row would still say
// "Claim goal" and offer an empty recent-goals picker even after the
// button worked. It also proves review19 finding 5: RiskMode.Classifier
// reaches the window instead of staying "" regardless of what the
// gateway actually reports — the same guiAdminLists call.

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestGuiAdminListsFillsGoalAndRiskModeClassifier(t *testing.T) {
	root := t.TempDir()
	serverDir := filepath.Join(root, "server")
	clientDir := filepath.Join(root, "client")

	adminSigner, err := client.EnsureKey(clientDir)
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	adminPubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(adminSigner.PublicKey())))
	adminFP, err := state.ComputeFingerprint(adminPubLine)
	if err != nil {
		t.Fatalf("ComputeFingerprint(admin): %v", err)
	}
	machineSigner := genEd25519Signer(t)
	machinePubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(machineSigner.PublicKey())))
	machineFP, err := state.ComputeFingerprint(machinePubLine)
	if err != nil {
		t.Fatalf("ComputeFingerprint(machine): %v", err)
	}

	// Seed state.json directly (no bootstrap/enrol chain needed: this
	// test is about the read side, guiAdminLists, not about how a person
	// or machine came to exist) and close the store before the gateway
	// opens the same directory - state.Open takes an exclusive lock.
	store, err := state.Open(serverDir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	if err := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "root", Role: "admin",
			Keys: []state.Key{{Fingerprint: adminFP, Pub: adminPubLine, Added: state.NewZonedTime(time.Now())}},
		})
		st.Machines = append(st.Machines, state.Machine{
			ID: "vm1", Name: "vm1", State: "verified", MachineKey: machinePubLine, OSUser: `CORP\svc`,
		})
		st.Grants = append(st.Grants, state.Grant{
			Person: "root", Machine: "vm1", MachineKeyFingerprint: machineFP, Caps: []string{"exec"},
		})
		_, gerr := st.SetGoal("root", "vm1", "keep the printer running", time.Now())
		return gerr
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	addr, hostPub, stop := gatewayServeForChain(t, serverDir, "127.0.0.1")
	t.Cleanup(stop)

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("gateway address is not a TCPAddr: %T", addr)
	}
	if err := client.SaveConnection(clientDir, config.ConnString{
		Host: "127.0.0.1", Port: tcpAddr.Port, Person: "root", Fingerprint: auth.Fingerprint(hostPub),
	}, true); err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}

	lists, err := guiAdminLists(context.Background(), clientDir)
	if err != nil {
		t.Fatalf("guiAdminLists: %v", err)
	}
	if len(lists.Grants) != 1 {
		t.Fatalf("guiAdminLists grants = %#v, want exactly one", lists.Grants)
	}
	g := lists.Grants[0]
	if g.Goal != "keep the printer running" {
		t.Errorf("Grant.Goal = %q, want the declared goal", g.Goal)
	}
	if len(g.RecentGoals) != 1 || g.RecentGoals[0] != "keep the printer running" {
		t.Errorf("Grant.RecentGoals = %#v, want one entry with the declared goal", g.RecentGoals)
	}
	// review19 finding 5: this used to be "" unconditionally (the field
	// was never assigned), regardless of what "admin gateway status"
	// answered. A fresh gateway's classifier defaults to "rules"
	// (internal/gateway/config.go), which is exactly why "" looked like
	// a plausible value and the gap went unnoticed: rules IS the value
	// that makes the Access tab's "no effect while rules" caveat true,
	// so the bug only ever showed up as a caveat that stayed wrong after
	// switching to ai/both — never as an obviously-empty field.
	if lists.RiskMode.Classifier != "rules" {
		t.Errorf("RiskMode.Classifier = %q, want the gateway's own classifier (\"rules\")", lists.RiskMode.Classifier)
	}
}
