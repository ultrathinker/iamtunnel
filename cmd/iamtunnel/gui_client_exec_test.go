//go:build (windows || linux || darwin) && !nogui

package main

// gui_client_exec_test.go pins guiClientExec's LOCAL refusal: a
// malformed machine name is rejected before internal/client.Exec is
// ever asked to dial anything. A valid connection string and key are
// seeded first (client.SaveConnection/client.EnsureKey) specifically so
// this is a real proof and not an accident of "nothing was configured
// anyway" — without that seeding, loadClientIdentity itself would refuse
// first for an unrelated reason, and a test that removed the name check
// entirely would still pass.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
)

func TestGuiClientExecRefusesABadMachineNameBeforeDialingTheGateway(t *testing.T) {
	root := t.TempDir()
	cs, err := config.ParseConnString(connStr) // 127.0.0.1:1 -- closed port, main_test.go
	if err != nil {
		t.Fatalf("ParseConnString: %v", err)
	}
	if err := client.SaveConnection(root, cs, false); err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}
	if _, err := client.EnsureKey(root); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}

	for _, machine := range []string{"WIN01", "win 01", ""} {
		start := time.Now()
		stdout, stderr, err := guiClientExec(context.Background(), root, machine, "echo hi")
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("guiClientExec accepted machine name %q", machine)
		}
		if !strings.Contains(err.Error(), "not a valid name") {
			t.Errorf("guiClientExec(%q) error = %v, want the \"not a valid name\" refusal — a dial-shaped error here means the name check was skipped", machine, err)
		}
		if stdout != "" || stderr != "" {
			t.Errorf("guiClientExec(%q) = (%q, %q), want both empty on a local refusal", machine, stdout, stderr)
		}
		if elapsed > 500*time.Millisecond {
			t.Errorf("guiClientExec(%q) took %s — looks like it tried to dial the gateway instead of refusing the name locally", machine, elapsed)
		}
	}
}
