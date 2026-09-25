package main

// IAMT-400 canary: a shell grant confirmed in the CLI carries the same
// honest sentence the window keeps next to the capability picker
// (layoutShellCapabilityWarning): on a shell grant the gateway sees
// keystrokes, never a whole command, so no safety mode — log, warn, ask
// or block — has anything to act on. An administrator who scripts grants
// never opens the window; the printed confirmation is the only surface
// the truth reaches. An exec grant stays warning-free: its commands ARE
// classified, and a warning there would be noise.
//
// The test drives the real CLI against a real gatewayServe (the same
// posture TestGate2_AdminSuccessPath uses), because the warning lives in
// the print path after a successful round trip — there is nothing to
// read it off of but the real command's stdout.

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestIAMT400_AShellGrantInTheCLICarriesTheHonestReason(t *testing.T) {
	tg := startTestGateway(t, "alice", func(st *state.State) error {
		st.People = append(st.People,
			state.Person{Name: "bob", Role: "user"},
			state.Person{Name: "carol", Role: "user"},
		)
		_, _, signer := genTestKey(t)
		st.Machines = append(st.Machines, state.Machine{
			ID: "win01", Name: "win01", State: "verified",
			MachineKey: authorizedKeyLine(signer.PublicKey()),
			OSUser:     `MACHINE\svc`,
		})
		return nil
	})
	_, portStr, err := net.SplitHostPort(tg.addr.String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	rootDir := t.TempDir()
	cDir := clientDirFor(t, rootDir)
	writeClientKeyPEM(t, cDir, tg.adminPriv)
	cs := config.ConnString{Host: "127.0.0.1", Port: port, Person: "alice", Fingerprint: tg.hostFP}
	if err := client.SaveConnection(cDir, cs, false); err != nil {
		t.Fatalf("SaveConnection: %v", err)
	}

	out, errs, code := driveInDir(t, rootDir, "admin", "grants", "grant", "bob", "win01", "2027-01-31T18:00:00Z", "--cap", "shell")
	if code != exitOK {
		t.Fatalf("admin grants grant --cap shell: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, "granted bob -> win01 until 2027-01-31T18:00:00Z") {
		t.Fatalf("shell grant stdout lost the ordinary confirmation: %q", out)
	}
	// The same sentence the window shows, so both surfaces tell one truth.
	if !strings.Contains(out, "No safety mode applies to a shell grant") {
		t.Fatalf("a shell grant is confirmed without the honest reason — the window says %q, the CLI printed only:\n%s",
			"No safety mode applies to a shell grant", out)
	}
	if !strings.Contains(out, "never a whole command to classify") {
		t.Fatalf("the CLI warning does not say WHY no safety mode applies (\"never a whole command to classify\"):\n%s", out)
	}

	outExec, errsExec, codeExec := driveInDir(t, rootDir, "admin", "grants", "grant", "carol", "win01", "2027-01-31T18:00:00Z", "--cap", "exec")
	if codeExec != exitOK {
		t.Fatalf("admin grants grant --cap exec: code=%d out=%q errs=%q", codeExec, outExec, errsExec)
	}
	if strings.Contains(outExec, "No safety mode applies") {
		t.Fatalf("an exec grant carries the shell warning — its commands ARE classified:\n%s", outExec)
	}
}
