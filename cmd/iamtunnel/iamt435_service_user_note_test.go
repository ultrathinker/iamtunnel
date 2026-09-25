package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
)

// IAMT-435: a machine bound to the gateway's own service account gets a
// warning at enrol, in words, before machine.key is written. The Linux
// gateway service account ("iamtunnel") has its home INSIDE the gateway
// data directory and a nologin shell; the macOS LaunchDaemon account
// ("_iamtunnel") has home /var/empty and shell /usr/bin/false. A door
// for such an account cannot ever work, and on Linux it would land in
// the gateway's own state.

func TestIAMT435_TheServiceAccountNoteNamesOnlyTheGatewayAccounts(t *testing.T) {
	cases := []struct {
		goos, name string
		wantNote   bool
	}{
		{"linux", "iamtunnel", true},
		{"darwin", "_iamtunnel", true},
		{"linux", "alice", false},
		{"darwin", "alice", false},
		// The other platform's service account is an ordinary name here.
		{"linux", "_iamtunnel", false},
		{"darwin", "iamtunnel", false},
		// Windows has no Unix service account, and its os-user form is
		// DOMAIN\name anyway.
		{"windows", "iamtunnel", false},
		{"windows", `CONTOSO\iamtunnel`, false},
	}
	for _, tc := range cases {
		got := gatewayServiceUserNote(tc.goos, tc.name)
		if (got != "") != tc.wantNote {
			t.Errorf("gatewayServiceUserNote(%q, %q) = %q, want a note: %v", tc.goos, tc.name, got, tc.wantNote)
			continue
		}
		if tc.wantNote && !strings.Contains(got, tc.name) {
			t.Errorf("the note must name the account it warns about: %q", got)
		}
		if tc.wantNote && !strings.Contains(got, "set-user") {
			t.Errorf("the note must name the way out (admin machines set-user): %q", got)
		}
	}
}

// The wiring proof: a real enrol exchange whose gateway binds the
// platform's own service account still registers (the binding stands —
// the note is a warning, not a refusal) and the console reads the price.
func TestIAMT435_EnrolPrintsTheServiceAccountWarningAndStillRegisters(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("enrol refuses root by design (SPEC §3.2.1) — same posture as TestGate2_EnrolSuccessPath")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the service accounts this warning names are the Linux/macOS ones; on Windows a bare account name is refused by the DOMAIN\\name format gate before any note could fire")
	}
	name := gatewayServiceUser
	if runtime.GOOS == "darwin" {
		name = darwinServiceUser
	}
	// The bound account need not exist in the test runner's user database:
	// the note is about the binding, not about presence (that gate has its
	// own tests).
	savedVerify := verifyOSUserFn
	verifyOSUserFn = func(string) error { return nil }
	t.Cleanup(func() { verifyOSUserFn = savedVerify })

	const secret = "s3cret-token2"
	addr, fp := startFakeEnrolGateway(t, secret, "win01-coexist", name)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	code := fmt.Sprintf("iamtunnel-enrol://%s:%s#%s:%s", host, port, fp, secret)

	out, errs, exitCode := driveInDir(t, t.TempDir(), "enrol", code)
	if exitCode != exitOK {
		t.Fatalf("enrol: code=%d out=%q errs=%q — the note is a warning, enrol must still register", exitCode, out, errs)
	}
	if !strings.Contains(errs, name) {
		t.Fatalf("the machine was bound to the gateway service account %q and the console said nothing about it (IAMT-435): errs=%q", name, errs)
	}
}
