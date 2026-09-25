package main

// iamt336_one_string_cli_test.go — IAMT-336, the CLI half of SPEC §3.6
// ("one string, one field") and of the §3.3 paragraph the live run of
// 17.09 wrote.
//
// Three defects are pinned here, each the way it was met in practice:
//
//  1. the gateway printed a ready command line, the person copied it
//     whole, and "admin pair" — which wanted exactly two arguments —
//     answered a refusal while the two-minute window burned;
//  2. "gateway install" printed a token that still had to be assembled
//     into a command by hand, and once the terminal scrolled away there
//     was nowhere to see it: the token expired silently and recovery
//     went through the emergency path of RUNBOOK §5.11;
//  3. a dead string reprinted as if it worked would be worse than not
//     reprinting it at all.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// iamt336ServeOn starts a real gateway on an ALREADY BOUND listener, so
// the caller can learn the port before the gateway owns the state lock.
// That order is what the "gateway pair" half of this file needs:
// "gateway pair" is the local recovery command, refused while a gateway
// holds the lock, so it must run first — and the reference it prints
// must carry the port the gateway will actually listen on.
//
// It mirrors gatewayServeForChain (iamt131_bootstrap_install_test.go),
// which binds :0 itself and therefore cannot be used here.
func iamt336ServeOn(t *testing.T, dir, publicHost string, ln net.Listener) func() {
	t.Helper()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("setup: open state: %v", err)
	}
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		_ = store.Close()
		t.Fatalf("setup: open events log: %v", err)
	}
	hostSigner, err := loadOrGenerateSigner(hostkeyPath(dir))
	if err != nil {
		_ = store.Close()
		_ = log.Close()
		t.Fatalf("setup: host key: %v", err)
	}
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = store.Close()
		_ = log.Close()
		t.Fatalf("setup: listener address is not a TCPAddr: %T", ln.Addr())
	}
	gw, err := gateway.New(gateway.Config{
		Store:            store,
		Log:              log,
		HostKey:          hostSigner,
		PublicHost:       publicHost,
		PublicPort:       tcpAddr.Port,
		RecordingBaseDir: filepath.Join(dir, "recordings"),
	})
	if err != nil {
		_ = store.Close()
		_ = log.Close()
		t.Fatalf("setup: gateway.New: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- gw.Serve(ln) }()
	return func() {
		_ = gw.Close()
		<-serveErr
		_ = store.Close()
		_ = log.Close()
	}
}

// iamt336FreePort binds 127.0.0.1:0 and hands back the listener itself,
// not just its number: keeping it bound is what makes the port reserved
// while "gateway pair" prints a reference that names it.
func iamt336FreePort(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("setup: listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// TestIAMT336_GatewayPairPrintoutPastedWholeIntoAdminPair is THE test
// of this change: whatever "gateway pair" prints, pasted whole — every
// line of it, the sentence above the command included — into "admin
// pair" as one argument, makes this machine an administrator.
//
// Failure path (it really can go red): before this change "admin pair"
// took exactly two positionals, so the whole printed block arrived as
// one argument and wantN(2) refused it with exit code 2 and not one
// byte sent to the gateway. Reverting cmdAdminPair to fs.wantN(2) +
// config.ParsePairingRef(fs.pos[0]) turns this test red on the exit
// code alone. Narrowing the paste (dropping the prose line, or dropping
// the "iamtunnel admin pair" prefix) is checked in the sub-tests below,
// so a parser that only handles the bare pair also fails here.
func TestIAMT336_GatewayPairPrintoutPastedWholeIntoAdminPair(t *testing.T) {
	cases := []struct {
		name string
		// pick turns the exact stdout of "gateway pair" into the one
		// string a person would have in the clipboard.
		pick func(t *testing.T, printed string) string
	}{
		{
			name: "whole printout",
			pick: func(_ *testing.T, printed string) string { return printed },
		},
		{
			name: "the command line and the sentence above it",
			pick: func(t *testing.T, printed string) string {
				return iamt336RunLineWithLeadIn(t, printed)
			},
		},
		{
			name: "the command line alone",
			pick: func(t *testing.T, printed string) string {
				return iamt336CommandLine(t, printed)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gwDir := t.TempDir()
			ln := iamt336FreePort(t)
			port := ln.Addr().(*net.TCPAddr).Port

			// Step 1: the local recovery command, on the gateway host,
			// with no gateway running and no admin key anywhere.
			printed, errs, code := drive(t, "gateway", "pair",
				"--data-dir", gwDir, "--public-host", "127.0.0.1",
				"--port", fmt.Sprint(port))
			if code != exitOK {
				t.Fatalf("gateway pair: code=%d out=%q errs=%q", code, printed, errs)
			}
			if !strings.Contains(printed, "iamtunnel admin pair ") {
				t.Fatalf("gateway pair no longer prints a ready \"iamtunnel admin pair\" line, so there is nothing for a person to copy:\n%s", printed)
			}

			// Step 2: the gateway comes up on the very port the printed
			// reference names.
			stop := iamt336ServeOn(t, gwDir, "127.0.0.1", ln)
			t.Cleanup(stop)

			// Step 3: the new admin's machine. Nothing but the paste.
			paste := tc.pick(t, printed)
			dir2 := t.TempDir()
			out, errs, code := driveInDir(t, dir2, "admin", "pair", paste, "--json")
			if code != exitOK {
				t.Fatalf("admin pair with the pasted string:\ncode=%d\npaste=%q\nout=%q\nerrs=%q", code, paste, out, errs)
			}
			var paired struct {
				Person          string `json:"person"`
				Role            string `json:"role"`
				ConnectionSaved bool   `json:"connectionSaved"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &paired); err != nil {
				t.Fatalf("admin pair printed %q, not the promised JSON result: %v", out, err)
			}
			if paired.Role != "admin" || paired.Person == "" {
				t.Fatalf("admin pair result = %+v, want a person name and role admin", paired)
			}
			if !paired.ConnectionSaved {
				t.Fatalf("admin pair reports connectionSaved=false — the paired machine would still need the manual connect-string step")
			}
			// The pairing is real on the gateway's side, not just in the
			// CLI's printout: an ordinary admin command now works from
			// the machine that pasted the string.
			out, errs, code = driveInDir(t, dir2, "admin", "people", "list")
			if code != exitOK {
				t.Fatalf("admin people list from the freshly paired machine: code=%d out=%q errs=%q", code, out, errs)
			}
			if !strings.Contains(out, paired.Person) {
				t.Fatalf("admin people list does not mention the new admin %q:\n%s", paired.Person, out)
			}
		})
	}
}

// iamt336RunLineWithLeadIn returns the "On the new admin's machine run:"
// sentence together with the command line under it — the two lines a
// person selects when they copy "the thing that was printed".
func iamt336RunLineWithLeadIn(t *testing.T, printed string) string {
	t.Helper()
	lines := strings.Split(strings.ReplaceAll(printed, "\r\n", "\n"), "\n")
	for i, l := range lines {
		if strings.Contains(l, "iamtunnel admin pair ") {
			if i == 0 {
				t.Fatalf("the command line has no sentence above it, so this sub-test has nothing to paste:\n%s", printed)
			}
			return lines[i-1] + "\n" + lines[i] + "\n"
		}
	}
	t.Fatalf("no \"iamtunnel admin pair\" line in:\n%s", printed)
	return ""
}

// iamt336CommandLine returns just the command line, indentation and all.
func iamt336CommandLine(t *testing.T, printed string) string {
	t.Helper()
	for _, l := range strings.Split(strings.ReplaceAll(printed, "\r\n", "\n"), "\n") {
		if strings.Contains(l, "iamtunnel admin pair ") {
			return l
		}
	}
	t.Fatalf("no \"iamtunnel admin pair\" line in:\n%s", printed)
	return ""
}

// TestIAMT336_AdminPairStillTakesTwoArguments holds the promise made to
// everyone who wrote the old form down: RUNBOOK §1.4.1 and every note
// that says "admin pair <ref> <pin>" keeps working, and it ends in the
// same registration the one-string form does.
//
// Failure path: make the one-string form the only one — drop the join
// of the positionals, or refuse len(fs.pos) == 2 — and this goes red at
// the exit code. It is not a duplicate of the sub-tests above: those
// paste one argument, this one passes two.
func TestIAMT336_AdminPairStillTakesTwoArguments(t *testing.T) {
	gwDir := t.TempDir()
	ln := iamt336FreePort(t)
	port := ln.Addr().(*net.TCPAddr).Port

	printed, errs, code := drive(t, "gateway", "pair",
		"--data-dir", gwDir, "--public-host", "127.0.0.1", "--port", fmt.Sprint(port))
	if code != exitOK {
		t.Fatalf("gateway pair: code=%d out=%q errs=%q", code, printed, errs)
	}
	ref, pin := iamt336RefAndPin(t, printed)

	stop := iamt336ServeOn(t, gwDir, "127.0.0.1", ln)
	t.Cleanup(stop)

	dir2 := t.TempDir()
	out, errs, code := driveInDir(t, dir2, "admin", "pair", ref, pin, "--json")
	if code != exitOK {
		t.Fatalf("admin pair <ref> <pin>: code=%d out=%q errs=%q (ref=%q pin=%q)", code, out, errs, ref, pin)
	}
	var paired struct {
		Person string `json:"person"`
		Role   string `json:"role"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &paired); err != nil {
		t.Fatalf("admin pair printed %q, not the promised JSON result: %v", out, err)
	}
	if paired.Role != "admin" || paired.Person == "" {
		t.Fatalf("admin pair result = %+v, want a person name and role admin", paired)
	}
}

// TestIAMT336_AdminPairRefusesTheWrongKindOfString: the single argument
// is not a hole. A bootstrap string pasted into "admin pair" is a user
// error with a sentence that names what was pasted and where it should
// go, exit code 2, and nothing sent to any gateway.
//
// Failure path: accept any paste kind (drop the Kind check) and the
// refusal disappears, turning this red.
func TestIAMT336_AdminPairRefusesTheWrongKindOfString(t *testing.T) {
	// A well-formed claim string (SPEC §3.6) — the wrong one for pair.
	fp := strings.Repeat("A", 43)
	claim := "iamtunnel-claim://gw.example.test:2222#" + fp + ":abcdefgh12345678"
	out, errs, code := drive(t, "admin", "pair", claim)
	if code != exitUser {
		t.Fatalf("admin pair with a bootstrap string: code=%d, want the user-error class %d\nout=%q errs=%q", code, exitUser, out, errs)
	}
	if !strings.Contains(errs, "iamtunnel admin claim") {
		t.Fatalf("the refusal does not say where a bootstrap string actually goes:\n%s", errs)
	}
}

// TestIAMT336_AdminPairWithNoArgumentAsksForThePaste: zero positionals
// is still a refusal, and it asks for the pasted line rather than for
// "exactly two arguments".
//
// Failure path: accept len(fs.pos) == 0 and paste.Parse("") decides
// what to do — exit code would stay 2 but the message would stop naming
// the line to paste; assert on both.
func TestIAMT336_AdminPairWithNoArgumentAsksForThePaste(t *testing.T) {
	out, errs, code := drive(t, "admin", "pair")
	if code != exitUser {
		t.Fatalf("admin pair with no argument: code=%d, want %d\nout=%q errs=%q", code, exitUser, out, errs)
	}
	if !strings.Contains(errs, "paste") {
		t.Fatalf("the refusal does not tell the person to paste the printed line:\n%s", errs)
	}
}

// iamt336RefAndPin pulls the reference and the PIN out of what "gateway
// pair" printed, from its own labelled lines — not from the command
// line, so the two-argument test does not silently depend on the
// one-string plumbing it is meant to be independent of.
func iamt336RefAndPin(t *testing.T, printed string) (ref, pin string) {
	t.Helper()
	for _, raw := range strings.Split(strings.ReplaceAll(printed, "\r\n", "\n"), "\n") {
		l := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(l, "pairing reference: "):
			ref = strings.TrimSpace(strings.TrimPrefix(l, "pairing reference: "))
		case strings.HasPrefix(l, "PIN: "):
			pin = strings.TrimSpace(strings.TrimPrefix(l, "PIN: "))
		}
	}
	if ref == "" || pin == "" {
		t.Fatalf("gateway pair printed no labelled reference/PIN lines:\n%s", printed)
	}
	return ref, pin
}

// ---- the bootstrap string: install prints it, status reprints it -----

// iamt336Install runs "gateway install" against a temporary data
// directory with every OS seam faked, and returns its stdout.
func iamt336Install(t *testing.T, dir string) string {
	t.Helper()
	withFakeSystemd(t)
	_ = withFakeGatewayService(t)
	_ = withFakeLaunchd(t)
	out, errs, code := drive(t, "gateway", "install",
		"--data-dir", dir, "--public-host", "gw.example.test")
	expectInstallExit(t, out, errs, code, "install")
	return out
}

// iamt336ClaimString returns the one iamtunnel-claim:// line in a
// printout, trimmed of the indentation install and status print it with.
func iamt336ClaimString(t *testing.T, printed string) string {
	t.Helper()
	var found []string
	for _, l := range strings.Split(strings.ReplaceAll(printed, "\r\n", "\n"), "\n") {
		if strings.Contains(l, "iamtunnel-claim://") {
			found = append(found, strings.TrimSpace(l))
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one iamtunnel-claim:// line, found %d in:\n%s", len(found), printed)
	}
	return found[0]
}

// TestIAMT336_InstallPrintsTheOneClaimString: install prints the
// bootstrap secret as the single pasteable string of SPEC §3.6, and
// that string is built from the very token and host key it just wrote
// to disk — not from anything the printout invented.
//
// Failure path: remove the bootstrapClaimBlock call from
// runGatewayInstall and there is no claim line to find; print the wrong
// token or the "SHA256:" form of the fingerprint and the comparison
// against the on-disk bootstrap-token and host key goes red.
func TestIAMT336_InstallPrintsTheOneClaimString(t *testing.T) {
	dir := t.TempDir()
	out := iamt336Install(t, dir)

	claim := iamt336ClaimString(t, out)
	tokenBytes, err := os.ReadFile(filepath.Join(dir, bootstrapFileName))
	if err != nil {
		t.Fatalf("read bootstrap-token: %v", err)
	}
	diskToken := strings.TrimSpace(string(tokenBytes))
	diskFP := strings.TrimPrefix(iamt200ReadOnDiskFingerprint(t, dir), "SHA256:")
	want := "iamtunnel-claim://gw.example.test:2222#" + diskFP + ":" + diskToken
	if claim != want {
		t.Fatalf("install printed the claim string\n  %s\nwant\n  %s", claim, want)
	}
}

// TestIAMT336_StatusReprintsTheLiveClaimString: the defect of 17.09 —
// the operator whose terminal scrolled away has somewhere to look.
// Status prints the same string install printed, character for
// character, while the token is unspent and inside its 24 hours.
//
// Failure path: drop the printBootstrapStatus call from
// runGatewayStatus (any one of its three branches loses the string) or
// let it print something of its own instead of bootstrapClaimBlock, and
// the equality against install's own line goes red.
func TestIAMT336_StatusReprintsTheLiveClaimString(t *testing.T) {
	dir := t.TempDir()
	installed := iamt336ClaimString(t, iamt336Install(t, dir))

	out, errs, code := drive(t, "gateway", "status",
		"--data-dir", dir, "--public-host", "gw.example.test")
	if code != exitOK {
		t.Fatalf("gateway status: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, "unspent") {
		t.Fatalf("status does not say the bootstrap string is still usable:\n%s", out)
	}
	if got := iamt336ClaimString(t, out); got != installed {
		t.Fatalf("status reprinted\n  %s\ninstall printed\n  %s", got, installed)
	}
}

// TestIAMT336_StatusRefusesToPrintADeadClaimString: spent and expired
// are the two ways the string dies, and neither may be reprinted. Each
// gets a sentence instead — silence is what leads to the emergency
// path of RUNBOOK §5.11.
//
// Failure path: print the string unconditionally (drop the presence or
// the deadline branch of printBootstrapStatus) and both sub-tests go
// red on the "no claim string" assertion.
func TestIAMT336_StatusRefusesToPrintADeadClaimString(t *testing.T) {
	cases := []struct {
		name string
		// kill makes the bootstrap entry dead in the way the name says.
		kill func(st *state.State)
		want string
	}{
		{
			name: "spent",
			kill: func(st *state.State) { st.BootstrapPending = nil },
			want: "already used",
		},
		{
			name: "expired",
			kill: func(st *state.State) {
				st.BootstrapPending.Expires = state.NewZonedTime(time.Now().UTC().Add(-time.Minute))
			},
			want: "EXPIRED",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_ = iamt336Install(t, dir)

			store, err := state.Open(dir)
			if err != nil {
				t.Fatalf("open state: %v", err)
			}
			if uerr := store.Update(func(st *state.State) error {
				if st.BootstrapPending == nil {
					t.Fatalf("install left no bootstrapPending entry to kill")
				}
				tc.kill(st)
				return nil
			}); uerr != nil {
				t.Fatalf("update state: %v", uerr)
			}
			if cerr := store.Close(); cerr != nil {
				t.Fatalf("close state: %v", cerr)
			}

			out, errs, code := drive(t, "gateway", "status",
				"--data-dir", dir, "--public-host", "gw.example.test")
			if code != exitOK {
				t.Fatalf("gateway status: code=%d out=%q errs=%q", code, out, errs)
			}
			if strings.Contains(out, "iamtunnel-claim://") {
				t.Fatalf("status reprinted a %s bootstrap string — the person would paste a string that cannot work:\n%s", tc.name, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("status does not say the bootstrap string is %s (want %q):\n%s", tc.name, tc.want, out)
			}
		})
	}
}

// TestIAMT336_StatusSaysWhyItCannotRenderTheString: without a public
// host there is no address to put in the string, and inventing one
// would hand out a string that dials the wrong machine. Status says so
// and prints nothing.
//
// Failure path: fall back to a placeholder host (the <this-host> of
// IAMT-202) or print the string anyway, and the "no claim string"
// assertion goes red.
func TestIAMT336_StatusSaysWhyItCannotRenderTheString(t *testing.T) {
	dir := t.TempDir()
	_ = iamt336Install(t, dir)

	out, errs, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("gateway status: code=%d out=%q errs=%q", code, out, errs)
	}
	if strings.Contains(out, "iamtunnel-claim://") {
		t.Fatalf("status rendered a claim string with no public host to put in it:\n%s", out)
	}
	if !strings.Contains(out, "public host is not set") {
		t.Fatalf("status does not say why the string is missing:\n%s", out)
	}
}

// TestIAMT336_StatusSaysNothingAboutBootstrapWithoutAHostKey: the
// bootstrap string names the host key a client must pin, so without a
// host key on disk there is no string to render and nothing truthful to
// say about one. Two shapes of that: a directory with no gateway in it
// at all, and a directory whose state.json survived but whose host key
// did not — what "gateway restore" leaves behind, since it extracts
// state.json and nothing else.
//
// Failure path: drop the hasKey guard in printBootstrapStatus and the
// second sub-test goes red — status starts discussing a bootstrap
// string whose fingerprint it does not have, and the string it would
// eventually print would pin an empty key.
func TestIAMT336_StatusSaysNothingAboutBootstrapWithoutAHostKey(t *testing.T) {
	t.Run("nothing installed at all", func(t *testing.T) {
		dir := t.TempDir()
		out, errs, code := drive(t, "gateway", "status", "--data-dir", dir, "--public-host", "gw.example.test")
		if code != exitOK {
			t.Fatalf("gateway status: code=%d out=%q errs=%q", code, out, errs)
		}
		if strings.Contains(out, "bootstrap string") {
			t.Fatalf("status talks about a bootstrap string in a directory with no gateway in it:\n%s", out)
		}
	})

	t.Run("state survived, host key did not", func(t *testing.T) {
		dir := t.TempDir()
		_ = iamt336Install(t, dir)
		// Every other file install wrote stays: only the host key goes,
		// which is exactly the shape "gateway restore" produces.
		if err := os.Remove(hostkeyPath(dir)); err != nil {
			t.Fatalf("remove host key: %v", err)
		}
		out, errs, code := drive(t, "gateway", "status", "--data-dir", dir, "--public-host", "gw.example.test")
		if code != exitOK {
			t.Fatalf("gateway status: code=%d out=%q errs=%q", code, out, errs)
		}
		if !strings.Contains(out, "host key: not generated yet") {
			t.Fatalf("this sub-test needs the host-key-less branch of status, got:\n%s", out)
		}
		if strings.Contains(out, "bootstrap string") || strings.Contains(out, "iamtunnel-claim://") {
			t.Fatalf("status discusses a bootstrap string although the host key it would have to pin is gone:\n%s", out)
		}
	})
}
