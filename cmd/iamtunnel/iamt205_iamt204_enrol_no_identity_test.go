package main

// iamt205_iamt204_enrol_no_identity_test.go proves what the CLIENT half
// of "iamtunnel enrol" puts on the wire — through the real product
// path, cmdEnrol -> enrolMachine, not a hand-built body.
//
// The rule has been rewritten twice, and this file carries the scar
// tissue of both, because the second rewrite made the first one wrong
// in a way nothing caught.
//
// IAMT-205/204, the live defect: enrolMachine guessed BOTH fields from
// this host — the name from os.Hostname(), the account from
// USERDOMAIN + USERNAME — and both guesses were wrong in the field. A
// hostname that did not byte-for-byte match the code's bound name was
// refused; a workgroup machine's guess silently overwrote the
// administrator's binding and left sshd user-auth rejecting the login.
// The fix sent BOTH empty and let the gateway's binding decide.
//
// 1.3 then removed the account half of that binding — rightly: the
// administrator could not have known the account — without this half
// following. The gateway began REQUIRING a value nothing sent, and
// "iamtunnel enrol" refused every code with `osUser "" is not a valid
// Windows principal`. Registration was broken end to end, and this test
// stayed green throughout, because it asserts against a FAKE gateway
// that was still content with an empty body. A test that pins what a
// client sends without ever meeting the real server pins agreement
// with nothing.
//
// 1.4 settles it by asking who could possibly know:
//
//   - the NAME: the administrator. It rides in the invitation, and the
//     body still sends nothing.
//   - the ACCOUNT: the machine. The body sends it, and the gateway
//     proves it by logging in as it (SPEC §3.4 step 3) rather than
//     trusting it.
//
// Canary: drop the OSUser field from enrolMachine's Exec body and this
// test goes red at "the client sent no osUser"; put a Machine value
// back and it goes red at "the client named the machine".

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// startFakeBindingGateway is startFakeEnrolGateway's twin (see
// gate2_enrol_test.go), except it captures the enrolRequest the client
// actually sent and always answers with the FIXED machine/osUser the
// code was "issued" for — exactly what a real gateway does under the
// IAMT-205/204 fix: the response reflects its own binding, never
// whatever the client's body claimed.
func startFakeBindingGateway(t *testing.T, secret, boundMachine, boundOSUser string) (addr, fingerprint string, gotReq *enrolRequest) {
	t.Helper()
	hostSigner := genTestSigner(t)
	wantSigner, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive expected ephemeral signer: %v", err)
	}
	wantPub := wantSigner.PublicKey().Marshal()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	captured := &enrolRequest{}
	done := make(chan struct{})

	go func() {
		defer close(done)
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		cfg := &ssh.ServerConfig{
			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				if conn.User() != "enrol" {
					return nil, fmt.Errorf("fake binding gateway: wrong username %q", conn.User())
				}
				if string(key.Marshal()) != string(wantPub) {
					return nil, fmt.Errorf("fake binding gateway: key does not match the HKDF-derived enrol key")
				}
				return &ssh.Permissions{}, nil
			},
		}
		cfg.AddHostKey(hostSigner)
		sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		for n := range chans {
			if n.ChannelType() != "session" {
				_ = n.Reject(ssh.UnknownChannelType, "only session")
				continue
			}
			ch, chReqs, err := n.Accept()
			if err != nil {
				continue
			}
			req := <-chReqs
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			body, _ := io.ReadAll(ch)
			_ = json.Unmarshal(body, captured)
			resp := struct {
				Proto  int         `json:"proto"`
				Caps   []string    `json:"caps"`
				OK     bool        `json:"ok"`
				Result enrolResult `json:"result"`
			}{Proto: 1, Caps: []string{}, OK: true, Result: enrolResult{
				// The response is the gateway's OWN binding — fixed here —
				// never an echo of whatever the client's body said.
				Machine: boundMachine, State: "enrolled", RequestedOSUser: boundOSUser,
				OSUserStatus: "pending", HostKeyStatus: "unverified", ServerTime: "2026-09-14T00:00:00Z",
			}}
			raw, _ := json.Marshal(resp)
			_, _ = ch.Write(append(raw, '\n'))
			_ = ch.Close()
			return
		}
	}()

	sum := sha256.Sum256(hostSigner.PublicKey().Marshal())
	addr = ln.Addr().String()
	fingerprint = base64.RawStdEncoding.EncodeToString(sum[:])
	t.Cleanup(func() { <-done })
	return addr, fingerprint, captured
}

// TestIAMT205_ClientEnrolSendsEmptyMachineAndOSUser drives the real
// "iamtunnel enrol <code>" CLI path (cmdEnrol -> enrolMachine) against a
// fake gateway that was "issued" for machine "vmwin" / an osUser in the
// platform's principal form (`MACHINE\svc` on Windows, "svc-ssh" on
// Linux/macOS — the binding's FORM is per-OS, IAMT-271). It proves two
// things at once, exactly the live scenario:
//
//   - the client body reaching the wire carries EMPTY machine/osUser —
//     it never invents them from this test process's real hostname or
//     environment (IAMT-205/IAMT-204's fix);
//   - the CLI's own success message echoes the gateway's answer
//     ("vmwin" / the bound osUser), which is what the fake gateway
//     bound the code to, not anything the client sent.
func TestEnrolSendsTheAccountAndNotTheName(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("enrol refuses root by design (SPEC §3.2.1: a machine does not register as root) — the wire round trip this test drives cannot run under root, as inside a root container")
	}
	const secret = "iamt205-binding-secret-012345678901"
	const boundMachine = "vmwin"
	boundOSUser := `MACHINE\svc`
	if runtime.GOOS != "windows" {
		boundOSUser = "svc-ssh"
		// The client verifies the gateway-bound user exists locally
		// before persisting (IAMT-248 fix1); the fixed observer keeps
		// that product gate fully live on the wire value while making
		// the local-existence half of it a no-op in the test process —
		// the same posture userLookupFn has in
		// iamt248_server_start_linux_test.go.
		savedVerify := verifyOSUserFn
		verifyOSUserFn = func(string) error { return nil }
		t.Cleanup(func() { verifyOSUserFn = savedVerify })
	}
	if runtime.GOOS == "windows" {
		// Since 1.4 the Windows account comes from the process TOKEN, not
		// from %USERNAME%/%USERDOMAIN% — an environment variable must not
		// be able to rewrite whose registration this is (misc.go
		// currentOSUser). So the fixture pins the token seam, which is
		// also the only way this assertion can stop depending on whoever
		// is signed in while the suite runs.
		withAccount(t, `TESTMACHINE\testuser`)
	}
	addr, fp, got := startFakeBindingGateway(t, secret, boundMachine, boundOSUser)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	code := fmt.Sprintf("iamtunnel-enrol://%s:%s#%s:%s", host, port, fp, secret)

	// R4 F-04: enrol writes the enrolment anchor too; the fixture's
	// ancestors carry sandbox ACEs, so the write's ancestor check is set
	// aside here (its own refusals are pinned elsewhere).
	relaxAnchorAncestorCheck(t)
	dir := t.TempDir()
	out, errs, exitCode := driveInDir(t, dir, "enrol", code)
	if exitCode != exitOK {
		t.Fatalf("enrol: code=%d out=%q errs=%q", exitCode, out, errs)
	}

	if got.Machine != "" {
		t.Fatalf("the client named the machine %q — the name rides in the invitation, chosen by the administrator, and a client that names itself is refused rather than silently renamed", got.Machine)
	}
	// The account IS sent, and it is the value the fixture pins rather
	// than this host's real one, so the test does not depend on who is
	// signed in while it runs.
	if got.OSUser == "" {
		t.Fatal("the client sent no osUser — the account it runs as is the one fact only this machine knows, and the gateway requires it (SPEC §3.4)")
	}
	if runtime.GOOS == "windows" && got.OSUser != `TESTMACHINE\testuser` {
		t.Errorf("client sent osUser %q, want the account the process token names", got.OSUser)
	}

	if !strings.Contains(out, boundMachine) {
		t.Fatalf("enrol stdout does not echo the gateway-bound machine %q: %q", boundMachine, out)
	}
	if !strings.Contains(out, boundOSUser) {
		t.Fatalf("enrol stdout does not echo the gateway-bound osUser %q: %q", boundOSUser, out)
	}
}
