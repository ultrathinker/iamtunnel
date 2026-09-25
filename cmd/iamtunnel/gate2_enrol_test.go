package main

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
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// gate2_enrol_test.go proves the success-path gate for "enrol". The
// gateway side of the enrol role now exists in internal/gateway
// (IAMT-90) and is exercised end-to-end by test/e2e against a real
// gateway.New+Serve; this file keeps a small protocol-faithful fake
// gateway so the CLIENT
// path — code parsing, PROTOCOL §3.2's HKDF key derivation, the SSH
// dial as username "enrol", the exec round trip, and saving the result
// to disk — stays covered in isolation, without spinning up a whole
// gateway inside the cmd package.

// fakeEnrolGateway accepts exactly one SSH connection as username
// "enrol" authenticated with the PROTOCOL §3.2 HKDF-derived key for the
// given secret, serves exactly one "enrol" exec command, and answers
// with a fixed, valid PROTOCOL §6 result — the gateway's OWN binding
// (machine id and OS user), never an echo of what the client sent
// (IAMT-205/IAMT-204 semantics).
func startFakeEnrolGateway(t *testing.T, secret, wantMachine, wantOSUser string) (addr string, fingerprint string) {
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

	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		cfg := &ssh.ServerConfig{
			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				if conn.User() != "enrol" {
					return nil, fmt.Errorf("fake enrol gateway: wrong username %q", conn.User())
				}
				if string(key.Marshal()) != string(wantPub) {
					return nil, fmt.Errorf("fake enrol gateway: key does not match the HKDF-derived enrol key")
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
			var got enrolRequest
			_ = json.Unmarshal(body, &got)
			if got.Secret != secret {
				_ = ch.Close()
				continue
			}
			resp := struct {
				Proto  int         `json:"proto"`
				Caps   []string    `json:"caps"`
				OK     bool        `json:"ok"`
				Result enrolResult `json:"result"`
			}{Proto: 1, Caps: []string{}, OK: true, Result: enrolResult{
				Machine: wantMachine, State: "enrolled", RequestedOSUser: wantOSUser,
				OSUserStatus: "pending", HostKeyStatus: "unverified", ServerTime: "2026-09-13T00:00:00Z",
			}}
			raw, _ := json.Marshal(resp)
			_, _ = ch.Write(append(raw, '\n'))
			_ = ch.Close()
		}
	}()

	sum := sha256.Sum256(hostSigner.PublicKey().Marshal())
	return ln.Addr().String(), base64.RawStdEncoding.EncodeToString(sum[:])
}

// TestGate2_EnrolSuccessPath: "iamtunnel enrol <code>" against a real
// (fake but protocol-faithful) gateway really saves the machine identity
// to disk — exit 0 plus machine.key, machine.id and gateway.json really
// exist and parse (the gate's "observable consequence").
func TestGate2_EnrolSuccessPath(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("enrol refuses root by design (SPEC §3.2.1: a machine does not register as root) — the success path this test drives cannot run under root, as inside a root container")
	}
	const secret = "s3cret-token1"
	const wantMachine = "win01-test"
	// The gateway binds an OS user at enrol-code time and the client
	// verifies that binding against the local machine before persisting
	// anything (IAMT-248 fix1). The binding's FORM is per-OS (IAMT-271):
	// an empty binding is legal on Windows (the Windows server role has
	// no per-user OS binding), while Linux/macOS require a POSIX local
	// name and its local existence — checked through the verifyOSUserFn
	// seam (elevate.VerifyOSUser in production, fixed observation here,
	// the same posture userLookupFn has in iamt248_server_start_linux_test.go).
	// The product gate itself is untouched: the format check and the
	// existence check both still run on the wire-side value.
	wantOSUser := ""
	if runtime.GOOS != "windows" {
		wantOSUser = "svc-ssh"
		savedVerify := verifyOSUserFn
		verifyOSUserFn = func(string) error { return nil }
		t.Cleanup(func() { verifyOSUserFn = savedVerify })
	}
	addr, fp := startFakeEnrolGateway(t, secret, wantMachine, wantOSUser)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	code := fmt.Sprintf("iamtunnel-enrol://%s:%s#%s:%s", host, port, fp, secret)

	// R4 F-04: enrol now also writes the enrolment anchor under the
	// fixture's %ProgramData%; the fixture's ancestors carry this box's
	// sandbox ACEs, so the anchor write's ancestor check is set aside
	// (its refusals themselves stay pinned by the r2cx ancestor tests).
	relaxAnchorAncestorCheck(t)
	dir := t.TempDir()
	out, errs, exitCode := driveInDir(t, dir, "enrol", code)
	if exitCode != exitOK {
		t.Fatalf("enrol: code=%d out=%q errs=%q", exitCode, out, errs)
	}
	if !strings.Contains(out, wantMachine) {
		t.Fatalf("enrol: stdout does not mention the assigned machine id: %q", out)
	}

	serverDir := dir
	if runtime.GOOS == "windows" {
		resolved, err := config.DirsFor(runtime.GOOS, testsupport.PlatformDataEnvAt(t, dir))
		if err != nil {
			t.Fatalf("resolve server dir for %q: %v", dir, err)
		}
		serverDir = resolved.Server
	}
	dirs := config.Dirs{Server: serverDir}

	if _, err := loadSignerStrict(dirs.MachineKey()); err != nil {
		t.Errorf("machine.key was not saved usably: %v", err)
	}
	idData, err := os.ReadFile(dirs.MachineID())
	if err != nil {
		t.Fatalf("machine.id was not saved: %v", err)
	}
	if string(idData) != wantMachine {
		t.Errorf("machine.id = %q, want %q", idData, wantMachine)
	}
	rec, err := loadGatewayRecord(serverDir)
	if err != nil {
		t.Fatalf("gateway.json was not saved usably: %v", err)
	}
	if rec.MachineID != wantMachine || rec.Host != host || rec.OSUser != wantOSUser {
		t.Errorf("gateway.json = %+v, want machineId=%q host=%q os-user=%q", rec, wantMachine, host, wantOSUser)
	}
}
