package gateway

// iamt217_pty_zero_size_test.go is the canary for IAMT-217: OpenSSH's client
// sends pty-req with cols=0/rows=0 when stdin is not a terminal (RFC 4254
// §6.2 explicitly permits a zero size; this is not malformed input). A
// live probe against a real Windows 11 machine showed the
// gateway substituting 80x24 only for its OWN bookkeeping - the sessionStart
// used for the .cast header and the VT parser - while forwarding the raw
// 0x0 payload to the machine via target.SendRequest. OpenSSH for Windows/
// ConPTY then picks its own default size for the pty (observed 120x30),
// so the .cast header (80x24) and the machine's actual screen (120x30)
// disagree, and the VT parser replays the session in the wrong geometry.
//
// Canary: revert human_role.go's awaitSessionStart to parse pty.Columns/Rows
// only for the LOCAL cols/rows returned in sessionStart, without also
// rewriting r.Payload via fixPTYSize, and this test's first assertion
// (machine side sees 0x0) starts failing this test in the other direction -
// or, if fixPTYSize is removed but the substitution is dropped
// entirely, the .cast header assertion catches a mismatched size instead.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// TestIAMT217_ZeroSizePTYReqGetsDefaultSizeOnWire drives a PTY session where
// the human's pty-req carries cols=0/rows=0 (OpenSSH's real behaviour when
// stdin is not a terminal) and checks that the machine receives the SAME
// 80x24 substituted size that ends up in the .cast header - not the raw
// 0x0 the human actually sent.
func TestIAMT217_ZeroSizePTYReqGetsDefaultSizeOnWire(t *testing.T) {
	var gotCols, gotRows int
	seen := make(chan struct{}, 1)

	f := newFixture(t, nil)
	f.sshd.setOnPTYReq(func(cols, rows int) {
		gotCols, gotRows = cols, rows
		select {
		case seen <- struct{}{}:
		default:
		}
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)

	ok, err := hs.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 0, Rows: 0}))
	if err != nil || !ok {
		t.Fatalf("pty-req 0x0: ok=%v err=%v", ok, err)
	}
	ok, err = hs.ch.SendRequest("shell", true, nil)
	if err != nil || !ok {
		t.Fatalf("shell: ok=%v err=%v", ok, err)
	}

	select {
	case <-seen:
	case <-time.After(3 * time.Second):
		t.Fatal("IAMT-217 canary precondition failed: the fake machine sshd never observed the forwarded pty-req")
	}
	if gotCols != defaultPTYColumns || gotRows != defaultPTYRows {
		t.Fatalf("IAMT-217 canary: machine side saw pty-req %dx%d, want %dx%d (the default substituted for 0x0) - "+
			"the gateway forwarded the raw 0x0 payload instead of the corrected one",
			gotCols, gotRows, defaultPTYColumns, defaultPTYRows)
	}

	_ = hs.ch.CloseWrite()
	_ = hs.ch.Close()
	waitUntil(t, "PTY session did not close", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	paths, err := filepath.Glob(filepath.Join(f.recordingsDir(), "*", "*", "*.cast"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("IAMT-217: pty session must create exactly one .cast, paths=%v err=%v", paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	header := struct {
		Width, Height int
	}{}
	headerLine := raw
	if i := bytes.IndexByte(raw, '\n'); i >= 0 {
		headerLine = raw[:i]
	}
	if err := json.Unmarshal(headerLine, &header); err != nil {
		t.Fatalf("decode cast header: %v", err)
	}
	if header.Width != defaultPTYColumns || header.Height != defaultPTYRows {
		t.Fatalf("IAMT-217 canary: .cast header is %dx%d, want %dx%d - it must match what the machine actually got",
			header.Width, header.Height, defaultPTYColumns, defaultPTYRows)
	}
}

// TestIAMT217_NonZeroPTYReqIsForwardedUnchanged is the companion canary: a
// pty-req that already carries a real size must reach the machine
// byte-for-byte, with no substitution.
func TestIAMT217_NonZeroPTYReqIsForwardedUnchanged(t *testing.T) {
	var gotCols, gotRows int
	seen := make(chan struct{}, 1)

	f := newFixture(t, nil)
	f.sshd.setOnPTYReq(func(cols, rows int) {
		gotCols, gotRows = cols, rows
		select {
		case seen <- struct{}{}:
		default:
		}
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)

	ok, err := hs.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 132, Rows: 43}))
	if err != nil || !ok {
		t.Fatalf("pty-req 132x43: ok=%v err=%v", ok, err)
	}
	ok, err = hs.ch.SendRequest("shell", true, nil)
	if err != nil || !ok {
		t.Fatalf("shell: ok=%v err=%v", ok, err)
	}

	select {
	case <-seen:
	case <-time.After(3 * time.Second):
		t.Fatal("IAMT-217 canary precondition failed: the fake machine sshd never observed the forwarded pty-req")
	}
	if gotCols != 132 || gotRows != 43 {
		t.Fatalf("IAMT-217 canary: machine side saw pty-req %dx%d, want 132x43 unchanged", gotCols, gotRows)
	}
}
