package server

// acceptance_findings_test.go — finding tests from an independent
// review (IAMT-62, first pass). Each one FAILS if t.Skip is removed: it
// encodes a PROTOCOL.md/SPEC.md requirement the product code does not
// meet today. Skip is set explicitly, with the finding number named in
// the comment; once the author fixes it, Skip is removed — the test
// must go green.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// reviewDialOnly — like reviewStart, but WITHOUT opening the control
// channel (needed to check how the first channel-open with a non-empty
// initial payload is received).
func reviewDialOnly(t *testing.T) (*ssh.ServerConn, context.CancelFunc) {
	t.Helper()
	machineKey := mustSigner(t)
	gw := newReviewGateway(t)
	gw.startAccept()

	tree := testsupport.NewSSHTree(t)
	cfg := Config{
		GatewayAddr:        gw.addr(),
		GatewayFingerprint: gw.fingerprint(),
		MachineID:          "vm-review",
		MachineKey:         machineKey,
		KeyFile:            tree.KeyPath("administrators_authorized_keys"),
		DoorLockPath:       filepath.Join(tree.Home, "door.lock"),
		OwnerUID:           testUIDForDoor(),
		OwnerGID:           testGIDForDoor(),
		TargetAddr:         "127.0.0.1:1",
		SpawnWatchdog:      noopSpawnWatchdog,
		Keepalive:          sshx.Keepalive{Interval: 120 * time.Millisecond, MaxMisses: 3},
		DialTimeout:        5 * time.Second,
		HandshakeTimeout:   5 * time.Second,
	}
	if err := cfg.setDefaults(); err != nil {
		t.Fatalf("setDefaults: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	serveInBackground(t, ctx, cancel, m)
	return gw.wait(t), cancel
}

// FINDING-2: PROTOCOL §5.1 door.sanitize requires the machine to remove
// "every line with the iamtunnel-door= marker prefix (including
// corrupted ones and ones with an invalid UUID)", and SPEC §3.2
// promises the same for SweepStale. Reality:
// winkeys.IsOurs requires a strict tail ("marker + exactly 32 hex"), so
// a line with a corrupted tail is not considered "ours", and neither
// SweepStale nor door.sanitize removes it. The line stays in the file
// forever (inert, but SPEC §8 explicitly promises "a file with no dead
// lines" after a reconnect).
func TestReviewFINDING_SanitizeMustRemoveDamagedMarkerLine(t *testing.T) {
	damagedOurs := `restrict,pty,from="127.0.0.1" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7fakeProductKeyForTestsOnlyDoNotUseAnywhere iamtunnel-door=zzzz`
	dc, keyFile := newTestDoorController(t, nil)
	if err := os.WriteFile(keyFile, []byte(damagedOurs+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := dc.sanitize(controlRequest{ID: "z", Op: "door.sanitize", Reason: "corrupted"}); !r.OK {
		t.Fatalf("sanitize refused: %+v", r.Error)
	}
	b, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "iamtunnel-door=") {
		t.Fatalf("PROTOCOL §5.1: door.sanitize must remove a line with a corrupted marker, it stayed: %q", string(b))
	}
}

// TestSanitizeAndSweepStale_PreservesForeignLinesWithMarkerText verifies that widening
// the ownership rule to sweep unreadable-key door lines (IAMT-94) does not delete or
// alter any foreign keys or comments, even if they contain the text "iamtunnel-door=".
// All foreign lines are preserved byte-for-byte and in their exact original order.
func TestSanitizeAndSweepStale_PreservesForeignLinesWithMarkerText(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)

	foreign1 := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRealAdminKey1 admin@example.com`
	foreign2 := `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQRealAdminKey2 admin@example.com backup key iamtunnel-door=deadbeefcafebabe1234567890abcdef`
	foreign3 := `# human comment: iamtunnel-door=deadbeef`
	damagedOurs1 := `restrict,pty,from="127.0.0.1" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7fakeProductKeyForTestsOnlyDoNotUseAnywhere iamtunnel-door=zzzz`
	foreign4 := `restrict,pty,from="127.0.0.1" ssh-ed25519 ` + winkeys.TestKey + ` ordinary-comment iamtunnel-door=deadbeef`
	damagedOurs2 := `restrict,pty,from="127.0.0.1" ssh-ed25519 not-a-base64-key iamtunnel-door=deadbeefdeadbeefdeadbeefdeadbeef`
	foreign5 := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRealAdminKey3 admin3@example.com`

	initialContent := foreign1 + "\r\n" +
		foreign2 + "\r\n\r\n" +
		foreign3 + "\r\n" +
		damagedOurs1 + "\r\n" +
		foreign4 + "\r\n" +
		damagedOurs2 + "\r\n" +
		foreign5 + "\r\n"

	wantContent := foreign1 + "\r\n" +
		foreign2 + "\r\n\r\n" +
		foreign3 + "\r\n" +
		foreign4 + "\r\n" +
		foreign5 + "\r\n"

	if err := os.WriteFile(keyFile, []byte(initialContent), 0o600); err != nil {
		t.Fatal(err)
	}

	resp := dc.sanitize(controlRequest{ID: "clean-corrupt", Op: "door.sanitize", Reason: "corrupted"})
	if !resp.OK {
		t.Fatalf("sanitize failed: %+v", resp.Error)
	}

	got, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != wantContent {
		t.Fatalf("foreign lines corrupted or reordered after sanitize:\n got: %q\nwant: %q", string(got), wantContent)
	}
}

// FINDING-3: PROTOCOL §5 requires that a channel-open to the machine
// with a non-empty initial payload get a channel failure ("any other
// channel-open, non-empty initial payload, or an attempt by the
// machine to open a channel gets a channel failure"). The machine does
// not look at ExtraData at all and accepts such a channel: both
// control on a fresh tunnel, and target.
func TestReviewFINDING_ChannelOpenWithInitialPayloadRejected(t *testing.T) {
	sc, cancel := reviewDialOnly(t)
	defer cancel()

	if ch, _, err := sc.OpenChannel("iamtunnel-control", []byte("attacker-controlled-bytes")); err == nil {
		_ = ch.Close()
		t.Fatal("PROTOCOL §5: a control channel with a non-empty initial payload must be rejected, but was accepted")
	}
	if ch, _, err := sc.OpenChannel("iamtunnel-target", []byte("attacker-controlled-bytes")); err == nil {
		_ = ch.Close()
		t.Fatal("PROTOCOL §5: a target channel with a non-empty initial payload must be rejected, but was accepted")
	}
}

// FINDING-4: PROTOCOL §5.1 requires the proto, caps, id (uuid type)
// fields in every control-channel object; §1.3 requires E_JSON_INVALID
// for a missing required field. decodeControlRequest checks none of
// proto, caps, or id: an object without them is accepted and executed,
// and the response goes out with an empty id.
func TestReviewFINDING_EnvelopeFieldsUnchecked(t *testing.T) {
	for name, line := range map[string]string{
		"no id at all":  `{"proto":1,"caps":[],"op":"door.status"}`,
		"no proto":      `{"caps":[],"id":"11111111-1111-1111-1111-111111111111","op":"door.status"}`,
		"no caps":       `{"proto":1,"id":"11111111-1111-1111-1111-111111111111","op":"door.status"}`,
		"id not a uuid": `{"proto":1,"caps":[],"id":"not-a-uuid","op":"door.status"}`,
	} {
		if req, err := decodeControlRequest([]byte(line), DefaultControlJSONDepth); err == nil {
			t.Fatalf("PROTOCOL §5.1/§1.3: request [%s] must be refused (missing a required field), was accepted as %+v", name, req)
		}
	}
}
