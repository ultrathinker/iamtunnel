package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// The CLI test below deliberately uses a small machine-side protocol peer.
// The gateway and command client remain the production implementations; the
// peer only supplies the two SSH channels that a real machine would supply.
type iamt133ControlDoor struct {
	ID     string `json:"id"`
	PubKey string `json:"pubkey"`
	Opened string `json:"opened"`
	Idle   string `json:"idleDeadline"`
	Hard   string `json:"hardDeadline"`
}

type iamt133ControlRequest struct {
	ID     string              `json:"id"`
	Op     string              `json:"op"`
	Door   *iamt133ControlDoor `json:"door,omitempty"`
	DoorID string              `json:"doorId,omitempty"`
}

type iamt133ControlResponse struct {
	Proto  int             `json:"proto"`
	Caps   []string        `json:"caps"`
	ID     string          `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type iamt133DoorOpenResult struct {
	DoorID               string `json:"doorId"`
	Installed            bool   `json:"installed"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint"`
}

type iamt133DoorCloseResult struct {
	DoorID  string `json:"doorId"`
	Removed bool   `json:"removed"`
}

type iamt133DoorStatusResult struct {
	Installed bool   `json:"installed"`
	DoorID    string `json:"doorId,omitempty"`
}

type iamt133Target struct {
	listener net.Listener
	signer   ssh.Signer

	mu      sync.Mutex
	allowed []byte
}

func newIAMT133Target(t *testing.T) *iamt133Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listener: %v", err)
	}
	target := &iamt133Target{listener: ln, signer: genTestSigner(t)}
	go target.accept()
	t.Cleanup(func() { _ = ln.Close() })
	return target
}

func (target *iamt133Target) addr() string { return target.listener.Addr().String() }

func (target *iamt133Target) accept() {
	for {
		raw, err := target.listener.Accept()
		if err != nil {
			return
		}
		go target.serve(raw)
	}
}

func (target *iamt133Target) serve(raw net.Conn) {
	defer raw.Close()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			target.mu.Lock()
			allowed := append([]byte(nil), target.allowed...)
			target.mu.Unlock()
			if bytes.Equal(key.Marshal(), allowed) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("IAMT-133 target: key is not the temporary door key")
		},
	}
	cfg.AddHostKey(target.signer)
	sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for n := range chans {
		_ = n.Reject(ssh.Prohibited, "probe does not open target channels")
	}
}

func (target *iamt133Target) setAllowed(blob []byte) {
	target.mu.Lock()
	target.allowed = append([]byte(nil), blob...)
	target.mu.Unlock()
}

func (target *iamt133Target) clearAllowed() {
	target.mu.Lock()
	target.allowed = nil
	target.mu.Unlock()
}

type iamt133Machine struct {
	conn       ssh.Conn
	raw        net.Conn
	target     *iamt133Target
	targetAddr string

	writeMu  sync.Mutex
	closeOne sync.Once
}

func newIAMT133Machine(t *testing.T, gatewayAddr, id string, signer ssh.Signer, target *iamt133Target) *iamt133Machine {
	t.Helper()
	raw, err := net.DialTimeout("tcp", gatewayAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("machine dial: %v", err)
	}
	cfg := &ssh.ClientConfig{
		User:            "machine:" + id,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, gatewayAddr, cfg)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("machine handshake: %v", err)
	}
	machine := &iamt133Machine{conn: conn, raw: raw, target: target, targetAddr: target.addr()}
	go machine.answerGlobalRequests(reqs)
	go machine.acceptChannels(chans)
	t.Cleanup(machine.close)
	return machine
}

func (machine *iamt133Machine) answerGlobalRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
	}
}

func (machine *iamt133Machine) acceptChannels(chans <-chan ssh.NewChannel) {
	for incoming := range chans {
		switch incoming.ChannelType() {
		case "iamtunnel-control":
			ch, reqs, err := incoming.Accept()
			if err != nil {
				continue
			}
			go discardIAMT133Requests(reqs)
			go machine.serveControl(ch)
		case "iamtunnel-target":
			ch, reqs, err := incoming.Accept()
			if err != nil {
				continue
			}
			go discardIAMT133Requests(reqs)
			go machine.spliceTarget(ch)
		default:
			_ = incoming.Reject(ssh.UnknownChannelType, "unexpected channel")
		}
	}
}

func discardIAMT133Requests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

func (machine *iamt133Machine) spliceTarget(ch ssh.Channel) {
	target, err := net.DialTimeout("tcp", machine.targetAddr, 5*time.Second)
	if err != nil {
		_ = ch.Close()
		return
	}
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, ch)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ch, target)
		_ = ch.CloseWrite()
	}()
	wg.Wait()
	_ = ch.Close()
}

func (machine *iamt133Machine) reply(ch ssh.Channel, response iamt133ControlResponse) {
	raw, err := json.Marshal(response)
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	machine.writeMu.Lock()
	_, _ = ch.Write(raw)
	machine.writeMu.Unlock()
}

func (machine *iamt133Machine) serveControl(ch ssh.Channel) {
	dec := json.NewDecoder(ch)
	for {
		var req iamt133ControlRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		switch req.Op {
		case "door.open":
			if req.Door == nil {
				machine.reply(ch, iamt133ControlResponse{Proto: 1, Caps: []string{}, ID: req.ID, Error: &struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{Code: "E_CONTROL_PROTOCOL", Message: "door.open has no door"}})
				continue
			}
			blob, err := state.DecodeKeyBlob(req.Door.PubKey)
			if err != nil {
				machine.reply(ch, iamt133ControlResponse{Proto: 1, Caps: []string{}, ID: req.ID, Error: &struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{Code: "E_CONTROL_PROTOCOL", Message: err.Error()}})
				continue
			}
			machine.target.setAllowed(blob)
			fp, _ := state.ComputeFingerprint(req.Door.PubKey)
			result, _ := json.Marshal(iamt133DoorOpenResult{DoorID: req.Door.ID, Installed: true, PublicKeyFingerprint: fp})
			machine.reply(ch, iamt133ControlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true, Result: result})
		case "door.close":
			machine.target.clearAllowed()
			result, _ := json.Marshal(iamt133DoorCloseResult{DoorID: req.DoorID, Removed: true})
			machine.reply(ch, iamt133ControlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true, Result: result})
		case "door.status":
			result, _ := json.Marshal(iamt133DoorStatusResult{})
			machine.reply(ch, iamt133ControlResponse{Proto: 1, Caps: []string{}, ID: req.ID, OK: true, Result: result})
		default:
			machine.reply(ch, iamt133ControlResponse{Proto: 1, Caps: []string{}, ID: req.ID, Error: &struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}{Code: "E_CONTROL_PROTOCOL", Message: "unknown operation"}})
		}
	}
}

func (machine *iamt133Machine) close() {
	machine.closeOne.Do(func() {
		_ = machine.conn.Close()
		_ = machine.raw.Close()
	})
}

func machineEvidenceLines(output string) (string, int) {
	var evidence string
	count := 0
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "  requested=") {
			evidence = line
			count++
		}
	}
	return evidence, count
}

func unverifiedMachineLine(output string) (string, int) {
	var line string
	count := 0
	for _, candidate := range strings.Split(output, "\n") {
		if strings.HasPrefix(candidate, "unverified-machine ") {
			line = candidate
			count++
		}
	}
	return line, count
}

// TestFinding03_TextMachineListRendersAllFiveVerdictFields exercises the
// ordinary list and verify commands through the real CLI and gateway. It
// protects the human recovery path: all three previously hidden evidence
// fields are visible, observed is rendered as the rekey-compatible
// fingerprint, and an unverified machine does not get invented evidence.
func TestFinding03_TextMachineListRendersAllFiveVerdictFields(t *testing.T) {
	const (
		machineID       = "vm133"
		machineName     = "verified-machine"
		unverifiedID    = "vm133-pending"
		unverifiedName  = "unverified-machine"
		adminName       = "alice"
		requestedOSUser = `CORP\iamt133`
	)

	target := newIAMT133Target(t)
	_, _, machineSigner := genTestKey(t)
	_, _, unverifiedSigner := genTestKey(t)
	hostLine := authorizedKeyLine(target.signer.PublicKey())
	hostFingerprint, err := state.ComputeFingerprint(hostLine)
	if err != nil {
		t.Fatalf("compute target host fingerprint: %v", err)
	}
	if normalized, err := config.NormalizeFingerprint(hostFingerprint); err != nil || normalized != hostFingerprint {
		t.Fatalf("target host fingerprint is not accepted by --confirm-fingerprint: %q, %v", hostFingerprint, err)
	}
	verifiedOSUser := requestedOSUser
	pinnedHostLine := hostLine
	observedHostLine := hostLine

	tg := startTestGateway(t, adminName, func(st *state.State) error {
		st.Machines = append(st.Machines,
			state.Machine{
				ID:                  machineID,
				Name:                machineName,
				State:               "verified",
				MachineKey:          authorizedKeyLine(machineSigner.PublicKey()),
				SSHDHostKey:         &pinnedHostLine,
				ObservedSSHDHostKey: &observedHostLine,
				HostKeyStatus:       state.HostKeyStatusMatch,
				RequestedOSUser:     requestedOSUser,
				VerifiedOSUser:      &verifiedOSUser,
				OSUserStatus:        state.OSUserStatusVerified,
				OSUser:              requestedOSUser,
			},
			state.Machine{
				ID:              unverifiedID,
				Name:            unverifiedName,
				State:           "enrolled",
				MachineKey:      authorizedKeyLine(unverifiedSigner.PublicKey()),
				HostKeyStatus:   state.HostKeyStatusUnverified,
				OSUserStatus:    state.OSUserStatusPending,
				RequestedOSUser: `CORP\pending`,
				OSUser:          `MACHINE\pending`,
			},
		)
		return nil
	})
	_ = newIAMT133Machine(t, tg.addr.String(), machineID, machineSigner, target)

	_, portString, err := net.SplitHostPort(tg.addr.String())
	if err != nil {
		t.Fatalf("split gateway address: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portString, "%d", &port); err != nil {
		t.Fatalf("parse gateway port: %v", err)
	}
	rootDir := t.TempDir()
	clientDir := clientDirFor(t, rootDir)
	writeClientKeyPEM(t, clientDir, tg.adminPriv)
	if err := client.SaveConnection(clientDir, config.ConnString{
		Host:        "127.0.0.1",
		Port:        port,
		Person:      adminName,
		Fingerprint: tg.hostFP,
	}, false); err != nil {
		t.Fatalf("save admin connection: %v", err)
	}

	var listOutput, listErrs string
	var listCode int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		listOutput, listErrs, listCode = driveInDir(t, rootDir, "admin", "machines", "list")
		if listCode == exitOK && strings.Contains(listOutput, machineID+" ") && strings.Contains(listOutput, "online") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if listCode != exitOK || !strings.Contains(listOutput, "online") {
		t.Fatalf("admin machines list: code=%d out=%q errs=%q, machine did not become online", listCode, listOutput, listErrs)
	}
	wantEvidence := fmt.Sprintf("  requested=%s verified=%s observed=%s", requestedOSUser, verifiedOSUser, hostFingerprint)
	if evidence, count := machineEvidenceLines(listOutput); count != 1 || evidence != wantEvidence {
		t.Fatalf("admin machines list evidence = %q (count=%d), want exactly %q; out=%q", evidence, count, wantEvidence, listOutput)
	}
	if strings.Contains(listOutput, hostLine) {
		t.Fatalf("admin machines list printed the raw observed host key instead of its fingerprint: %q", listOutput)
	}
	if pendingLine, count := unverifiedMachineLine(listOutput); count != 1 || strings.Contains(pendingLine, "requested=") || strings.Contains(pendingLine, "verified=") || strings.Contains(pendingLine, "observed=") {
		t.Fatalf("unverified machine evidence line = %q (count=%d), want no evidence fields; out=%q", pendingLine, count, listOutput)
	}

	verifyOutput, verifyErrs, verifyCode := driveInDir(t, rootDir, "admin", "machines", "verify", machineID)
	if verifyCode != exitOK || verifyErrs != "" {
		t.Fatalf("admin machines verify: code=%d out=%q errs=%q", verifyCode, verifyOutput, verifyErrs)
	}
	if evidence, count := machineEvidenceLines(verifyOutput); count != 1 || evidence != wantEvidence {
		t.Fatalf("admin machines verify evidence = %q (count=%d), want exactly %q; out=%q", evidence, count, wantEvidence, verifyOutput)
	}
	if strings.Contains(verifyOutput, hostLine) {
		t.Fatalf("admin machines verify printed the raw observed host key instead of its fingerprint: %q", verifyOutput)
	}
}
