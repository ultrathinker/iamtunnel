package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

const iamt143ChildEnv = "IAMT143_CHILD"

// The parent process is deliberate: removing the production recovery would
// kill the child test process with an unrecovered panic, while the parent can
// still report the canary at its own assertion instead of disappearing with
// the handler goroutine.
func runIAMT143Child(t *testing.T, testName, role string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "^"+testName+"$", "-test.v", "-test.count=1")
	cmd.Env = make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, iamt143ChildEnv+"=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, iamt143ChildEnv+"="+role)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("IAMT-143 %s child process crashed before isolation assertion: %v\n%s", role, err, out)
	}
	if !bytes.Contains(out, []byte("PASS")) {
		t.Fatalf("IAMT-143 %s child did not report PASS:\n%s", role, out)
	}
}

func TestIAMT143_BootstrapPanicIsolated(t *testing.T) {
	if os.Getenv(iamt143ChildEnv) == "bootstrap" {
		iamt143BootstrapChild(t)
		return
	}
	runIAMT143Child(t, "TestIAMT143_BootstrapPanicIsolated", "bootstrap")
}

func TestIAMT143_EnrolPanicIsolated(t *testing.T) {
	if os.Getenv(iamt143ChildEnv) == "enrol" {
		iamt143EnrolChild(t)
		return
	}
	runIAMT143Child(t, "TestIAMT143_EnrolPanicIsolated", "enrol")
}

type iamt143WireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type iamt143WireEnvelope struct {
	Proto  int               `json:"proto"`
	OK     bool              `json:"ok"`
	Result json.RawMessage   `json:"result"`
	Error  *iamt143WireError `json:"error"`
}

func iamt143Exec(t *testing.T, addr, user string, signer ssh.Signer, command string, body any) (iamt143WireEnvelope, uint32) {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("IAMT-143 %s dial: %v", user, err)
	}
	defer client.Close()

	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("IAMT-143 %s open session: %v", user, err)
	}
	defer ch.Close()

	exits := make(chan uint32, 1)
	go func() {
		for req := range reqs {
			if req.Type == "exit-status" {
				if status, parseErr := sshx.ParseExitStatus(req.Payload); parseErr == nil {
					select {
					case exits <- status.Status:
					default:
					}
				}
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()

	rawBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("IAMT-143 %s encode body: %v", user, err)
	}
	ok, err := ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command}))
	if err != nil {
		t.Fatalf("IAMT-143 %s exec request: %v", user, err)
	}
	if !ok {
		t.Fatalf("IAMT-143 %s exec request was refused before the handler ran", user)
	}
	if _, err := ch.Write(rawBody); err != nil {
		t.Fatalf("IAMT-143 %s write body: %v", user, err)
	}
	if err := ch.CloseWrite(); err != nil {
		t.Fatalf("IAMT-143 %s close request body: %v", user, err)
	}

	type readResult struct {
		raw []byte
		err error
	}
	readDone := make(chan readResult, 1)
	go func() {
		raw, readErr := io.ReadAll(ch)
		readDone <- readResult{raw: raw, err: readErr}
	}()
	var read readResult
	select {
	case read = <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("IAMT-143 %s did not receive a response", user)
	}
	if read.err != nil {
		t.Fatalf("IAMT-143 %s read response: %v", user, read.err)
	}

	var envelope iamt143WireEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(read.raw), &envelope); err != nil {
		t.Fatalf("IAMT-143 %s response is not JSON: %v; raw=%q", user, err, read.raw)
	}

	var status uint32
	select {
	case status = <-exits:
	case <-time.After(5 * time.Second):
		t.Fatalf("IAMT-143 %s response had no exit-status", user)
	}
	return envelope, status
}

func setIAMT143BootstrapPending(t *testing.T, f *fixture, secret, publicKey string) {
	t.Helper()
	hash := state.HashEnrolSecret(f.gw.enrolHMAC, []byte(secret))
	if err := f.store.Update(func(st *state.State) error {
		st.BootstrapPending = &state.BootstrapPending{
			SecretHash: hash,
			PublicKey:  publicKey,
			Expires:    state.NewZonedTime(f.clock.Now().Add(time.Hour)),
		}
		return nil
	}); err != nil {
		t.Fatalf("IAMT-143 seed bootstrap pending: %v", err)
	}
}

func setIAMT143EnrolPending(t *testing.T, f *fixture, secret, publicKey string) {
	t.Helper()
	hash := state.HashEnrolSecret(f.gw.enrolHMAC, []byte(secret))
	// The invitation lives in state.PendingEnrolments and carries the
	// name (1.4). This scenario must exercise ONLY the HMAC-zero panic
	// path, so the fixture's seeded machine is dropped first: otherwise
	// the invitation's name would meet the collision check and the test
	// would be measuring that instead.
	if err := f.store.Update(func(st *state.State) error {
		// Drop any seeded machine with this id; the test asserts the
		// enrol path creates one fresh.
		for i := range st.Machines {
			if st.Machines[i].ID == f.machineID {
				st.Machines = append(st.Machines[:i], st.Machines[i+1:]...)
				break
			}
		}
		st.PendingEnrolments = append(st.PendingEnrolments, state.PendingEnrolment{
			Name:       f.machineID,
			SecretHash: hash,
			PublicKey:  publicKey,
			Expires:    state.NewZonedTime(f.clock.Now().Add(time.Hour)),
		})
		return nil
	}); err != nil {
		t.Fatalf("IAMT-143 seed enrol pending: %v", err)
	}
}

func iamt143BootstrapChild(t *testing.T) {
	f := newFixture(t, nil)
	const secret = "iamt143-bootstrap-secret"
	eph, err := config.DeriveEphemeralSigner(secret, config.BootstrapKeySalt)
	if err != nil {
		t.Fatalf("IAMT-143 derive bootstrap signer: %v", err)
	}
	pubkey := authorizedLine(eph.PublicKey())
	adminKey := genSigner(t)
	setIAMT143BootstrapPending(t, f, secret, pubkey)

	validHMAC := f.gw.enrolHMAC
	f.gw.enrolHMAC = state.EnrolHMACKey{}
	first, firstStatus := iamt143Exec(t, f.addr, "bootstrap", eph, "admin.claim", bootstrapRequest{
		Proto: 1, Bootstrap: secret, Pubkey: authorizedLine(adminKey.PublicKey()),
	})
	if first.OK || first.Error == nil || first.Error.Code != "E_INTERNAL" {
		t.Fatalf("bootstrap panic did not become an E_INTERNAL refusal for this request: %+v", first)
	}
	if firstStatus != 70 {
		t.Fatalf("bootstrap panic refusal exit status = %d, want 70", firstStatus)
	}
	f.gw.enrolHMAC = validHMAC

	second, secondStatus := iamt143Exec(t, f.addr, "bootstrap", eph, "admin.claim", bootstrapRequest{
		Proto: 1, Bootstrap: secret, Pubkey: authorizedLine(adminKey.PublicKey()),
	})
	if !second.OK {
		t.Fatalf("independent bootstrap session did not remain alive after recovered panic: %+v", second)
	}
	if secondStatus != 0 {
		t.Fatalf("independent bootstrap session exit status = %d, want 0", secondStatus)
	}
	var result bootstrapResult
	if err := json.Unmarshal(second.Result, &result); err != nil {
		t.Fatalf("bootstrap success result: %v", err)
	}
	if result.Role != "admin" {
		t.Fatalf("bootstrap success role = %q, want %q", result.Role, "admin")
	}

	eventsSeen, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}})
	if err != nil {
		t.Fatalf("read bootstrap panic event: %v", err)
	}
	panicLogged := false
	for _, event := range eventsSeen {
		if event.Result == "bootstrap:panic" {
			panicLogged = true
			if !strings.Contains(event.Details["panic"].(string), "zero EnrolHMACKey") {
				t.Fatalf("bootstrap panic event lost the invariant detail: %+v", event)
			}
		}
	}
	if !panicLogged {
		t.Fatalf("bootstrap panic was not recorded as existing admin.op result %q", "bootstrap:panic")
	}
}

func iamt143EnrolChild(t *testing.T) {
	f := newFixture(t, nil)
	const secret = "iamt143-enrol-secret"
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("IAMT-143 derive enrol signer: %v", err)
	}
	setIAMT143EnrolPending(t, f, secret, authorizedLine(eph.PublicKey()))
	newMachineKey := genSigner(t)
	// No Machine field: the invitation names the registration (1.4),
	// and a body that named one too would only be checked for
	// agreement.
	request := enrolRequest{
		Proto:      1,
		Secret:     secret,
		OSUser:     `MACHINE\svc`,
		MachineKey: authorizedLine(newMachineKey.PublicKey()),
	}

	validHMAC := f.gw.enrolHMAC
	f.gw.enrolHMAC = state.EnrolHMACKey{}
	first, firstStatus := iamt143Exec(t, f.addr, "enrol", eph, "enrol", request)
	if first.OK || first.Error == nil || first.Error.Code != "E_INTERNAL" {
		t.Fatalf("enrol panic did not become an E_INTERNAL refusal for this request: %+v", first)
	}
	if firstStatus != 70 {
		t.Fatalf("enrol panic refusal exit status = %d, want 70", firstStatus)
	}
	f.gw.enrolHMAC = validHMAC

	second, secondStatus := iamt143Exec(t, f.addr, "enrol", eph, "enrol", request)
	if !second.OK {
		t.Fatalf("independent enrol session did not remain alive after recovered panic: %+v", second)
	}
	if secondStatus != 0 {
		t.Fatalf("independent enrol session exit status = %d, want 0", secondStatus)
	}
	var result enrolResult
	if err := json.Unmarshal(second.Result, &result); err != nil {
		t.Fatalf("enrol success result: %v", err)
	}
	if result.State != "enrolled" {
		t.Fatalf("enrol success state = %q, want %q", result.State, "enrolled")
	}

	st := f.store.Get()
	machine, ok := st.MachineByID(f.machineID)
	if !ok || machine.EnrolPending != nil || machine.State != "enrolled" {
		t.Fatalf("independent enrol session did not commit after recovery: machine=%+v found=%v", machine, ok)
	}

	eventsSeen, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventEnrolFailed}})
	if err != nil {
		t.Fatalf("read enrol panic event: %v", err)
	}
	panicLogged := false
	for _, event := range eventsSeen {
		if event.Result == "panic" {
			panicLogged = true
			if !strings.Contains(event.Details["panic"].(string), "zero EnrolHMACKey") {
				t.Fatalf("enrol panic event lost the invariant detail: %+v", event)
			}
		}
	}
	if !panicLogged {
		t.Fatalf("enrol panic was not recorded as existing enrol.failed result %q", "panic")
	}
}
