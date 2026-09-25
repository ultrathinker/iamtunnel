package main

// iamt340_tail_control_test.go — IAMT-340 at the local end: the control
// socket's "tail" command.
//
// What is real here: the listener, control.json, the running server's own
// handler (serveControl → handleControlConn), and the client half the
// window will call (sendControlTail). What is faked is only the thing
// that needs a tunnel and a gateway — the tailFunc seam, which is the
// same kind of substitution doorStatusFunc already gets in IAMT-182's
// tests. So this file pins the machine's own boundary: what the socket
// asks, what it hands back, and — the part worth the most care — which
// failures are the gateway's verdict and which are this server's own.

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/server"
)

// tailControlServer starts the product's own control listener for one
// test and returns the data dir control.json was written into.
func tailControlServer(t *testing.T, tail tailFunc) string {
	t.Helper()
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("control listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	token := "iamt340-control-token"
	port := ln.Addr().(*net.TCPAddr).Port
	// atomicWriteJSON, not atomicWriteMachineJSON: the machine writer
	// stamps a Windows DACL this test process may not hold, and the file
	// itself is byte-identical either way (the same choice IAMT-249's
	// stop/status test makes for the same reason).
	if werr := atomicWriteJSON(controlFilePath(dir), controlFileRecord{PID: os.Getpid(), Port: port, Token: token}); werr != nil {
		t.Fatalf("control.json: %v", werr)
	}
	go serveControl(ln, dir, token, func() {}, func() (bool, bool) { return true, false }, tail, nil, nil)
	return dir
}

// recordingTail is the fake tunnel: it remembers what it was asked and
// answers with whatever the test decided.
type recordingTail struct {
	mu      sync.Mutex
	got     []server.TailRequest
	answer  server.TailAnswer
	err     error
	release chan struct{}
}

func (r *recordingTail) call(_ context.Context, req server.TailRequest) (server.TailAnswer, error) {
	r.mu.Lock()
	r.got = append(r.got, req)
	r.mu.Unlock()
	if r.release != nil {
		<-r.release
	}
	return r.answer, r.err
}

func (r *recordingTail) requests() []server.TailRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]server.TailRequest(nil), r.got...)
}

func decodeTailReply(t *testing.T, reply controlReplyMsg) tailReplyMsg {
	t.Helper()
	if reply.Tail == nil {
		t.Fatalf("the reply carries no tail object at all: %+v", reply)
	}
	return *reply.Tail
}

// TestIAMT340_LocalTailRelaysTheQuestionAndTheAnswer is the path in one
// piece: the window asks its own server, the server asks the tunnel with
// the very same fields, and the tunnel's answer comes back byte for byte.
//
// Canary: drop `ID: req.SessionID` in sendControlTail (or swap
// `Offset`/`Limit`) — "the tunnel was asked %+v, want the window's
// own request %+v" turns red; and if handleTailCommand reassembles the
// reply instead of passing `Result: answer.Result` — "result came back as %q, want
// the tunnel's own bytes %q".
func TestIAMT340_LocalTailRelaysTheQuestionAndTheAnswer(t *testing.T) {
	const body = `{"id":"1758130000000000000-alice-vm1","offset":4096,"total":81234,"live":true,"data":"AAECA/8="}`
	tun := &recordingTail{answer: server.TailAnswer{Result: json.RawMessage(body)}}
	dir := tailControlServer(t, tun.call)

	want := server.TailRequest{SessionID: "1758130000000000000-alice-vm1", Offset: 4096, Limit: 8192}
	reply, contacted, err := sendControlTail(dir, want)
	if err != nil {
		t.Fatalf("sendControlTail: %v", err)
	}
	if !contacted {
		t.Fatal("sendControlTail reported the server was not running, but this test just started one")
	}
	if !reply.OK {
		t.Fatalf("reply.OK = false for a successful answer: %+v", reply)
	}

	got := tun.requests()
	if len(got) != 1 {
		t.Fatalf("the tunnel was called %d times, want exactly 1", len(got))
	}
	if got[0] != want {
		t.Fatalf("the tunnel was asked %+v, want the window's own request %+v — the socket must not rewrite the question", got[0], want)
	}

	tail := decodeTailReply(t, reply)
	if string(tail.Result) != body {
		t.Fatalf("result came back as %q, want the tunnel's own bytes %q — the socket must not retell the answer", string(tail.Result), body)
	}
	if tail.Refusal != nil {
		t.Fatalf("a successful answer carried a refusal: %+v", tail.Refusal)
	}
	if reply.Message != "" {
		t.Fatalf("a successful answer carried a message: %q", reply.Message)
	}
}

// TestIAMT340_LocalTailCarriesTheGatewayRefusalAsTheGatewaysAnswer is the
// third claim at the socket: the gateway's no reaches the window as the
// gateway's no — its code, its message — and NOT as a transport error,
// which would be this server claiming the question never got through.
//
// Canary: return `fail("tail refused")` from handleTailCommand in the
// `case answer.Refusal != nil:` branch — "refusal code = %q, want the
// gateway's own %q" turns red (Tail would come out nil).
func TestIAMT340_LocalTailCarriesTheGatewayRefusalAsTheGatewaysAnswer(t *testing.T) {
	tun := &recordingTail{answer: server.TailAnswer{Refusal: &server.TailRefusal{
		Code:    "E_NOT_FOUND",
		Message: "no such session",
	}}}
	dir := tailControlServer(t, tun.call)

	reply, contacted, err := sendControlTail(dir, server.TailRequest{SessionID: "1758130000000000000-bob-other", Limit: 1024})
	if err != nil {
		t.Fatalf("sendControlTail returned %v — the gateway answered, and its no is not a transport failure", err)
	}
	if !contacted {
		t.Fatal("sendControlTail reported the server was not running")
	}
	if reply.OK {
		t.Fatalf("reply.OK = true for a refusal: %+v", reply)
	}
	tail := decodeTailReply(t, reply)
	if tail.Refusal == nil {
		t.Fatalf("the refusal was dropped: %+v", tail)
	}
	if tail.Refusal.Code != "E_NOT_FOUND" {
		t.Fatalf("refusal code = %q, want the gateway's own %q", tail.Refusal.Code, "E_NOT_FOUND")
	}
	if reply.Message != "no such session" {
		t.Fatalf("reply.Message = %q, want the gateway's own message %q", reply.Message, "no such session")
	}
	if len(tail.Result) != 0 {
		t.Fatalf("a refusal carried a body too: %q", string(tail.Result))
	}
}

// TestIAMT340_LocalTailMachineSideFailureIsNotDressedAsTheGatewaysRefusal
// is the other half of the same rule, and the one a helpful-looking
// shortcut would break: when the tunnel is down, this server may say so
// in its own words, but it must not produce a tail object at all. The
// presence of that object is the window's only signal that the GATEWAY
// spoke; a machine-side failure wearing one would be a lie about who
// refused.
//
// Canary: in handleTailCommand's `if err != nil` branch return
// `controlReplyMsg{OK: false, Tail: &tailReplyMsg{Refusal: &server.TailRefusal{Code: "E_OFFLINE"}}}` —
// "a machine-side failure produced a tail object" turns red.
func TestIAMT340_LocalTailMachineSideFailureIsNotDressedAsTheGatewaysRefusal(t *testing.T) {
	tun := &recordingTail{err: server.ErrNoControlChannel}
	dir := tailControlServer(t, tun.call)

	reply, contacted, err := sendControlTail(dir, server.TailRequest{SessionID: "1758130000000000000-alice-vm1", Limit: 1024})
	if err != nil {
		t.Fatalf("sendControlTail returned %v — a server-side failure is an ANSWER on this socket, not a broken socket", err)
	}
	if !contacted {
		t.Fatal("sendControlTail reported the server was not running")
	}
	if reply.OK {
		t.Fatalf("reply.OK = true although the tunnel could not be asked: %+v", reply)
	}
	if reply.Tail != nil {
		t.Fatalf("a machine-side failure produced a tail object (%+v) — and with it the implication that the gateway spoke", reply.Tail)
	}
	if reply.Message == "" {
		t.Fatal("a machine-side failure came back with no explanation at all")
	}
	if len(tun.requests()) != 1 {
		t.Fatalf("the tunnel was called %d times, want exactly 1", len(tun.requests()))
	}
}

// TestIAMT340_LocalTailWithNoServerRunning pins the "not running" case:
// no control.json, so nothing is dialled and nothing is invented.
//
// Canary: make sendControlTail return an error instead of contacted=false
// on a missing control.json — "sendControlTail on an empty
// directory returned err …, want the ordinary not-running answer".
func TestIAMT340_LocalTailWithNoServerRunning(t *testing.T) {
	reply, contacted, err := sendControlTail(t.TempDir(), server.TailRequest{SessionID: "x", Limit: 1024})
	if err != nil {
		t.Fatalf("sendControlTail on an empty directory returned err %v, want the ordinary not-running answer", err)
	}
	if contacted {
		t.Fatal("sendControlTail reported a running server in an empty directory")
	}
	if reply.Tail != nil || reply.OK {
		t.Fatalf("a not-running server produced an answer: %+v", reply)
	}
}

// TestIAMT340_TailAnswersWhileOtherCommandsKeepWorking is the socket's
// own regression guard: "tail" was added next to "status" and "stop", and
// the two that were already there must be untouched by it. The running
// server answers a tail from the (slow) tunnel and a status from memory,
// concurrently, with no interference between them.
//
// Canary: remove `case "tail":` from handleControlConn (that is, answer
// "unknown control command tail") — "the tunnel was called 0
// times, want exactly 1" turns red: the question never reached the
// tunnel.
func TestIAMT340_TailAnswersWhileOtherCommandsKeepWorking(t *testing.T) {
	release := make(chan struct{})
	tun := &recordingTail{
		answer:  server.TailAnswer{Result: json.RawMessage(`{"id":"s","offset":0,"total":0,"live":true,"data":""}`)},
		release: release,
	}
	dir := tailControlServer(t, tun.call)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = sendControlTail(dir, server.TailRequest{SessionID: "1758130000000000000-alice-vm1", Limit: 1024})
	}()

	// While the tail is parked inside the tunnel, "status" must be
	// answered from the listener with no delay at all.
	reply, contacted, err := sendControl(dir, "status")
	if err != nil || !contacted {
		close(release)
		t.Fatalf("status while a tail was in flight: contacted=%v err=%v", contacted, err)
	}
	if !reply.OK || reply.PID != os.Getpid() {
		close(release)
		t.Fatalf("status reply = %+v, want this process's own pid %s", reply, strconv.Itoa(os.Getpid()))
	}
	close(release)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the tail never finished after the tunnel was released")
	}
	if got := tun.requests(); len(got) != 1 {
		t.Fatalf("the tunnel was called %d times, want exactly 1", len(got))
	}
}

// TestIAMT340_TailIsRefusedWithoutTheControlToken keeps the socket's own
// door shut: the new command is behind the same token check as the old
// ones, not beside it.
//
// Canary: move `case "tail":` above the `req.Token != token` check —
// "a tail with a wrong token was answered: %+v" turns red.
func TestIAMT340_TailIsRefusedWithoutTheControlToken(t *testing.T) {
	tun := &recordingTail{answer: server.TailAnswer{Result: json.RawMessage(`{}`)}}
	dir := tailControlServer(t, tun.call)

	data, err := os.ReadFile(controlFilePath(dir))
	if err != nil {
		t.Fatalf("control.json: %v", err)
	}
	var rec controlFileRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("control.json: %v", err)
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(rec.Port), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(conn).Encode(controlRequestMsg{Token: "wrong", Cmd: "tail", ID: "s", Limit: 1}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var reply controlReplyMsg
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	if reply.OK || reply.Tail != nil {
		t.Fatalf("a tail with a wrong token was answered: %+v", reply)
	}
	if len(tun.requests()) != 0 {
		t.Fatal("a tail with a wrong token reached the tunnel")
	}
}
