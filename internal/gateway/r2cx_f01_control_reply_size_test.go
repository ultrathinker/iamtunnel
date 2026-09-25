package gateway

// R2-CX F-01: the gateway bounded the control lines it READ from a
// machine to 16 KiB (PROTOCOL §5.1; control_read.go) but not the ones it
// WROTE back. Its answers to the machine's own requests went out at
// whatever size json.Marshal made them, and the machine reads that
// channel with the same 16-KiB frame and tears the tunnel down on the
// first line past it - its door and every live session on it with it.
// Two requests that fit the frame made answers that did not: an unknown
// op, echoed in full in the refusal, and a sessions.tail with the limit
// §6 allows an admin exec (1 MiB), which only the honest machine clamps
// to what fits (TailChunkMax, 11520). And every answer said caps:null,
// where §1.1 and §5.1 require caps:[] in every reply.

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/proto"
)

// r2cxCapturedChannel is the gateway's end of the control channel with
// nothing behind it but a buffer: what the gateway writes to the machine.
type r2cxCapturedChannel struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *r2cxCapturedChannel) Read([]byte) (int, error) { return 0, io.EOF }
func (c *r2cxCapturedChannel) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}
func (c *r2cxCapturedChannel) Close() error                                   { return nil }
func (c *r2cxCapturedChannel) CloseWrite() error                              { return nil }
func (c *r2cxCapturedChannel) SendRequest(string, bool, []byte) (bool, error) { return false, nil }
func (c *r2cxCapturedChannel) Stderr() io.ReadWriter                          { return nil }

// r2cxAnswerAsTheMachineReadsIt reads what the gateway wrote the way the
// machine does - one LF-terminated line in a 16-KiB frame
// (internal/server/wire.go readControlLine, which this package's reader
// mirrors) - and fails the test where the machine would tear the tunnel
// down.
func r2cxAnswerAsTheMachineReadsIt(t *testing.T, c *r2cxCapturedChannel, what string) map[string]json.RawMessage {
	t.Helper()
	c.mu.Lock()
	wrote := append([]byte(nil), c.buf.Bytes()...)
	c.mu.Unlock()
	if len(wrote) == 0 {
		t.Fatalf("%s: the gateway wrote no answer at all", what)
	}
	line, err := readControlLine(bufio.NewReaderSize(bytes.NewReader(wrote), controlLineMax+1), controlLineMax)
	if err != nil {
		t.Fatalf("%s: the gateway's answer is %d bytes, and the machine's reader refuses it (%v) - the machine closes its control channel and its whole tunnel on that, sessions and all", what, len(wrote)-1, err)
	}
	var answer map[string]json.RawMessage
	if err := json.Unmarshal(line, &answer); err != nil {
		t.Fatalf("%s: the answer is not a JSON object: %v", what, err)
	}
	if got := string(answer["caps"]); got != "[]" {
		t.Errorf("%s: the answer carries caps:%s - PROTOCOL §1.1 and §5.1 require caps:[] in every reply, and a strict reader refuses anything else", what, got)
	}
	return answer
}

// r2cxMachineLine is a request line exactly as the gateway's reader takes
// it off the channel, so a test cannot hand handleMachineRequest a
// request the gateway would never have read.
func r2cxMachineLine(t *testing.T, raw []byte) controlInbound {
	t.Helper()
	if len(raw) > controlLineMax {
		t.Fatalf("the request itself is %d bytes, over the %d-byte line: the test must stay inside what the gateway accepts", len(raw), controlLineMax)
	}
	line, err := readControlLine(bufio.NewReaderSize(bytes.NewReader(append(raw, '\n')), controlLineMax+1), controlLineMax)
	if err != nil {
		t.Fatalf("the gateway would not read this request: %v", err)
	}
	in, err := decodeControlInbound(line)
	if err != nil {
		t.Fatalf("the gateway would not accept this request: %v", err)
	}
	return in
}

// An unknown op as long as the request line allows. The refusal names
// the op, and naming it whole made the answer longer than the line - in
// '<'-characters six times longer, since the JSON encoder writes each as
// <.
func TestR2CX_F01_AnUnknownOpAsLongAsTheLineAllowsIsAnsweredInsideTheLine(t *testing.T) {
	for _, c := range []struct{ name, char string }{{"plain", "x"}, {"escaped-by-json", "<"}} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, nil)
			head, err := json.Marshal(proto.TailEnvelope{Proto: 1, Caps: []string{}, ID: "00000000-0000-4000-8000-000000000101", Op: ""})
			if err != nil {
				t.Fatal(err)
			}
			// The op the machine sends raw, one byte a character, as long
			// as the line still fits: the gateway reads it.
			room := controlLineMax - len(head)
			raw := bytes.Replace(head, []byte(`"op":""`), []byte(`"op":"`+strings.Repeat(c.char, room)+`"`), 1)
			in := r2cxMachineLine(t, raw)

			ch := &r2cxCapturedChannel{}
			mc := &machineConn{id: "pc1", g: f.gw, ctrlCh: ch}
			mc.handleMachineRequest(in)

			answer := r2cxAnswerAsTheMachineReadsIt(t, ch, "the refusal of an unknown op")
			if string(answer["ok"]) != "false" {
				t.Errorf("an unknown op was answered ok:%s", answer["ok"])
			}
			// Still the refusal it was - the op named, clipped - not the
			// catch-all for an answer that would not fit.
			var refusal struct{ Code, Message string }
			if err := json.Unmarshal(answer["error"], &refusal); err != nil {
				t.Fatalf("the refusal carries no error body: %v", err)
			}
			if refusal.Code != "E_CONTROL_PROTOCOL" || !strings.Contains(refusal.Message, "does not know the control op") {
				t.Errorf("the refusal = %s %q, want E_CONTROL_PROTOCOL naming the op it does not know", refusal.Code, refusal.Message)
			}
		})
	}
}

// A raw sessions.tail with the largest limit §6 allows. The honest
// machine clamps its own requests (TailChunkMax); the gateway took the
// limit as sent, read up to a mebibyte of the recording and put it,
// base64, on one line.
func TestR2CX_F01_ATailAskingForAMebibyteIsAnsweredInsideTheLine(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	sess, err := f.gw.aclE.OpenSession(f.person, f.machineID, f.clock.Now(), func(acl.DenyReason) {})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	recording := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
	cast := filepath.Join(t.TempDir(), "live.cast")
	if err := os.WriteFile(cast, recording, 0o600); err != nil {
		t.Fatal(err)
	}
	f.gw.live.addFile(sess.ID.String(), record.LiveFile{Path: cast, Mode: "cast"}, f.machineID)

	in := r2cxMachineLine(t, machineTailLine(t, sess.ID.String(), 0, 1<<20))
	ch := &r2cxCapturedChannel{}
	mc := &machineConn{id: f.machineID, g: f.gw, ctrlCh: ch}
	mc.handleMachineRequest(in)

	answer := r2cxAnswerAsTheMachineReadsIt(t, ch, "the answer to a 1-MiB tail")
	// Clamped, not refused - the machine's own rule (PROTOCOL §5.1): a
	// smaller answer, from the same offset, that the viewer then asks on
	// from.
	var result struct {
		Offset uint64 `json:"offset"`
		Total  uint64 `json:"total"`
		Data   string `json:"data"`
	}
	if err := json.Unmarshal(answer["result"], &result); err != nil {
		t.Fatalf("the answer carries no tail result: %v (%s)", err, answer["error"])
	}
	data, err := base64.StdEncoding.DecodeString(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || !bytes.Equal(data, recording[:len(data)]) {
		t.Fatalf("the clamped answer carries %d bytes that are not the start of the recording", len(data))
	}
	if result.Total != uint64(len(recording)) {
		t.Errorf("total = %d, want %d: the viewer reads on to the real end", result.Total, len(recording))
	}
}

// The short answers too: caps:[] is not a size question.
func TestR2CX_F01_AnAnswerToTheMachineCarriesCapsAsAnEmptyList(t *testing.T) {
	f := newFixture(t, nil)
	ch := &r2cxCapturedChannel{}
	mc := &machineConn{id: "pc1", g: f.gw, ctrlCh: ch}
	mc.handleMachineRequest(mineLine(t))
	r2cxAnswerAsTheMachineReadsIt(t, ch, "the answer to sessions.mine")
}

// Whatever an answer would have been, the line holds: one that would not
// fit is a short refusal of that request, and the channel stays up.
func TestR2CX_F01_AnAnswerThatWouldNotFitTheLineIsRefusedNotWritten(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000103"
	ch := &r2cxCapturedChannel{}
	mc := &machineConn{id: "pc1", ctrlCh: ch}
	mc.replyControl(id, controlResponse{OK: true, Result: mustJSON(map[string]string{"data": strings.Repeat("x", controlLineMax)})})

	answer := r2cxAnswerAsTheMachineReadsIt(t, ch, "an answer too long for the line")
	if string(answer["ok"]) != "false" || answer["error"] == nil {
		t.Fatalf("an answer too long for the line went out as ok:%s error:%s", answer["ok"], answer["error"])
	}
	if got := string(answer["id"]); got != `"`+id+`"` {
		t.Errorf("the refusal answers id %s, want the request's %q: the machine routes answers by id", got, id)
	}
}
