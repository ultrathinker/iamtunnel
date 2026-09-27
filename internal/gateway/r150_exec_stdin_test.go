package gateway

// 1.50 part B: stdin reopened on exec grants; a script piped into an
// interpreter is shown to the classifier together with the command. A
// script that could not be judged whole is never forwarded as if it had
// been (fixup round 1, V-01), and no approval can cover it: ask and block
// refuse it, log and warn let it through with every byte recorded (fixup
// round 2, V-09).

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// r150EchoMachine is an interpreter-shaped machine: it echoes stdin and
// exits on EOF. execSeen fires when the exec reaches it.
func r150EchoMachine(f *fixture) chan time.Time {
	execSeen := make(chan time.Time, 4)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- time.Now()
		buf := make([]byte, 4096)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				_, _ = ch.Write(buf[:n])
			}
			if err != nil {
				_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
				return
			}
		}
	})
	return execSeen
}

// r150ShortScriptWait makes the gateway give up on an unfinished stdin
// script quickly, for the length of one test.
func r150ShortScriptWait(t *testing.T, d time.Duration) {
	t.Helper()
	saved := stdinScriptWait
	stdinScriptWait = d
	t.Cleanup(func() { stdinScriptWait = saved })
}

// r150RecordedStdin is every stdin chunk of every exec recording of the
// fixture, decoded and concatenated per recording.
func r150RecordedStdin(t *testing.T, f *fixture) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(f.recordingsDir(), "*", "*", "*.exec.jsonl"))
	if err != nil {
		t.Fatalf("glob recordings: %v", err)
	}
	var out []string
	for _, p := range paths {
		file, err := os.Open(p)
		if err != nil {
			continue
		}
		var sb strings.Builder
		sc := bufio.NewScanner(file)
		sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for sc.Scan() {
			var ev struct {
				Type, Stream, Data string
			}
			if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.Type != "chunk" || ev.Stream != "stdin" {
				continue
			}
			b, err := base64.StdEncoding.DecodeString(ev.Data)
			if err == nil {
				sb.Write(b)
			}
		}
		_ = file.Close()
		out = append(out, sb.String())
	}
	return out
}

func r150RecordedStdinContains(t *testing.T, f *fixture, want string) bool {
	t.Helper()
	for _, s := range r150RecordedStdin(t, f) {
		if s == want {
			return true
		}
	}
	return false
}

func TestR150_ExecStdinScriptReachesClassifier(t *testing.T) {
	stub := &r150Classifier{}
	f := iamt354EnabledFixture(t, stub, nil)
	r150EchoMachine(f)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "powershell -NoProfile -Command -")
	defer client.Close()
	const script = "Get-ChildItem C:\\TEST111\r\nRemove-Item C:\\TEST111\\old.txt\r\n"
	if _, err := hs.ch.Write([]byte(script)); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := hs.ch.CloseWrite(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	if got := readUntil(t, hs.ch, "old.txt"); !strings.Contains(got, "Remove-Item") {
		t.Fatalf("the script did not reach the machine whole: %q", got)
	}
	seen, ok := stub.saw("--- stdin script ---")
	if !ok {
		t.Fatalf("classifier never saw the stdin script; it saw %q", stub.seen)
	}
	if seen != "powershell -NoProfile -Command -\n--- stdin script ---\n"+script {
		t.Fatalf("classifier text = %q, want the command, the separator and the whole script", seen)
	}
}

// V-09: an unjudged stdin script is refused under ask and block — no
// approval id, nothing that could later let it through — and every byte
// the gateway took from the channel is in the record, the part past the
// cap included. Two shapes: a script that does not end (the
// V-01 repro), and one longer than the cap whose tail differs from its
// head (the V-09 repro).
func TestR150_ExecUnjudgedStdinScriptIsRefusedInAskAndBlock(t *testing.T) {
	r150ShortScriptWait(t, 400*time.Millisecond)
	for _, mode := range []RiskAction{RiskActionAsk, RiskActionBlock} {
		for _, shape := range []string{"does not end", "longer than the cap"} {
			t.Run(string(mode)+"/"+shape, func(t *testing.T) {
				stub := &r150Classifier{}
				f := iamt354EnabledFixture(t, stub, func(c *Config) { c.RiskAction = mode })
				execSeen := r150EchoMachine(f)
				f.connectMachine(fakeMachineBehavior{})
				f.waitMachineOnline(t)

				client, hs := iamt353OpenExec(t, f, "powershell -NoProfile -Command -")
				defer client.Close()
				sent := "Get-Date\r\n"
				if shape == "longer than the cap" {
					sent = strings.Repeat("# harmless\r\n", stdinScriptMaxBytes/12+1) + "Remove-Item -Recurse C:\\work\r\n"
				}
				go func() {
					_, _ = hs.ch.Write([]byte(sent))
					if shape == "longer than the cap" {
						_ = hs.ch.CloseWrite()
					}
				}()
				stderr := readUntil(t, hs.ch.Stderr(), stdinScriptUnjudgedCode)
				if !strings.Contains(stderr, "could not be judged whole") || !strings.Contains(stderr, "Send it as a file with scp") {
					t.Fatalf("refusal = %q, want the reason and the way that works", stderr)
				}
				if strings.Contains(stderr, "approval-id") {
					t.Fatalf("an unjudged script was offered an approval: %q", stderr)
				}
				select {
				case status := <-hs.exits:
					if status != 126 {
						t.Fatalf("refused exec exit status = %d, want 126", status)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("refused exec did not end with exit-status 126")
				}
				select {
				case <-execSeen:
					t.Fatal("an unjudged stdin script reached the machine")
				case <-time.After(200 * time.Millisecond):
				}
				if got := f.lastSessionDropResult(f.person, f.machineID); got != stdinScriptUnjudgedCode {
					t.Fatalf("session.drop = %q, want %s", got, stdinScriptUnjudgedCode)
				}
				evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventRiskApproval}})
				if err != nil {
					t.Fatalf("read risk.approval: %v", err)
				}
				if len(evs) != 0 {
					t.Fatalf("an approval was created for an unjudged script: %+v", evs)
				}
				ev := iamt353RiskEvent(t, f)
				if ev.Result != "red" || ev.Details["rule"] != stdinScriptUnjudgedRule || ev.Details["action"] != "block" {
					t.Fatalf("session.risk = %+v, want red/%s/block", ev, stdinScriptUnjudgedRule)
				}
				// For the long shape this includes the tail past the cap.
				waitUntil(t, "every refused stdin byte in the recording", func() bool {
					return r150RecordedStdinContains(t, f, sent)
				})
			})
		}
	}
}

// Under log an unfinished script goes through, the journal says why it was
// not judged, and every byte sent — before and after the read-ahead gave
// up — is in the recording.
func TestR150_ExecStdinScriptThatDoesNotEndPassesUnderLog(t *testing.T) {
	r150ShortScriptWait(t, 300*time.Millisecond)
	stub := &r150Classifier{}
	f := iamt354EnabledFixture(t, stub, func(c *Config) { c.RiskAction = RiskActionLog })
	execSeen := r150EchoMachine(f)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "powershell -NoProfile -Command -")
	defer client.Close()
	if _, err := hs.ch.Write([]byte("Get-Date\r\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	select {
	case <-execSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("under log, an unfinished stdin script did not reach the machine")
	}
	ev := iamt353RiskEvent(t, f)
	if ev.Details["action"] != "log" || ev.Details["rule"] != stdinScriptUnjudgedRule || !strings.Contains(ev.Details["stdinScriptUnjudged"].(string), "did not end") {
		t.Fatalf("session.risk = %+v, want log with the unjudged reason", ev)
	}
	if _, err := hs.ch.Write([]byte("Remove-Item C:\\later\r\n")); err != nil {
		t.Fatalf("write more stdin: %v", err)
	}
	if err := hs.ch.CloseWrite(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	if got := readUntil(t, hs.ch, "later"); !strings.Contains(got, "Get-Date") {
		t.Fatalf("stdin did not reach the machine whole: %q", got)
	}
	waitUntil(t, "every stdin byte in the recording", func() bool {
		return r150RecordedStdinContains(t, f, "Get-Date\r\nRemove-Item C:\\later\r\n")
	})
}

// A command that does not read a script from the session's stdin starts
// at once, with stdin left open: the read-ahead limit is 60 s, and the
// exec reaches the machine long before that. python --version is the V-08
// case: an interpreter by name, but a version query.
func TestR150_ExecWithoutStdinReaderDoesNotWait(t *testing.T) {
	for _, command := range []string{"whoami", "python --version", "echo x | powershell -Command -",
		"pwsh -NoProfile -Version", "pwsh -Version -Command -", "pwsh -NoProfile -ve"} {
		t.Run(command, func(t *testing.T) {
			stub := &r150Classifier{}
			f := iamt354EnabledFixture(t, stub, nil)
			execSeen := r150EchoMachine(f)
			f.connectMachine(fakeMachineBehavior{})
			f.waitMachineOnline(t)

			started := time.Now()
			client, hs := iamt353OpenExec(t, f, command)
			defer client.Close()
			select {
			case at := <-execSeen:
				if waited := at.Sub(started); waited > 2*time.Second {
					t.Fatalf("%s reached the machine after %v — it waited for stdin", command, waited)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("%s did not reach the machine within 3 s — it is waiting for stdin", command)
			}
			if seen, ok := stub.saw(strings.Fields(command)[0]); !ok || strings.Contains(seen, "stdin script") {
				t.Fatalf("classifier text = %q (seen %v), want the bare command", seen, ok)
			}
			_ = hs.ch.Close()
		})
	}
}

// readScript itself: a script that ends is judged whole; one padded past
// the cap, one that never ends, and one that is not text are not. Every
// byte read stays available, past the cap included.
func TestR150_ReadScriptJudgesOnlyWholeTextScripts(t *testing.T) {
	feed := func(data []byte, close bool) (stdinScript, []byte) {
		pr, pw := io.Pipe()
		go func() {
			_, _ = pw.Write(data)
			if close {
				_ = pw.Close()
			}
		}()
		p := newStdinPreviewReader(pr, 1024)
		defer p.stop()
		defer pw.Close()
		s := p.readScript(300*time.Millisecond, 1024)
		return s, p.taken()
	}
	if s, _ := feed([]byte("Get-Date\n"), true); s.unjudged != "" || string(s.data) != "Get-Date\n" {
		t.Fatalf("whole script = %+v, want judged", s)
	}
	if s, _ := feed(nil, true); s.unjudged != "" || len(s.data) != 0 {
		t.Fatalf("empty stdin = %+v, want judged and empty", s)
	}
	padded := append([]byte(strings.Repeat("# harmless\n", 100)), "Remove-Item C:\\work\n"...)
	s, taken := feed(padded, true)
	if !strings.Contains(s.unjudged, "longer than") || len(s.data) != 1024 {
		t.Fatalf("padded script = %q / %d bytes, want unjudged at the cap", s.unjudged, len(s.data))
	}
	if s.total <= 1024 || !strings.HasPrefix(string(padded), string(taken)) || len(taken) != s.total {
		t.Fatalf("taken = %d bytes, total %d: the bytes past the cap must stay available for the record", len(taken), s.total)
	}
	if s, _ := feed([]byte("Get-Date\n"), false); !strings.Contains(s.unjudged, "did not end") {
		t.Fatalf("open-ended script = %q, want unjudged", s.unjudged)
	}
	if s, _ := feed([]byte{0xff, 0xfe, 0x00}, true); !strings.Contains(s.unjudged, "not text") {
		t.Fatalf("binary stdin = %q, want unjudged", s.unjudged)
	}
	if got := execStdinClassifyText("bash", stdinScript{data: []byte{0xff, 0x00}, unjudged: "it is not text"}); !strings.Contains(got, "2 bytes, not text") {
		t.Fatalf("binary classify text = %q", got)
	}
}

// r150GatedReader blocks its first Read until gate closes, then returns
// data; after that it reports EOF.
type r150GatedReader struct {
	gate chan struct{}
	data string
	sent bool
}

func (r *r150GatedReader) Read(b []byte) (int, error) {
	if r.sent {
		return 0, io.EOF
	}
	<-r.gate
	r.sent = true
	return copy(b, r.data), nil
}

// V-12, at the reader: a Read in flight at the refusal is not lost. seal
// reports it, and once the Read is released (the channel closes) its bytes
// come out of drainAfterClose; after that the reader never takes more.
func TestR150_SealedStdinReaderAccountsForTheReadInFlight(t *testing.T) {
	r := &r150GatedReader{gate: make(chan struct{}), data: "late line\r\n"}
	p := newStdinPreviewReader(r, 1024)
	defer p.stop()
	if s := p.readScript(100*time.Millisecond, 1024); !strings.Contains(s.unjudged, "did not end") {
		t.Fatalf("readScript = %+v, want a timeout", s)
	}
	quiet, taken := p.seal()
	if quiet || len(taken) != 0 {
		t.Fatalf("seal = quiet %v, %q; want a Read in flight and nothing taken yet", quiet, taken)
	}
	close(r.gate) // the blocked Read returns between the decision and the close
	rest, ok := p.drainAfterClose(2 * time.Second)
	if !ok || string(rest) != "late line\r\n" {
		t.Fatalf("drainAfterClose = %q, %v; want the late bytes", rest, ok)
	}
	if more := p.taken(); len(more) != 0 {
		t.Fatalf("the sealed reader took more after it was done: %q", more)
	}

	// With no Read in flight, seal is final at once.
	done := &r150GatedReader{gate: make(chan struct{}), sent: true}
	q := newStdinPreviewReader(done, 1024)
	defer q.stop()
	q.readScript(time.Second, 1024)
	if quiet, _ := q.seal(); !quiet {
		t.Fatal("seal after EOF reported a Read in flight")
	}
}

// r150DeafPeer is a person's client that never acknowledges the channel
// close: a pending channel Read returns only when the whole connection
// (the transport) is closed, as with x/crypto when the peer's close never
// arrives.
type r150DeafPeer struct {
	connClosed chan struct{}
	closes     atomic.Int32
}

func (d *r150DeafPeer) Read(b []byte) (int, error) {
	<-d.connClosed
	return 0, io.EOF
}

func (d *r150DeafPeer) Close() error {
	if d.closes.Add(1) == 1 {
		close(d.connClosed)
	}
	return nil
}

// V-14: after the refusal closes the channel, a client that never answers
// the close keeps the reader blocked. endLateStdin must not return with the
// reader still in Read: it closes the connection and waits for the reader
// goroutine to end.
func TestR150_LateStdinReaderEndsWhenThePeerNeverAcksTheClose(t *testing.T) {
	peer := &r150DeafPeer{connClosed: make(chan struct{})}
	p := newStdinPreviewReader(peer, 1024)
	defer p.stop()
	p.readScript(50*time.Millisecond, 1024)
	if quiet, _ := p.seal(); quiet {
		t.Fatal("seal found no Read in flight; the test needs one")
	}
	start := time.Now()
	_, forced, ok := endLateStdin(p, peer, 200*time.Millisecond, 2*time.Second)
	if !forced || !ok {
		t.Fatalf("endLateStdin = forced %v, ok %v; want the connection forced closed and the reader ended", forced, ok)
	}
	if peer.closes.Load() != 1 {
		t.Fatalf("the connection was closed %d times, want once", peer.closes.Load())
	}
	select {
	case <-p.done:
	default:
		t.Fatal("endLateStdin returned while the reader goroutine was still running")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("ending the reader took %v", waited)
	}

	// A client that does answer the close: the connection is left alone.
	r := &r150GatedReader{gate: make(chan struct{}), data: "x"}
	q := newStdinPreviewReader(r, 1024)
	defer q.stop()
	q.readScript(50*time.Millisecond, 1024)
	q.seal()
	conn := &r150DeafPeer{connClosed: make(chan struct{})}
	close(r.gate)
	if rest, forced, ok := endLateStdin(q, conn, 2*time.Second, time.Second); forced || !ok || string(rest) != "x" || conn.closes.Load() != 0 {
		t.Fatalf("compliant close: rest %q forced %v ok %v closes %d; want the Read's bytes and no forced close", rest, forced, ok, conn.closes.Load())
	}
}

// V-12, end to end: under ask, an unfinished stdin script is refused while
// the reader is blocked in Read; bytes the person sends between the
// refusal decision and the channel close are consumed by that Read, and
// they are in the recording.
func TestR150_RefusedStdinBytesArrivingBeforeCloseAreRecorded(t *testing.T) {
	r150ShortScriptWait(t, 300*time.Millisecond)
	channels := make(chan ssh.Channel, 1)
	consumed := make(chan bool, 1)
	hook := func(p *stdinPreviewReader) {
		ch := <-channels
		_, _ = ch.Write([]byte("late line\r\n"))
		// Wait until the in-flight Read has taken the bytes: they were
		// consumed after the decision, and must still reach the record.
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			p.mu.Lock()
			n := len(p.buf)
			p.mu.Unlock()
			if n > 0 {
				consumed <- true
				return
			}
			time.Sleep(time.Millisecond)
		}
		consumed <- false
	}
	stdinRefusalHook.Store(&hook)
	t.Cleanup(func() { stdinRefusalHook.Store(nil) })

	stub := &r150Classifier{}
	f := iamt354EnabledFixture(t, stub, func(c *Config) { c.RiskAction = RiskActionAsk })
	execSeen := r150EchoMachine(f)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "powershell -NoProfile -Command -")
	defer client.Close()
	channels <- hs.ch
	select {
	case ok := <-consumed:
		if !ok {
			t.Fatal("the late bytes were never consumed by the in-flight Read")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the refusal never reached the moment between decision and close")
	}
	select {
	case status := <-hs.exits:
		if status != 126 {
			t.Fatalf("refused exec exit status = %d, want 126", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refused exec did not end with exit-status 126")
	}
	select {
	case <-execSeen:
		t.Fatal("the refused command reached the machine")
	default:
	}
	waitUntil(t, "the bytes consumed after the refusal decision in the recording", func() bool {
		return r150RecordedStdinContains(t, f, "late line\r\n")
	})
}
