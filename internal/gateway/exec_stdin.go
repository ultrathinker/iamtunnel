package gateway

// exec_stdin.go: 1.50's reopened exec stdin, and the one case where stdin
// is read and judged before it reaches the machine.
//
// R4 F-03 closed a real hole (a bare `powershell` exec turning into an
// unmonitored shell) by refusing to carry stdin at all on an exec-only
// grant. The product's security model changed on 27.09.2026: no
// prohibitions in advance, only judgement against the declared goal — so
// the fix now is to make the classifier see the script, not to forbid the
// channel that carries it. human_role.go no longer closes the machine's
// stdin or guards it; every byte the person sends reaches the machine and
// is recorded (record.ExecRecorder.AddBytesIn).
//
// An interpreter launched with no script argument (`powershell`, `bash`,
// `python -`, `powershell -Command -`, the same behind `cmd /c` or a full
// path, see risk.ReadsStdinScript) carries nothing on its command line for
// the classifier to read: the real commands arrive on stdin. For exactly
// that shape the gateway reads the whole script first — until stdin ends,
// up to stdinScriptMaxBytes and stdinScriptWait — and the classifier judges
// the command together with it. An ordinary agent pipes a script and
// closes stdin, and the command passes after that one judgement.
//
// A script the gateway could not read whole (longer than the cap, did not
// end in time) or that is not text was not judged. An approval could only
// ever name the part that was seen, and would then release whatever came
// after it (fixup round 2, V-09), so no approval applies to it: under ask
// and block it is refused outright (E_STDIN_SCRIPT_UNJUDGED, exit status
// 126) with the advice to send it as a file or as a finite text script;
// under log and warn it passes, as those modes let any red command pass.
// Every byte the gateway took from the channel is recorded either way.
//
// Every other command is unaffected: no read-ahead, no delay, stdin is
// just data.

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

// stdinScriptWait bounds how long the gateway waits for a stdin script to
// end, first byte included. The interpreter would wait for its input just
// the same, so the wait costs nothing a piped script notices. A variable
// only so tests can shorten it.
var stdinScriptWait = 60 * time.Second

// stdinScriptMaxBytes bounds the script the gateway holds and judges.
const stdinScriptMaxBytes = 1024 * 1024

// stdinScriptUnjudgedRule names the red verdict an unjudged stdin script
// gets, in session.risk and in the notice the person reads.
const stdinScriptUnjudgedRule = "stdin-script-unjudged"

// stdinScriptUnjudgedCode is the session.drop result of a refused
// unjudged stdin script.
const stdinScriptUnjudgedCode = "E_STDIN_SCRIPT_UNJUDGED" // errdict:internal

// stdinRefusalHook, set only by tests, runs on a refusal whose stdin Read
// was in flight: after the decision and the first snapshot, before the
// channel closes — the window V-12 is about.
var stdinRefusalHook atomic.Pointer[func(*stdinPreviewReader)]

// stdinScriptSeparator joins the command line and the stdin script in the
// text the classifier judges.
const stdinScriptSeparator = "\n--- stdin script ---\n"

// stdinPreviewReader takes over Read of a stream (human's exec data
// channel) from the moment it is created. One background goroutine reads
// the stream and appends every chunk to buf at once, under mu: whatever
// the gateway has taken from the channel is in buf until it is handed on,
// never held privately by the goroutine, so a refusal can record all of it
// (V-09). The goroutine pauses while buf holds limit bytes or more, so the
// SSH window still pushes back on a sender the machine cannot keep up
// with, and memory stays bounded.
type stdinPreviewReader struct {
	mu      sync.Mutex
	room    *sync.Cond // signalled when buf shrinks or the reader stops
	buf     []byte
	err     error
	stopped bool
	// inRead is true while the goroutine is inside r.Read: bytes it
	// returns will still be appended. It is set and cleared under mu,
	// cleared together with the append.
	inRead  bool
	limit   int
	changed chan struct{} // capacity 1: a token after every append
	done    chan struct{} // closed when the goroutine has returned
}

// newStdinPreviewReader starts reading r. It buffers up to max+1 bytes
// ahead, so readScript can tell a script of exactly max bytes from a
// longer one.
func newStdinPreviewReader(r io.Reader, max int) *stdinPreviewReader {
	p := &stdinPreviewReader{limit: max + 1, changed: make(chan struct{}, 1), done: make(chan struct{})}
	p.room = sync.NewCond(&p.mu)
	go p.pump(r)
	return p
}

func (p *stdinPreviewReader) pump(r io.Reader) {
	defer close(p.done)
	b := make([]byte, 32*1024)
	for {
		p.mu.Lock()
		for len(p.buf) >= p.limit && !p.stopped {
			p.room.Wait()
		}
		if p.stopped {
			p.mu.Unlock()
			return
		}
		// Decided under the same lock seal() takes: once stopped is seen
		// here, no new Read starts; a Read already begun is visible to
		// seal() as inRead.
		p.inRead = true
		p.mu.Unlock()
		n, err := r.Read(b)
		p.mu.Lock()
		p.inRead = false
		p.buf = append(p.buf, b[:n]...)
		if err != nil {
			p.err = err
		}
		p.mu.Unlock()
		select {
		case p.changed <- struct{}{}:
		default:
		}
		if err != nil {
			return
		}
	}
}

// stop releases the background reader when nobody will read any more (the
// session was refused, or has ended). Safe to call more than once.
func (p *stdinPreviewReader) stop() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	p.room.Broadcast()
}

// Read implements io.Reader, handing on buffered bytes first.
func (p *stdinPreviewReader) Read(dst []byte) (int, error) {
	for {
		p.mu.Lock()
		if len(p.buf) > 0 {
			n := copy(dst, p.buf)
			p.buf = p.buf[n:]
			p.mu.Unlock()
			p.room.Broadcast()
			return n, nil
		}
		if p.err != nil {
			err := p.err
			p.mu.Unlock()
			return 0, err
		}
		p.mu.Unlock()
		<-p.changed
	}
}

// taken returns a copy of every byte taken from the channel and not yet
// handed on.
func (p *stdinPreviewReader) taken() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.buf...)
}

// seal is the first half of ending a refused session's stdin (fixup round
// 3, V-12): no Read starts after it. It reports whether the pump is done
// for good — no Read in flight, so nothing more can ever be appended —
// and returns, and clears, every byte taken so far. When it reports false
// a Read is in flight: it can only end when the channel closes, and the
// caller finishes with drainAfterClose once it has closed the channel.
func (p *stdinPreviewReader) seal() (quiet bool, taken []byte) {
	p.mu.Lock()
	p.stopped = true
	quiet = !p.inRead
	taken = append([]byte(nil), p.buf...)
	p.buf = nil
	p.mu.Unlock()
	p.room.Broadcast()
	return quiet, taken
}

// lateStdinCloseWait is how long a refused session waits for the person's
// client to answer the channel close, which is what ends a Read in
// flight; lateStdinForcedWait is how long it waits after closing the
// whole connection instead. Variables only so tests can shorten them.
var (
	lateStdinCloseWait  = 10 * time.Second
	lateStdinForcedWait = 5 * time.Second
)

// endLateStdin finishes a sealed reader whose Read was in flight at the
// refusal, after the channel has been closed. A compliant client answers
// the close and the Read ends. One that never answers keeps the Read
// blocked — x/crypto releases a channel's pending Read only when the
// peer's close arrives — so after closeWait the owning connection
// (transport) is closed, which ends every channel on it, and the reader
// is waited for again (fixup round 4, V-14). It never returns while the
// reader is known to be blocked and the connection still open.
//
// rest is what the last Read brought; forced reports that the connection
// had to be closed; ok is false only if the reader still had not returned
// after that.
func endLateStdin(p *stdinPreviewReader, transport io.Closer, closeWait, forcedWait time.Duration) (rest []byte, forced, ok bool) {
	rest, ok = p.drainAfterClose(closeWait)
	if ok {
		return rest, false, true
	}
	if transport != nil {
		_ = transport.Close()
	}
	rest, ok = p.drainAfterClose(forcedWait)
	return rest, true, ok
}

// drainAfterClose is the second half, for a seal that found a Read in
// flight: it waits for the pump to return (the channel is closed by now,
// so the Read ends) and returns what that last Read appended. ok is false
// if the pump did not return within wait; the bytes it may still take
// then cannot be accounted for.
func (p *stdinPreviewReader) drainAfterClose(wait time.Duration) (rest []byte, ok bool) {
	select {
	case <-p.done:
	case <-time.After(wait):
		return nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	rest = append([]byte(nil), p.buf...)
	p.buf = nil
	return rest, true
}

// stdinScript is what the read-ahead found on stdin.
type stdinScript struct {
	// data is what was read, at most the byte cap: what a classifier and
	// a person are shown. It stays buffered in the reader too.
	data []byte
	// total is every byte read before the decision, past the cap included.
	total int
	// unjudged is empty for a script that ended within the limits and is
	// text (or empty); otherwise it says why it could not be judged whole.
	unjudged string
}

// readScript waits until stdin ends, more than max bytes have arrived, or
// wait has passed, whichever comes first, without taking anything out of
// the buffer. It must be called at most once, before anything else reads
// from p.
func (p *stdinPreviewReader) readScript(wait time.Duration, max int) stdinScript {
	deadline := time.After(wait)
	timedOut := false
wait:
	for {
		p.mu.Lock()
		done := p.err != nil || len(p.buf) > max
		p.mu.Unlock()
		if done {
			break
		}
		select {
		case <-p.changed:
		case <-deadline:
			timedOut = true
			break wait
		}
	}
	p.mu.Lock()
	all := append([]byte(nil), p.buf...)
	ended := p.err != nil
	p.mu.Unlock()
	s := stdinScript{data: all, total: len(all)}
	if len(all) > max {
		s.data = all[:max]
	}
	switch {
	case len(all) > max:
		s.unjudged = fmt.Sprintf("it is longer than %d KiB", max/1024)
	case timedOut || !ended:
		s.unjudged = fmt.Sprintf("it did not end within %s", wait)
	case !utf8.Valid(all):
		s.unjudged = "it is not text"
	}
	return s
}

// stdinPreviewStream is human's exec data channel with its Read routed
// through a stdinPreviewReader that has already read ahead: writes, closes
// and everything else pass through to the real channel unchanged.
type stdinPreviewStream struct {
	ssh.Channel
	reader io.Reader
}

func (s stdinPreviewStream) Read(p []byte) (int, error) { return s.reader.Read(p) }

// replyEarly answers the person's exec request with success before the
// machine has seen it (see the call site in serveHumanSession for why).
func replyEarly(start *sessionStart) {
	if start.request != nil && start.request.WantReply && !start.replied {
		_ = start.request.Reply(true, nil)
	}
	start.replied = true
}

// execStdinClassifyText is the text the classifier judges for a command
// whose script came on stdin, which is also the key of any approval for
// it: the command, then the whole script. An unjudged script never reaches
// an approval (V-09); for it the text only informs the classifier and the
// journal: the part that was seen (text only) and why the rest was not.
func execStdinClassifyText(command string, s stdinScript) string {
	if s.unjudged == "" {
		if len(s.data) == 0 {
			return command
		}
		return command + stdinScriptSeparator + string(s.data)
	}
	text := s.data
	for i := 0; i < utf8.UTFMax && len(text) > 0 && !utf8.Valid(text); i++ {
		text = text[:len(text)-1]
	}
	out := command
	if utf8.Valid(text) && len(text) > 0 {
		out += stdinScriptSeparator + string(text)
	} else if len(s.data) > 0 {
		out += fmt.Sprintf("\n--- stdin: %d bytes, not text ---", len(s.data))
	}
	return out + "\n--- the stdin script could not be judged whole: " + s.unjudged + " ---"
}

// stdinScriptVerdict is the red verdict of a script that could not be
// judged, or nil for one that was.
func stdinScriptVerdict(s stdinScript) *risk.Verdict {
	if s.unjudged == "" {
		return nil
	}
	return &risk.Verdict{Level: risk.Red, Rule: stdinScriptUnjudgedRule,
		Reason: "the stdin script could not be judged whole: " + s.unjudged, Matched: true}
}

// stdinScriptRefusal is what the person reads when an unjudged stdin
// script is refused under ask or block.
func stdinScriptRefusal(v risk.Verdict, pty bool) []byte {
	reason := strings.TrimPrefix(v.Reason, "the stdin script could not be judged whole: ")
	lines := []string{
		"REFUSED — this command was not run. Not a byte of it reached the machine.",
		"This stdin script could not be judged whole (" + reason + "), and no approval can cover bytes that were never judged.",
		"Send it as a file with scp and run the file, or pipe a finite text script under 1 MiB and close standard input.",
		"risk=red rule=" + stdinScriptUnjudgedRule + " action=refuse " + stdinScriptUnjudgedCode,
	}
	return formatGatewayNotice(lines, "\x1b[31m", "[iamtunnel] ", pty)
}
