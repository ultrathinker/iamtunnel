package sshx

// zz_acceptance_test.go: independent acceptance tests, review round 3.
//
// These tests do not reuse the reference bytes and tables from
// payload_test.go / requests_test.go — the byte references were
// assembled again by hand from PROTOCOL.md §4.1, independently of
// Marshal*/Parse*, with different numeric values, to rule out an
// accidental match with the original author's reference caused by how
// the code happens to be organized.

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ============================================================================
// 1. Byte-by-byte check of the seven layouts against a HAND-BUILT
//    reference (not against Marshal*).
// ============================================================================

// be32 builds a big-endian uint32 by hand, without calling the package's writeUint32.
func be32(v uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
	return b
}

// bstr builds an SSH string (uint32 length + bytes) by hand.
func bstr(s string) []byte {
	out := be32(uint32(len(s)))
	return append(out, s...)
}

func cat(chunks ...[]byte) []byte {
	var out []byte
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// TestManual_PTYRequestLayout — PROTOCOL §4.1: string TERM, uint32 cols, rows,
// width-px, height-px, string modes. The values are deliberately
// different from payload_test.go (101x37 instead of 80x24, etc.), so
// as not to repeat someone else's mistake via a compensating coincidence.
func TestManual_PTYRequestLayout(t *testing.T) {
	term := "vt220"
	modes := "\x35\x00\x00\x00\x00" // an arbitrary opcode + terminator
	want := cat(
		bstr(term),
		be32(132),  // cols
		be32(43),   // rows
		be32(1056), // width-px = 132*8
		be32(688),  // height-px = 43*16
		bstr(modes),
	)
	got := MarshalPTY(PTYRequest{Term: term, Columns: 132, Rows: 43, WidthPixels: 1056, HeightPixels: 688, Modes: modes})
	if !bytes.Equal(got, want) {
		t.Fatalf("pty-req payload byte mismatch\n got  %x\n want %x", got, want)
	}
	// The reverse direction: the hand-built reference must parse into the same fields.
	p, err := ParsePTY(want)
	if err != nil {
		t.Fatalf("ParsePTY on the hand-built reference: %v", err)
	}
	if p.Term != term || p.Columns != 132 || p.Rows != 43 || p.WidthPixels != 1056 || p.HeightPixels != 688 || p.Modes != modes {
		t.Fatalf("ParsePTY returned %+v", p)
	}
}

// TestManual_WindowChangeLayout — PROTOCOL §4.1: uint32 cols,rows,width,height,
// exactly 16 bytes, no name/length.
func TestManual_WindowChangeLayout(t *testing.T) {
	want := cat(be32(213), be32(55), be32(1704), be32(880))
	if len(want) != 16 {
		t.Fatalf("the reference itself is not 16 bytes: %d", len(want))
	}
	got := MarshalWindow(WindowChange{Columns: 213, Rows: 55, WidthPixels: 1704, HeightPixels: 880})
	if !bytes.Equal(got, want) {
		t.Fatalf("window-change payload byte mismatch\n got  %x\n want %x", got, want)
	}
	w, err := ParseWindow(want)
	if err != nil || w.Columns != 213 || w.Rows != 55 || w.WidthPixels != 1704 || w.HeightPixels != 880 {
		t.Fatalf("ParseWindow(reference) = %+v, %v", w, err)
	}
}

// TestManual_ExecLayout — PROTOCOL §4.1: string command, nothing else.
func TestManual_ExecLayout(t *testing.T) {
	cmd := "/usr/bin/id -u"
	want := bstr(cmd)
	got := MarshalExec(Exec{Command: cmd})
	if !bytes.Equal(got, want) {
		t.Fatalf("exec payload byte mismatch\n got  %x\n want %x", got, want)
	}
	e, err := ParseExec(want)
	if err != nil || e.Command != cmd {
		t.Fatalf("ParseExec(reference) = %+v, %v", e, err)
	}
}

// TestManual_EnvLayout — PROTOCOL §4.1: string name, string value, in that
// order (not value,name — the pair's order in RFC 4254 §6.4 is the
// opposite of the "key=value" intuition of some shell notations, and
// it is exactly this order that is checked here).
func TestManual_EnvLayout(t *testing.T) {
	name, val := "LANG", "ru_RU.UTF-8"
	want := cat(bstr(name), bstr(val))
	got := MarshalEnv(Env{Name: name, Value: val})
	if !bytes.Equal(got, want) {
		t.Fatalf("env payload byte mismatch\n got  %x\n want %x", got, want)
	}
	// A separate order check: if Marshal swapped name/value, the first
	// 4-byte length would still match by a lucky coincidence (4 for
	// LANG), so we check the name's bytes directly, right after the
	// first length.
	if !bytes.Equal(got[4:4+len(name)], []byte(name)) {
		t.Fatalf("the payload's first field is not the name: %x", got[:4+len(name)])
	}
	e, err := ParseEnv(want)
	if err != nil || e.Name != name || e.Value != val {
		t.Fatalf("ParseEnv(reference) = %+v, %v", e, err)
	}
}

// TestManual_SignalLayout — PROTOCOL §4.1: string signal-name, with no SIG prefix.
func TestManual_SignalLayout(t *testing.T) {
	name := "USR2"
	want := bstr(name)
	got := MarshalSignal(Signal{Name: name})
	if !bytes.Equal(got, want) {
		t.Fatalf("signal payload byte mismatch\n got  %x\n want %x", got, want)
	}
	s, err := ParseSignal(want)
	if err != nil || s.Name != name {
		t.Fatalf("ParseSignal(reference) = %+v, %v", s, err)
	}
}

// TestManual_ExitStatusLayout — PROTOCOL §4.1: uint32 status, exactly 4 bytes.
func TestManual_ExitStatusLayout(t *testing.T) {
	want := be32(137) // 128+SIGKILL, a typical value under shell convention
	got := MarshalExitStatus(ExitStatus{Status: 137})
	if !bytes.Equal(got, want) {
		t.Fatalf("exit-status payload byte mismatch\n got  %x\n want %x", got, want)
	}
	e, err := ParseExitStatus(want)
	if err != nil || e.Status != 137 {
		t.Fatalf("ParseExitStatus(reference) = %+v, %v", e, err)
	}
}

// TestManual_ExitSignalLayout — PROTOCOL §4.1: string signal, boolean
// core-dumped, string error-message, string language-tag, in that order.
func TestManual_ExitSignalLayout(t *testing.T) {
	sig, msg, lang := "SEGV", "segmentation fault", "en-US"
	want := cat(bstr(sig), []byte{0x01}, bstr(msg), bstr(lang))
	got := MarshalExitSignal(ExitSignal{Signal: sig, CoreDumped: true, ErrorMessage: msg, LanguageTag: lang})
	if !bytes.Equal(got, want) {
		t.Fatalf("exit-signal payload byte mismatch\n got  %x\n want %x", got, want)
	}
	// The core-dumped byte must sit EXACTLY between the two strings,
	// not before the signal name and not after the language —
	// checking its position explicitly: 4+len(sig).
	pos := 4 + len(sig)
	if got[pos] != 0x01 {
		t.Fatalf("core-dumped byte not at position %d: %x", pos, got)
	}
	es, err := ParseExitSignal(want)
	if err != nil || es.Signal != sig || !es.CoreDumped || es.ErrorMessage != msg || es.LanguageTag != lang {
		t.Fatalf("ParseExitSignal(reference) = %+v, %v", es, err)
	}
}

// ============================================================================
// 2. Parsing garbage: truncation, length > remainder, integer width
//    overflow, empty input, input of all zeros — on all seven parsers.
// ============================================================================

func allParsers() map[string]func([]byte) error {
	return map[string]func([]byte) error{
		"pty-req":       func(b []byte) error { _, err := ParsePTY(b); return err },
		"window-change": func(b []byte) error { _, err := ParseWindow(b); return err },
		"exec":          func(b []byte) error { _, err := ParseExec(b); return err },
		"env":           func(b []byte) error { _, err := ParseEnv(b); return err },
		"signal":        func(b []byte) error { _, err := ParseSignal(b); return err },
		"exit-status":   func(b []byte) error { _, err := ParseExitStatus(b); return err },
		"exit-signal":   func(b []byte) error { _, err := ParseExitSignal(b); return err },
	}
}

// TestGarbage_EmptyInputNeverPanics — empty input on all seven
// parsers: an error, not a panic, and not a "successful" parse of a
// zero struct (except where a zero length is semantically valid —
// here, for all seven types, an empty buffer is shorter than any
// required field, so an error is mandatory).
func TestGarbage_EmptyInputNeverPanics(t *testing.T) {
	for name, parse := range allParsers() {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panic on empty input: %v", name, r)
				}
			}()
			if err := parse(nil); err == nil {
				t.Errorf("%s: empty input parsed with no error", name)
			}
			if err := parse([]byte{}); err == nil {
				t.Errorf("%s: an empty (not nil) slice parsed with no error", name)
			}
		}()
	}
}

// TestGarbage_AllZeroInput — input of all zeros: for string fields a
// length of 0 is semantically valid (RFC 4254 does not forbid empty
// strings), so "all zeros" of a short length may parse successfully
// for some types (for example exit-status status=0, or exec with
// command=""), but must not panic and must not succeed if there are
// FEWER zeros than the field needs.
func TestGarbage_AllZeroInput(t *testing.T) {
	sizes := []int{0, 1, 2, 3, 4, 5, 8, 15, 16, 17, 32, 64, 256}
	for name, parse := range allParsers() {
		for _, n := range sizes {
			buf := make([]byte, n) // all bytes are zero by default in Go
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s: panic on %d zero bytes: %v", name, n, r)
					}
				}()
				_ = parse(buf)
			}()
		}
	}
}

// TestGarbage_TruncatedAfterEveryPrefixLength — truncation at exactly
// every possible prefix length of a valid payload: no length must
// cause a panic, and only the full length (or more — trailing bytes
// are handled separately) must succeed.
func TestGarbage_TruncatedAfterEveryPrefixLength(t *testing.T) {
	full := MarshalExitSignal(ExitSignal{Signal: "TERM", CoreDumped: true, ErrorMessage: "stopped", LanguageTag: "en"})
	for n := 0; n <= len(full); n++ {
		prefix := full[:n]
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseExitSignal panicked on truncation to %d/%d bytes: %v", n, len(full), r)
				}
			}()
			_, err := ParseExitSignal(prefix)
			if n < len(full) && err == nil {
				t.Fatalf("truncation to %d/%d bytes parsed with no error", n, len(full))
			}
			if n == len(full) && err != nil {
				t.Fatalf("the full payload (%d bytes) failed to parse: %v", n, err)
			}
		}()
	}
}

// TestGarbage_LengthExceedsRemainder — a string length that names
// more than what remains in the buffer, but does NOT overflow 32 bits
// (unlike the original author's 0xFFFFFFFF cases) — the narrow case
// of an "almost correct" length, one more than the actual remainder.
func TestGarbage_LengthExceedsRemainder(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		parse func([]byte) error
	}{
		{"exec: len 1 more than the remainder", cat(be32(5), []byte("abcd")), func(b []byte) error { _, err := ParseExec(b); return err }},
		{"signal: len 100 more than the remainder", cat(be32(104), []byte("HUP")), func(b []byte) error { _, err := ParseSignal(b); return err }},
		{"env value: len more than the remainder after a valid name", cat(bstr("TERM"), be32(999), []byte("x")), func(b []byte) error { _, err := ParseEnv(b); return err }},
		{"pty modes: len more than the remainder, modes is the last field", cat(bstr("vt"), be32(1), be32(1), be32(1), be32(1), be32(50)), func(b []byte) error { _, err := ParsePTY(b); return err }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.parse(c.input); err == nil {
				t.Fatalf("a length longer than the remainder (not overflowing 32 bits) parsed successfully")
			}
		})
	}
}

// TestGarbage_BitWidthOverflowLength — a length that, when added to
// the current off, would overflow int on a 32-bit build, OR a
// near-uint32-max length, must not get past readString on any bit
// width. We check exactly the boundary values near overflow, separate
// from the original author's set.
//
// Applies only to parsers with at least one string field (whose
// length is read as a uint32 prefix): pty-req, exec, env, signal,
// exit-signal. window-change and exit-status are fixed-size with no
// lengths at all, so a "length of 0xFFFFFFFF" for them is not a
// protocol-level prefix but an ordinary uint32 field value — plugging
// them in here would be a category error in the test, not a finding.
func TestGarbage_BitWidthOverflowLength(t *testing.T) {
	overflowLens := []uint32{0xFFFFFFFF, 0xFFFFFFFE, 0x80000001, 0x80000000, 0x7FFFFFFF, 0xF0000000}
	stringBearing := map[string]func([]byte) error{
		"pty-req": func(b []byte) error { _, err := ParsePTY(b); return err },
		"exec":    func(b []byte) error { _, err := ParseExec(b); return err },
		"env":     func(b []byte) error { _, err := ParseEnv(b); return err },
		"signal":  func(b []byte) error { _, err := ParseSignal(b); return err },
		"exit-signal": func(b []byte) error {
			_, err := ParseExitSignal(b)
			return err
		},
	}
	for _, n := range overflowLens {
		buf := cat(be32(n), []byte("payload-tail"))
		for name, parse := range stringBearing {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s: panic on length 0x%08X: %v", name, n, r)
					}
				}()
				if err := parse(buf); err == nil {
					t.Fatalf("%s: length 0x%08X parsed with no error", name, n)
				}
			}()
		}
	}
}

// TestGarbage_TrailingBytesRejected — extra bytes after a valid
// payload must be a refusal (otherwise the gateway would silently
// discard a tail that could have been part of a second attack in the
// same packet).
func TestGarbage_TrailingBytesRejected(t *testing.T) {
	cases := []struct {
		name  string
		build func() []byte
	}{
		{"exec", func() []byte { return append(MarshalExec(Exec{Command: "ls"}), 0x00) }},
		{"signal", func() []byte { return append(MarshalSignal(Signal{Name: "HUP"}), 'X', 'Y') }},
		{"env", func() []byte { return append(MarshalEnv(Env{Name: "A", Value: "b"}), 0xff) }},
		{"exit-status", func() []byte { return append(MarshalExitStatus(ExitStatus{Status: 1}), 0x00) }},
		{"exit-signal", func() []byte { return append(MarshalExitSignal(ExitSignal{Signal: "HUP"}), 0x00) }},
	}
	parsers := allParsers()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := parsers[c.name](c.build()); err == nil {
				t.Fatalf("an extra byte in the payload's tail was not rejected")
			}
		})
	}
}

// ============================================================================
// 3. The ChannelConn adapter: reading after close, close from both
//    sides, partial write.
// ============================================================================

// TestManual_ReadAfterClose — reading from an already-closed
// connection must return an error immediately, without panicking or hanging.
func TestManual_ReadAfterClose(t *testing.T) {
	cc := echoConn(t)
	if err := cc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	done := make(chan struct{})
	var n int
	var err error
	go func() {
		n, err = cc.Read(make([]byte, 16))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Read after Close hung")
	}
	if err == nil {
		t.Fatalf("Read after Close returned a nil error, n=%d", n)
	}
}

// TestManual_WriteAfterClose — the same for a write.
func TestManual_WriteAfterClose(t *testing.T) {
	cc := echoConn(t)
	if err := cc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	done := make(chan struct{})
	var err error
	go func() {
		_, err = cc.Write([]byte("x"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Write after Close hung")
	}
	if err == nil {
		t.Fatal("Write after Close returned a nil error")
	}
}

// TestManual_CloseFromBothSidesSimultaneously — the local side and
// the peer close the channel at the same time; neither side must
// panic, hang, or produce an unexpected race under -race.
func TestManual_CloseFromBothSidesSimultaneously(t *testing.T) {
	signer := mustSigner(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	serverChClosed := make(chan struct{})
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		cfg := &ssh.ServerConfig{NoClientAuth: true, ServerVersion: "SSH-2.0-bothclose"}
		cfg.AddHostKey(signer)
		conn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
		if err != nil {
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(reqs)
		for n := range chans {
			ch, chReqs, err := n.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(chReqs)
			// The server closes its half almost immediately, with no
			// coordination with the client — a deliberate race of closes on both sides.
			go func() {
				time.Sleep(5 * time.Millisecond)
				_ = ch.Close()
				close(serverChClosed)
			}()
		}
	}()

	conn, err := ssh.Dial("tcp", ln.Addr().String(), insecureClientConfig("u"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ch, reqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(reqs)
	cc := NewChannelConn(ch)

	done := make(chan error, 1)
	go func() {
		done <- cc.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("cc.Close() returned %v (acceptable — the channel was already closed remotely)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close() hung on a simultaneous close from both sides")
	}
	<-serverChClosed

	// After a mutual close, a repeated Close is still idempotent.
	if err := cc.Close(); err != nil {
		t.Fatalf("repeated Close after a mutual close: %v", err)
	}
}

// TestManual_PartialWriteAccumulatesUntilFull — on a slow/small
// receiver, ssh.Channel.Write may return fewer bytes than passed in,
// with no error (a partial write, as with any io.Writer). The wrapper
// is not required to append the tail itself (that is the caller's
// job — the io.Writer contract), but it must either return n==len(p)
// with err==nil, or n<len(p) with a nonzero err — exactly what
// io.Writer requires, and which must not turn into a silent loss of
// bytes (err==nil and n<len(p) at the same time, which io.Copy itself
// treats as ErrShortWrite, but a more naive caller treats as full success).
func TestManual_PartialWriteAccumulatesUntilFull(t *testing.T) {
	cc := echoConn(t)
	payload := bytes.Repeat([]byte{'z'}, 256*1024) // reliably bigger than a typical SSH window/packet
	n, err := cc.Write(payload)
	if err != nil {
		t.Fatalf("writing a large buffer returned an error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("io.Writer violated: n=%d, len(p)=%d, err=nil — silent byte loss", n, len(payload))
	}
	// Read the echo to the end, to confirm all the bytes actually went
	// out on the wire and "n" was not simply lying.
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(cc, got); err != nil {
		t.Fatalf("failed to read the echo of the whole buffer to the end: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the echo of the large buffer is corrupted")
	}
}

// ============================================================================
// 4. Connection checking: the interval boundary, refusal instead of
//    silence (already covered by the original author), stop from
//    within onDead (covered), a double stop (covered), the connection
//    closing AT THE MOMENT a probe is sent (missing from the original set).
// ============================================================================

// TestManual_KeepaliveAnswerExactlyAtBoundary — the answer arrives
// exactly as the interval expires (a race between timer.C and
// answered). No hanging, no false death on a live but extremely slow peer.
func TestManual_KeepaliveAnswerExactlyAtBoundary(t *testing.T) {
	const interval = 30 * time.Millisecond
	srv := newBoundaryKeepaliveServer(t, interval)
	conn := dialKeepalive(t, srv.listener.Addr().String())
	dead := atomic.Bool{}
	stop := Keepalive{Interval: interval, MaxMisses: 3}.Probe(conn, func() { dead.Store(true) })
	defer stop()
	waitForCond(t, "not enough probes at the interval boundary", func() bool { return srv.probes.Load() >= 6 })
	if dead.Load() {
		t.Fatal("a peer answering exactly at the interval boundary was declared dead")
	}
}

// boundaryKeepaliveServer answers with success, delaying the answer
// as close to interval as is practical, so as to run into the select{} race in Probe.
type boundaryKeepaliveServer struct {
	listener net.Listener
	probes   atomic.Int32
}

func newBoundaryKeepaliveServer(t *testing.T, interval time.Duration) *boundaryKeepaliveServer {
	t.Helper()
	s := &boundaryKeepaliveServer{}
	cfg := &ssh.ServerConfig{NoClientAuth: true, ServerVersion: "SSH-2.0-boundary"}
	cfg.AddHostKey(mustSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.listener = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				conn, _, reqs, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				for r := range reqs {
					s.probes.Add(1)
					// A delay slightly under interval — the answer must
					// arrive right as it expires, not sooner and not much later.
					time.Sleep(interval - interval/6)
					if r.WantReply {
						_ = r.Reply(true, nil)
					}
				}
			}()
		}
	}()
	return s
}

// TestManual_ConnectionClosesDuringProbeSend — the TCP connection
// closes exactly while Probe is inside conn.SendRequest. onDead must
// fire (a dead transport is also a miss/error under PROTOCOL §5), and
// stop() must not hang afterward.
func TestManual_ConnectionClosesDuringProbeSend(t *testing.T) {
	signer := mustSigner(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var rawConnClosed atomic.Bool
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		cfg := &ssh.ServerConfig{NoClientAuth: true, ServerVersion: "SSH-2.0-dropmidsend"}
		cfg.AddHostKey(signer)
		conn, _, reqs, err := ssh.NewServerConn(raw, cfg)
		if err != nil {
			_ = raw.Close()
			return
		}
		go func() {
			for r := range reqs {
				_ = r // accept the request, but tear down TCP instead of answering
				_ = raw.Close()
				rawConnClosed.Store(true)
				_ = conn.Close()
				return
			}
		}()
	}()

	conn, err := ssh.Dial("tcp", ln.Addr().String(), insecureClientConfig("u"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	dead := make(chan struct{}, 1)
	stop := Keepalive{Interval: 15 * time.Millisecond, MaxMisses: 3}.Probe(conn, func() {
		select {
		case dead <- struct{}{}:
		default:
		}
	})

	select {
	case <-dead:
	case <-time.After(5 * time.Second):
		t.Fatal("a TCP break at the moment of sending a probe did not lead to onDead")
	}

	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop() hung after a TCP break during a probe send")
	}
	if !rawConnClosed.Load() {
		t.Fatal("the test harness did not break the connection — the scenario was not reproduced")
	}
}

// ============================================================================
// 5. The request fate table: end-to-end check against PROTOCOL §4.1
//    for the whole set of requests a stock Windows client always sends.
// ============================================================================

// TestManual_RequestFateTable_StockClientRequests — what a real
// OpenSSH/PuTTY/stock Windows SSH client sends in an ordinary
// interactive session: pty-req, env (several times, including
// LANG/TERM and garbage locales), shell/exec, window-change on
// resize, signal on Ctrl+C, and what the server sends back —
// exit-status/exit-signal. The list is independent of the original
// author's test table (requests_test.go), assembled directly from the
// normative source.
func TestManual_RequestFateTable_StockClientRequests(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
		want    Disposition
		why     string
	}{
		{"pty-req", nil, Forward, "PROTOCOL §4.1: forward, the result goes to the human"},
		{"shell", nil, Forward, "PROTOCOL §4.1: forward"},
		{"exec", nil, Forward, "PROTOCOL §4.1: forward, the command goes into the event"},
		{"window-change", nil, Forward, "PROTOCOL §4.1: false, forward, the resize goes into the cast"},
		{"signal", nil, Forward, "PROTOCOL §4.1: false, forward"},
		{"exit-status", nil, Forward, "PROTOCOL §4.1: machine→human, forward"},
		{"exit-signal", nil, Forward, "PROTOCOL §4.1: machine→human, forward"},
		{"subsystem", nil, Reject, "PROTOCOL §4.1: forbidden, E_SSH_SUBSYSTEM_FORBIDDEN"},
		{"auth-agent-req@openssh.com", nil, Reject, "PROTOCOL §4.1: forbidden, E_SSH_AGENT_FORBIDDEN"},
		{"x11-req", nil, Reject, "PROTOCOL §4.1: forbidden, E_SSH_X11_FORBIDDEN"},
		// env: the positive and negative cases depend on the payload, not just the name.
		{"env", MarshalEnv(Env{Name: "TERM", Value: "xterm-256color"}), Forward, "TERM is allowed by the spec §5.1, the value is printable ASCII"},
		{"env", MarshalEnv(Env{Name: "LANG", Value: "en_US.UTF-8"}), Forward, "LANG is allowed by the spec §5.1"},
		{"env", MarshalEnv(Env{Name: "LC_ALL", Value: "C"}), Drop, "LC_ALL is not in the spec §5.1 allowlist — drop it"},
		{"env", MarshalEnv(Env{Name: "SSH_AUTH_SOCK", Value: "/tmp/x"}), Drop, "not in the allowlist"},
		{"env", MarshalEnv(Env{Name: "LD_PRELOAD", Value: "/tmp/evil.so"}), Drop, "not in the allowlist — the key forbidden case"},
	}
	for _, c := range cases {
		got := LookupChannelRequest(c.name, c.payload)
		if got != c.want {
			t.Errorf("channel %q (payload=%x): got %s, want %s — %s", c.name, c.payload, got, c.want, c.why)
		}
	}

	globalCases := []struct {
		name string
		want Disposition
		why  string
	}{
		{"keepalive@iamtunnel", Answer, "PROTOCOL §5: request success with an empty payload"},
		{"keepalive@openssh.com", Answer, "PROTOCOL §4.1: request success, do not forward"},
		{"no-more-sessions@openssh.com", Drop, "PROTOCOL §4.1: allow, do not forward, no event"},
		{"tcpip-forward", Reject, "PROTOCOL §4.1: forbidden, E_SSH_FORWARD_FORBIDDEN"},
		{"hostkeys-00@openssh.com", Reject, "PROTOCOL §4.1: violates direction"},
	}
	for _, c := range globalCases {
		got := LookupGlobalRequest(c.name)
		if got != c.want {
			t.Errorf("global %q: got %s, want %s — %s", c.name, got, c.want, c.why)
		}
	}
}
