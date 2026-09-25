package sshx

// requests_test.go: tests for the table of fate for requests.
//
// The normative source is PROTOCOL.md §4.1 and §5. The main test here is TestTableMatchesProtocol: it
// checks the tables row by row and for completeness, not just for
// unique names. Any changed, removed, or extra row turns exactly this
// test red.

import (
	"errors"
	"strings"
	"testing"
)

// --- table completeness against PROTOCOL §4.1 --------------------------------

// protocolChannelRows — the channel requests of PROTOCOL §4.1 in
// full, exactly as the spec describes them. The list is closed:
// anything not here must be rejected under default-deny.
var protocolChannelRows = []requestRow{
	{"pty-req", Forward},
	{"shell", Forward},
	{"exec", Forward},
	{"window-change", Forward},
	{"signal", Forward},
	{"exit-status", Forward},
	{"exit-signal", Forward},
	{"env", Drop}, // the real decision is by payload, see LookupChannelRequest
	{"eow@openssh.com", Drop},
	{"subsystem", Reject},
	{"x11-req", Reject},
	{"auth-agent-req@openssh.com", Reject},
}

// protocolGlobalRows — the global requests of PROTOCOL §4.1 and §5 in full.
var protocolGlobalRows = []requestRow{
	{"keepalive@iamtunnel", Answer},
	{"keepalive@openssh.com", Answer},
	{"no-more-sessions@openssh.com", Drop},
	{"tcpip-forward", Reject},
	{"cancel-tcpip-forward", Reject},
	{"hostkeys-00@openssh.com", Reject},
}

func checkTable(t *testing.T, what string, got, want []requestRow) {
	t.Helper()
	gotByName := map[string]Disposition{}
	for _, r := range got {
		if _, dup := gotByName[r.name]; dup {
			t.Errorf("%s: row %q appears twice", what, r.name)
		}
		gotByName[r.name] = r.disp
	}
	wantByName := map[string]Disposition{}
	for _, r := range want {
		wantByName[r.name] = r.disp
	}
	for _, r := range want {
		d, ok := gotByName[r.name]
		if !ok {
			t.Errorf("%s: row %q is missing from the table, PROTOCOL §4.1 requires it (%s)", what, r.name, r.disp)
			continue
		}
		if d != r.disp {
			t.Errorf("%s: %q has disposition %s, PROTOCOL §4.1 requires %s", what, r.name, d, r.disp)
		}
	}
	for _, r := range got {
		if _, ok := wantByName[r.name]; !ok {
			t.Errorf("%s: the table has a made-up row %q (%s); PROTOCOL §4.1 has none", what, r.name, r.disp)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%s: %d rows, the spec requires %d; table: %s", what, len(got), len(want), requestNames(got))
	}
}

// TestTableMatchesProtocol — the tables match PROTOCOL §4.1/§5 row by
// row. Replaces the previous TestTableSanity, which only checked name
// uniqueness and stayed green even if all twelve dispositions were flipped.
func TestTableMatchesProtocol(t *testing.T) {
	checkTable(t, "channelRequestTable", channelRequestTable, protocolChannelRows)
	checkTable(t, "globalRequestTable", globalRequestTable, protocolGlobalRows)
}

// TestLookupMatchesProtocol — the same thing, but through the public
// entry point: the table could match while Lookup lies.
func TestLookupMatchesProtocol(t *testing.T) {
	for _, r := range protocolChannelRows {
		if r.name == "env" {
			continue // env is decided by payload, see TestEnv*
		}
		if got := LookupChannelRequest(r.name, nil); got != r.disp {
			t.Errorf("LookupChannelRequest(%q) = %s, want %s", r.name, got, r.disp)
		}
		if !IsKnownChannelRequest(r.name) {
			t.Errorf("IsKnownChannelRequest(%q) = false", r.name)
		}
	}
	for _, r := range protocolGlobalRows {
		if got := LookupGlobalRequest(r.name); got != r.disp {
			t.Errorf("LookupGlobalRequest(%q) = %s, want %s", r.name, got, r.disp)
		}
		if !IsKnownGlobalRequest(r.name) {
			t.Errorf("IsKnownGlobalRequest(%q) = false", r.name)
		}
	}
}

// TestUnknownRequestsDefaultToReject — default-deny PROTOCOL §4.1.
func TestUnknownRequestsDefaultToReject(t *testing.T) {
	for _, name := range []string{
		"totally-unknown-request-name",
		"", "PTY-REQ", "pty-req ", " pty-req", "shell\x00",
		"direct-tcpip", "x11", "sftp",
	} {
		if got := LookupChannelRequest(name, nil); got != Reject {
			t.Errorf("channel %q: got %s, want reject", name, got)
		}
		if IsKnownChannelRequest(name) {
			t.Errorf("channel %q is considered known", name)
		}
		if got := LookupGlobalRequest(name); got != Reject {
			t.Errorf("global %q: got %s, want reject", name, got)
		}
		if IsKnownGlobalRequest(name) {
			t.Errorf("global %q is considered known", name)
		}
	}
}

// TestZeroDispositionIsReject — the type's zero value must be a
// rejection. Otherwise a forgotten initialization means "let through".
func TestZeroDispositionIsReject(t *testing.T) {
	var d Disposition
	if d != Reject {
		t.Fatalf("zero Disposition = %s, want reject", d)
	}
	if Reject.String() != "reject" || Drop.String() != "drop" ||
		Answer.String() != "answer" || Forward.String() != "forward" {
		t.Fatalf("disposition names drifted apart: %s %s %s %s", Reject, Drop, Answer, Forward)
	}
}

// TestEOFAndCloseAreNotRequests — PROTOCOL §4.1: "eof and close are
// carved out into their true packet types". So they must not be in
// the channel-request table, and a name arriving as a request is a
// forgery of a protocol-level packet.
func TestEOFAndCloseAreNotRequests(t *testing.T) {
	for _, name := range []string{"eof", "close", "eof@"} {
		if IsKnownChannelRequest(name) {
			t.Errorf("%q is declared a channel request; PROTOCOL §4.1 knows it as a packet type", name)
		}
		if got := LookupChannelRequest(name, nil); got != Reject {
			t.Errorf("%q: got %s, want reject", name, got)
		}
	}
	if !IsChannelControlPacket("eof") || !IsChannelControlPacket("close") {
		t.Fatal("IsChannelControlPacket does not distinguish eof/close")
	}
	if IsChannelControlPacket("eof@") || IsChannelControlPacket("shell") {
		t.Fatal("IsChannelControlPacket fired on a non-protocol name")
	}
}

// TestCompatibilityNotificationsAreSilent — PROTOCOL §4.1 requires for
// these "do not forward and do not create an event".
func TestCompatibilityNotificationsAreSilent(t *testing.T) {
	for _, name := range []string{"eow@openssh.com", "no-more-sessions@openssh.com"} {
		if !IsCompatibilityNotification(name) {
			t.Errorf("%q is not recognized as a compatibility notification", name)
		}
	}
	for _, name := range []string{"subsystem", "env", "tcpip-forward", "keepalive@iamtunnel"} {
		if IsCompatibilityNotification(name) {
			t.Errorf("%q is wrongly recognized as a compatibility notification", name)
		}
	}
	if got := LookupChannelRequest("eow@openssh.com", nil); got != Drop {
		t.Errorf("eow@openssh.com: got %s, want drop", got)
	}
	if got := LookupGlobalRequest("no-more-sessions@openssh.com"); got != Drop {
		t.Errorf("no-more-sessions@openssh.com: got %s, want drop", got)
	}
}

// TestGlobalKeepaliveIsAnswered — §5's key row: keepalive@iamtunnel
// gets a local success. Forward here would break bidirectional
// keepalive: there is nowhere to forward a global request to, and
// ApplyDisposition would answer with a failure, meaning the passive
// side would rack up misses.
func TestGlobalKeepaliveIsAnswered(t *testing.T) {
	for _, name := range []string{"keepalive@iamtunnel", "keepalive@openssh.com"} {
		if got := LookupGlobalRequest(name); got != Answer {
			t.Fatalf("%s: got %s, want answer", name, got)
		}
		replies := 0
		var last bool
		reply := func(ok bool, _ []byte) error {
			replies++
			last = ok
			return nil
		}
		forwarded := false
		fw := func() (bool, error) { forwarded = true; return true, nil }
		d := ApplyDisposition(name, true, reply, LookupGlobalRequest(name), fw)
		if d != Answer {
			t.Fatalf("%s: ApplyDisposition = %s, want answer", name, d)
		}
		if replies != 1 || !last {
			t.Fatalf("%s: %d answers (last ok=%v), want exactly one success", name, replies, last)
		}
		if forwarded {
			t.Fatalf("%s: was forwarded, even though PROTOCOL §5 requires a local answer", name)
		}
	}
}

// TestHostkeysFromClientIsRejected — PROTOCOL §4.1: an incoming
// hostkeys-00@openssh.com from a client violates the direction and
// gets a request failure.
func TestHostkeysFromClientIsRejected(t *testing.T) {
	if got := LookupGlobalRequest("hostkeys-00@openssh.com"); got != Reject {
		t.Fatalf("hostkeys-00@openssh.com: got %s, want reject", got)
	}
	got := ApplyDisposition("hostkeys-00@openssh.com", true, func(ok bool, _ []byte) error {
		if ok {
			t.Error("unsolicited success on hostkeys-00@openssh.com")
		}
		return nil
	}, Reject, nil)
	if got != Reject {
		t.Fatalf("got %s, want reject", got)
	}
}

// --- env --------------------------------------------------------------------

// TestEnvDispositionAllowed — SPEC §5.1: only TERM and LANG.
func TestEnvDispositionAllowed(t *testing.T) {
	cases := []struct {
		name string
		disp Disposition
	}{
		{"TERM", Forward},
		{"LANG", Forward},
		{"PATH", Drop},
		{"LC_ALL", Drop},
		{"HOME", Drop},
		{"LD_PRELOAD", Drop},
		{"", Drop},
		// name-based bypasses, enumerated in review
		{"term", Drop}, {"Term", Drop}, {"TERM ", Drop}, {"\tTERM", Drop},
		{"TERM\x00PATH", Drop},
		{"\u0422ERM", Drop}, // Cyrillic \u0422 (U+0422)
		{strings.Repeat("T", MaxEnvNameLen+1), Drop},
	}
	for _, c := range cases {
		if got := EnvDisposition(c.name); got != c.disp {
			t.Errorf("%q: got %s, want %s", c.name, got, c.disp)
		}
	}
}

// TestEnvLookupGoesThroughSingleEntryPoint — fix #10: the single entry
// point does not drop TERM/LANG. LookupChannelRequest("env") used to
// unconditionally return Drop, and a well-behaved gateway broke the
// human's terminal.
func TestEnvLookupGoesThroughSingleEntryPoint(t *testing.T) {
	term := MarshalEnv(Env{Name: "TERM", Value: "xterm-256color"})
	if got := LookupChannelRequest("env", term); got != Forward {
		t.Fatalf("env TERM via LookupChannelRequest: got %s, want forward", got)
	}
	path := MarshalEnv(Env{Name: "PATH", Value: "/usr/bin"})
	if got := LookupChannelRequest("env", path); got != Drop {
		t.Fatalf("env PATH via LookupChannelRequest: got %s, want drop", got)
	}
	// A malformed payload is a violation of the RFC 4254 §6.4 layout,
	// not "a different variable": we reject it explicitly.
	if got := LookupChannelRequest("env", []byte{0, 0, 0, 9, 'T'}); got != Reject {
		t.Fatalf("malformed env: got %s, want reject", got)
	}
	if got := LookupChannelRequest("env", nil); got != Reject {
		t.Fatalf("empty env payload: got %s, want reject", got)
	}
}

// TestEnvValueIsFiltered — the value of TERM/LANG must not carry
// control octets: they end up in the process environment on the
// target machine.
func TestEnvValueIsFiltered(t *testing.T) {
	bad := []string{
		"xterm\x00extra",
		"xterm\r\nLD_PRELOAD=/tmp/x",
		"\x1b]0;title\x07",
		"xterm\x1b[2J",
		strings.Repeat("x", MaxEnvValueLen+1),
	}
	for _, v := range bad {
		p := MarshalEnv(Env{Name: "TERM", Value: v})
		if got := LookupChannelRequest("env", p); got != Drop {
			t.Errorf("TERM=%q: got %s, want drop", v, got)
		}
	}
	for _, v := range []string{"", "xterm-256color", "en_US.UTF-8", strings.Repeat("x", MaxEnvValueLen)} {
		p := MarshalEnv(Env{Name: "TERM", Value: v})
		if got := LookupChannelRequest("env", p); got != Forward {
			t.Errorf("TERM=%q: got %s, want forward", v, got)
		}
	}
}

// TestEnvBudgetLimitsCount — a hundred thousand env TERM requests no
// longer grow the process environment without a limit.
func TestEnvBudgetLimitsCount(t *testing.T) {
	b := NewEnvBudget()
	p := MarshalEnv(Env{Name: "TERM", Value: "xterm"})
	for i := 0; i < MaxEnvRequests; i++ {
		if got := b.Decide(p); got != Forward {
			t.Fatalf("env #%d: got %s, want forward", i+1, got)
		}
	}
	for i := 0; i < 3; i++ {
		if got := b.Decide(p); got != Drop {
			t.Fatalf("env over budget: got %s, want drop", got)
		}
	}
	// Requests dropped by name do not spend the budget: otherwise a
	// client could burn the limit with garbage and lock itself out of TERM.
	b2 := NewEnvBudget()
	junk := MarshalEnv(Env{Name: "PATH", Value: "/x"})
	for i := 0; i < MaxEnvRequests*4; i++ {
		if got := b2.Decide(junk); got != Drop {
			t.Fatalf("junk env: got %s, want drop", got)
		}
	}
	if got := b2.Decide(p); got != Forward {
		t.Fatalf("TERM after garbage: got %s, want forward", got)
	}
	// A nil budget is allowed and means "no counting".
	var nilBudget *EnvBudget
	if got := nilBudget.Decide(p); got != Forward {
		t.Fatalf("nil EnvBudget: got %s, want forward", got)
	}
}

// TestEnvBudgetIsConcurrencySafe — the budget lives in the session's
// goroutine and must survive concurrent calls under -race.
func TestEnvBudgetIsConcurrencySafe(t *testing.T) {
	b := NewEnvBudget()
	p := MarshalEnv(Env{Name: "TERM", Value: "xterm"})
	forwarded := make(chan Disposition, 64)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 8; j++ {
				forwarded <- b.Decide(p)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	close(forwarded)
	n := 0
	for d := range forwarded {
		if d == Forward {
			n++
		}
	}
	if n != MaxEnvRequests {
		t.Fatalf("%d env passed through, budget = %d", n, MaxEnvRequests)
	}
}

// TestEnvDispositionRoundTrip checks that MarshalEnv + ParseEnv yield
// the correct name, which EnvDisposition then reacts to.
func TestEnvDispositionRoundTrip(t *testing.T) {
	for _, name := range []string{"TERM", "LANG", "PATH", "FOO"} {
		payload := MarshalEnv(Env{Name: name, Value: "v"})
		env, err := ParseEnv(payload)
		if err != nil {
			t.Fatal(err)
		}
		want := Drop
		if name == "TERM" || name == "LANG" {
			want = Forward
		}
		if got := EnvDisposition(env.Name); got != want {
			t.Fatalf("%q: got %s, want %s", env.Name, got, want)
		}
	}
}

// --- ApplyDisposition -------------------------------------------------------

// recorder counts answers and forwards.
type recorder struct {
	replies []bool
	forward int
}

func (r *recorder) reply(ok bool, _ []byte) error {
	r.replies = append(r.replies, ok)
	return nil
}

func (r *recorder) check(t *testing.T, what string, want ...bool) {
	t.Helper()
	if len(r.replies) != len(want) {
		t.Fatalf("%s: %v answers, wanted %v", what, r.replies, want)
	}
	for i := range want {
		if r.replies[i] != want[i] {
			t.Fatalf("%s: answer #%d = %v, want %v", what, i, r.replies[i], want[i])
		}
	}
}

// TestApplyDisposition_RepliesExactlyOnce — PROTOCOL §4.1's rule for
// all four dispositions: exactly one answer on want-reply=true, none on false.
func TestApplyDisposition_RepliesExactlyOnce(t *testing.T) {
	cases := []struct {
		d        Disposition
		wantOK   bool
		wantDisp Disposition
	}{
		{Reject, false, Reject},
		{Drop, false, Drop}, // §4.1: "on true, return a failure"
		{Answer, true, Answer},
		{Forward, true, Forward},
	}
	for _, c := range cases {
		t.Run(c.d.String(), func(t *testing.T) {
			r := &recorder{}
			fw := func() (bool, error) { r.forward++; return true, nil }
			if got := ApplyDisposition("x", true, r.reply, c.d, fw); got != c.wantDisp {
				t.Fatalf("want-reply=true: got %s, want %s", got, c.wantDisp)
			}
			r.check(t, "want-reply=true", c.wantOK)

			r2 := &recorder{}
			fw2 := func() (bool, error) { r2.forward++; return true, nil }
			if got := ApplyDisposition("x", false, r2.reply, c.d, fw2); got != c.wantDisp {
				t.Fatalf("want-reply=false: got %s, want %s", got, c.wantDisp)
			}
			r2.check(t, "want-reply=false")

			wantForward := 0
			if c.d == Forward {
				wantForward = 1
			}
			if r.forward != wantForward || r2.forward != wantForward {
				t.Fatalf("forward called %d/%d times, wanted %d", r.forward, r2.forward, wantForward)
			}
		})
	}
}

// TestApplyDisposition_DropAnswersFailure — Drop used to always stay
// silent, and the client hung until its own timeout. PROTOCOL §4.1:
// "drop other names, on true return a failure, on false do not answer".
func TestApplyDisposition_DropAnswersFailure(t *testing.T) {
	r := &recorder{}
	if got := ApplyDisposition("env", true, r.reply, Drop, nil); got != Drop {
		t.Fatalf("got %s, want drop", got)
	}
	r.check(t, "drop+want-reply", false)
}

// TestApplyDisposition_ForwardWithoutWantReply — IAMT-216 round 2:
// replaces the test removed by "fix #4", which had pinned down a
// stale (incorrect) contract.
//
// It used to assert: want-reply=false + forward()==(false, nil) must
// yield Reject. But golang.org/x/crypto/ssh's (*channel).SendRequest
// ALWAYS returns ok=false when wantReply=false — it physically never
// reads an answer off the wire (see ssh/channel.go: the `if wantReply
// { m, ok := <-ch.msg; ... }` branch is skipped entirely), so "false"
// here does not mean "the forward failed" - it means nothing at all.
// A real client (Session.WindowChange) and our own
// internal/client/connect.go send window-change exactly that way, so
// the old contract meant: EVERY real window-change was read as a
// refusal and resizeRecording was never called (IAMT-216, live corpus:
// 37 "o" events, 0 "r").
//
// A transport error (forward genuinely failed to send the packet) is
// still Reject regardless of want-reply: there is a real failure
// signal there, and it must not be lost.
func TestApplyDisposition_ForwardWithoutWantReply(t *testing.T) {
	transportErr := func() (bool, error) { return false, errors.New("peer gone") }
	noReply := func() (bool, error) { return false, nil }

	r := &recorder{}
	if got := ApplyDisposition("window-change", false, r.reply, Forward, transportErr); got != Reject {
		t.Fatalf("transport error, want-reply=false: ApplyDisposition = %s, want reject", got)
	}
	r.check(t, "transport error, want-reply=false")

	r2 := &recorder{}
	if got := ApplyDisposition("shell", true, r2.reply, Forward, transportErr); got != Reject {
		t.Fatalf("transport error, want-reply=true: got %s, want reject", got)
	}
	r2.check(t, "transport error, want-reply=true", false)

	// The core of the fix: (false, nil) with no want-reply is NOT a
	// refusal, it is the only thing forward() can possibly return in this case.
	r3 := &recorder{}
	if got := ApplyDisposition("window-change", false, r3.reply, Forward, noReply); got != Forward {
		t.Fatalf("(false, nil), want-reply=false: ApplyDisposition = %s, want forward", got)
	}
	r3.check(t, "(false, nil), want-reply=false")

	// With want-reply=true, ok genuinely arrived off the wire, and
	// false remains a real refusal.
	r4 := &recorder{}
	if got := ApplyDisposition("shell", true, r4.reply, Forward, noReply); got != Reject {
		t.Fatalf("(false, nil), want-reply=true: got %s, want reject", got)
	}
	r4.check(t, "(false, nil), want-reply=true", false)
}

// TestApplyDisposition_NilForwardIsReject — nowhere to forward to:
// that is a refusal, not a silent success. This is exactly the case
// that arises for global requests.
func TestApplyDisposition_NilForwardIsReject(t *testing.T) {
	r := &recorder{}
	if got := ApplyDisposition("keepalive@iamtunnel", true, r.reply, Forward, nil); got != Reject {
		t.Fatalf("got %s, want reject", got)
	}
	r.check(t, "forward=nil", false)
}

// TestApplyDisposition_NilReplyFuncSafe — replyFunc may be nil.
func TestApplyDisposition_NilReplyFuncSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil replyFunc panicked: %v", r)
		}
	}()
	want := map[Disposition]Disposition{
		Reject:  Reject,
		Drop:    Drop,
		Answer:  Answer,
		Forward: Reject, // nowhere to forward to — that is a refusal
	}
	for d, exp := range want {
		if got := ApplyDisposition("subsystem", true, nil, d, nil); got != exp {
			t.Fatalf("%s with no replyFunc and forward(): got %s, want %s", d, got, exp)
		}
	}
}

// TestApplyDisposition_UnknownDispositionIsReject — a value outside
// the enum must not mean "let through".
func TestApplyDisposition_UnknownDispositionIsReject(t *testing.T) {
	r := &recorder{}
	forwarded := false
	fw := func() (bool, error) { forwarded = true; return true, nil }
	if got := ApplyDisposition("x", true, r.reply, Disposition(99), fw); got != Reject {
		t.Fatalf("got %s, want reject", got)
	}
	if forwarded {
		t.Fatal("an unknown disposition forwarded the request")
	}
	r.check(t, "disposition=99", false)
}
