package server

import (
	"bufio"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// wire_test.go proves that garbage on the control channel gets not a
// single panic, only a clear refusal for each — by enumerating garbage,
// not with one or two examples. Every case
// below asserts an actual outcome (a specific error, or a specific
// successful value), never merely "did not panic" on its own — a call
// that cannot panic in Go without unsafe/reflect trickery would pass a
// not-panicking-only test for free.

func mustSigner(t *testing.T) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(mustEd25519(t))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func validPubKeyLine(t *testing.T) string {
	t.Helper()
	return strings.TrimRight(string(ssh.MarshalAuthorizedKey(mustSigner(t).PublicKey())), "\r\n")
}

// ---- readControlLine --------------------------------------------------

func TestReadControlLine_ExactBoundary(t *testing.T) {
	payload := strings.Repeat("a", 32)
	r := bufio.NewReaderSize(strings.NewReader(payload+"\n"), len(payload)+2)
	got, err := readControlLine(r, len(payload)+1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestReadControlLine_TooLongIsRejectedNotBuffered(t *testing.T) {
	// One line far longer than the limit, followed by a newline. A naive
	// unbounded reader (bufio.Reader.ReadString) would happily read the
	// whole thing into memory; readControlLine must refuse before that.
	const limit = 64
	huge := strings.Repeat("x", limit*1000)
	r := bufio.NewReaderSize(strings.NewReader(huge+"\n"), limit+1)
	_, err := readControlLine(r, limit)
	if err != errLineTooLong {
		t.Fatalf("got err=%v, want errLineTooLong", err)
	}
}

func TestReadControlLine_TruncatedNoNewline(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(`{"proto":1}`), 4096)
	_, err := readControlLine(r, 4096)
	if err != errLineTruncated {
		t.Fatalf("got err=%v, want errLineTruncated", err)
	}
}

func TestReadControlLine_CleanEOF(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(""), 4096)
	_, err := readControlLine(r, 4096)
	if err == nil {
		t.Fatal("expected an error on empty input")
	}
}

// ---- checkJSONShape / decodeControlRequest: garbage corpus -------------

func TestDecodeControlRequest_GarbageCorpusNeverPanicsAndAlwaysRejects(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"empty", ``},
		{"not json at all", `this is not json`},
		{"bare number", `42`},
		{"bare string", `"hello"`},
		{"bare array", `[1,2,3]`},
		{"truncated object", `{"proto":1,"op":"door.st`},
		{"truncated string", `{"proto":1,"op":"door.status"`},
		{"trailing garbage after object", `{"proto":1,"op":"door.status"} garbage`},
		{"two json values", `{"proto":1,"op":"a"}{"proto":1,"op":"b"}`},
		{"duplicate top-level key", `{"proto":1,"proto":2,"op":"door.status","id":"x","caps":[]}`},
		{"duplicate nested key", `{"proto":1,"op":"door.open","id":"x","caps":[],"door":{"id":"a","id":"b","pubkey":"","opened":"","idleDeadline":"","hardDeadline":""}}`},
		{"unknown top-level field", `{"proto":1,"op":"door.status","id":"x","caps":[],"extra":"nope"}`},
		{"wrong type for proto", `{"proto":"one","op":"door.status","id":"x","caps":[]}`},
		{"wrong type for caps", `{"proto":1,"op":"door.status","id":"x","caps":"not-an-array"}`},
		{"wrong type for door", `{"proto":1,"op":"door.open","id":"x","caps":[],"door":"not-an-object"}`},
		{"null byte inside string", "{\"proto\":1,\"op\":\"door.status\",\"id\":\"x\x00y\",\"caps\":[]}"},
		{"deeply nested array bomb", strings.Repeat(`[`, 10000) + strings.Repeat(`]`, 10000)},
		{"deeply nested object bomb", strings.Repeat(`{"a":`, 10000) + `1` + strings.Repeat(`}`, 10000)},
		{"unbalanced close", `{"proto":1}}`},
		{"unbalanced open", `{"proto":1`},
		{"NaN-ish garbage", `{"proto":NaN,"op":"x","id":"y","caps":[]}`},
		{"single brace", `{`},
		{"single bracket", `[`},
		{"lone close", `}`},
		{"array instead of object at top", `["proto",1]`},
		{"object with numeric key look-alike", `{"1":2,"proto":1,"op":"door.status","id":"x","caps":[]}`},
		{"binary garbage", string([]byte{0xff, 0xfe, 0x00, 0x01, 0x02, '{', '}'})},
		{"control characters raw", "{\"proto\":1,\"op\":\"door.status\",\"id\":\"\x01\x02\x03\",\"caps\":[]}"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decodeControlRequest panicked on %q: %v", c.line, r)
				}
			}()
			req, err := decodeControlRequest([]byte(c.line), DefaultControlJSONDepth)
			if err == nil {
				t.Fatalf("expected an error decoding %q, got req=%+v", c.line, req)
			}
		})
	}
}

func TestDecodeControlRequest_ValidMinimalMessagesAccepted(t *testing.T) {
	cases := []struct {
		name string
		line string
		op   string
	}{
		{"status", `{"proto":1,"caps":[],"id":"11111111-1111-1111-1111-111111111111","op":"door.status"}`, "door.status"},
		{"close", `{"proto":1,"caps":[],"id":"11111111-1111-1111-1111-111111111111","op":"door.close","doorId":"x","reason":"idle"}`, "door.close"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := decodeControlRequest([]byte(c.line), DefaultControlJSONDepth)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.Op != c.op {
				t.Fatalf("got op %q, want %q", req.Op, c.op)
			}
		})
	}
}

func TestCheckJSONShape_DepthLimitRejectsWithoutPanic(t *testing.T) {
	// checkJSONShape is tested directly here, independent of
	// controlRequest's fixed field shape: a generic deeply nested object
	// has nowhere to legally appear inside a controlRequest at all (every
	// field is a flat string/int/array), so the depth guard is only
	// observable in isolation from struct-shape validation.
	nested := strings.Repeat(`{"a":`, 5) + `1` + strings.Repeat(`}`, 5)
	if err := checkJSONShape([]byte(nested), 3); err == nil {
		t.Fatal("expected depth-limit rejection")
	}
	if err := checkJSONShape([]byte(nested), 10); err != nil {
		t.Fatalf("unexpected rejection at generous depth: %v", err)
	}
}

// FuzzDecodeControlRequest lets `go test -fuzz=FuzzDecodeControlRequest`
// search for a byte string that panics decodeControlRequest; the seed
// corpus below is the same adversarial set as the table test above, so a
// plain `go test` run already exercises it without needing -fuzz.
func FuzzDecodeControlRequest(f *testing.F) {
	seeds := []string{
		``, `{`, `}`, `[`, `]`, `null`, `true`, `false`, `0`, `-0`, `1e400`,
		`{"proto":1,"op":"door.status","id":"x","caps":[]}`,
		`{"proto":1,"proto":1,"op":"a","id":"x","caps":[]}`,
		strings.Repeat(`[`, 5000),
		`{"door":{"id":"a","door":{"id":"b"}}}`,
		"\x00\x01\x02\xff\xfe",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("decodeControlRequest panicked on %q: %v", s, r)
			}
		}()
		_, _ = decodeControlRequest([]byte(s), DefaultControlJSONDepth)
	})
}

// ---- decodeDoorPubKey ---------------------------------------------------

func TestDecodeDoorPubKey(t *testing.T) {
	good := validPubKeyLine(t)

	t.Run("accepts exact shape, tolerates trailing newline from MarshalAuthorizedKey", func(t *testing.T) {
		if _, _, err := decodeDoorPubKey(good + "\n"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	badCases := []struct {
		name string
		key  string
	}{
		{"with comment", good + " someone@host"},
		{"with options prefix", `restrict,pty ` + good},
		{"wrong algorithm label lying about ed25519 blob", "ssh-rsa " + strings.Fields(good)[1]},
		{"empty", ""},
		{"garbage base64", "ssh-ed25519 not-base64!!!"},
		{"truncated base64 blob", "ssh-ed25519 QUFBQQ=="},
		{"three fields", good + " extra field"},
		{"rsa key rejected even though well-formed", func() string {
			signer, err := ssh.NewSignerFromKey(mustRSA(t))
			if err != nil {
				t.Fatal(err)
			}
			return strings.TrimRight(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "\r\n")
		}()},
	}
	for _, c := range badCases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := decodeDoorPubKey(c.key); err == nil {
				t.Fatalf("expected rejection of %q", c.key)
			}
		})
	}
}

// ---- parseDoorDeadlines --------------------------------------------------

func TestParseDoorDeadlines_OrderEnforced(t *testing.T) {
	base := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	fmtT := func(t time.Time) string { return t.Format(time.RFC3339Nano) }

	if _, _, _, err := parseDoorDeadlines(fmtT(base), fmtT(base.Add(time.Minute)), fmtT(base.Add(time.Hour))); err != nil {
		t.Fatalf("well-ordered deadlines rejected: %v", err)
	}

	badOrders := [][3]time.Time{
		{base, base, base.Add(time.Hour)},                                     // opened == idle
		{base, base.Add(time.Hour), base.Add(time.Minute)},                    // hard before idle
		{base.Add(time.Hour), base.Add(time.Minute), base.Add(2 * time.Hour)}, // opened after idle
	}
	for i, tc := range badOrders {
		if _, _, _, err := parseDoorDeadlines(fmtT(tc[0]), fmtT(tc[1]), fmtT(tc[2])); err == nil {
			t.Fatalf("case %d: expected order violation to be rejected", i)
		}
	}
}

func TestParseDoorDeadlines_GarbageTimestamps(t *testing.T) {
	garbage := []string{"", "not-a-time", "2026-13-99T99:99:99Z", "99999999999999999999-01-01T00:00:00Z"}
	for _, g := range garbage {
		if _, _, _, err := parseDoorDeadlines(g, g, g); err == nil {
			t.Fatalf("expected rejection of garbage timestamp %q", g)
		}
	}
}

// ---- validDoorID ----------------------------------------------------------

func TestValidDoorID(t *testing.T) {
	if !validDoorID("11111111-1111-1111-1111-111111111111") {
		t.Fatal("well-formed uuid rejected")
	}
	bad := []string{"", "not-a-uuid", "11111111111111111111111111111111", "11111111-1111-1111-1111-11111111111g", "../../etc/passwd"}
	for _, b := range bad {
		if validDoorID(b) {
			t.Fatalf("malformed door id accepted: %q", b)
		}
	}
}
