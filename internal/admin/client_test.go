package admin

// client_test.go exercises the wire client against a small fake gateway
// double (not the real internal/gateway - that package has its own
// admin_scenarios_test.go proving the real end-to-end behaviour). What
// belongs here is what only the client can prove on its own: that a
// gateway response - however garbled - never panics this package and
// always turns into a clean, returned error, and that requests/responses
// round-trip correctly when the gateway is honest.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func genSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func fingerprintFor(t *testing.T, key ssh.PublicKey) string {
	t.Helper()
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// fakeGateway accepts exactly one command-login connection per dial and
// hands every exec request's (command, body) to respond, writing back
// whatever raw bytes it returns completely unmodified - this is what
// lets a test feed the client literal garbage without needing a real
// gateway to produce it.
type fakeGateway struct {
	ln         net.Listener
	hostSigner ssh.Signer
	personKey  ssh.Signer
	respond    func(command string, body []byte) []byte
	// cfgMod, if set, is applied to this fake gateway's own ssh.ServerConfig
	// before it starts accepting - IAMT-173's policy tests use it to pin
	// the server side to a single algorithm so the real wire handshake,
	// not just a struct field, proves the client's policy.
	cfgMod func(*ssh.ServerConfig)
	// whoamiToRespond hands whoami to respond like any other command. By
	// default the fake answers it itself, as a v1 gateway does: the client
	// runs whoami before its first application command (R2-CX F-06,
	// PROTOCOL §1.1), and a test written for one command need not answer
	// the preflight in front of it. Tests of whoami's own answer set it,
	// through newFakeGatewayForWhoami.
	whoamiToRespond bool
}

// fakeWhoamiV1 is the fake's own answer to the whoami preflight.
const fakeWhoamiV1 = `{"proto":1,"caps":[],"ok":true,"result":{"subject":"alice","role":"admin","serverTime":"2026-09-12T10:00:00Z","person":"alice"}}` + "\n"

// newFakeGatewayForWhoami is newFakeGateway for a test of whoami's own
// answer: whoami goes to respond like any other command.
func newFakeGatewayForWhoami(t *testing.T, personKey ssh.Signer, respond func(string, []byte) []byte) *fakeGateway {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fg := &fakeGateway{ln: ln, hostSigner: genSigner(t), personKey: personKey, respond: respond, whoamiToRespond: true}
	go fg.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return fg
}

func newFakeGateway(t *testing.T, personKey ssh.Signer, respond func(string, []byte) []byte) *fakeGateway {
	t.Helper()
	return newFakeGatewayWithServerConfig(t, personKey, respond, nil)
}

func newFakeGatewayWithServerConfig(t *testing.T, personKey ssh.Signer, respond func(string, []byte) []byte, cfgMod func(*ssh.ServerConfig)) *fakeGateway {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fg := &fakeGateway{ln: ln, hostSigner: genSigner(t), personKey: personKey, respond: respond, cfgMod: cfgMod}
	go fg.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return fg
}

func (fg *fakeGateway) acceptLoop() {
	for {
		raw, err := fg.ln.Accept()
		if err != nil {
			return
		}
		go fg.serveConn(raw)
	}
}

func (fg *fakeGateway) serveConn(raw net.Conn) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if fg.personKey != nil && bytes.Equal(key.Marshal(), fg.personKey.PublicKey().Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("fake gateway: unknown key")
		},
	}
	if fg.cfgMod != nil {
		fg.cfgMod(cfg)
	}
	cfg.AddHostKey(fg.hostSigner)
	sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for n := range chans {
		if n.ChannelType() != "session" {
			_ = n.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := n.Accept()
		if err != nil {
			continue
		}
		go fg.serveSession(ch, chReqs)
	}
}

func (fg *fakeGateway) serveSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	req, ok := <-reqs
	if !ok {
		return
	}
	command := ""
	if req.Type == "exec" {
		if e, perr := sshx.ParseExec(req.Payload); perr == nil {
			command = e.Command
		}
	}
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
	go func() {
		for extra := range reqs {
			if extra.WantReply {
				_ = extra.Reply(false, nil)
			}
		}
	}()
	body, _ := io.ReadAll(ch)
	if command == "whoami" && !fg.whoamiToRespond {
		_, _ = ch.Write([]byte(fakeWhoamiV1))
		return
	}
	_, _ = ch.Write(fg.respond(command, body))
}

func dialFake(t *testing.T, fg *fakeGateway, personKey ssh.Signer) *Conn {
	t.Helper()
	c, err := Dial(Peer{Addr: fg.ln.Addr().String(), Fingerprint: fingerprintFor(t, fg.hostSigner.PublicKey())}, "alice", personKey, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// ---- gate 8: no gateway response, however garbled, ever panics -----------

func TestExec_GarbageResponsesNeverPanicAndAlwaysError(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"not json at all", []byte("\x00\x01\x02garbage-not-json\xff\xfe\n")},
		{"truncated mid-object", []byte(`{"proto":1,"caps":[],"ok":true,"result":{"foo"`)},
		{"empty response", []byte("")},
		{"only a newline", []byte("\n")},
		{"oversized response", bytes.Repeat([]byte("a"), 20<<20)},
		{"top-level array instead of object", []byte(`[1,2,3]`)},
		{"proto has the wrong JSON type", []byte(`{"proto":"one","caps":[],"ok":true,"result":{}}`)},
		{"ok true, result is a bare string not an object", []byte(`{"proto":1,"caps":[],"ok":true,"result":"not-an-object"}`)},
		{"ok false with no error object", []byte(`{"proto":1,"caps":[],"ok":false}`)},
		{"ok false with an empty error code", []byte(`{"proto":1,"caps":[],"ok":false,"error":{"code":"","message":"x"}}`)},
		{"two JSON values back to back", []byte(`{"proto":1,"caps":[],"ok":true,"result":{}}{"proto":1,"caps":[],"ok":true,"result":{}}`)},
		{"protocol version this client cannot speak", []byte(`{"proto":2,"caps":[],"ok":true,"result":{}}`)},
		{"deeply nested but well-formed garbage", []byte(nestedJSON(2000))},
		{"unknown fields alongside a valid envelope", []byte(`{"proto":1,"caps":[],"ok":true,"result":{},"totallyUnexpectedField":{"a":[1,2,3]}}`)},
	}
	personKey := genSigner(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fg := newFakeGatewayForWhoami(t, personKey, func(string, []byte) []byte { return tc.raw })
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Exec panicked on input %q: %v", tc.name, r)
					}
				}()
				c := dialFake(t, fg, personKey)
				if _, err := c.Whoami(); err == nil {
					t.Fatalf("%s: want an error, got success", tc.name)
				}
			}()
		})
	}
}

func nestedJSON(depth int) string {
	var b bytes.Buffer
	b.WriteString(`{"proto":1,"caps":[],"ok":true,"result":`)
	for i := 0; i < depth; i++ {
		b.WriteString(`{"a":`)
	}
	b.WriteString(`1`)
	for i := 0; i < depth; i++ {
		b.WriteString(`}`)
	}
	b.WriteString(`}`)
	return b.String()
}

// ---- honest round trips still work ----------------------------------------

func TestExec_WellFormedSuccessRoundTrips(t *testing.T) {
	personKey := genSigner(t)
	fg := newFakeGatewayForWhoami(t, personKey, func(command string, body []byte) []byte {
		if command != "whoami" {
			return []byte(`{"proto":1,"caps":[],"ok":false,"error":{"code":"E_EXEC_UNKNOWN","message":"nope"}}` + "\n")
		}
		return []byte(`{"proto":1,"caps":[],"ok":true,"result":{"subject":"alice","role":"admin","serverTime":"2026-09-12T10:00:00Z","person":"alice"}}` + "\n")
	})
	c := dialFake(t, fg, personKey)
	who, err := c.Whoami()
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if who.Subject != "alice" || who.Role != "admin" {
		t.Fatalf("whoami = %+v, want subject=alice role=admin", who)
	}
}

func TestExec_NamedGatewayErrorSurfacesAsCommandError(t *testing.T) {
	personKey := genSigner(t)
	fg := newFakeGatewayForWhoami(t, personKey, func(string, []byte) []byte {
		return []byte(`{"proto":1,"caps":[],"ok":false,"error":{"code":"E_GRANT_EXPIRED","message":"The grant has expired."}}` + "\n")
	})
	c := dialFake(t, fg, personKey)
	_, err := c.Whoami()
	var cmdErr *CommandError
	if err == nil {
		t.Fatal("want an error")
	}
	if ce, ok := asCommandError(err); ok {
		cmdErr = ce
	} else {
		t.Fatalf("error is not a *CommandError: %v (%T)", err, err)
	}
	if cmdErr.Code != "E_GRANT_EXPIRED" {
		t.Fatalf("code = %q, want E_GRANT_EXPIRED", cmdErr.Code)
	}
}

func asCommandError(err error) (*CommandError, bool) {
	ce, ok := err.(*CommandError)
	return ce, ok
}

// PeopleAdd must send exactly the fields PROTOCOL §6 names, with proto:1,
// and must decode the gateway's own response shape back correctly.
func TestPeopleAdd_RequestShapeAndResponseDecoding(t *testing.T) {
	personKey := genSigner(t)
	var gotReq map[string]any
	fg := newFakeGateway(t, personKey, func(command string, body []byte) []byte {
		if command != "people.add" {
			return []byte(`{"proto":1,"caps":[],"ok":false,"error":{"code":"E_EXEC_UNKNOWN","message":"x"}}` + "\n")
		}
		_ = json.Unmarshal(body, &gotReq)
		return []byte(`{"proto":1,"caps":[],"ok":true,"result":{"name":"bob","role":"user","keys":[{"fingerprint":"SHA256:aaaa","pubkey":"ssh-ed25519 AAAA bob","added":"2026-09-12T10:00:00Z"}]}}` + "\n")
	})
	c := dialFake(t, fg, personKey)
	person, err := c.PeopleAdd("bob", "user", []string{"ssh-ed25519 AAAA bob"})
	if err != nil {
		t.Fatalf("people.add: %v", err)
	}
	if person.Name != "bob" || person.Role != "user" || len(person.Keys) != 1 {
		t.Fatalf("people.add result = %+v", person)
	}
	if gotReq["proto"] != float64(1) || gotReq["name"] != "bob" || gotReq["role"] != "user" {
		t.Fatalf("request sent to gateway was %+v, missing/wrong proto,name,role", gotReq)
	}
}

// ---- host key pinning: SPEC §3.1, no TOFU ---------------------------------

func TestDial_RefusesOnFingerprintMismatch(t *testing.T) {
	personKey := genSigner(t)
	fg := newFakeGateway(t, personKey, func(string, []byte) []byte {
		return []byte(`{"proto":1,"caps":[],"ok":true,"result":{}}` + "\n")
	})
	wrongFP := "SHA256:" + base64.RawStdEncoding.EncodeToString(sha256Sum32([]byte("not-the-real-key")))
	_, err := Dial(Peer{Addr: fg.ln.Addr().String(), Fingerprint: wrongFP}, "alice", personKey, 2*time.Second)
	if err == nil {
		t.Fatal("Dial with a wrong pinned fingerprint: want an error, got success")
	}
}

func TestDial_RefusesWithoutAPinnedFingerprint(t *testing.T) {
	personKey := genSigner(t)
	fg := newFakeGateway(t, personKey, func(string, []byte) []byte { return nil })
	_, err := Dial(Peer{Addr: fg.ln.Addr().String()}, "alice", personKey, 2*time.Second)
	if err == nil {
		t.Fatal("Dial with an empty fingerprint: want a refusal (SPEC §3.1: no TOFU)")
	}
}

func sha256Sum32(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
