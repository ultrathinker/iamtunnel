package gateway

// 1.50 part A: the sftp subsystem through the gateway, parsed read-only,
// journaled, and judged against the goal like an exec command.
//
// The machine side is r150ServeSFTP, a small SFTP v3 server over an
// in-memory file map; the person side is r150SFTPClient, which writes raw
// SFTP packets on the session channel. Both speak the same draft the
// gateway parses, and neither shares code with it beyond sftpwire's
// framer, so a gateway that rewrote a byte would show up as a broken
// answer here.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
	"github.com/ultrathinker/iamtunnel/internal/sshx/sftpwire"
)

// --- wire builders ----------------------------------------------------------

func r150U32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func r150U64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func r150Str(s string) []byte { return append(r150U32(uint32(len(s))), s...) }

// r150Pkt builds one whole SFTP packet: length, type, id, then fields.
func r150Pkt(typ byte, id uint32, fields ...[]byte) []byte {
	body := append([]byte{typ}, r150U32(id)...)
	for _, f := range fields {
		body = append(body, f...)
	}
	return append(r150U32(uint32(len(body))), body...)
}

func r150Init() []byte {
	return append(r150U32(5), append([]byte{sftpwire.TypeInit}, r150U32(3)...)...)
}

func r150Open(id uint32, path string, pflags uint32) []byte {
	return r150Pkt(sftpwire.TypeOpen, id, r150Str(path), r150U32(pflags), r150U32(0))
}

func r150Write(id uint32, handle string, off uint64, data string) []byte {
	return r150Pkt(sftpwire.TypeWrite, id, r150Str(handle), r150U64(off), r150Str(data))
}

func r150Read(id uint32, handle string, off uint64, n uint32) []byte {
	return r150Pkt(sftpwire.TypeRead, id, r150Str(handle), r150U64(off), r150U32(n))
}

func r150Close(id uint32, handle string) []byte {
	return r150Pkt(sftpwire.TypeClose, id, r150Str(handle))
}

func r150Status(id, code uint32, msg string) []byte {
	return r150Pkt(sftpwire.TypeStatus, id, r150U32(code), r150Str(msg), r150Str(""))
}

const r150WriteFlags = sftpwire.FlagWrite | sftpwire.FlagCreat | sftpwire.FlagTrunc

// --- the machine's sftp-server ------------------------------------------------

type r150FS struct {
	mu    sync.Mutex
	files map[string][]byte
	ops   []string
}

func newR150FS() *r150FS { return &r150FS{files: map[string][]byte{}} }

func (fs *r150FS) saw(op string) bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for _, o := range fs.ops {
		if o == op {
			return true
		}
	}
	return false
}

func (fs *r150FS) file(path string) string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return string(fs.files[path])
}

// r150ServeSFTP answers SFTP requests on rw until it closes.
func r150ServeSFTP(rw io.ReadWriter, fs *r150FS) {
	var fr sftpwire.Framer
	handles := map[string]string{}
	next := 0
	buf := make([]byte, 64*1024)
	for {
		n, err := rw.Read(buf)
		pkts, ferr := fr.Feed(buf[:n])
		for _, p := range pkts {
			if _, werr := rw.Write(fs.answer(p, handles, &next)); werr != nil {
				return
			}
		}
		if err != nil || ferr != nil {
			return
		}
	}
}

func (fs *r150FS) answer(p sftpwire.Packet, handles map[string]string, next *int) []byte {
	if p.Type == sftpwire.TypeInit {
		return append(r150U32(5), append([]byte{sftpwire.TypeVersion}, r150U32(3)...)...)
	}
	id, _ := p.ID()
	data := p.Data()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	switch p.Type {
	case sftpwire.TypeOpen:
		req, _ := sftpwire.ParseOpen(data)
		fs.ops = append(fs.ops, "open "+req.Path)
		if _, ok := fs.files[req.Path]; !ok {
			if req.Pflags&sftpwire.FlagCreat == 0 {
				return r150Status(id, sftpwire.StatusNoSuchFile, "no such file")
			}
			fs.files[req.Path] = nil
		}
		if req.Pflags&sftpwire.FlagTrunc != 0 {
			fs.files[req.Path] = nil
		}
		h := "h" + string(rune('0'+*next))
		*next++
		handles[h] = req.Path
		return r150Pkt(sftpwire.TypeHandle, id, r150Str(h))
	case sftpwire.TypeWrite:
		req, _ := sftpwire.ParseWrite(data)
		path := handles[req.Handle]
		f := fs.files[path]
		if end := int(req.Offset) + len(req.Data); end > len(f) {
			f = append(f, make([]byte, end-len(f))...)
		}
		copy(f[req.Offset:], req.Data)
		fs.files[path] = f
		return r150Status(id, sftpwire.StatusOK, "")
	case sftpwire.TypeRead:
		req, _ := sftpwire.ParseRead(data)
		f := fs.files[handles[req.Handle]]
		if int(req.Offset) >= len(f) {
			return r150Status(id, sftpwire.StatusEOF, "eof")
		}
		end := int(req.Offset) + int(req.Length)
		if end > len(f) {
			end = len(f)
		}
		return r150Pkt(sftpwire.TypeData, id, r150Str(string(f[req.Offset:end])))
	case sftpwire.TypeClose:
		req, _ := sftpwire.ParseHandleRequest(data)
		delete(handles, req.Handle)
		return r150Status(id, sftpwire.StatusOK, "")
	case sftpwire.TypeRemove, sftpwire.TypeMkdir, sftpwire.TypeRmdir, sftpwire.TypeSetstat:
		req, _ := sftpwire.ParsePath(data)
		name := map[byte]string{sftpwire.TypeRemove: "remove", sftpwire.TypeMkdir: "mkdir", sftpwire.TypeRmdir: "rmdir", sftpwire.TypeSetstat: "setstat"}[p.Type]
		fs.ops = append(fs.ops, name+" "+req.Path)
		if p.Type == sftpwire.TypeRemove {
			delete(fs.files, req.Path)
		}
		return r150Status(id, sftpwire.StatusOK, "")
	case sftpwire.TypeExtended:
		ext, _ := sftpwire.ParseExtended(data)
		fs.ops = append(fs.ops, "extended "+ext.Name)
		if ext.Name != "copy-data" {
			return r150Status(id, sftpwire.StatusOK, "")
		}
		req, _ := sftpwire.ParseCopyData(ext.Data)
		src := fs.files[handles[req.ReadHandle]]
		fs.files[handles[req.WriteHandle]] = append([]byte(nil), src...)
		return r150Status(id, sftpwire.StatusOK, "")
	default:
		return r150Status(id, sftpwire.StatusOpUnsupported, "unsupported")
	}
}

func r150Extended(id uint32, name string, fields ...[]byte) []byte {
	return r150Pkt(sftpwire.TypeExtended, id, append([][]byte{r150Str(name)}, fields...)...)
}

func r150CopyData(id uint32, src, dst string) []byte {
	return r150Extended(id, "copy-data", r150Str(src), r150U64(0), r150U64(0), r150Str(dst), r150U64(0))
}

// --- the person's client ------------------------------------------------------

// r150SFTPClient reads whole packets from r on its own goroutine, so a
// test can write several requests before it reads a single answer.
type r150SFTPClient struct {
	t    *testing.T
	w    io.Writer
	pkts chan sftpwire.Packet
}

func newR150SFTPClient(t *testing.T, r io.Reader, w io.Writer) *r150SFTPClient {
	c := &r150SFTPClient{t: t, w: w, pkts: make(chan sftpwire.Packet, 64)}
	go func() {
		defer close(c.pkts)
		var fr sftpwire.Framer
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			pkts, ferr := fr.Feed(buf[:n])
			for _, p := range pkts {
				c.pkts <- p
			}
			if err != nil || ferr != nil {
				return
			}
		}
	}()
	return c
}

func (c *r150SFTPClient) send(raw ...[]byte) {
	c.t.Helper()
	var all []byte
	for _, r := range raw {
		all = append(all, r...)
	}
	if _, err := c.w.Write(all); err != nil {
		c.t.Fatalf("sftp client write: %v", err)
	}
}

func (c *r150SFTPClient) recv() sftpwire.Packet {
	c.t.Helper()
	select {
	case p, ok := <-c.pkts:
		if !ok {
			c.t.Fatal("sftp stream ended before the expected answer")
		}
		return p
	case <-time.After(5 * time.Second):
		c.t.Fatal("no sftp answer within 5 s")
	}
	return sftpwire.Packet{}
}

func (c *r150SFTPClient) handle(wantID uint32) string {
	c.t.Helper()
	p := c.recv()
	id, _ := p.ID()
	if p.Type != sftpwire.TypeHandle || id != wantID {
		st, _ := sftpwire.ParseStatus(p.Data())
		c.t.Fatalf("answer to %d = type %d id %d (%+v), want HANDLE", wantID, p.Type, id, st)
	}
	h, err := sftpwire.ParseHandleResponse(p.Data())
	if err != nil {
		c.t.Fatalf("parse handle: %v", err)
	}
	return h.Handle
}

func (c *r150SFTPClient) status(wantID uint32) sftpwire.StatusResponse {
	c.t.Helper()
	p := c.recv()
	id, _ := p.ID()
	if p.Type != sftpwire.TypeStatus || id != wantID {
		c.t.Fatalf("answer to %d = type %d id %d, want STATUS", wantID, p.Type, id)
	}
	st, err := sftpwire.ParseStatus(p.Data())
	if err != nil {
		c.t.Fatalf("parse status: %v", err)
	}
	return st
}

func (c *r150SFTPClient) data(wantID uint32) string {
	c.t.Helper()
	p := c.recv()
	id, _ := p.ID()
	if p.Type != sftpwire.TypeData || id != wantID {
		c.t.Fatalf("answer to %d = type %d id %d, want DATA", wantID, p.Type, id)
	}
	d, err := sftpwire.ParseDataResponse(p.Data())
	if err != nil {
		c.t.Fatalf("parse data: %v", err)
	}
	return string(d.Data)
}

func (c *r150SFTPClient) version() {
	c.t.Helper()
	if p := c.recv(); p.Type != sftpwire.TypeVersion {
		c.t.Fatalf("answer to INIT = type %d, want VERSION", p.Type)
	}
}

// --- journal helpers ----------------------------------------------------------

func r150FileEvents(t *testing.T, f *fixture) []events.Event {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionFile}, Actor: f.person, Object: f.machineID})
	if err != nil {
		t.Fatalf("read session.file: %v", err)
	}
	return evs
}

// r150WaitFileEvent waits for the session.file event whose details match
// op and path and returns the last such.
func r150WaitFileEvent(t *testing.T, f *fixture, op, path string, n int) events.Event {
	t.Helper()
	var got []events.Event
	waitUntil(t, "session.file "+op+" "+path, func() bool {
		got = got[:0]
		for _, ev := range r150FileEvents(t, f) {
			if ev.Details["op"] == op && ev.Details["path"] == path {
				got = append(got, ev)
			}
		}
		return len(got) >= n
	})
	return got[len(got)-1]
}

func r150Sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// --- parser/tracker, driven through sftpTargetStream ------------------------

// pipeStream is net.Pipe's end as a core.Stream.
type r150PipeStream struct{ net.Conn }

func (r150PipeStream) CloseWrite() error { return nil }

// TestR150_SFTPProxyTracksHandlesAndHashes drives the proxy exactly as
// core.Bridge does — requests into Write, answers out of Read — with a
// request split into single bytes, several requests in one Write, and a
// handle whose writes arrive out of order.
func TestR150_SFTPProxyTracksHandlesAndHashes(t *testing.T) {
	f := newFixture(t, nil)
	gwSide, machineSide := net.Pipe()
	defer gwSide.Close()
	defer machineSide.Close()
	fs := newR150FS()
	fs.files["/C:/have.bin"] = []byte("helloworld")
	go r150ServeSFTP(machineSide, fs)

	proxy := newSFTPProxy(f.gw, f.person, f.machineID, "sid-r150", "", nil, nil, nil)
	ts := newSFTPTargetStream(r150PipeStream{gwSide}, proxy)
	defer ts.Close()
	c := newR150SFTPClient(t, ts, ts)

	// INIT one byte per Write: nothing may reach the machine until the
	// packet is whole, and the answer must still come back.
	for _, b := range r150Init() {
		c.send([]byte{b})
	}
	c.version()

	// Sequential upload, the two WRITEs in one Write call.
	c.send(r150Open(1, "/C:/up.bin", r150WriteFlags))
	h := c.handle(1)
	c.send(r150Write(2, h, 0, "hello"), r150Write(3, h, 5, "world"))
	c.status(2)
	c.status(3)
	c.send(r150Close(4, h))
	c.status(4)
	up := r150WaitFileEvent(t, f, "open", "/C:/up.bin", 1)
	if up.Details["direction"] != "upload" || up.Details["sha256"] != r150Sha("helloworld") || up.Details["size"] != float64(10) || up.Result != "ok" {
		t.Fatalf("sequential upload journaled as %+v, want upload/10/sha256(helloworld)/ok", up.Details)
	}
	if fs.file("/C:/up.bin") != "helloworld" {
		t.Fatalf("machine received %q, want helloworld — the proxy changed bytes", fs.file("/C:/up.bin"))
	}

	// Out-of-order upload: size is still right, the hash is not claimed.
	c.send(r150Open(5, "/C:/scatter.bin", r150WriteFlags))
	h = c.handle(5)
	c.send(r150Write(6, h, 5, "world"), r150Write(7, h, 0, "hello"), r150Close(8, h))
	c.status(6)
	c.status(7)
	c.status(8)
	scatter := r150WaitFileEvent(t, f, "open", "/C:/scatter.bin", 1)
	if scatter.Details["sha256"] != "non-sequential" || scatter.Details["size"] != float64(10) {
		t.Fatalf("out-of-order upload journaled as %+v, want non-sequential/10", scatter.Details)
	}

	// Download: the handle the machine minted for a read-only OPEN is tied
	// back to its path, and the DATA answers are hashed in order.
	c.send(r150Open(9, "/C:/have.bin", sftpwire.FlagRead))
	h = c.handle(9)
	c.send(r150Read(10, h, 0, 4), r150Read(11, h, 4, 100), r150Read(12, h, 10, 100))
	if got := c.data(10) + c.data(11); got != "helloworld" {
		t.Fatalf("download read %q", got)
	}
	if st := c.status(12); st.Code != sftpwire.StatusEOF {
		t.Fatalf("read past end = %+v, want EOF", st)
	}
	c.send(r150Close(13, h))
	c.status(13)
	down := r150WaitFileEvent(t, f, "open", "/C:/have.bin", 1)
	if down.Details["direction"] != "download" || down.Details["sha256"] != r150Sha("helloworld") || down.Details["size"] != float64(10) {
		t.Fatalf("download journaled as %+v, want download/10/sha256(helloworld)", down.Details)
	}

	// A removal is journaled with the machine's outcome.
	c.send(r150Pkt(sftpwire.TypeRemove, 14, r150Str("/C:/up.bin")))
	c.status(14)
	if rm := r150WaitFileEvent(t, f, "remove", "/C:/up.bin", 1); rm.Details["outcome"] != "ok" {
		t.Fatalf("remove journaled as %+v", rm.Details)
	}
}

// --- end to end through the gateway -----------------------------------------

// r150Classifier is an external classifier double: red for any action
// containing redFor, green otherwise; every text it is asked about is kept.
type r150Classifier struct {
	redFor string
	mu     sync.Mutex
	seen   []string
}

func (c *r150Classifier) Classify(_ context.Context, command string) (risk.ExternalAssessment, error) {
	c.mu.Lock()
	c.seen = append(c.seen, command)
	c.mu.Unlock()
	if c.redFor != "" && strings.Contains(command, c.redFor) {
		return risk.ExternalAssessment{Scores: map[string]float64{"destroys": 0.99, "access": 0.99}}, nil
	}
	return risk.ExternalAssessment{Scores: map[string]float64{"destroys": 0.01, "access": 0.01}}, nil
}

func (c *r150Classifier) saw(sub string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.seen {
		if strings.Contains(s, sub) {
			return s, true
		}
	}
	return "", false
}

// r150OpenSFTP starts the sftp subsystem as the fixture person and returns
// the client speaking on it.
func r150OpenSFTP(t *testing.T, f *fixture) (*ssh.Client, *humanSession, *r150SFTPClient) {
	t.Helper()
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("subsystem", true, sshx.MarshalSubsystem(sshx.Subsystem{Name: "sftp"}))
	if err != nil || !ok {
		_ = client.Close()
		t.Fatalf("subsystem sftp: ok=%v err=%v", ok, err)
	}
	c := newR150SFTPClient(t, hs.ch, hs.ch)
	c.send(r150Init())
	c.version()
	return client, hs, c
}

func r150SFTPFixture(t *testing.T, action RiskAction, redFor string) (*fixture, *r150FS, *r150Classifier) {
	t.Helper()
	stub := &r150Classifier{redFor: redFor}
	f := iamt354EnabledFixture(t, stub, func(c *Config) { c.RiskAction = action })
	fs := newR150FS()
	f.sshd.setOnSubsystemImmediate(func(ch ssh.Channel, name string) {
		if name == "sftp" {
			r150ServeSFTP(ch, fs)
		}
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	return f, fs, stub
}

func TestR150_SFTPAskRefusesThenApprovalPassesOnce(t *testing.T) {
	f, fs, stub := r150SFTPFixture(t, RiskActionAsk, "sftp: write /C:/TEST111/car.jpg")
	client, hs, c := r150OpenSFTP(t, f)
	defer client.Close()
	const path = "/C:/TEST111/car.jpg"

	c.send(r150Open(1, path, r150WriteFlags))
	st := c.status(1)
	if st.Code != sftpwire.StatusPermissionDenied || !strings.Contains(st.Message, "E_APPROVAL_REQUIRED") {
		t.Fatalf("held OPEN answered %+v, want PERMISSION_DENIED with E_APPROVAL_REQUIRED", st)
	}
	id := iamt394ApprovalID(st.Message)
	if id == "" || !riskApprovalIDValid(id) {
		t.Fatalf("held OPEN message has no valid approval-id: %q", st.Message)
	}
	if fs.saw("open " + path) {
		t.Fatal("the held OPEN reached the machine")
	}
	if _, ok := stub.saw("sftp: write " + path); !ok {
		t.Fatalf("classifier never saw the action text; it saw %q", stub.seen)
	}
	// OpenSSH's clients print only "Permission denied" from a status; the
	// same sentence therefore goes to stderr, where ssh shows it.
	if stderr := readUntil(t, hs.ch.Stderr(), "E_APPROVAL_REQUIRED"); !strings.Contains(stderr, "approval-id="+id) {
		t.Fatalf("stderr = %q, want the approval sentence with approval-id=%s", stderr, id)
	}
	if denied := r150WaitFileEvent(t, f, "open", path, 1); denied.Result != "denied" {
		t.Fatalf("refused OPEN journaled as %+v, want denied", denied)
	}

	// The session is still open: an unjudged request goes through.
	c.send(r150Pkt(sftpwire.TypeMkdir, 2, r150Str("/C:/TEST111/sub"), r150U32(0)))
	if st := c.status(2); st.Code != sftpwire.StatusOK || !fs.saw("mkdir /C:/TEST111/sub") {
		t.Fatalf("mkdir after a refusal = %+v (machine saw it: %v), want the session still working", st, fs.saw("mkdir /C:/TEST111/sub"))
	}

	iamt394Approve(t, f, f.person, id)

	// The same action again, now let through once — in a new session, the
	// way re-running scp would do it.
	client2, _, c2 := r150OpenSFTP(t, f)
	defer client2.Close()
	c2.send(r150Open(1, path, r150WriteFlags))
	h := c2.handle(1)
	c2.send(r150Write(2, h, 0, "JPEG"), r150Close(3, h))
	c2.status(2)
	c2.status(3)
	if fs.file(path) != "JPEG" {
		t.Fatalf("approved upload stored %q, want JPEG", fs.file(path))
	}
	ok := r150WaitFileEvent(t, f, "open", path, 2)
	if ok.Result != "ok" || ok.Details["sha256"] != r150Sha("JPEG") {
		t.Fatalf("approved upload journaled as %+v", ok)
	}

	// Once: the approval is spent.
	c2.send(r150Open(4, path, r150WriteFlags))
	if st := c2.status(4); st.Code != sftpwire.StatusPermissionDenied || iamt394ApprovalID(st.Message) == id {
		t.Fatalf("second OPEN after one approval = %+v, want a fresh refusal", st)
	}
}

func TestR150_SFTPLogModeLetsRedThroughAndJournals(t *testing.T) {
	f, fs, _ := r150SFTPFixture(t, RiskActionLog, "sftp: remove")
	client, _, c := r150OpenSFTP(t, f)
	defer client.Close()

	fs.mu.Lock()
	fs.files["/C:/x/y.txt"] = []byte("y")
	fs.mu.Unlock()
	c.send(r150Pkt(sftpwire.TypeRemove, 1, r150Str("/C:/x/y.txt")))
	if st := c.status(1); st.Code != sftpwire.StatusOK {
		t.Fatalf("red remove under log = %+v, want the machine's OK", st)
	}
	if !fs.saw("remove /C:/x/y.txt") {
		t.Fatal("red remove under log did not reach the machine")
	}
	riskEv := iamt353RiskEvent(t, f)
	if riskEv.Result != "red" || riskEv.Details["action"] != "log" || riskEv.Details["command"] != "sftp: remove /C:/x/y.txt" || riskEv.Details["subsystem"] != "sftp" {
		t.Fatalf("session.risk = %+v, want red/log for the sftp action", riskEv)
	}
	if ev := r150WaitFileEvent(t, f, "remove", "/C:/x/y.txt", 1); ev.Result != "ok" {
		t.Fatalf("session.file = %+v, want ok", ev)
	}
}

// Any other subsystem stays refused with its named code.
func TestR150_OtherSubsystemStaysRefused(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("subsystem", true, sshx.MarshalSubsystem(sshx.Subsystem{Name: "netconf"}))
	if err != nil || ok {
		t.Fatalf("subsystem netconf: ok=%v err=%v, want a refusal", ok, err)
	}
}

// A machine without an sftp-server refuses the subsystem. The person gets
// that refusal as an ordinary failure reply, and the channel stays usable:
// an exec on the same channel still runs (fixup round 1, the regression
// e2e scenario 18 caught — the refusal used to end the whole session).
func TestR150_SFTPRefusedByMachineKeepsChannelUsable(t *testing.T) {
	f := newFixture(t, nil)
	execSeen := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- struct{}{}
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("subsystem", true, sshx.MarshalSubsystem(sshx.Subsystem{Name: "sftp"}))
	if err != nil || ok {
		t.Fatalf("sftp refused by the machine: ok=%v err=%v, want a failure reply on a live channel", ok, err)
	}
	ok, err = hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "echo after-sftp"}))
	if err != nil || !ok {
		t.Fatalf("exec after a refused sftp: ok=%v err=%v", ok, err)
	}
	select {
	case <-execSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("exec after a refused sftp never reached the machine")
	}
}
