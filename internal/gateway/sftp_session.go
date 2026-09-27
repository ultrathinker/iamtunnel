package gateway

// sftp_session.go: the 1.50 SFTP subsystem proxy (part A of "files and
// stdin without prohibitions").
//
// The gateway bridges the sftp subsystem channel exactly like an exec
// channel — see serveHumanSession's isSFTP branch — except the target
// side of core.Bridge is wrapped in sftpTargetStream, which parses the
// SFTP v3 wire stream (draft-ietf-secsh-filexfer-02) in both directions
// without ever rewriting a byte on the success path:
//
//   - a mutating request (a write-intent OPEN, REMOVE, RENAME, RMDIR,
//     SETSTAT/FSETSTAT, and the OpenSSH extensions and SYMLINK that do the
//     same things by another name) is judged against the session's goal
//     the same way an exec command is judged, before it is forwarded —
//     see judge, which runs Gateway.judgeRisk, the exec barrier's own code;
//   - every other request/response is only observed, to track a
//     handle's path, direction and running size/hash, and to notice when
//     an operation completes so it can be journaled (journalFile).
//
// A refused request never reaches the machine: the proxy answers it
// itself with a synthetic SSH_FXP_STATUS carrying SSH_FX_PERMISSION_DENIED
// and the same approval/blocked sentence exec prints. OpenSSH's sftp and
// scp clients print only the status code's own text ("Permission denied"),
// never the server's message, so the same sentence also goes to the
// channel's stderr — where ssh shows it to the agent, as it already shows
// the "This session is recorded" banner. The session itself stays open —
// only that one request is refused.
//
// Packets are forwarded whole, in the order they arrived, in both
// directions. The machine->person direction runs through one pump
// goroutine and one channel, which is also the path a refusal takes: a
// synthetic STATUS can therefore never land in the middle of a packet the
// machine is still sending, and it never waits for the machine to say
// something first.
import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/sshx/sftpwire"
)

// sftpHandle is what the proxy knows about one handle the server has
// minted: the path its OPEN named, and the running byte count and hash
// for whichever direction moves data through it (WRITE packets for an
// upload, DATA answers to READ for a download).
type sftpHandle struct {
	path       string
	direction  string // "upload" or "download"
	moved      bool   // a byte (or an empty WRITE/DATA) moved through it
	size       int64
	hasher     hash.Hash
	sequential bool
	nextOffset uint64
	// copied is set once copy-data wrote into this handle on the machine:
	// those bytes never crossed the gateway, so neither the file's size
	// nor its hash is known here.
	copied bool
}

// newSFTPHandle starts a handle's tracking. Its direction is the OPEN's
// intent until a byte actually moves: an upload of an empty file writes
// nothing, and is still an upload.
func newSFTPHandle(path string, pflags uint32) *sftpHandle {
	dir := "download"
	if (sftpwire.OpenRequest{Pflags: pflags}).Mutating() {
		dir = "upload"
	}
	return &sftpHandle{path: path, direction: dir, hasher: sha256.New(), sequential: true}
}

// observe folds one WRITE (direction "upload") or one READ's DATA answer
// (direction "download") into the handle's running total: size grows to
// the furthest byte touched regardless of order, and the hash keeps going
// only while every chunk so far has arrived in sequence from offset 0 —
// the moment one does not, sequential turns false for good and sha
// reports "non-sequential" instead of a hash that would cover only part
// of the file.
func (h *sftpHandle) observe(direction string, offset uint64, data []byte) {
	if !h.moved {
		h.moved = true
		h.direction = direction
	}
	if end := int64(offset) + int64(len(data)); end > h.size {
		h.size = end
	}
	if !h.sequential {
		return
	}
	if offset != h.nextOffset || direction != h.direction {
		h.sequential = false
		return
	}
	h.hasher.Write(data)
	h.nextOffset += uint64(len(data))
}

func (h *sftpHandle) sha() string {
	if h.copied {
		return "not computed: written by copy-data"
	}
	if !h.sequential {
		return "non-sequential"
	}
	return hex.EncodeToString(h.hasher.Sum(nil))
}

// sftpPending is what the proxy remembers about one request it forwarded,
// keyed by the request's SFTP id, so the matching HANDLE/DATA/STATUS
// answer can be interpreted and journaled.
type sftpPending struct {
	op      string // "open", "close", "read", "remove", "rename", "mkdir", "rmdir", "setstat", "fsetstat", "hardlink", "symlink"
	path    string
	newPath string
	pflags  uint32
	handle  string // close/fsetstat/read: the handle named
	offset  uint64 // read: the offset this request's DATA answer starts at
	// copyLength is copy-data's requested length; 0 means "to the end of
	// the source", a byte count the gateway does not learn.
	copyLength uint64
	// extended marks a request sent as SSH_FXP_EXTENDED, which may be
	// answered by SSH_FXP_EXTENDED_REPLY instead of a STATUS.
	extended bool
}

// errSFTPFraming ends an sftp session whose byte stream stopped being a
// sequence of SFTP packets. Forwarding the rest raw would let every later
// request past the judgement unseen, and OpenSSH's sftp-server itself
// gives up on the same input, so the session ends here instead, with this
// text as session.drop's result.
var errSFTPFraming = errors.New("sftp stream is not valid SFTP framing")

// sftpProxy is one subsystem channel's worth of SFTP state: parsing,
// judgement and journaling. mu guards the maps and history, because the
// client->server path (core.Bridge's human->target copy, in Write) and
// the server->client pump run on different goroutines.
type sftpProxy struct {
	g         *Gateway
	person    string
	machine   string
	sessionID string
	goal      string
	rec       *record.ExecRecorder
	// notices is where a refusal's sentence is written for the person to
	// read (the channel's stderr, through the recording). nil writes none.
	notices io.Writer

	mu      sync.Mutex
	history []risk.RecentCommandContext
	handles map[string]*sftpHandle
	pending map[uint32]*sftpPending

	in       sftpwire.Framer // client->server; only Write touches it
	readRest []byte          // the unread tail of the last packet; only Read touches it

	// toHuman carries whole packets to Read, from the pump (the machine's
	// answers) and from Write (synthetic refusals).
	toHuman  chan []byte
	pumpDone chan struct{} // closed once the pump has stopped; readErr is then set
	readErr  error
	stopped  chan struct{}
	stopOnce sync.Once
}

func newSFTPProxy(g *Gateway, person, machine, sessionID, goal string, history []risk.RecentCommandContext, rec *record.ExecRecorder, notices io.Writer) *sftpProxy {
	return &sftpProxy{
		g: g, person: person, machine: machine, sessionID: sessionID, goal: goal, rec: rec, notices: notices,
		history:  append([]risk.RecentCommandContext(nil), history...),
		handles:  make(map[string]*sftpHandle),
		pending:  make(map[uint32]*sftpPending),
		toHuman:  make(chan []byte),
		pumpDone: make(chan struct{}),
		stopped:  make(chan struct{}),
	}
}

// stop releases the pump and any refusal waiting to be read, once nobody
// will read from this proxy again. Safe to call more than once.
func (p *sftpProxy) stop() {
	p.stopOnce.Do(func() { close(p.stopped) })
}

// sendToHuman hands one whole packet to Read. It gives up (false) once
// the proxy is stopped.
func (p *sftpProxy) sendToHuman(pkt []byte) bool {
	select {
	case p.toHuman <- pkt:
		return true
	case <-p.stopped:
		return false
	}
}

// sftpTargetStream is the target side of core.Bridge for an sftp
// subsystem session: Write (person -> machine) judges and may refuse;
// Read (machine -> person) only observes. Close also stops the proxy, so
// a bridge that ends on an error does not leave the pump behind.
type sftpTargetStream struct {
	core.Stream
	p *sftpProxy
}

// newSFTPTargetStream wraps target and starts the pump that reads it.
func newSFTPTargetStream(target core.Stream, p *sftpProxy) sftpTargetStream {
	go p.pump(target)
	return sftpTargetStream{Stream: target, p: p}
}

func (s sftpTargetStream) Close() error {
	s.p.stop()
	return s.Stream.Close()
}

func (s sftpTargetStream) Write(b []byte) (int, error) {
	packets, err := s.p.in.Feed(b)
	for _, pkt := range packets {
		forward, reply, jerr := s.p.handleClientPacket(pkt)
		if jerr != nil {
			return 0, jerr
		}
		if !forward {
			if !s.p.sendToHuman(reply) {
				return 0, io.ErrClosedPipe
			}
			continue
		}
		if _, werr := s.Stream.Write(pkt.Raw); werr != nil {
			return 0, werr
		}
	}
	if err != nil {
		return 0, fmt.Errorf("%w (from the person): %v", errSFTPFraming, err)
	}
	return len(b), nil
}

func (s sftpTargetStream) Read(b []byte) (int, error) {
	// A packet may be larger than the caller's buffer (Bridge reads 32 KiB
	// at a time): the rest is handed out by the next Read, before any
	// other packet, so packets never interleave.
	if len(s.p.readRest) > 0 {
		n := copy(b, s.p.readRest)
		s.p.readRest = s.p.readRest[n:]
		return n, nil
	}
	select {
	case pkt := <-s.p.toHuman:
		n := copy(b, pkt)
		s.p.readRest = pkt[n:]
		return n, nil
	case <-s.p.pumpDone:
		return 0, s.p.readErr
	}
}

// pump reads the machine's side, splits it into packets, lets the proxy
// observe each, and hands it on whole. On the machine's EOF, bytes of an
// unfinished packet still go through as they are — nothing is dropped —
// and Read then reports the EOF.
func (p *sftpProxy) pump(target io.Reader) {
	var out sftpwire.Framer
	defer close(p.pumpDone)
	defer func() {
		if r := recover(); r != nil {
			p.readErr = fmt.Errorf("sftp proxy panicked: %v", r)
		}
	}()
	buf := make([]byte, 32*1024)
	for {
		n, err := target.Read(buf)
		if n > 0 {
			packets, ferr := out.Feed(buf[:n])
			for _, pkt := range packets {
				if jerr := p.handleServerPacket(pkt); jerr != nil {
					p.readErr = jerr
					return
				}
				if !p.sendToHuman(pkt.Raw) {
					p.readErr = io.ErrClosedPipe
					return
				}
			}
			if ferr != nil {
				p.readErr = fmt.Errorf("%w (from the machine): %v", errSFTPFraming, ferr)
				return
			}
		}
		if err != nil {
			if rest := out.Pending(); len(rest) > 0 {
				if !p.sendToHuman(rest) {
					err = io.ErrClosedPipe
				}
			}
			p.readErr = err
			return
		}
	}
}

// sftpBridgeRecording is the core.Recording core.Bridge sees for an sftp
// session: Close/Abort forward to the real recorder (a bridging fault
// must still abort it, exactly as any other session does), but Write and
// AddBytesIn record nothing. The raw SFTP wire bytes are not content —
// journalFile's structured per-operation entries (ExecRecorder.SFTPFile)
// are the record here; AddBytesIn would otherwise write the entire binary
// request stream into the JSONL as "stdin" chunks.
type sftpBridgeRecording struct{ real core.Recording }

func (s sftpBridgeRecording) Write(p []byte) (int, error) { return len(p), nil }
func (s sftpBridgeRecording) Close() error                { return s.real.Close() }
func (s sftpBridgeRecording) Abort(reason string) error   { return s.real.Abort(reason) }
func (s sftpBridgeRecording) AddBytesIn(p []byte)         {}

// sftpJudged is one mutating request as the classifier will see it.
type sftpJudged struct {
	pend   *sftpPending
	action string // the text the classifier judges, e.g. "sftp: write C:/x"
}

// handleClientPacket decides one client->server packet's fate: forward it
// raw (true), or answer it here (false, with a complete SSH_FXP_STATUS
// packet in reply). A non-nil error ends the session: the refusal could
// not be recorded.
func (p *sftpProxy) handleClientPacket(pkt sftpwire.Packet) (forward bool, reply []byte, err error) {
	id, hasID := pkt.ID()
	if !hasID || pkt.Type == sftpwire.TypeInit {
		return true, nil, nil
	}
	// Every forwarded request holds its id until the machine answers it.
	// A client reusing an id that is still outstanding would make two
	// requests share one answer and one journal line, so the session ends
	// here, before the second request is forwarded (fixup round 1, V-05).
	if err := p.reserve(id); err != nil {
		return false, nil, err
	}
	forward, reply, err = p.decideClientPacket(pkt, id)
	if !forward || err != nil {
		p.release(id)
	}
	return forward, reply, err
}

// decideClientPacket is handleClientPacket once the id is reserved.
func (p *sftpProxy) decideClientPacket(pkt sftpwire.Packet, id uint32) (forward bool, reply []byte, err error) {
	data := pkt.Data()
	var judged *sftpJudged
	var parseErr error
	switch pkt.Type {
	case sftpwire.TypeOpen:
		req, err := sftpwire.ParseOpen(data)
		if err != nil {
			parseErr = err
			break
		}
		pend := &sftpPending{op: "open", path: req.Path, pflags: req.Pflags}
		if !req.Mutating() {
			p.setPending(id, pend)
			return true, nil, nil
		}
		judged = &sftpJudged{pend: pend, action: "sftp: write " + req.Path}

	case sftpwire.TypeClose:
		if req, err := sftpwire.ParseHandleRequest(data); err == nil {
			p.setPending(id, &sftpPending{op: "close", handle: req.Handle})
		}
		return true, nil, nil

	case sftpwire.TypeRead:
		if req, err := sftpwire.ParseRead(data); err == nil {
			p.setPending(id, &sftpPending{op: "read", handle: req.Handle, offset: req.Offset})
		}
		return true, nil, nil

	case sftpwire.TypeWrite:
		if req, err := sftpwire.ParseWrite(data); err == nil {
			p.mu.Lock()
			if h, ok := p.handles[req.Handle]; ok {
				h.observe("upload", req.Offset, req.Data)
			}
			p.mu.Unlock()
		}
		return true, nil, nil

	case sftpwire.TypeRemove, sftpwire.TypeRmdir, sftpwire.TypeSetstat, sftpwire.TypeMkdir:
		req, err := sftpwire.ParsePath(data)
		if err != nil {
			parseErr = err
			break
		}
		op := map[byte]string{sftpwire.TypeRemove: "remove", sftpwire.TypeRmdir: "rmdir", sftpwire.TypeSetstat: "setstat", sftpwire.TypeMkdir: "mkdir"}[pkt.Type]
		judged = &sftpJudged{pend: &sftpPending{op: op, path: req.Path}, action: "sftp: " + op + " " + req.Path}

	case sftpwire.TypeFsetstat:
		req, err := sftpwire.ParseHandleRequest(data)
		if err != nil {
			parseErr = err
			break
		}
		path := p.handlePath(req.Handle)
		judged = &sftpJudged{pend: &sftpPending{op: "fsetstat", path: path, handle: req.Handle}, action: "sftp: setstat " + path}

	case sftpwire.TypeRename:
		req, err := sftpwire.ParseRename(data)
		if err != nil {
			parseErr = err
			break
		}
		judged = &sftpJudged{pend: &sftpPending{op: "rename", path: req.OldPath, newPath: req.NewPath},
			action: "sftp: rename " + req.OldPath + " -> " + req.NewPath}

	case sftpwire.TypeSymlink:
		req, err := sftpwire.ParseTwoPaths(data)
		if err != nil {
			parseErr = err
			break
		}
		judged = &sftpJudged{pend: &sftpPending{op: "symlink", path: req.First, newPath: req.Second},
			action: "sftp: symlink " + req.First + " " + req.Second}

	case sftpwire.TypeExtended:
		// OpenSSH's own sftp client renames through posix-rename when the
		// server offers it, and sets attributes on a link through lsetstat:
		// the same operations under another name, judged the same way.
		ext, err := sftpwire.ParseExtended(data)
		if err != nil {
			parseErr = err
			break
		}
		switch ext.Name {
		case "posix-rename@openssh.com", "hardlink@openssh.com":
			req, err := sftpwire.ParseTwoPaths(ext.Data)
			if err != nil {
				parseErr = err
				break
			}
			op, verb := "rename", "rename "+req.First+" -> "+req.Second
			if ext.Name == "hardlink@openssh.com" {
				op, verb = "hardlink", "hardlink "+req.First+" -> "+req.Second
			}
			judged = &sftpJudged{pend: &sftpPending{op: op, path: req.First, newPath: req.Second}, action: "sftp: " + verb}
		case "lsetstat@openssh.com":
			req, err := sftpwire.ParsePath(ext.Data)
			if err != nil {
				parseErr = err
				break
			}
			judged = &sftpJudged{pend: &sftpPending{op: "setstat", path: req.Path}, action: "sftp: setstat " + req.Path}
		case "copy-data":
			// Copies bytes between two open handles on the machine: the
			// destination file changes without a WRITE ever crossing the
			// gateway (fixup round 1, V-04).
			req, err := sftpwire.ParseCopyData(ext.Data)
			if err != nil {
				parseErr = err
				break
			}
			src, dst := p.handlePath(req.ReadHandle), p.handlePath(req.WriteHandle)
			judged = &sftpJudged{pend: &sftpPending{op: "copy", path: src, newPath: dst, handle: req.WriteHandle, copyLength: req.Length},
				action: "sftp: copy " + src + " -> " + dst}
		case "statvfs@openssh.com", "fstatvfs@openssh.com", "limits@openssh.com", "expand-path@openssh.com",
			"home-directory", "users-groups-by-id@openssh.com":
			// Read-only: they report on the machine and change nothing.
			return true, nil, nil
		default:
			// An extension this gateway has not reviewed may write: it is
			// judged by name before it is forwarded, never passed silently.
			judged = &sftpJudged{pend: &sftpPending{op: "extension", path: ext.Name}, action: "sftp: extension " + ext.Name}
		}

	default:
		return true, nil, nil
	}

	if judged != nil && pkt.Type == sftpwire.TypeExtended {
		judged.pend.extended = true
	}
	if parseErr != nil {
		// A request of a judged kind that does not parse is not forwarded
		// unjudged: the machine might read it differently than this parser
		// did. It is answered as the malformed message it is.
		return false, sftpwire.MarshalStatus(id, sftpwire.StatusBadMessage, "iamtunnel: malformed request: "+parseErr.Error()), nil
	}
	allow, message, outcome := p.judge(judged.action)
	if !allow {
		if err := p.journalFile(judged.pend.op, directionOf(judged.pend), judged.pend.path, judged.pend.newPath, -1, "", outcome); err != nil {
			return false, nil, err
		}
		if p.notices != nil {
			if _, err := p.notices.Write([]byte(message)); err != nil {
				return false, nil, err
			}
		}
		return false, sftpwire.MarshalStatus(id, sftpwire.StatusPermissionDenied, message), nil
	}
	p.setPending(id, judged.pend)
	return true, nil, nil
}

// directionOf names the transfer direction of a refused OPEN (always an
// upload: only a write-intent OPEN is judged) and none for anything else.
func directionOf(pend *sftpPending) string {
	if pend.op == "open" {
		return "upload"
	}
	return ""
}

// setPending records what a reserved id was forwarded for.
func (p *sftpProxy) setPending(id uint32, pend *sftpPending) {
	p.mu.Lock()
	p.pending[id] = pend
	p.mu.Unlock()
}

// errSFTPDuplicateID ends a session whose client reused an outstanding
// request id.
var errSFTPDuplicateID = errors.New("sftp request id reused while the earlier request with it was still outstanding")

// reserve claims id for a request about to be decided. It fails, and
// changes nothing, when the id is already outstanding.
func (p *sftpProxy) reserve(id uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, busy := p.pending[id]; busy {
		return fmt.Errorf("%w (id %d)", errSFTPDuplicateID, id)
	}
	p.pending[id] = &sftpPending{op: "other"}
	return nil
}

// release frees an id the gateway answered itself.
func (p *sftpProxy) release(id uint32) {
	p.mu.Lock()
	delete(p.pending, id)
	p.mu.Unlock()
}

// handlePath is the path a handle was opened with, or "handle:<raw>" when
// the proxy never saw that handle minted.
func (p *sftpProxy) handlePath(handle string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if h, ok := p.handles[handle]; ok {
		return h.path
	}
	return "handle:" + handle
}

// judge runs action through the exec barrier's own decision
// (Gateway.judgeRisk: classifier, goal, history, risk_action, approvals,
// session.risk) and folds it into the recent-command history — both the
// pair's persistent buffer and this session's own copy, so a later
// request in the same session is judged with this one in context.
//
// allow is false exactly when exec would not have run the command. For a
// refusal, message is the sentence exec prints and outcome the short form
// the journal and recording carry. log and warn let the request through
// without a word on the wire: SFTP has no stderr of its own to warn on,
// and session.risk already carries the classification.
func (p *sftpProxy) judge(action string) (allow bool, message, outcome string) {
	p.mu.Lock()
	history := append([]risk.RecentCommandContext(nil), p.history...)
	p.mu.Unlock()

	d := p.g.judgeRisk(p.sessionID, p.person, p.machine, action, action, p.goal, history, nil, map[string]interface{}{"subsystem": "sftp"})
	allow = !d.refused()
	exit := "ok"
	if !allow {
		message = string(d.notice(false))
		exit = "denied"
		switch {
		case d.failureStops:
			outcome = "denied: " + riskClassifierFailureCode
		case d.action == RiskActionAsk:
			outcome = "denied: E_APPROVAL_REQUIRED approval-id=" + d.approvalID // errdict:internal
		default:
			outcome = "denied: E_COMMAND_BLOCKED" // errdict:internal
		}
	}
	p.g.recordRecentCommand(p.person, p.machine, action, exit, "")
	p.mu.Lock()
	// pairRecentCommandHistory hands entries out newest first.
	p.history = append([]risk.RecentCommandContext{{Command: risk.ScrubCommand(action), Exit: exit}}, p.history...)
	p.mu.Unlock()
	return allow, message, outcome
}

// handleServerPacket observes one server->client answer: it correlates
// HANDLE/DATA/STATUS with the pending request of the same id, updates
// handle state, and journals a completed operation once one is known.
func (p *sftpProxy) handleServerPacket(pkt sftpwire.Packet) error {
	id, ok := pkt.ID()
	if !ok || pkt.Type == sftpwire.TypeVersion {
		return nil
	}
	p.mu.Lock()
	pend, ok := p.pending[id]
	if ok {
		delete(p.pending, id)
	}
	p.mu.Unlock()
	if !ok {
		return nil
	}

	switch pkt.Type {
	case sftpwire.TypeHandle:
		if pend.op != "open" {
			return nil
		}
		resp, err := sftpwire.ParseHandleResponse(pkt.Data())
		if err != nil {
			return nil
		}
		p.mu.Lock()
		p.handles[resp.Handle] = newSFTPHandle(pend.path, pend.pflags)
		p.mu.Unlock()

	case sftpwire.TypeData:
		if pend.op != "read" {
			return nil
		}
		resp, err := sftpwire.ParseDataResponse(pkt.Data())
		if err != nil {
			return nil
		}
		p.mu.Lock()
		if h, ok := p.handles[pend.handle]; ok {
			h.observe("download", pend.offset, resp.Data)
		}
		p.mu.Unlock()

	case sftpwire.TypeStatus:
		status, err := sftpwire.ParseStatus(pkt.Data())
		if err != nil {
			return nil
		}
		return p.finishOp(pend, status)

	case sftpwire.TypeExtendedReply:
		// draft-02 §8: an extended request may be answered with
		// SSH_FXP_EXTENDED_REPLY and extension-specific data instead of a
		// STATUS. That is a successful end of the operation, and it is
		// journaled like one (fixup round 2, V-10).
		if pend.extended {
			return p.finishOp(pend, sftpwire.StatusResponse{Code: sftpwire.StatusOK})
		}
	}
	return nil
}

// finishOp turns one resolved request into the journal/recording entry a
// completed file operation gets. A READ's own STATUS (routinely just EOF)
// is not an operation: a transfer is journaled once, at its CLOSE, from
// the handle's accumulated total.
func (p *sftpProxy) finishOp(pend *sftpPending, status sftpwire.StatusResponse) error {
	outcome := "ok"
	if status.Code != sftpwire.StatusOK {
		outcome = fmt.Sprintf("status %d: %s", status.Code, status.Message)
	}
	switch pend.op {
	case "open":
		// The machine refused an OPEN the gateway let through (no such
		// file, access denied, ...): no handle, nothing moved, one line.
		dir := "download"
		if (sftpwire.OpenRequest{Pflags: pend.pflags}).Mutating() {
			dir = "upload"
		}
		return p.journalFile("open", dir, pend.path, "", -1, "", outcome)
	case "close":
		p.mu.Lock()
		h, ok := p.handles[pend.handle]
		if ok {
			delete(p.handles, pend.handle)
		}
		p.mu.Unlock()
		if !ok {
			return nil
		}
		size := h.size
		if h.copied {
			size = -1
		}
		return p.journalFile("open", h.direction, h.path, "", size, h.sha(), outcome)
	case "copy":
		p.mu.Lock()
		if h, ok := p.handles[pend.handle]; ok && status.Code == sftpwire.StatusOK {
			h.copied = true
			h.direction = "upload"
		}
		p.mu.Unlock()
		// The machine does not say how many bytes it copied: the source
		// may be shorter than the length asked for. So no size is claimed;
		// the journal carries the request as it was made.
		requested := "to the end of the source"
		if pend.copyLength > 0 {
			requested = fmt.Sprintf("%d bytes", pend.copyLength)
		}
		return p.journalFileWith("copy", "", pend.path, pend.newPath, -1, "", outcome, map[string]interface{}{"requestedLength": requested})
	case "extension":
		return p.journalFile("extension", "", pend.path, "", -1, "", outcome)
	case "remove", "rmdir", "mkdir", "setstat", "fsetstat":
		return p.journalFile(pend.op, "", pend.path, "", -1, "", outcome)
	case "rename", "hardlink", "symlink":
		return p.journalFile(pend.op, "", pend.path, pend.newPath, -1, "", outcome)
	}
	return nil
}

// finish journals every file still open when the session ends — a client
// that died mid-transfer, or a machine that went away — so a partial
// upload is never silent. It must run before the recording is finalized.
func (p *sftpProxy) finish() {
	p.stop()
	p.mu.Lock()
	open := p.handles
	p.handles = make(map[string]*sftpHandle)
	p.mu.Unlock()
	for _, h := range open {
		_ = p.journalFile("open", h.direction, h.path, "", h.size, h.sha(), "not closed: the session ended")
	}
}

// journalFile is the one place a file operation becomes durable: the
// exec-style recording entry (History reads this) and the events.jsonl
// line session.file (an operator's audit reads this). size < 0 omits the
// size; direction/newPath/sha256 are omitted when empty. A recording
// failure is returned: like every recording write, it ends the session.
func (p *sftpProxy) journalFile(op, direction, path, newPath string, size int64, sha256, outcome string) error {
	return p.journalFileWith(op, direction, path, newPath, size, sha256, outcome, nil)
}

// journalFileWith is journalFile with extra session.file details.
func (p *sftpProxy) journalFileWith(op, direction, path, newPath string, size int64, sha256, outcome string, extra map[string]interface{}) error {
	var recErr error
	if p.rec != nil {
		if err := p.rec.SFTPFile(op, direction, path, newPath, size, sha256, outcome); err != nil {
			recErr = fmt.Errorf("recording: %w", err)
		}
	}
	details := map[string]interface{}{
		"sessionId": p.sessionID,
		"op":        op,
		"path":      path,
		"outcome":   outcome,
	}
	if direction != "" {
		details["direction"] = direction
	}
	if newPath != "" {
		details["newPath"] = newPath
	}
	if size >= 0 {
		details["size"] = size
	}
	if sha256 != "" {
		details["sha256"] = sha256
	}
	result := "ok"
	if outcome != "ok" {
		result = "failed"
		if len(outcome) >= 7 && outcome[:7] == "denied:" {
			result = "denied"
		}
	}
	for k, v := range extra {
		details[k] = v
	}
	if recErr != nil {
		details["recordingError"] = recErr.Error()
	}
	p.g.appendEvent(events.Event{Type: events.EventSessionFile, Actor: p.person, Object: p.machine, Result: result, Details: details})
	return recErr
}
