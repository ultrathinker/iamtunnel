package gateway

// Fixup round 1 of 1.50: MKDIR judged (V-03), copy-data and unknown
// extensions judged (V-04), a reused outstanding request id ends the
// session (V-05).

import (
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx/sftpwire"
)

func TestR150_SFTPMkdirIsJudged(t *testing.T) {
	f, fs, stub := r150SFTPFixture(t, RiskActionAsk, "sftp: mkdir /C:/Windows/evil")
	client, _, c := r150OpenSFTP(t, f)
	defer client.Close()

	c.send(r150Pkt(sftpwire.TypeMkdir, 1, r150Str("/C:/Windows/evil"), r150U32(0)))
	st := c.status(1)
	if st.Code != sftpwire.StatusPermissionDenied || !strings.Contains(st.Message, "E_APPROVAL_REQUIRED") {
		t.Fatalf("red mkdir under ask = %+v, want PERMISSION_DENIED with an approval", st)
	}
	if fs.saw("mkdir /C:/Windows/evil") {
		t.Fatal("the held mkdir reached the machine")
	}
	if _, ok := stub.saw("sftp: mkdir /C:/Windows/evil"); !ok {
		t.Fatalf("classifier never saw the mkdir; it saw %q", stub.seen)
	}

	// A green mkdir is judged too, and goes through.
	c.send(r150Pkt(sftpwire.TypeMkdir, 2, r150Str("/C:/TEST111/new"), r150U32(0)))
	if st := c.status(2); st.Code != sftpwire.StatusOK || !fs.saw("mkdir /C:/TEST111/new") {
		t.Fatalf("green mkdir = %+v", st)
	}
	if _, ok := stub.saw("sftp: mkdir /C:/TEST111/new"); !ok {
		t.Fatal("a green mkdir was forwarded without being judged")
	}
}

func TestR150_SFTPCopyDataIsJudgedAndJournaledHonestly(t *testing.T) {
	f, fs, stub := r150SFTPFixture(t, RiskActionAsk, "sftp: copy /C:/src.bin -> /C:/Windows/dst.bin")
	fs.files["/C:/src.bin"] = []byte("0123456789")
	client, _, c := r150OpenSFTP(t, f)
	defer client.Close()

	c.send(r150Open(1, "/C:/src.bin", sftpwire.FlagRead))
	src := c.handle(1)

	// Red copy: refused, the machine never sees the extension.
	c.send(r150Open(2, "/C:/Windows/dst.bin", r150WriteFlags))
	dst := c.handle(2)
	c.send(r150CopyData(3, src, dst))
	if st := c.status(3); st.Code != sftpwire.StatusPermissionDenied {
		t.Fatalf("red copy-data under ask = %+v, want PERMISSION_DENIED", st)
	}
	if fs.saw("extended copy-data") {
		t.Fatal("the held copy-data reached the machine")
	}
	c.send(r150Close(4, dst))
	c.status(4)

	// Green copy: judged by both paths, forwarded, journaled with the
	// requested length, and the destination's CLOSE claims no size or hash.
	c.send(r150Open(5, "/C:/TEST111/dst.bin", r150WriteFlags))
	dst = c.handle(5)
	c.send(r150CopyData(6, src, dst))
	if st := c.status(6); st.Code != sftpwire.StatusOK {
		t.Fatalf("green copy-data = %+v", st)
	}
	if _, ok := stub.saw("sftp: copy /C:/src.bin -> /C:/TEST111/dst.bin"); !ok {
		t.Fatalf("classifier never saw the copy; it saw %q", stub.seen)
	}
	c.send(r150Close(7, dst))
	c.status(7)
	if fs.file("/C:/TEST111/dst.bin") != "0123456789" {
		t.Fatalf("copy did not happen on the machine: %q", fs.file("/C:/TEST111/dst.bin"))
	}
	copyEv := r150WaitFileEvent(t, f, "copy", "/C:/src.bin", 1)
	if copyEv.Details["newPath"] != "/C:/TEST111/dst.bin" || copyEv.Details["requestedLength"] != "to the end of the source" || copyEv.Details["size"] != nil {
		t.Fatalf("copy journaled as %+v", copyEv.Details)
	}
	closeEv := r150WaitFileEvent(t, f, "open", "/C:/TEST111/dst.bin", 1)
	if closeEv.Details["size"] != nil || closeEv.Details["sha256"] != "not computed: written by copy-data" || closeEv.Details["direction"] != "upload" {
		t.Fatalf("destination CLOSE journaled as %+v, want no size and no hash claimed", closeEv.Details)
	}
}

func TestR150_SFTPUnknownExtensionIsJudgedReadOnlyOnesPass(t *testing.T) {
	f, fs, stub := r150SFTPFixture(t, RiskActionAsk, "sftp: extension fsync@openssh.com")
	client, _, c := r150OpenSFTP(t, f)
	defer client.Close()

	c.send(r150Extended(1, "fsync@openssh.com", r150Str("h0")))
	if st := c.status(1); st.Code != sftpwire.StatusPermissionDenied {
		t.Fatalf("red unknown extension = %+v, want PERMISSION_DENIED", st)
	}
	if fs.saw("extended fsync@openssh.com") {
		t.Fatal("the held extension reached the machine")
	}

	c.send(r150Extended(2, "vendor-write@example.com", r150Str("/C:/x")))
	if st := c.status(2); st.Code != sftpwire.StatusOK || !fs.saw("extended vendor-write@example.com") {
		t.Fatalf("green unknown extension = %+v", st)
	}
	if _, ok := stub.saw("sftp: extension vendor-write@example.com"); !ok {
		t.Fatal("an unknown extension was forwarded without being judged")
	}
	if ev := r150WaitFileEvent(t, f, "extension", "vendor-write@example.com", 1); ev.Result != "ok" {
		t.Fatalf("extension journaled as %+v", ev)
	}

	c.send(r150Extended(3, "statvfs@openssh.com", r150Str("/C:/")))
	if st := c.status(3); st.Code != sftpwire.StatusOK || !fs.saw("extended statvfs@openssh.com") {
		t.Fatalf("statvfs = %+v", st)
	}
	if _, ok := stub.saw("statvfs"); ok {
		t.Fatal("a read-only extension was sent to the classifier")
	}
}

// V-05, at the proxy: the machine never answers, so the first request is
// still outstanding when the second arrives with the same id. The second
// is not forwarded and the stream ends with the reason.
func TestR150_SFTPReusedOutstandingIDEndsTheStream(t *testing.T) {
	f := newFixture(t, nil)
	gwSide, machineSide := net.Pipe()
	defer gwSide.Close()
	defer machineSide.Close()
	got := make(chan sftpwire.Packet, 8)
	go func() {
		var fr sftpwire.Framer
		buf := make([]byte, 4096)
		for {
			n, err := machineSide.Read(buf)
			pkts, _ := fr.Feed(buf[:n])
			for _, p := range pkts {
				got <- p
			}
			if err != nil {
				close(got)
				return
			}
		}
	}()
	proxy := newSFTPProxy(f.gw, f.person, f.machineID, "sid-dup", "", nil, nil, nil)
	ts := newSFTPTargetStream(r150PipeStream{gwSide}, proxy)
	defer ts.Close()

	a := r150Pkt(sftpwire.TypeStat, 7, r150Str("/C:/a"))
	b := r150Pkt(sftpwire.TypeStat, 7, r150Str("/C:/b"))
	_, err := ts.Write(append(append([]byte(nil), a...), b...))
	if err == nil || !strings.Contains(err.Error(), "request id reused") {
		t.Fatalf("Write of a reused outstanding id = %v, want the session-ending error", err)
	}
	first := <-got
	if string(first.Raw) != string(a) {
		t.Fatalf("machine got %x, want the first request", first.Raw)
	}
	select {
	case p, ok := <-got:
		if ok {
			t.Fatalf("the request with the reused id reached the machine: %x", p.Raw)
		}
	case <-time.After(200 * time.Millisecond):
	}
}

// V-05, end to end: the session ends with session.drop naming the reason.
func TestR150_SFTPReusedOutstandingIDDropsSession(t *testing.T) {
	f := newFixture(t, nil)
	// A machine that answers INIT and then never answers again.
	f.sshd.setOnSubsystemImmediate(func(ch ssh.Channel, name string) {
		var fr sftpwire.Framer
		buf := make([]byte, 4096)
		for {
			n, err := ch.Read(buf)
			pkts, _ := fr.Feed(buf[:n])
			for _, p := range pkts {
				if p.Type == sftpwire.TypeInit {
					_, _ = ch.Write(append(r150U32(5), append([]byte{sftpwire.TypeVersion}, r150U32(3)...)...))
				}
			}
			if err != nil {
				return
			}
		}
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, _, c := r150OpenSFTP(t, f)
	defer client.Close()
	c.send(r150Pkt(sftpwire.TypeStat, 9, r150Str("/C:/a")), r150Pkt(sftpwire.TypeStat, 9, r150Str("/C:/b")))
	waitUntil(t, "session.drop for a reused sftp request id", func() bool {
		evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}, Actor: f.person, Object: f.machineID})
		if err != nil {
			t.Fatalf("read events: %v", err)
		}
		for _, ev := range evs {
			if strings.Contains(ev.Result, "request id reused") {
				return true
			}
		}
		return false
	})
}

// V-10: a judged unknown extension answered with SSH_FXP_EXTENDED_REPLY
// (type 201) instead of a STATUS is a completed operation: it is journaled,
// and the reply reaches the person unchanged.
func TestR150_SFTPExtendedReplyIsJournaled(t *testing.T) {
	f := newFixture(t, nil)
	gwSide, machineSide := net.Pipe()
	defer gwSide.Close()
	defer machineSide.Close()
	reply := r150Pkt(sftpwire.TypeExtendedReply, 5, r150Str("vendor data"))
	go func() {
		var fr sftpwire.Framer
		buf := make([]byte, 4096)
		for {
			n, err := machineSide.Read(buf)
			pkts, _ := fr.Feed(buf[:n])
			for _, p := range pkts {
				if p.Type == sftpwire.TypeExtended {
					_, _ = machineSide.Write(reply)
				}
			}
			if err != nil {
				return
			}
		}
	}()
	proxy := newSFTPProxy(f.gw, f.person, f.machineID, "sid-ext", "", nil, nil, nil)
	ts := newSFTPTargetStream(r150PipeStream{gwSide}, proxy)
	defer ts.Close()
	c := newR150SFTPClient(t, ts, ts)

	c.send(r150Extended(5, "vendor-write@example.com", r150Str("/C:/x")))
	got := c.recv()
	if string(got.Raw) != string(reply) {
		t.Fatalf("the extended reply reached the person as %x, want it unchanged", got.Raw)
	}
	ev := r150WaitFileEvent(t, f, "extension", "vendor-write@example.com", 1)
	if ev.Result != "ok" || ev.Details["outcome"] != "ok" {
		t.Fatalf("extended reply journaled as %+v, want ok", ev)
	}
	// The id is free again: the same id may be used for a new request.
	proxy.mu.Lock()
	_, busy := proxy.pending[5]
	proxy.mu.Unlock()
	if busy {
		t.Fatal("the pending entry of an answered extended request was not released")
	}
}
