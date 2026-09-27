package sftpwire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildOpen marshals a minimal SSH_FXP_OPEN packet (path, pflags, no
// ATTRS) with the given id — enough for ParseOpen and the framer, since
// nothing here reads past pflags.
func buildOpen(id uint32, path string, pflags uint32) []byte {
	payload := []byte{TypeOpen}
	idb := make([]byte, 4)
	binary.BigEndian.PutUint32(idb, id)
	payload = append(payload, idb...)
	payload = writeString(payload, path)
	payload = writeUint32(payload, pflags)
	payload = writeUint32(payload, 0) // empty ATTRS "valid-attribute-flags"
	out := writeUint32(nil, uint32(len(payload)))
	return append(out, payload...)
}

func buildClose(id uint32, handle string) []byte {
	payload := []byte{TypeClose}
	idb := make([]byte, 4)
	binary.BigEndian.PutUint32(idb, id)
	payload = append(payload, idb...)
	payload = writeString(payload, handle)
	out := writeUint32(nil, uint32(len(payload)))
	return append(out, payload...)
}

func TestFramer_SplitAcrossReads(t *testing.T) {
	pkt := buildOpen(7, `C:\TEST111\car.jpg`, FlagWrite|FlagCreat)
	var f Framer

	// Feed it one byte at a time: the framer must not emit anything
	// until the whole packet, length prefix included, has arrived.
	var got []Packet
	for i := 0; i < len(pkt); i++ {
		out, err := f.Feed(pkt[i : i+1])
		if err != nil {
			t.Fatalf("feed byte %d: %v", i, err)
		}
		got = append(got, out...)
		if i < len(pkt)-1 && len(out) != 0 {
			t.Fatalf("packet completed early at byte %d", i)
		}
	}
	if len(got) != 1 {
		t.Fatalf("got %d packets, want 1", len(got))
	}
	if !bytes.Equal(got[0].Raw, pkt) {
		t.Fatalf("packet bytes mutated: got %x, want %x", got[0].Raw, pkt)
	}
	if got[0].Type != TypeOpen {
		t.Fatalf("type = %d, want TypeOpen", got[0].Type)
	}
	if pid(got[0]) != 7 {
		t.Fatalf("id = %d, want 7", pid(got[0]))
	}
	open, err := ParseOpen(got[0].Data())
	if err != nil {
		t.Fatalf("ParseOpen: %v", err)
	}
	if open.Path != `C:\TEST111\car.jpg` || !open.Mutating() {
		t.Fatalf("parsed open = %+v, want the write path", open)
	}
}

func TestFramer_SeveralPacketsInOneRead(t *testing.T) {
	p1 := buildOpen(1, `C:\a.txt`, FlagRead)
	p2 := buildClose(2, "handle-1")
	p3 := buildOpen(3, `C:\b.txt`, FlagWrite|FlagCreat|FlagTrunc)

	var f Framer
	combined := append(append(append([]byte(nil), p1...), p2...), p3...)
	out, err := f.Feed(combined)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %d packets, want 3", len(out))
	}
	if pid(out[0]) != 1 || out[0].Type != TypeOpen {
		t.Fatalf("packet 0 = %+v", out[0])
	}
	if pid(out[1]) != 2 || out[1].Type != TypeClose {
		t.Fatalf("packet 1 = %+v", out[1])
	}
	if pid(out[2]) != 3 || out[2].Type != TypeOpen {
		t.Fatalf("packet 2 = %+v", out[2])
	}
	h, err := ParseHandleRequest(out[1].Data())
	if err != nil || h.Handle != "handle-1" {
		t.Fatalf("ParseHandleRequest = %+v, %v", h, err)
	}
}

func TestFramer_PartialThenMoreArrivesLater(t *testing.T) {
	p1 := buildOpen(1, `C:\a.txt`, FlagRead)
	p2 := buildClose(2, "h")
	var f Framer

	// First Feed carries packet 1 whole plus half of packet 2.
	split := len(p1) + len(p2)/2
	combined := append(append([]byte(nil), p1...), p2...)
	out, err := f.Feed(combined[:split])
	if err != nil {
		t.Fatalf("feed 1: %v", err)
	}
	if len(out) != 1 || pid(out[0]) != 1 {
		t.Fatalf("first feed = %+v, want just packet 1", out)
	}
	out, err = f.Feed(combined[split:])
	if err != nil {
		t.Fatalf("feed 2: %v", err)
	}
	if len(out) != 1 || pid(out[0]) != 2 {
		t.Fatalf("second feed = %+v, want just packet 2", out)
	}
}

func TestFramer_RejectsOversizedPacket(t *testing.T) {
	var f Framer
	huge := make([]byte, 4)
	binary.BigEndian.PutUint32(huge, MaxPacketSize+1)
	if _, err := f.Feed(huge); err == nil {
		t.Fatal("expected an error for a packet declared larger than MaxPacketSize")
	}
}

func TestFramer_RejectsZeroLength(t *testing.T) {
	var f Framer
	if _, err := f.Feed([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("expected an error for a zero-length packet")
	}
}

func TestParseRename(t *testing.T) {
	data := writeString(writeString(nil, `C:\a.txt`), `C:\b.txt`)
	r, err := ParseRename(data)
	if err != nil {
		t.Fatalf("ParseRename: %v", err)
	}
	if r.OldPath != `C:\a.txt` || r.NewPath != `C:\b.txt` {
		t.Fatalf("ParseRename = %+v", r)
	}
}

func TestParseWriteAndRead(t *testing.T) {
	body := []byte("hello, sftp")
	data := writeString(nil, "handle-1")
	data = append(data, 0, 0, 0, 0, 0, 0, 0, 0) // offset = 0
	data = writeUint32(data, uint32(len(body)))
	data = append(data, body...)
	w, err := ParseWrite(data)
	if err != nil {
		t.Fatalf("ParseWrite: %v", err)
	}
	if w.Handle != "handle-1" || w.Offset != 0 || !bytes.Equal(w.Data, body) {
		t.Fatalf("ParseWrite = %+v", w)
	}

	rdata := writeString(nil, "handle-1")
	rdata = append(rdata, 0, 0, 0, 0, 0, 0, 0, 42) // offset = 42
	rdata = writeUint32(rdata, 4096)
	r, err := ParseRead(rdata)
	if err != nil {
		t.Fatalf("ParseRead: %v", err)
	}
	if r.Handle != "handle-1" || r.Offset != 42 || r.Length != 4096 {
		t.Fatalf("ParseRead = %+v", r)
	}
}

func TestParseStatusAndHandleAndData(t *testing.T) {
	sdata := writeString(writeUint32(nil, StatusPermissionDenied), "denied")
	sdata = writeString(sdata, "") // language tag
	st, err := ParseStatus(sdata)
	if err != nil || st.Code != StatusPermissionDenied || st.Message != "denied" {
		t.Fatalf("ParseStatus = %+v, %v", st, err)
	}

	hdata := writeString(nil, "h-99")
	hr, err := ParseHandleResponse(hdata)
	if err != nil || hr.Handle != "h-99" {
		t.Fatalf("ParseHandleResponse = %+v, %v", hr, err)
	}

	ddata := writeUint32(nil, 3)
	ddata = append(ddata, 'a', 'b', 'c')
	dr, err := ParseDataResponse(ddata)
	if err != nil || string(dr.Data) != "abc" {
		t.Fatalf("ParseDataResponse = %+v, %v", dr, err)
	}
}

func TestMarshalStatus_RoundTrips(t *testing.T) {
	raw := MarshalStatus(55, StatusPermissionDenied, "approval-id=apr-0011223344556677 E_APPROVAL_REQUIRED")
	var f Framer
	out, err := f.Feed(raw)
	if err != nil || len(out) != 1 {
		t.Fatalf("feed marshaled status: out=%v err=%v", out, err)
	}
	if out[0].Type != TypeStatus || pid(out[0]) != 55 {
		t.Fatalf("marshaled status packet = %+v", out[0])
	}
	st, err := ParseStatus(out[0].Data())
	if err != nil {
		t.Fatalf("ParseStatus: %v", err)
	}
	if st.Code != StatusPermissionDenied || st.Message == "" {
		t.Fatalf("ParseStatus round trip = %+v", st)
	}
}

func TestParseShortPayloadsFail(t *testing.T) {
	if _, err := ParseOpen(nil); err == nil {
		t.Fatal("ParseOpen on empty data should fail")
	}
	if _, err := ParseRename([]byte{0, 0, 0, 1}); err == nil {
		t.Fatal("ParseRename on truncated data should fail")
	}
	if _, err := ParseWrite([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("ParseWrite on truncated data should fail")
	}
}

// pid is Packet.ID for a packet the test built whole.
func pid(p Packet) uint32 {
	id, _ := p.ID()
	return id
}

// A length prefix of 1..4 is valid framing, but such a packet carries no
// request id. ID and Data must say so instead of slicing past the end —
// in the gateway that slice would be a panic on a byte a client chose.
func TestShortPacketHasNoID(t *testing.T) {
	var f Framer
	out, err := f.Feed([]byte{0, 0, 0, 2, TypeOpen, 0})
	if err != nil || len(out) != 1 {
		t.Fatalf("feed short packet: out=%v err=%v", out, err)
	}
	if _, ok := out[0].ID(); ok {
		t.Fatal("a 2-byte packet reported a request id")
	}
	if out[0].Data() != nil {
		t.Fatalf("a 2-byte packet reported data %x", out[0].Data())
	}
}

func TestParseTwoPathsAndExtended(t *testing.T) {
	data := writeString(nil, "posix-rename@openssh.com")
	data = writeString(data, "/a")
	data = writeString(data, "/b")
	ext, err := ParseExtended(data)
	if err != nil || ext.Name != "posix-rename@openssh.com" {
		t.Fatalf("ParseExtended = %+v, %v", ext, err)
	}
	two, err := ParseTwoPaths(ext.Data)
	if err != nil || two.First != "/a" || two.Second != "/b" {
		t.Fatalf("ParseTwoPaths = %+v, %v", two, err)
	}
}
