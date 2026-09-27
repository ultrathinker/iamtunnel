// Package sftpwire is a read-only parser for the SFTP v3 wire format
// (draft-ietf-secsh-filexfer-02, the dialect OpenSSH's sftp-server speaks).
// It exists so the gateway's SFTP subsystem proxy (1.50, IAMT-fileio) can
// tell what a byte stream is asking for without ever rewriting a byte of
// it: every parser here returns a view of the packet, never a modified
// copy, and the framer that splits a stream into packets hands back the
// exact wire bytes (Packet.Raw) for the caller to forward unchanged.
//
// The framer tolerates the two shapes a real transport actually produces:
// a read that stops mid-packet (a partial packet, completed by a later
// Feed), and a read that carries several whole packets at once. Nothing
// here understands SSH channels, gateway policy or judgement — that is
// the caller's job.
package sftpwire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Packet types (draft-ietf-secsh-filexfer-02 §3).
const (
	TypeInit          byte = 1
	TypeVersion       byte = 2
	TypeOpen          byte = 3
	TypeClose         byte = 4
	TypeRead          byte = 5
	TypeWrite         byte = 6
	TypeLstat         byte = 7
	TypeFstat         byte = 8
	TypeSetstat       byte = 9
	TypeFsetstat      byte = 10
	TypeOpendir       byte = 11
	TypeReaddir       byte = 12
	TypeRemove        byte = 13
	TypeMkdir         byte = 14
	TypeRmdir         byte = 15
	TypeRealpath      byte = 16
	TypeStat          byte = 17
	TypeRename        byte = 18
	TypeReadlink      byte = 19
	TypeSymlink       byte = 20
	TypeStatus        byte = 101
	TypeHandle        byte = 102
	TypeData          byte = 103
	TypeName          byte = 104
	TypeAttrs         byte = 105
	TypeExtended      byte = 200
	TypeExtendedReply byte = 201
)

// SSH_FXF_* open flags (draft-ietf-secsh-filexfer-02 §6.3).
const (
	FlagRead   uint32 = 0x00000001
	FlagWrite  uint32 = 0x00000002
	FlagAppend uint32 = 0x00000004
	FlagCreat  uint32 = 0x00000008
	FlagTrunc  uint32 = 0x00000010
	FlagExcl   uint32 = 0x00000020
)

// SSH_FX_* status codes (draft-ietf-secsh-filexfer-02 §7).
const (
	StatusOK               = 0
	StatusEOF              = 1
	StatusNoSuchFile       = 2
	StatusPermissionDenied = 3
	StatusFailure          = 4
	StatusBadMessage       = 5
	StatusNoConnection     = 6
	StatusConnectionLost   = 7
	StatusOpUnsupported    = 8
)

// MaxPacketSize bounds how large a single packet's length prefix may claim
// to be before the framer refuses to keep buffering it. It is generous
// relative to the data/write chunk sizes real clients use (commonly
// 16-32 KiB) while still bounding memory against a hostile or corrupt
// length field.
const MaxPacketSize = 1 << 20 // 1 MiB

// ErrPacketTooLarge is returned by Framer.Feed when a packet's declared
// length exceeds MaxPacketSize.
var ErrPacketTooLarge = errors.New("sftpwire: packet exceeds MaxPacketSize")

// ErrZeroLength is returned for a packet whose length prefix is 0 — every
// real SFTP packet has at least a one-byte type field.
var ErrZeroLength = errors.New("sftpwire: zero-length packet")

// ErrShortPacket is returned by the field parsers when the packet's data
// is shorter than the layout they expect.
var ErrShortPacket = errors.New("sftpwire: packet shorter than its layout")

// Packet is one complete SFTP packet as it appeared on the wire: a 4-byte
// big-endian length prefix (the length of everything that follows,
// PayloadLen), a 1-byte type, and the type-specific payload. Raw holds the
// full wire bytes, length prefix included, so a caller that decides to
// forward this packet can write Raw verbatim without re-marshalling
// anything.
type Packet struct {
	PayloadLen uint32
	Type       byte
	Raw        []byte
}

// ID returns the packet's request id: the first 4 bytes of the payload
// that follows the type byte. Every packet type this package parses
// carries one (draft-ietf-secsh-filexfer-02 §3); for INIT/VERSION the same
// bytes are the protocol version. ok is false for a packet too short to
// carry an id at all — the framer passes such packets through (a length
// prefix of 1..4 is well-formed framing), so a caller must not assume it.
func (p Packet) ID() (id uint32, ok bool) {
	if len(p.Raw) < 9 {
		return 0, false
	}
	return binary.BigEndian.Uint32(p.Raw[5:9]), true
}

// Data returns the packet's type-specific data: everything after the
// 4-byte length, the 1-byte type and the 4-byte id. It is nil for a
// packet too short to carry an id.
func (p Packet) Data() []byte {
	if len(p.Raw) < 9 {
		return nil
	}
	return p.Raw[9:]
}

// Framer incrementally splits a byte stream into complete Packets,
// buffering a partial packet across Feed calls and returning several
// packets from one Feed call when the underlying read delivered more than
// one. It is not safe for concurrent use — pair one Framer with one
// direction of one stream.
type Framer struct {
	buf []byte
}

// Feed appends p to the framer's buffer and returns every complete packet
// that can now be split off. Leftover partial bytes are kept for the next
// call. Once Feed returns a non-nil error the framer must not be fed
// again — the byte stream is no longer trustworthy as a sequence of SFTP
// packets, and a caller that still needs to move bytes must fall back to
// forwarding them raw, unparsed.
func (f *Framer) Feed(p []byte) ([]Packet, error) {
	if len(p) > 0 {
		f.buf = append(f.buf, p...)
	}
	var out []Packet
	for {
		if len(f.buf) < 4 {
			return out, nil
		}
		n := binary.BigEndian.Uint32(f.buf[:4])
		if n == 0 {
			return out, ErrZeroLength
		}
		if n > MaxPacketSize {
			return out, fmt.Errorf("%w: declared %d bytes", ErrPacketTooLarge, n)
		}
		total := 4 + int(n)
		if len(f.buf) < total {
			return out, nil
		}
		raw := make([]byte, total)
		copy(raw, f.buf[:total])
		f.buf = f.buf[total:]
		out = append(out, Packet{PayloadLen: n, Type: raw[4], Raw: raw})
	}
}

// Pending returns a copy of the bytes buffered toward an unfinished packet.
// A caller whose stream has ended forwards them as they are, so that
// nothing the peer sent is dropped even when it did not finish a packet.
func (f *Framer) Pending() []byte {
	return append([]byte(nil), f.buf...)
}

// --- field readers, RFC 4251 §5 wire primitives -----------------------------

func readUint32(b []byte, off *int) (uint32, error) {
	if len(b)-*off < 4 {
		return 0, ErrShortPacket
	}
	v := binary.BigEndian.Uint32(b[*off:])
	*off += 4
	return v, nil
}

func readUint64(b []byte, off *int) (uint64, error) {
	if len(b)-*off < 8 {
		return 0, ErrShortPacket
	}
	v := binary.BigEndian.Uint64(b[*off:])
	*off += 8
	return v, nil
}

func readString(b []byte, off *int) (string, error) {
	n, err := readUint32(b, off)
	if err != nil {
		return "", err
	}
	// 64-bit comparison: on a 32-bit build int(n) for n > MaxInt32
	// would wrap negative and a naive check would pass through to a
	// slice with a negative bound.
	if uint64(n) > uint64(len(b)-*off) {
		return "", ErrShortPacket
	}
	s := string(b[*off : *off+int(n)])
	*off += int(n)
	return s, nil
}

// --- request parsers (client -> server) -------------------------------------

// OpenRequest is SSH_FXP_OPEN's payload after the id: filename and pflags.
// The ATTRS group that follows is not parsed — nothing here needs it.
type OpenRequest struct {
	Path   string
	Pflags uint32
}

// ParseOpen parses a "open" packet's data (Packet.Data(), i.e. after id).
func ParseOpen(data []byte) (OpenRequest, error) {
	off := 0
	path, err := readString(data, &off)
	if err != nil {
		return OpenRequest{}, fmt.Errorf("sftpwire: open path: %w", err)
	}
	pflags, err := readUint32(data, &off)
	if err != nil {
		return OpenRequest{}, fmt.Errorf("sftpwire: open pflags: %w", err)
	}
	return OpenRequest{Path: path, Pflags: pflags}, nil
}

// Mutating reports whether pflags asks to open the file for anything other
// than a pure read: SFTP clients set at least one of write/create/trunc/
// append to change what is on disk.
func (o OpenRequest) Mutating() bool {
	return o.Pflags&(FlagWrite|FlagCreat|FlagTrunc|FlagAppend) != 0
}

// PathRequest is the shared shape of SSH_FXP_REMOVE, SSH_FXP_RMDIR,
// SSH_FXP_OPENDIR, SSH_FXP_STAT, SSH_FXP_LSTAT and SSH_FXP_READLINK: one
// path and nothing else.
type PathRequest struct {
	Path string
}

// ParsePath parses any of the single-path request types.
func ParsePath(data []byte) (PathRequest, error) {
	off := 0
	path, err := readString(data, &off)
	if err != nil {
		return PathRequest{}, fmt.Errorf("sftpwire: path: %w", err)
	}
	return PathRequest{Path: path}, nil
}

// MkdirRequest is SSH_FXP_MKDIR / SSH_FXP_SETSTAT's payload: a path
// followed by an ATTRS group this package does not decode.
type MkdirRequest struct {
	Path string
}

// ParseMkdir parses a "mkdir" or "setstat" packet's data (the ATTRS group
// that follows the path is ignored — the operation and the path are what
// judgement and journaling need).
func ParseMkdir(data []byte) (MkdirRequest, error) {
	off := 0
	path, err := readString(data, &off)
	if err != nil {
		return MkdirRequest{}, fmt.Errorf("sftpwire: mkdir path: %w", err)
	}
	return MkdirRequest{Path: path}, nil
}

// HandleRequest is the shared shape of SSH_FXP_CLOSE, SSH_FXP_FSTAT and
// SSH_FXP_FSETSTAT: one handle (and, for fsetstat, an ATTRS group this
// package does not decode).
type HandleRequest struct {
	Handle string
}

// ParseHandleRequest parses a "close"/"fstat"/"fsetstat" packet's data.
func ParseHandleRequest(data []byte) (HandleRequest, error) {
	off := 0
	h, err := readString(data, &off)
	if err != nil {
		return HandleRequest{}, fmt.Errorf("sftpwire: handle: %w", err)
	}
	return HandleRequest{Handle: h}, nil
}

// RenameRequest is SSH_FXP_RENAME's payload: old path and new path.
type RenameRequest struct {
	OldPath string
	NewPath string
}

// ParseRename parses a "rename" packet's data.
func ParseRename(data []byte) (RenameRequest, error) {
	off := 0
	oldPath, err := readString(data, &off)
	if err != nil {
		return RenameRequest{}, fmt.Errorf("sftpwire: rename oldpath: %w", err)
	}
	newPath, err := readString(data, &off)
	if err != nil {
		return RenameRequest{}, fmt.Errorf("sftpwire: rename newpath: %w", err)
	}
	return RenameRequest{OldPath: oldPath, NewPath: newPath}, nil
}

// TwoPathRequest is the shape of SSH_FXP_SYMLINK and of the OpenSSH
// extensions posix-rename@openssh.com and hardlink@openssh.com: two paths.
// For SYMLINK the order on the wire is disputed (OpenSSH sends target
// before link path, the reverse of the draft), so the fields are named by
// position, not meaning.
type TwoPathRequest struct {
	First  string
	Second string
}

// ParseTwoPaths parses two consecutive strings.
func ParseTwoPaths(data []byte) (TwoPathRequest, error) {
	off := 0
	a, err := readString(data, &off)
	if err != nil {
		return TwoPathRequest{}, fmt.Errorf("sftpwire: first path: %w", err)
	}
	b, err := readString(data, &off)
	if err != nil {
		return TwoPathRequest{}, fmt.Errorf("sftpwire: second path: %w", err)
	}
	return TwoPathRequest{First: a, Second: b}, nil
}

// ExtendedRequest is SSH_FXP_EXTENDED's payload: the extension name and
// its request-specific data, left undecoded.
type ExtendedRequest struct {
	Name string
	Data []byte
}

// ParseExtended parses an "extended" packet's data. Data aliases data.
func ParseExtended(data []byte) (ExtendedRequest, error) {
	off := 0
	name, err := readString(data, &off)
	if err != nil {
		return ExtendedRequest{}, fmt.Errorf("sftpwire: extended name: %w", err)
	}
	return ExtendedRequest{Name: name, Data: data[off:]}, nil
}

// CopyDataRequest is the data of OpenSSH's "copy-data" extension: copy
// Length bytes (0: to the end of the source) from ReadHandle at ReadOffset
// to WriteHandle at WriteOffset, on the server.
type CopyDataRequest struct {
	ReadHandle  string
	ReadOffset  uint64
	Length      uint64
	WriteHandle string
	WriteOffset uint64
}

// ParseCopyData parses ExtendedRequest.Data of a "copy-data" request.
func ParseCopyData(data []byte) (CopyDataRequest, error) {
	var r CopyDataRequest
	off := 0
	var err error
	if r.ReadHandle, err = readString(data, &off); err != nil {
		return CopyDataRequest{}, fmt.Errorf("sftpwire: copy-data read handle: %w", err)
	}
	if r.ReadOffset, err = readUint64(data, &off); err != nil {
		return CopyDataRequest{}, fmt.Errorf("sftpwire: copy-data read offset: %w", err)
	}
	if r.Length, err = readUint64(data, &off); err != nil {
		return CopyDataRequest{}, fmt.Errorf("sftpwire: copy-data length: %w", err)
	}
	if r.WriteHandle, err = readString(data, &off); err != nil {
		return CopyDataRequest{}, fmt.Errorf("sftpwire: copy-data write handle: %w", err)
	}
	if r.WriteOffset, err = readUint64(data, &off); err != nil {
		return CopyDataRequest{}, fmt.Errorf("sftpwire: copy-data write offset: %w", err)
	}
	return r, nil
}

// ReadWriteRequest is SSH_FXP_READ / SSH_FXP_WRITE's payload: a handle, a
// 64-bit offset, and either the length requested (read) or the data
// itself, whose length is Length (write).
type ReadWriteRequest struct {
	Handle string
	Offset uint64
	Length uint32
	// Data holds the write payload for ParseWrite; empty for ParseRead,
	// which carries only a requested length, not bytes.
	Data []byte
}

// ParseRead parses a "read" packet's data: handle, offset, requested length.
func ParseRead(data []byte) (ReadWriteRequest, error) {
	off := 0
	h, err := readString(data, &off)
	if err != nil {
		return ReadWriteRequest{}, fmt.Errorf("sftpwire: read handle: %w", err)
	}
	offset, err := readUint64(data, &off)
	if err != nil {
		return ReadWriteRequest{}, fmt.Errorf("sftpwire: read offset: %w", err)
	}
	length, err := readUint32(data, &off)
	if err != nil {
		return ReadWriteRequest{}, fmt.Errorf("sftpwire: read length: %w", err)
	}
	return ReadWriteRequest{Handle: h, Offset: offset, Length: length}, nil
}

// ParseWrite parses a "write" packet's data: handle, offset, and the data
// being written. The returned Data slice aliases data — callers that keep
// it past the packet's lifetime must copy it.
func ParseWrite(data []byte) (ReadWriteRequest, error) {
	off := 0
	h, err := readString(data, &off)
	if err != nil {
		return ReadWriteRequest{}, fmt.Errorf("sftpwire: write handle: %w", err)
	}
	offset, err := readUint64(data, &off)
	if err != nil {
		return ReadWriteRequest{}, fmt.Errorf("sftpwire: write offset: %w", err)
	}
	length, err := readUint32(data, &off)
	if err != nil {
		return ReadWriteRequest{}, fmt.Errorf("sftpwire: write length: %w", err)
	}
	if uint64(length) > uint64(len(data)-off) {
		return ReadWriteRequest{}, fmt.Errorf("sftpwire: write data: %w", ErrShortPacket)
	}
	return ReadWriteRequest{Handle: h, Offset: offset, Length: length, Data: data[off : off+int(length)]}, nil
}

// --- response parsers (server -> client) ------------------------------------

// StatusResponse is SSH_FXP_STATUS's payload: the result code and a
// human-readable message (language tag ignored — nothing here needs it).
type StatusResponse struct {
	Code    uint32
	Message string
}

// ParseStatus parses a "status" packet's data.
func ParseStatus(data []byte) (StatusResponse, error) {
	off := 0
	code, err := readUint32(data, &off)
	if err != nil {
		return StatusResponse{}, fmt.Errorf("sftpwire: status code: %w", err)
	}
	msg, err := readString(data, &off)
	if err != nil {
		return StatusResponse{}, fmt.Errorf("sftpwire: status message: %w", err)
	}
	return StatusResponse{Code: code, Message: msg}, nil
}

// HandleResponse is SSH_FXP_HANDLE's payload: the handle opaque string the
// server minted for a successful OPEN/OPENDIR.
type HandleResponse struct {
	Handle string
}

// ParseHandleResponse parses a "handle" packet's data.
func ParseHandleResponse(data []byte) (HandleResponse, error) {
	off := 0
	h, err := readString(data, &off)
	if err != nil {
		return HandleResponse{}, fmt.Errorf("sftpwire: handle response: %w", err)
	}
	return HandleResponse{Handle: h}, nil
}

// DataResponse is SSH_FXP_DATA's payload: the bytes read. The returned
// slice aliases data.
type DataResponse struct {
	Data []byte
}

// ParseDataResponse parses a "data" packet's data.
func ParseDataResponse(data []byte) (DataResponse, error) {
	off := 0
	n, err := readUint32(data, &off)
	if err != nil {
		return DataResponse{}, fmt.Errorf("sftpwire: data length: %w", err)
	}
	if uint64(n) > uint64(len(data)-off) {
		return DataResponse{}, fmt.Errorf("sftpwire: data payload: %w", ErrShortPacket)
	}
	return DataResponse{Data: data[off : off+int(n)]}, nil
}

// --- marshalling (gateway-generated responses only) -------------------------

func writeUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func writeString(b []byte, s string) []byte {
	b = writeUint32(b, uint32(len(s)))
	return append(b, s...)
}

// MarshalStatus builds a complete wire-ready SSH_FXP_STATUS packet
// (length prefix included) for the given request id, code and message,
// with an empty language tag. This is the one packet shape the gateway
// itself ever originates on the wire — used to answer a request it
// decided not to forward (1.50 SFTP judgement).
func MarshalStatus(id uint32, code uint32, message string) []byte {
	payload := make([]byte, 0, 1+4+4+4+len(message)+4)
	payload = append(payload, TypeStatus)
	payload = writeUint32(payload, id)
	payload = writeUint32(payload, code)
	payload = writeString(payload, message)
	payload = writeString(payload, "") // language tag
	out := make([]byte, 0, 4+len(payload))
	out = writeUint32(out, uint32(len(payload)))
	out = append(out, payload...)
	return out
}
