package sshx

// payload.go: manual wire layout for SSH channel requests per RFC 4254 §6 and §7.
//
// In golang.org/x/crypto/ssh the ptyRequestMsg/windowChangeMsg/execMsg
// etc. types are unexported and tied to unexported parsers. The
// iamtunnel protocol requires an exact byte layout for the payload
// (SPEC §5.1, §5.2), so we declare our own types and write
// marshal/parse ourselves, byte-for-byte against the reference in
// payload_test.go.
//
// Every Marshal* returns only the type-specific data, with no common
// SSH_MSG_CHANNEL_REQUEST header (recipient channel, request name, want
// reply) — ssh.Channel itself adds that header on SendRequest. This
// split is deliberate: the payload layout does not depend on the
// channel number or the request name.

import (
	"encoding/binary"
	"fmt"
	"math"
)

// payloadErr — the type of the package's sentinel errors. A string
// type is needed so the sentinel can be declared as a constant: an
// exported variable can be reassigned by an importer, breaking
// errors.Is for every caller; a constant cannot.
type payloadErr string

func (e payloadErr) Error() string { return string(e) }

// ErrShortPayload is returned by the parsers when the payload is
// shorter than the expected layout or holds an incomplete string length.
const ErrShortPayload = payloadErr("sshx: payload too short")

// PTYRequest — RFC 4254 §6.2, "pty-req".
type PTYRequest struct {
	Term         string
	Columns      uint32
	Rows         uint32
	WidthPixels  uint32
	HeightPixels uint32
	Modes        string
}

// WindowChange — RFC 4254 §6.7, "window-change".
type WindowChange struct {
	Columns      uint32
	Rows         uint32
	WidthPixels  uint32
	HeightPixels uint32
}

// Exec — RFC 4254 §6.5, "exec".
type Exec struct {
	Command string
}

// Env — RFC 4254 §6.4, "env".
type Env struct {
	Name  string
	Value string
}

// Signal — RFC 4254 §6.9, "signal".
type Signal struct {
	// Name with no "SIG" prefix. For example "TERM", "KILL", "INT", "HUP".
	Name string
}

// ExitStatus — RFC 4254 §6.10, "exit-status".
type ExitStatus struct {
	Status uint32
}

// ExitSignal — RFC 4254 §6.10, "exit-signal".
type ExitSignal struct {
	Signal       string // with no "SIG" prefix
	CoreDumped   bool
	ErrorMessage string // ISO-10646 UTF-8
	LanguageTag  string
}

// --- marshal ----------------------------------------------------------------

func writeString(b []byte, s string) []byte {
	if uint64(len(s)) > math.MaxUint32 {
		// uint32(len(s)) would silently truncate the length and shift
		// the whole layout. Unreachable in practice given the SSH
		// packet limit, but silently corrupting bytes on the wire is
		// unacceptable regardless.
		panic("sshx: string exceeds SSH uint32 length")
	}
	n := uint32(len(s))
	b = append(b, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	b = append(b, s...)
	return b
}

func writeUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// MarshalPTY returns the type-specific payload for "pty-req".
func MarshalPTY(p PTYRequest) []byte {
	out := make([]byte, 0, 32+len(p.Term)+len(p.Modes))
	out = writeString(out, p.Term)
	out = writeUint32(out, p.Columns)
	out = writeUint32(out, p.Rows)
	out = writeUint32(out, p.WidthPixels)
	out = writeUint32(out, p.HeightPixels)
	out = writeString(out, p.Modes)
	return out
}

// MarshalWindow returns the type-specific payload for "window-change".
func MarshalWindow(w WindowChange) []byte {
	out := make([]byte, 0, 16)
	out = writeUint32(out, w.Columns)
	out = writeUint32(out, w.Rows)
	out = writeUint32(out, w.WidthPixels)
	out = writeUint32(out, w.HeightPixels)
	return out
}

// MarshalExec returns the type-specific payload for "exec".
func MarshalExec(e Exec) []byte {
	return writeString(nil, e.Command)
}

// MarshalEnv returns the type-specific payload for "env".
func MarshalEnv(e Env) []byte {
	out := make([]byte, 0, 8+len(e.Name)+len(e.Value))
	out = writeString(out, e.Name)
	out = writeString(out, e.Value)
	return out
}

// MarshalSignal returns the type-specific payload for "signal".
func MarshalSignal(s Signal) []byte {
	return writeString(nil, s.Name)
}

// MarshalExitStatus returns the type-specific payload for "exit-status".
func MarshalExitStatus(e ExitStatus) []byte {
	return writeUint32(nil, e.Status)
}

// MarshalExitSignal returns the type-specific payload for "exit-signal".
func MarshalExitSignal(e ExitSignal) []byte {
	out := make([]byte, 0, 16+len(e.Signal)+len(e.ErrorMessage)+len(e.LanguageTag))
	out = writeString(out, e.Signal)
	out = append(out, boolByte(e.CoreDumped))
	out = writeString(out, e.ErrorMessage)
	out = writeString(out, e.LanguageTag)
	return out
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// --- parse ------------------------------------------------------------------

// readUint32 advances off by 4 and returns the value in big-endian. If
// there is not enough data, it returns ErrShortPayload.
func readUint32(b []byte, off *int) (uint32, error) {
	if len(b)-*off < 4 {
		return 0, ErrShortPayload
	}
	v := binary.BigEndian.Uint32(b[*off:])
	*off += 4
	return v, nil
}

// readString advances off by 4 + the length and returns the string's
// bytes. If there is not enough data — ErrShortPayload. Allows an
// empty string (length 0 is fine).
func readString(b []byte, off *int) (string, error) {
	n, err := readUint32(b, off)
	if err != nil {
		return "", err
	}
	// The comparison must happen in 64 bits. On a 32-bit build, int(n)
	// for n > MaxInt32 is negative, the check in int comes out false,
	// and control falls through to a slice with a negative upper
	// bound — a panic remotely triggerable by a single payload with
	// length 0xFFFFFFFF.
	if uint64(n) > uint64(len(b)-*off) {
		return "", ErrShortPayload
	}
	s := string(b[*off : *off+int(n)])
	*off += int(n)
	return s, nil
}

// readBool reads 1 byte and interprets it per RFC 4251: 0 == false, any
// other value == true. Any byte that is neither 0 nor 1 is treated as true.
func readBool(b []byte, off *int) (bool, error) {
	if len(b)-*off < 1 {
		return false, ErrShortPayload
	}
	v := b[*off]
	*off++
	return v != 0, nil
}

// ParsePTY parses the "pty-req" payload.
func ParsePTY(b []byte) (PTYRequest, error) {
	off := 0
	p := PTYRequest{}
	var err error
	if p.Term, err = readString(b, &off); err != nil {
		return p, fmt.Errorf("pty term: %w", err)
	}
	if p.Columns, err = readUint32(b, &off); err != nil {
		return p, fmt.Errorf("pty columns: %w", err)
	}
	if p.Rows, err = readUint32(b, &off); err != nil {
		return p, fmt.Errorf("pty rows: %w", err)
	}
	if p.WidthPixels, err = readUint32(b, &off); err != nil {
		return p, fmt.Errorf("pty width: %w", err)
	}
	if p.HeightPixels, err = readUint32(b, &off); err != nil {
		return p, fmt.Errorf("pty height: %w", err)
	}
	if p.Modes, err = readString(b, &off); err != nil {
		return p, fmt.Errorf("pty modes: %w", err)
	}
	if off != len(b) {
		return p, fmt.Errorf("pty trailing bytes: %d", len(b)-off)
	}
	return p, nil
}

// ParseWindow parses the "window-change" payload.
func ParseWindow(b []byte) (WindowChange, error) {
	if len(b) < 16 {
		return WindowChange{}, fmt.Errorf("window-change size %d, want 16: %w", len(b), ErrShortPayload)
	}
	if len(b) > 16 {
		return WindowChange{}, fmt.Errorf("window-change trailing bytes: %d", len(b)-16)
	}
	return WindowChange{
		Columns:      binary.BigEndian.Uint32(b[0:4]),
		Rows:         binary.BigEndian.Uint32(b[4:8]),
		WidthPixels:  binary.BigEndian.Uint32(b[8:12]),
		HeightPixels: binary.BigEndian.Uint32(b[12:16]),
	}, nil
}

// ParseExec parses the "exec" payload.
func ParseExec(b []byte) (Exec, error) {
	off := 0
	s, err := readString(b, &off)
	if err != nil {
		return Exec{}, fmt.Errorf("exec command: %w", err)
	}
	if off != len(b) {
		return Exec{}, fmt.Errorf("exec trailing bytes: %d", len(b)-off)
	}
	return Exec{Command: s}, nil
}

// ParseEnv parses the "env" payload.
func ParseEnv(b []byte) (Env, error) {
	off := 0
	out := Env{}
	var err error
	if out.Name, err = readString(b, &off); err != nil {
		return out, fmt.Errorf("env name: %w", err)
	}
	if out.Value, err = readString(b, &off); err != nil {
		return out, fmt.Errorf("env value: %w", err)
	}
	if off != len(b) {
		return out, fmt.Errorf("env trailing bytes: %d", len(b)-off)
	}
	return out, nil
}

// ParseSignal parses the "signal" payload.
func ParseSignal(b []byte) (Signal, error) {
	off := 0
	s, err := readString(b, &off)
	if err != nil {
		return Signal{}, fmt.Errorf("signal name: %w", err)
	}
	if off != len(b) {
		return Signal{}, fmt.Errorf("signal trailing bytes: %d", len(b)-off)
	}
	return Signal{Name: s}, nil
}

// ParseExitStatus parses the "exit-status" payload.
func ParseExitStatus(b []byte) (ExitStatus, error) {
	if len(b) < 4 {
		return ExitStatus{}, fmt.Errorf("exit-status size %d, want 4: %w", len(b), ErrShortPayload)
	}
	if len(b) > 4 {
		return ExitStatus{}, fmt.Errorf("exit-status trailing bytes: %d", len(b)-4)
	}
	return ExitStatus{Status: binary.BigEndian.Uint32(b)}, nil
}

// ParseExitSignal parses the "exit-signal" payload.
func ParseExitSignal(b []byte) (ExitSignal, error) {
	off := 0
	out := ExitSignal{}
	var err error
	if out.Signal, err = readString(b, &off); err != nil {
		return out, fmt.Errorf("exit-signal name: %w", err)
	}
	if out.CoreDumped, err = readBool(b, &off); err != nil {
		return out, fmt.Errorf("exit-signal core: %w", err)
	}
	if out.ErrorMessage, err = readString(b, &off); err != nil {
		return out, fmt.Errorf("exit-signal message: %w", err)
	}
	if out.LanguageTag, err = readString(b, &off); err != nil {
		return out, fmt.Errorf("exit-signal language: %w", err)
	}
	if off != len(b) {
		return out, fmt.Errorf("exit-signal trailing bytes: %d", len(b)-off)
	}
	return out, nil
}
