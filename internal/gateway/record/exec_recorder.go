package record

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ExecConfig describes one exec request without a PTY. It deliberately embeds
// SessionConfig so naming, permissions and metadata have the same rules as a
// terminal recording.
type ExecConfig struct {
	SessionConfig
	Command string
}

// ExecPaths identifies the two files that make up a non-PTY exec recording.
type ExecPaths struct {
	ExecPath string
	MetaPath string
}

// ExecRecorder writes a lossless, ordered JSONL stream. Each method which
// appends an event fsyncs it before returning, so recordingWriter cannot pass a
// machine byte on to the person until it is durable.
type ExecRecorder struct {
	mu          sync.Mutex
	cfg         ExecConfig
	startedAt   time.Time
	paths       ExecPaths
	file        *os.File
	seq         uint64
	closed      bool
	bytesIn     int64
	bytesOut    int64
	stdinHasher hash.Hash
	meta        Metadata
}

type execEvent struct {
	Sequence uint64  `json:"sequence"`
	Type     string  `json:"type"`
	Command  string  `json:"command,omitempty"`
	Stream   string  `json:"stream,omitempty"`
	Data     string  `json:"data,omitempty"`
	Status   *uint32 `json:"status,omitempty"`
	Signal   string  `json:"signal,omitempty"`
}

// NewExecRecorder opens the lossless writer and makes command its first,
// durable record. A caller must treat any error as a session-setup failure.
func NewExecRecorder(cfg ExecConfig) (*ExecRecorder, error) {
	if cfg.Clock == nil {
		cfg.Clock = RealClock{}
	}
	if cfg.FileMode == 0 {
		cfg.FileMode = 0600
	}
	if cfg.DirMode == 0 {
		cfg.DirMode = 0700
	}
	if cfg.SessionID == "" {
		cfg.SessionID = fmt.Sprintf("%d", cfg.Clock.Now().UnixNano())
	}
	startedAt := cfg.Clock.Now()
	basePath, err := recordingBasePath(cfg.SessionConfig, startedAt)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(basePath), cfg.DirMode); err != nil {
		return nil, fmt.Errorf("create exec recording directory: %w", err)
	}
	// Claim the .exec.jsonl through the same create-or-refuse plus
	// take-the-next-name rule as the .cast (sessionname.go): a plant is
	// refused and the session with it, while a name a previous recording
	// already holds — same clock-derived session id — just moves along
	// instead of turning into a dropped session.
	claimedBase, f, err := claimSessionName(basePath, ".exec.jsonl", cfg.FileMode)
	if err != nil {
		return nil, fmt.Errorf("open exec recording %s.exec.jsonl: %w", basePath, err)
	}
	paths := ExecPaths{ExecPath: claimedBase + ".exec.jsonl", MetaPath: claimedBase + ".meta"}
	meta := Metadata{
		Person: cfg.Person, Machine: cfg.Machine, OSUser: cfg.OSUser, SessionID: cfg.SessionID,
		Command:   cfg.Command,
		StartedAt: startedAt, Status: "recording", RecordingMode: "exec",
		ExecFile: &FileInfo{Name: filepath.Base(paths.ExecPath)},
	}
	if err := WriteMeta(paths.MetaPath, meta, cfg.FileMode); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write exec metadata: %w", err)
	}
	r := &ExecRecorder{cfg: cfg, startedAt: startedAt, paths: paths, file: f, stdinHasher: sha256.New(), meta: meta}
	if err := r.writeLocked(execEvent{Type: "command", Command: cfg.Command}); err != nil {
		_ = f.Close()
		return nil, err
	}
	return r, nil
}

func recordingBasePath(cfg SessionConfig, startedAt time.Time) (string, error) {
	baseDir := filepath.Clean(cfg.BaseDir)
	if baseDir == "" || baseDir == "." {
		baseDir = "recordings"
	}
	var base string
	if cfg.SubdirLayout {
		dir := filepath.Join(baseDir, sanitizePathSegment(cfg.Machine), startedAt.Format("2006-01-02"))
		base = filepath.Join(dir, fmt.Sprintf("%s-%s-%s", startedAt.Format("150405"), sanitizePathSegment(cfg.Person), sanitizePathSegment(cfg.SessionID)))
	} else {
		base = filepath.Join(baseDir, fmt.Sprintf("%s-%s", sanitizePathSegment(cfg.Person), sanitizePathSegment(cfg.SessionID)))
	}
	rel, err := filepath.Rel(baseDir, filepath.Dir(base))
	if err != nil || rel == ".." || len(rel) > 3 && rel[:3] == ".."+string(filepath.Separator) {
		return "", fmt.Errorf("exec recording directory escapes BaseDir %q", cfg.BaseDir)
	}
	return base, nil
}

// Write records stdout. It satisfies core.Recording.
func (r *ExecRecorder) Write(p []byte) (int, error) { return r.writeChunk("stdout", p) }

// WriteStderr records stderr separately from stdout while sharing sequence.
func (r *ExecRecorder) WriteStderr(p []byte) (int, error) { return r.writeChunk("stderr", p) }

func (r *ExecRecorder) writeChunk(stream string, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.writeLocked(execEvent{Type: "chunk", Stream: stream, Data: base64.StdEncoding.EncodeToString(p)}); err != nil {
		return 0, err
	}
	r.bytesOut += int64(len(p))
	return len(p), nil
}

// AddBytesIn counts stdin forwarded from the human to the exec process and
// streams it into a SHA-256 (SPEC §6.5, IAMT-336 phase 5). The bytes
// are intentionally not written to JSONL: PROTOCOL §8 permits only the
// count and the hash, never an input recording. As with Recorder, calls
// after finalization are ignored because metadata is already immutable
// on disk. The argument is the slice that was just accepted by the
// bridge, so a partial Write never over-counts nor feeds the wrong
// prefix into the hash.
func (r *ExecRecorder) AddBytesIn(p []byte) {
	if len(p) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.bytesIn += int64(len(p))
	// Streaming SHA-256: hash.Hash buffers nothing internally, it only
	// updates its state. A 47 KB image or a 4 GB file work the same way.
	r.stdinHasher.Write(p)
}

func (r *ExecRecorder) ExitStatus(status uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writeLocked(execEvent{Type: "exit-status", Status: &status})
}

func (r *ExecRecorder) ExitSignal(signal string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writeLocked(execEvent{Type: "exit-signal", Signal: signal})
}

func (r *ExecRecorder) writeLocked(event execEvent) error {
	if r.closed || r.file == nil {
		return ErrRecorderClosed
	}
	event.Sequence = r.seq
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal exec event: %w", err)
	}
	data = append(data, '\n')
	if n, err := r.file.Write(data); err != nil {
		return fmt.Errorf("write exec event: %w", err)
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	if err := fileSyncFn(r.file); err != nil {
		return fmt.Errorf("sync exec event: %w", err)
	}
	r.seq++
	return nil
}

// Close intentionally defers final EOF to Finish. core.Bridge reaches Close
// after data EOF, but exit-status is delivered on the separate request stream.
func (r *ExecRecorder) Close() error { return nil }

// Finish appends EOF only after the machine request stream has drained.
func (r *ExecRecorder) Finish() error { return r.finalize("completed", false, "normal exit", true) }

func (r *ExecRecorder) Abort(reason string) error {
	if reason == "" {
		reason = "session aborted"
	}
	return r.finalize("aborted", true, reason, false)
}

func (r *ExecRecorder) finalize(status string, aborted bool, reason string, eof bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	// The final eof goes first, but a failure to write it no longer ends
	// this function early (M-9b, code review 23.09.2026, F-15).
	// Returning at that line left the descriptor open, r.closed false and
	// the .meta still saying "recording": the session is already over at
	// this point (Close is a deliberate no-op and the caller only records
	// the bridge error), so each failed finalization leaked a descriptor
	// and left a recording that looks live forever. The resource is
	// released on EVERY outcome and the original failure is returned last.
	var eofErr error
	if eof {
		eofErr = r.writeLocked(execEvent{Type: "eof"})
	}
	r.closed = true
	closeErr := r.file.Close()
	r.file = nil
	meta := r.meta
	meta.EndedAt = r.cfg.Clock.Now()
	meta.DurationSeconds = meta.EndedAt.Sub(r.startedAt).Seconds()
	meta.Status, meta.Aborted, meta.ExitReason = status, aborted, reason
	if eofErr != nil {
		// Best-effort honesty in the metadata: the recording did not
		// reach its own end, so it is not "completed" whatever the
		// caller asked for. The file is closed by now, so this is the
		// last fact the .meta can be given.
		meta.Status, meta.Aborted = "aborted", true
		meta.ExitReason = "finalization failed: " + eofErr.Error()
	}
	meta.BytesIn = r.bytesIn
	meta.BytesOut = r.bytesOut
	meta.TotalBytes = r.bytesOut
	// stdin{bytes, sha256} only when stdin actually carried bytes — an
	// empty stdin has no fact to record, and a SHA-256 of zero bytes is
	// not a fact worth printing (SPEC §6.5).
	if r.bytesIn > 0 {
		meta.Stdin = &StdinInfo{
			Bytes:  r.bytesIn,
			SHA256: hex.EncodeToString(r.stdinHasher.Sum(nil)),
		}
	}
	if info, err := os.Stat(r.paths.ExecPath); err == nil && meta.ExecFile != nil {
		meta.ExecFile.Size = info.Size()
		if _, sum, err := hashFile(r.paths.ExecPath); err == nil {
			meta.ExecFile.SHA256 = sum
		}
	}
	metaErr := WriteMeta(r.paths.MetaPath, meta, r.cfg.FileMode)
	if metaErr == nil {
		r.meta = meta
	}
	if eofErr != nil {
		return eofErr
	}
	if closeErr != nil {
		return fmt.Errorf("close exec recording: %w", closeErr)
	}
	if metaErr != nil {
		return fmt.Errorf("write exec metadata: %w", metaErr)
	}
	return nil
}

func (r *ExecRecorder) Paths() ExecPaths { return r.paths }
