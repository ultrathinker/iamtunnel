package record

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

var (
	// ErrRecorderClosed indicates an operation was attempted on a closed recorder.
	ErrRecorderClosed = errors.New("recorder is closed")
)

// fileSyncFn is the fsync seam: after every successful cast chunk write
// the Recorder MUST call fileSyncFn(castFile) before returning from
// Write, so that "every machine byte is written and fsync-committed
// before it reaches the human" (PROTOCOL §8) holds at every chunk boundary, not
// only at session end. This is the single source of truth for what
// "Sync" means here; tests substitute it (same package) to assert
// the path without touching real disks.
//
// Production keeps it as a plain os.File.Sync. Substituting it for a
// test that never opens a file would be unsafe — only NewRecorder
// records a real *os.File — so the contract is "behave like
// (*os.File).Sync, or return the error the kernel would have returned".
var fileSyncFn = func(f *os.File) error { return f.Sync() }

// SessionConfig configures a recording session.
type SessionConfig struct {
	BaseDir      string
	Machine      string
	Person       string
	OSUser       string
	SessionID    string
	Cols         int
	Rows         int
	Term         string
	Title        string
	Clock        Clock
	FileMode     os.FileMode
	DirMode      os.FileMode
	SubdirLayout bool   // When true, uses recordings/<machine>/<YYYY-MM-DD>/<HHMMSS>-<person>-<session-id>
	BasePath     string // When set, overrides directory and filename prefix directly
	// Command is the program a terminal session was started with, when it
	// was started by an exec after pty-req ("ssh -t gw command") rather
	// than by a shell. The terminal does not echo an exec, so without this
	// the recording shows the output and never what produced it
	// (IAMT-454). It goes into the .cast header (asciicast v2's own
	// "command") and the .meta.
	Command string
}

// SessionPaths contains paths of generated files for a session.
type SessionPaths struct {
	CastPath string
	TxtPath  string
	MetaPath string
}

type hashingWriter struct {
	w     io.Writer
	h     hash.Hash
	count int64
}

func newHashingWriter(w io.Writer) *hashingWriter {
	return &hashingWriter{
		w: w,
		h: sha256.New(),
	}
}

func (hw *hashingWriter) Write(p []byte) (int, error) {
	n, err := hw.w.Write(p)
	if n > 0 {
		hw.h.Write(p[:n])
		hw.count += int64(n)
	}
	return n, err
}

func (hw *hashingWriter) SumSHA256() string {
	return hex.EncodeToString(hw.h.Sum(nil))
}

// Recorder manages recording of a single terminal session.
// It writes asciicast v2 (.cast), human-readable transcript (.txt),
// and metadata JSON (.meta).
type Recorder struct {
	mu sync.Mutex

	cfg       SessionConfig
	clock     Clock
	startTime time.Time
	paths     SessionPaths

	castFile   *os.File
	castWriter *hashingWriter
	castCW     *CastWriter

	vt *VT
	// vtErr is the emulator's first fault, if it had one (IAMT-441). From
	// then on it is not fed again - its state is whatever the panic left -
	// and the recording ends as an error. See feedVT.
	vtErr error

	pendingUTF8 []byte
	bytesOut    int64
	bytesIn     int64
	stdinHasher hash.Hash

	closed     bool
	aborted    bool
	status     string
	exitReason string
	meta       Metadata
	lastErr    error
}

var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// sanitizePathSegment converts an untrusted identifier (such as machine name,
// person, or session ID) into a safe single directory/file component.
// It neutralizes path traversals (.., /, \), absolute paths, drive letters,
// UNC network shares, Windows reserved names (CON, NUL, ...), control characters,
// and trailing dots/spaces that Windows silently discards.
func sanitizePathSegment(name string) string {
	s := strings.TrimSpace(name)
	if s == "" {
		return "unknown-machine"
	}

	// Slashes, colons, control chars, and illegal filesystem characters are replaced with '_'
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r == '/' || r == '\\':
			sb.WriteByte('_')
		case r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|':
			sb.WriteByte('_')
		case r < 0x20 || r == 0x7F:
			sb.WriteByte('_')
		default:
			sb.WriteRune(r)
		}
	}
	clean := sb.String()

	// Trim trailing dots and spaces (Windows silently strips them, which can cause collision or escapes)
	clean = strings.TrimRight(clean, ". ")
	if clean == "" {
		return "unknown-machine"
	}

	// If the string consists purely of dots (e.g. ".", "..", "...", "...."), replace with safe name
	onlyDots := true
	for _, r := range clean {
		if r != '.' {
			onlyDots = false
			break
		}
	}
	if onlyDots {
		return "unknown-machine"
	}

	// Check for Windows reserved device names (CON, PRN, AUX, NUL, COM1..9, LPT1..9)
	base := clean
	if dotIdx := strings.IndexByte(base, '.'); dotIdx != -1 {
		base = base[:dotIdx]
	}
	if windowsReservedNames[strings.ToUpper(base)] {
		clean = "_" + clean
	}

	return clean
}

// NewRecorder creates and starts a new session recording.
func NewRecorder(cfg SessionConfig) (*Recorder, error) {
	if cfg.Clock == nil {
		cfg.Clock = RealClock{}
	}
	// 80x24 for a size not given, and the emulator's own bound for one
	// past it (IAMT-442): the .cast header and the metadata must say the
	// size the transcript is really parsed in.
	cfg.Cols, cfg.Rows = boundSize(cfg.Cols, cfg.Rows)
	if cfg.FileMode == 0 {
		cfg.FileMode = 0600
	}
	if cfg.DirMode == 0 {
		cfg.DirMode = 0700
	}
	if cfg.Term == "" {
		cfg.Term = "xterm-256color"
	}
	if cfg.SessionID == "" {
		cfg.SessionID = fmt.Sprintf("%d", cfg.Clock.Now().UnixNano())
	}

	startTime := cfg.Clock.Now()

	cleanBaseDir := filepath.Clean(cfg.BaseDir)
	if cleanBaseDir == "" || cleanBaseDir == "." {
		cleanBaseDir = "recordings"
	}

	var basePath string
	if cfg.BasePath != "" {
		cleanBasePath := filepath.Clean(cfg.BasePath)
		if !filepath.IsAbs(cleanBasePath) {
			cleanBasePath = filepath.Join(cleanBaseDir, cleanBasePath)
		}
		rel, err := filepath.Rel(cleanBaseDir, cleanBasePath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("BasePath %q escapes BaseDir %q", cfg.BasePath, cfg.BaseDir)
		}
		basePath = cleanBasePath
	} else if cfg.SubdirLayout {
		dateStr := startTime.Format("2006-01-02")
		timeStr := startTime.Format("150405")
		cleanMachine := sanitizePathSegment(cfg.Machine)
		cleanPerson := sanitizePathSegment(cfg.Person)
		if cleanPerson == "unknown-machine" {
			cleanPerson = "unknown-user"
		}
		cleanSessionID := sanitizePathSegment(cfg.SessionID)
		if cleanSessionID == "unknown-machine" {
			cleanSessionID = "unknown-session"
		}
		dir := filepath.Join(cleanBaseDir, cleanMachine, dateStr)
		filename := fmt.Sprintf("%s-%s-%s", timeStr, cleanPerson, cleanSessionID)
		basePath = filepath.Join(dir, filename)
	} else {
		cleanPerson := sanitizePathSegment(cfg.Person)
		if cleanPerson == "unknown-machine" {
			cleanPerson = "unknown-user"
		}
		cleanSessionID := sanitizePathSegment(cfg.SessionID)
		if cleanSessionID == "unknown-machine" {
			cleanSessionID = "unknown-session"
		}
		basePath = filepath.Join(cleanBaseDir, fmt.Sprintf("%s-%s", cleanPerson, cleanSessionID))
	}

	dir := filepath.Dir(basePath)
	// Hard boundary invariant: recording directory MUST NOT escape cleanBaseDir
	relDir, err := filepath.Rel(cleanBaseDir, dir)
	if err != nil || relDir == ".." || strings.HasPrefix(relDir, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("recording directory %q escapes BaseDir %q", dir, cleanBaseDir)
	}

	if err := os.MkdirAll(dir, cfg.DirMode); err != nil {
		return nil, fmt.Errorf("create recording directory %s: %w", dir, err)
	}

	// Claim the .cast with restricted permissions (0600), through
	// datafile.Create's O_EXCL — a plant at the name is refused in words,
	// never truncated through (symlink, hard link) and never wedged on
	// (FIFO, junction) — and through claimSessionName's collision rule,
	// because the name is clock-derived and therefore repeats whenever
	// the clock stands still. sessionname.go carries the whole argument:
	// a repeated name takes the next name, a planted one still refuses
	// the session.
	claimedBase, castF, err := claimSessionName(basePath, ".cast", cfg.FileMode)
	if err != nil {
		return nil, fmt.Errorf("open cast file %s.cast: %w", basePath, err)
	}
	paths := SessionPaths{
		CastPath: claimedBase + ".cast",
		TxtPath:  claimedBase + ".txt",
		MetaPath: claimedBase + ".meta",
	}

	hw := newHashingWriter(castF)
	cw := NewCastWriter(hw)

	header := CastHeader{
		Version:   2,
		Width:     cfg.Cols,
		Height:    cfg.Rows,
		Timestamp: startTime.Unix(),
		Title:     cfg.Title,
		Command:   cfg.Command,
		Env: map[string]string{
			"TERM": cfg.Term,
		},
	}
	if err := cw.WriteHeader(header); err != nil {
		_ = castF.Close()
		return nil, fmt.Errorf("write cast header: %w", err)
	}

	vt := NewVT(cfg.Cols, cfg.Rows)

	initialMeta := Metadata{
		Person:    cfg.Person,
		Machine:   cfg.Machine,
		OSUser:    cfg.OSUser,
		SessionID: cfg.SessionID,
		Command:   cfg.Command,
		StartedAt: startTime,
		Status:    "recording",
		Aborted:   false,
		WindowSize: WindowSize{
			Cols:   cfg.Cols,
			Rows:   cfg.Rows,
			Width:  cfg.Cols,
			Height: cfg.Rows,
		},
		CastFile: FileInfo{
			Name: filepath.Base(paths.CastPath),
		},
		TxtFile: FileInfo{
			Name: filepath.Base(paths.TxtPath),
		},
	}

	// Write initial metadata so crash/abort before close still has valid facts on disk
	_ = WriteMeta(paths.MetaPath, initialMeta, cfg.FileMode)

	rec := &Recorder{
		cfg:         cfg,
		clock:       cfg.Clock,
		startTime:   startTime,
		paths:       paths,
		castFile:    castF,
		castWriter:  hw,
		castCW:      cw,
		vt:          vt,
		stdinHasher: sha256.New(),
		status:      "recording",
		meta:        initialMeta,
	}

	return rec, nil
}

// Write processes and records terminal output (stdout/"o"). Implements io.Writer.
func (r *Recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return 0, ErrRecorderClosed
	}

	if len(p) == 0 {
		return 0, nil
	}

	r.bytesOut += int64(len(p))

	var data []byte
	if len(r.pendingUTF8) > 0 {
		data = make([]byte, len(r.pendingUTF8)+len(p))
		copy(data, r.pendingUTF8)
		copy(data[len(r.pendingUTF8):], p)
		r.pendingUTF8 = nil
	} else {
		data = p
	}

	// Find boundary of complete runes
	completeLen := 0
	for completeLen < len(data) {
		if !utf8.FullRune(data[completeLen:]) {
			break
		}
		_, size := utf8.DecodeRune(data[completeLen:])
		completeLen += size
	}

	if completeLen < len(data) {
		r.pendingUTF8 = make([]byte, len(data)-completeLen)
		copy(r.pendingUTF8, data[completeLen:])
	}

	if completeLen > 0 {
		completeData := data[:completeLen]
		relTime := r.clock.Now().Sub(r.startTime).Seconds()
		if err := r.castCW.WriteOutput(relTime, completeData); err != nil {
			r.lastErr = err
			return 0, err
		}
		// PROTOCOL §8 / SPEC §6.5: every machine byte is written and
		// fsync-committed before it is forwarded to the human. Sync exactly
		// here, not at finalization: an fsync error = a write error, the same
		// path T7 (IAMT-164) takes.
		if r.castFile != nil {
			if syncErr := fileSyncFn(r.castFile); syncErr != nil {
				r.lastErr = syncErr
				return 0, fmt.Errorf("fsync cast file after chunk: %w", syncErr)
			}
		}

		var vtErr error
		if err := r.feedVT(func() { _, vtErr = r.vt.Write(completeData) }); err != nil {
			vtErr = err
		}
		if vtErr != nil {
			r.lastErr = vtErr
			return 0, vtErr
		}
	}

	return len(p), nil
}

// feedVT hands the terminal emulator one more piece of the session and
// turns a panic inside it into this recording's error.
//
// The emulator parses bytes a machine chose, so a fault in it is within
// reach of anyone with a shell there. Write runs in the bridge's copy
// goroutine, Resize in the goroutine forwarding the person's requests,
// and Close/Abort in the session's own: a panic let out of any of them
// ends the gateway process and every session on it, not this one
// recording (IAMT-441). The bridge sees the error instead, closes this
// session and aborts the recording.
//
// After the first fault the emulator is not fed again. The .cast is
// written before the emulator sees a byte, so it still holds everything
// the machine sent; only the transcript stops where the fault was.
func (r *Recorder) feedVT(call func()) error {
	if r.vtErr != nil {
		return r.vtErr
	}
	return r.guardVT(call)
}

// guardVT runs one call into the emulator and records a panic in it as
// the emulator's fault. Reading the transcript goes through here alone,
// without feedVT's refusal: reading changes nothing, and what the
// emulator had drawn before a fault is still the best text there is.
func (r *Recorder) guardVT(call func()) (err error) {
	defer func() {
		if p := recover(); p != nil {
			if r.vtErr == nil {
				r.vtErr = fmt.Errorf("record: the terminal emulator failed: %v", p)
			}
			err = r.vtErr
		}
	}()
	call()
	return nil
}

// AddBytesIn records the slice of bytes that were just forwarded
// human -> machine (SPEC §6.5, IAMT-336 phase 5). PROTOCOL §8 forbids
// recording input, so there is no fsync, no cast-file write, no VT
// effect: only a counter and a streaming SHA-256 of what passed
// through. The counter is surfaced in metadata.BytesIn and through the
// recordings.list admin exec (PROTOCOL §6); the hash is surfaced in
// metadata.Stdin.sha256 when there is anything to surface.
//
// Adding to a closed recorder is a no-op: the result is fixed at Close
// time, and the caller's bridge is just about to release the channel
// anyway. Storing nothing past Close avoids races with the metadata
// rewrite in finalize. The argument is the slice that was just
// accepted by the bridge, so a partial Write never over-counts nor
// feeds the wrong prefix into the hash.
func (r *Recorder) AddBytesIn(p []byte) {
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

// Resize records a window size change event ("r") and updates the VT matrix.
func (r *Recorder) Resize(cols, rows int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return ErrRecorderClosed
	}

	if cols <= 0 || rows <= 0 {
		return nil
	}
	// The emulator's bound (IAMT-442), applied here too, so the "r" event
	// and the metadata say the size the transcript is parsed in.
	cols, rows = boundSize(cols, rows)

	r.cfg.Cols = cols
	r.cfg.Rows = rows
	vtErr := r.feedVT(func() { r.vt.Resize(cols, rows) })

	relTime := r.clock.Now().Sub(r.startTime).Seconds()
	if err := r.castCW.WriteResize(relTime, cols, rows); err != nil {
		r.lastErr = err
		return err
	}
	if vtErr != nil {
		r.lastErr = vtErr
		return vtErr
	}

	return nil
}

// Close closes the recorder normally upon successful session termination.
func (r *Recorder) Close() error {
	return r.finalize("completed", false, "normal exit")
}

// Abort closes the recorder when the session is interrupted or aborted unexpectedly.
func (r *Recorder) Abort(reason string) error {
	if reason == "" {
		reason = "session aborted"
	}
	return r.finalize("aborted", true, reason)
}

// CloseWithReason allows custom status and exit reason on session close.
func (r *Recorder) CloseWithReason(status string, aborted bool, reason string) error {
	return r.finalize(status, aborted, reason)
}

func (r *Recorder) finalize(status string, aborted bool, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true
	r.aborted = aborted
	r.status = status
	r.exitReason = reason

	endTime := r.clock.Now()
	duration := endTime.Sub(r.startTime).Seconds()

	// Flush any pending trailing UTF-8 bytes to both cast and VT
	if len(r.pendingUTF8) > 0 {
		relTime := endTime.Sub(r.startTime).Seconds()
		_ = r.castCW.WriteOutput(relTime, r.pendingUTF8)
		_ = r.feedVT(func() { _, _ = r.vt.Write(r.pendingUTF8) })
		r.pendingUTF8 = nil
	}
	_ = r.feedVT(r.vt.Flush)

	// Close .cast file and sync
	var castErr error
	if r.castFile != nil {
		_ = r.castFile.Sync()
		castErr = r.castFile.Close()
		r.castFile = nil
	}

	// Write .txt transcript. WriteFileAtomic (IAMT-332 round nine), not
	// the flat os.WriteFile this was: a plant at the .txt name is
	// replaced at the entry, never written through or wedged on.
	var txtContent string
	var txtOmitted int64
	_ = r.guardVT(func() { txtContent, txtOmitted = r.vt.Transcript(), r.vt.OmittedLines() })
	txtBytes := []byte(txtContent)
	txtErr := datafile.WriteFileAtomic(r.paths.TxtPath, txtBytes, datafile.WithMode(r.cfg.FileMode))

	// Collect file sizes & checksums by READING DIRECTLY FROM DISK
	var castSize int64
	var castSHA256 string
	if castErr == nil {
		size, hash, err := hashFile(r.paths.CastPath)
		if err != nil {
			castErr = err
		} else {
			castSize = size
			castSHA256 = hash
		}
	}

	var txtSize int64
	var txtSHA256 string
	if txtErr == nil {
		size, hash, err := hashFile(r.paths.TxtPath)
		if err != nil {
			txtErr = err
		} else {
			txtSize = size
			txtSHA256 = hash
		}
	}

	// If there was an error writing/syncing any file, or the emulator
	// faulted and the transcript stops short, mark session status as "error"
	if castErr != nil || txtErr != nil || r.lastErr != nil || r.vtErr != nil {
		r.status = "error"
		if r.exitReason == "" || r.exitReason == "normal exit" {
			if txtErr != nil {
				r.exitReason = fmt.Sprintf("failed writing txt: %v", txtErr)
			} else if castErr != nil {
				r.exitReason = fmt.Sprintf("failed writing cast: %v", castErr)
			} else if r.lastErr != nil {
				r.exitReason = fmt.Sprintf("io error: %v", r.lastErr)
			} else {
				r.exitReason = r.vtErr.Error()
			}
		}
	}

	finalMeta := Metadata{
		Person:          r.cfg.Person,
		Machine:         r.cfg.Machine,
		OSUser:          r.cfg.OSUser,
		SessionID:       r.cfg.SessionID,
		Command:         r.cfg.Command,
		StartedAt:       r.startTime,
		EndedAt:         endTime,
		DurationSeconds: duration,
		Status:          r.status,
		Aborted:         r.aborted,
		ExitReason:      r.exitReason,
		WindowSize: WindowSize{
			Cols:   r.cfg.Cols,
			Rows:   r.cfg.Rows,
			Width:  r.cfg.Cols,
			Height: r.cfg.Rows,
		},
		CastFile: FileInfo{
			Name:   filepath.Base(r.paths.CastPath),
			Size:   castSize,
			SHA256: castSHA256,
		},
		TxtFile: FileInfo{
			Name:   filepath.Base(r.paths.TxtPath),
			Size:   txtSize,
			SHA256: txtSHA256,
		},
		TxtOmittedLines: txtOmitted,
		// bytesOut is "machine -> human", the recorded side (PROTOCOL §8).
		// TotalBytes stays as an alias for reading older meta files in the
		// admin recordings.list view.
		BytesOut:   r.bytesOut,
		TotalBytes: r.bytesOut,
		// bytesIn is "human -> machine": counted, never recorded.
		BytesIn: r.bytesIn,
	}
	// stdin{bytes, sha256} only when stdin actually carried bytes — an
	// empty stdin has no fact to record, and a SHA-256 of zero bytes is
	// not a fact worth printing (SPEC §6.5).
	if r.bytesIn > 0 {
		finalMeta.Stdin = &StdinInfo{
			Bytes:  r.bytesIn,
			SHA256: hex.EncodeToString(r.stdinHasher.Sum(nil)),
		}
	}

	metaErr := WriteMeta(r.paths.MetaPath, finalMeta, r.cfg.FileMode)
	r.meta = finalMeta

	if castErr != nil {
		return fmt.Errorf("close cast file: %w", castErr)
	}
	if txtErr != nil {
		return fmt.Errorf("write txt file: %w", txtErr)
	}
	if metaErr != nil {
		return fmt.Errorf("write meta file: %w", metaErr)
	}
	if r.lastErr != nil {
		return r.lastErr
	}
	if r.vtErr != nil {
		return r.vtErr
	}

	return nil
}

// hashFile streams a finalized recording part into its SHA-256. The open
// is the same no-follow regular-file-only open as every other data-file
// read (IAMT-332 round six) — but it stays a stream: recordings can be
// large, so the hash must not read whole files into memory.
func hashFile(path string) (int64, string, error) {
	f, err := datafile.OpenExisting(path, os.O_RDONLY)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return size, hex.EncodeToString(h.Sum(nil)), nil
}

// Paths returns the file paths for this session.
func (r *Recorder) Paths() SessionPaths {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.paths
}

// Metadata returns the current metadata snapshot.
func (r *Recorder) Metadata() Metadata {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.meta
}

// Transcript returns the current VT transcript string.
func (r *Recorder) Transcript() string {
	return r.vt.Transcript()
}
