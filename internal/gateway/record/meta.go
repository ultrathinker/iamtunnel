package record

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// WindowSize holds terminal dimensions.
type WindowSize struct {
	Cols   int `json:"cols"`
	Rows   int `json:"rows"`
	Width  int `json:"width,omitempty"`
	Height int `json:"height,omitempty"`
}

// FileInfo holds metadata about a generated file.
type FileInfo struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// StdinInfo is the fact about input that went human -> machine in an
// exec session, per SPEC §6.5: the volume and the streaming SHA-256,
// never the bytes themselves. The pointer is omitted from .meta when
// nothing was sent (PROTOCOL §8: no fabricated zero-bytes hash).
type StdinInfo struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Metadata records facts about a recorded session.
type Metadata struct {
	Person          string     `json:"person"`
	Machine         string     `json:"machine"`
	OSUser          string     `json:"os_user,omitempty"`
	SessionID       string     `json:"session_id"`
	Command         string     `json:"command,omitempty"` // what an exec ran, with a terminal or without (IAMT-454)
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         time.Time  `json:"ended_at"`
	DurationSeconds float64    `json:"duration_seconds"`
	Status          string     `json:"status"` // "completed", "aborted", "recording", "error"
	Aborted         bool       `json:"aborted"`
	ExitReason      string     `json:"exit_reason,omitempty"`
	WindowSize      WindowSize `json:"window_size"`
	CastFile        FileInfo   `json:"cast_file"`
	TxtFile         FileInfo   `json:"txt_file"`
	// TxtOmittedLines is how many lines from the middle of a long session
	// the .txt leaves out (R4 F-05); the .cast holds them. Absent when none.
	TxtOmittedLines int64 `json:"txt_omitted_lines,omitempty"`
	// RecordingMode distinguishes terminal recordings from lossless exec
	// recordings. ExecFile is present only when RecordingMode is "exec".
	RecordingMode string    `json:"recording_mode,omitempty"`
	ExecFile      *FileInfo `json:"exec_file,omitempty"`
	// BytesOut — bytes machine -> human (PROTOCOL §8: this is what
	// passes through Recorder.Write, hence what the cast file ends up
	// holding. Always equal to the cast file's useful payload; the
	// recorded duration matches the byte count read by the admin).
	BytesOut int64 `json:"bytes_out"`
	// TotalBytes — kept as alias of BytesOut for backward compatibility
	// with already shipped .meta files. New code should prefer BytesOut.
	TotalBytes int64 `json:"total_bytes"`
	// BytesIn — bytes human -> machine. PROTOCOL §8 forbids recording
	// input; this is a counter only and is not persisted to the cast
	// file. The admin recordings.list response surfaces both BytesIn
	// and BytesOut (PROTOCOL §6 + §8).
	BytesIn int64 `json:"bytes_in"`
	// Stdin — bytes human -> machine together with a streaming SHA-256
	// (SPEC §6.5, IAMT-336 phase 5). nil when nothing was sent so the
	// journal never carries a fabricated zero-bytes hash.
	Stdin *StdinInfo `json:"stdin,omitempty"`
}

// WriteMeta writes the metadata to path atomically. It is
// datafile.WriteFileAtomic since IAMT-332 round nine (§5.6: one writer
// for the whole program, not five): random O_EXCL temporary, fsync
// before the rename (WithSync, as this writer always did), the mode set
// on the temporary, and the replace acting on the entry — the old
// remove-and-retry for an existing Windows target is gone with it,
// because os.Rename is MoveFileEx REPLACE_EXISTING and never needed it.
func WriteMeta(path string, meta Metadata, perm os.FileMode) error {
	if perm == 0 {
		perm = 0600
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	data = append(data, '\n')

	return datafile.WriteFileAtomic(path, data, datafile.WithMode(perm), datafile.WithSync())
}

// ReadMeta reads and parses metadata JSON from path. The read opens the
// name the no-follow way via datafile.ReadFile (IAMT-332 round six):
// the recordings tree lives under the gateway data directory, so a
// symlink or FIFO planted at a .meta name is refused instead of being
// read through or wedged on.
func ReadMeta(path string) (Metadata, error) {
	data, err := datafile.ReadFile(path)
	if err != nil {
		return Metadata{}, fmt.Errorf("read metadata file: %w", err)
	}

	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return Metadata{}, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return meta, nil
}
