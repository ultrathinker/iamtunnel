package record

// LiveFile names the file a recording is being written into while its
// session runs, and how to read it (IAMT-453). The live registry used to
// learn the file from each recorder's Paths(), which answer differently
// shaped values - so a registry that asked for one shape silently never
// registered the other, and no exec session could be watched. And the two
// files are read differently: a reader has to know which it has before it
// opens the bytes.
type LiveFile struct {
	Path string
	// Mode is LiveModeCast or LiveModeExec - the same distinction
	// recordings.list draws with its mode.
	Mode string
}

// The two ways a live recording is read.
const (
	// LiveModeCast is asciicast v2, read with ParseCast.
	LiveModeCast = "cast"
	// LiveModeExec is an exec recording's .exec.jsonl, read with ParseExec.
	LiveModeExec = "exec"
)

// ParserFor is the reader for a recording in mode: ParseExec for an exec
// recording, ParseCast for anything else - a mode nobody named is what
// every recording was before exec recordings existed.
func ParserFor(mode string) func(chunk []byte, remainder []byte, vt *VT) []byte {
	if mode == LiveModeExec {
		return ParseExec
	}
	return ParseCast
}

// LiveFile is the cast file this recording writes into.
func (r *Recorder) LiveFile() LiveFile {
	return LiveFile{Path: r.Paths().CastPath, Mode: LiveModeCast}
}

// LiveFile is the .exec.jsonl this recording writes into.
func (r *ExecRecorder) LiveFile() LiveFile {
	return LiveFile{Path: r.Paths().ExecPath, Mode: LiveModeExec}
}
