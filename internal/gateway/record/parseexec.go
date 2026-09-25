package record

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"
)

// ParseExec is ParseCast's twin for the other recording format.
//
// A shell session is recorded as asciicast: a stream of terminal writes,
// which only a terminal emulator can turn back into a screen. A single
// command run without a terminal is recorded as .exec.jsonl instead: one
// JSON object per line, holding the command, its stdout and stderr in
// base64, and how it ended. The two files are in the same directory,
// under the same name, listed by the same verb, and nothing in the bytes
// themselves announces which is which -- that is what recordings.list's
// "mode" is for.
//
// Feeding one to the other's reader does not fail. An asciicast line
// handed to this function is skipped as an unknown type; a JSONL line
// handed to ParseCast begins with '{' and is read as a header. Both
// produce an empty transcript and no error at all, which is the worst
// possible answer to "what did this person run on my server": a blank
// page that looks like an answer. So the caller picks the reader by the
// metadata, never by looking at the bytes.
//
// The output goes through the same VT as a terminal recording, because
// exec output is not plain text either -- a compiler's diagnostics, git,
// anything with progress carries colour and carriage returns, and a
// reader that pasted those bytes verbatim would show the escapes.
//
// The signature matches ParseCast exactly, remainder and all, for the
// same reason: a chunk may end in the middle of a line, and a dropped
// remainder silently loses whichever event straddled the boundary.
func ParseExec(chunk []byte, remainder []byte, vt *VT) []byte {
	if vt == nil || len(chunk) == 0 {
		return remainder
	}
	combined := make([]byte, len(remainder)+len(chunk))
	copy(combined, remainder)
	copy(combined[len(remainder):], chunk)

	for {
		idx := bytes.IndexByte(combined, '\n')
		if idx < 0 {
			return combined
		}
		line := bytes.TrimSpace(combined[:idx])
		combined = combined[idx+1:]
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev struct {
			Type    string  `json:"type"`
			Command string  `json:"command"`
			Stream  string  `json:"stream"`
			Data    string  `json:"data"`
			Status  *uint32 `json:"status"`
			Signal  string  `json:"signal"`
		}
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		switch ev.Type {
		case "command":
			// The prompt the session never had. Without it the reader
			// sees output with no question above it, and a transcript
			// whose first line is an error message is unreadable.
			vt.Write([]byte("$ " + ev.Command + "\r\n"))
		case "chunk":
			data, err := base64.StdEncoding.DecodeString(ev.Data)
			if err != nil {
				continue
			}
			vt.Write(data)
		case "exit-status":
			// Only a non-zero status is worth a line: every successful
			// command ending in "[exit status 0]" buries the one that
			// did not.
			if ev.Status != nil && *ev.Status != 0 {
				vt.Write([]byte("\r\n[exit status " + strconv.FormatUint(uint64(*ev.Status), 10) + "]\r\n"))
			}
		case "exit-signal":
			if ev.Signal != "" {
				vt.Write([]byte("\r\n[killed by signal " + ev.Signal + "]\r\n"))
			}
		}
	}
}
