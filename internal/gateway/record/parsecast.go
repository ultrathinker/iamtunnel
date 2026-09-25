package record

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ParseCast feeds one chunk of an asciinema v2 recording to a terminal
// emulator and returns the trailing partial line, to be handed back on
// the next call.
//
// It lives here, beside the VT it drives, because this package is the
// one that owns the .cast format - it is the package that WRITES those
// files. It was briefly a private helper of the window and then an
// exported one, so that the Export button could replay a recording the
// same way the live tab does (IAMT-347). The need was real: two readers
// of the same format drift, and then the text under the button quietly
// stops being the text on the screen. But the window is not where a
// format parser belongs, and the command layer should not have to reach
// into the window to get at one. One reader, in the format's own home.
//
// A chunk may end anywhere - the gateway chooses where an answer stops,
// and it may stop in the middle of an event or of a UTF-8 rune - so the
// remainder is not an optimisation: dropping it loses whatever event
// straddled the boundary, for good, and only for some recordings.
func ParseCast(chunk []byte, remainder []byte, vt *VT) []byte {
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
		if len(line) == 0 {
			continue
		}

		if line[0] == '{' {
			var hdr struct {
				Width  int `json:"width"`
				Height int `json:"height"`
			}
			if err := json.Unmarshal(line, &hdr); err == nil && hdr.Width > 0 && hdr.Height > 0 {
				vt.Resize(hdr.Width, hdr.Height)
			}
			continue
		}

		if line[0] == '[' {
			var ev []any
			if err := json.Unmarshal(line, &ev); err == nil && len(ev) >= 3 {
				evType, _ := ev[1].(string)
				switch evType {
				case "o":
					if text, ok := ev[2].(string); ok {
						vt.Write([]byte(text))
					}
				case "r":
					if dim, ok := ev[2].(string); ok {
						var w, h int
						if _, err := fmt.Sscanf(dim, "%dx%d", &w, &h); err == nil && w > 0 && h > 0 {
							vt.Resize(w, h)
						}
					}
				}
			}
		}
	}
}
