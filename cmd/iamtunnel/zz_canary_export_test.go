//go:build !nogui

package main

// Canary for IAMT-347: an export must not depend on where the CHUNK
// BOUNDARIES happen to fall.
//
// The walk fetches the recording in bounded pieces, and the gateway is
// free to end a piece anywhere — in the middle of a JSON event, in the
// middle of a UTF-8 rune, between the quote and the text. The tab
// carries a remainder across pieces for exactly this reason. If the
// export ever stopped carrying it, or dropped the last partial line, the
// text under the button would silently differ from the text on screen,
// and it would differ ONLY for recordings whose events straddle a
// boundary — the kind of defect that survives every round test because
// every round test cuts on a round number.

import (
	"strings"
	"testing"
)

// TestCanary_ExportIsTheSameTextAtEveryChunkSize replays one
// recording at many different chunk sizes and demands one answer.
//
// Canary: drop the remainder from guiReplayCast (pass nil instead of
// carrying it, as the round-1 backfill did) — this goes red at the first
// size that splits an event, naming the size.
func TestCanary_ExportIsTheSameTextAtEveryChunkSize(t *testing.T) {
	// Two-byte runes and a line that is committed by CRLF, so both a
	// rune split and an event split are reachable by some chunk size.
	cast := []byte("{\"version\":2,\"width\":80,\"height\":24}\n" +
		"[0.1,\"o\",\"\u043f\u0440\u0438\u0432\u0435\u0442\"]\n" +
		"[0.2,\"o\",\" \u043c\u0438\u0440\\r\\n\"]\n" +
		"[0.3,\"o\",\"\u0432\u0442\u043e\u0440\u043e\u0439 \u0440\u044f\u0434\\r\\n\"]\n")

	want, _, _ := guiReplayCast([][]byte{cast}, nil)
	if !strings.Contains(want, "\u043f\u0440\u0438\u0432\u0435\u0442 \u043c\u0438\u0440") {
		t.Fatalf("the fixture itself does not replay: %q", want)
	}

	for size := 1; size <= len(cast); size++ {
		var chunks [][]byte
		for i := 0; i < len(cast); i += size {
			end := i + size
			if end > len(cast) {
				end = len(cast)
			}
			chunks = append(chunks, cast[i:end])
		}
		got, _, _ := guiReplayCast(chunks, nil)
		if got != want {
			t.Fatalf("at chunk size %d the export produced different text:\n got %q\nwant %q\nthe gateway chooses where an answer ends, so a transcript that depends on that boundary is a transcript that disagrees with the tab for some recordings and not others", size, got, want)
		}
	}
}
