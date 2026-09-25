//go:build !nogui

package main

// Canary for IAMT-349: the export must not grow with the recording.
//
// The existing tests check that the bytes come out right. Every one
// of them would still pass on the version this task exists to replace,
// which held the whole recording in memory twice: correctness was never
// the problem. So this canary measures the one thing they do not — the
// live heap WHILE the walk is running, read from inside the walk, where
// a buffering implementation is holding everything it has fetched so far
// and a streaming one is holding a single chunk.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"runtime"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/proto"
	"github.com/ultrathinker/iamtunnel/internal/server"
)

// TestCanary_ExportDoesNotGrowWithTheRecording.
//
// Canary: make the walk collect the chunks into a slice and replay them
// at the end (its shape before this task). The heap read at the midpoint
// then carries everything fetched so far and misses the bound below by
// an order of magnitude.
func TestCanary_ExportDoesNotGrowWithTheRecording(t *testing.T) {
	const header = "{\"version\":2,\"width\":80,\"height\":24}\n"
	const event = "[0.1,\"o\",\"0123456789012345678901234567890123456789012345678901234567890123\"]\n"
	const want = 24 << 20

	cast := make([]byte, 0, want+len(header))
	cast = append(cast, header...)
	for len(cast) < want {
		cast = append(cast, event...)
	}

	// The baseline is taken with the fixture's own 24 MB already built
	// and held: it is the same in either implementation, so what matters
	// is what the EXPORT adds on top of it, not the absolute figure.
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	var heapAtMidpoint, measuredAt uint64

	tail := func(_ context.Context, req server.TailRequest) (server.TailAnswer, error) {
		off := int(req.Offset)
		end := off + int(req.Limit)
		if end > len(cast) {
			end = len(cast)
		}
		data := ""
		if off < len(cast) {
			data = base64.StdEncoding.EncodeToString(cast[off:end])
		}
		// Halfway through, look at what this process is holding on to.
		if measuredAt == 0 && off > len(cast)/2 {
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			heapAtMidpoint = m.HeapAlloc
			measuredAt = uint64(off)
		}
		body, err := json.Marshal(map[string]any{
			"id": req.SessionID, "offset": req.Offset, "total": uint64(len(cast)),
			"live": true, "data": data,
		})
		if err != nil {
			return server.TailAnswer{}, err
		}
		return server.TailAnswer{Result: body}, nil
	}

	dir := exportTestServer(t, tail, staticMine([]proto.MineSession{{
		ID: exportTestSessionID, Person: "alice", Started: "2026-01-05T14:12:05Z",
	}}))
	exportTestMachine(t, dir, "vm-nine")

	if _, err := guiSessionExport(dir, exportTestSessionID); err != nil {
		t.Fatalf("export: %v", err)
	}
	if measuredAt == 0 {
		t.Fatal("the walk never reached the midpoint: the fixture is wrong, not the code")
	}

	// The line is drawn on the GROWTH, not on the total: the fixture
	// holds 24 MB of its own and both implementations pay that equally.
	// A streaming walk adds one chunk plus the emulator's own bounded
	// screen and scrollback; a buffering one adds every byte fetched so
	// far, twelve megabytes by the midpoint. Half of what has been
	// fetched sits far from both, so it separates them without being
	// brittle about allocator noise.
	grew := int64(heapAtMidpoint) - int64(base.HeapAlloc)
	if grew < 0 {
		grew = 0
	}
	limit := int64(measuredAt / 2)
	if grew > limit {
		t.Fatalf("by byte %d of %d the export had grown the heap by %d bytes, over the %d-byte line — it is growing with the recording, which is what runs a long session out of memory before a single text file appears",
			measuredAt, len(cast), grew, limit)
	}
}
