package ui

// The maintainer's canary: drawing the transcript and tail-fetching it
// must not touch the emulator at the same time.
//
// Found by the maintainer on 19.09.2026: they were watching a live
// session in a separate window, typing, deleting characters -- and the
// program CRASHED whole, together with both windows.
//
// The cause: one *record.VT was touched by two goroutines -- the one
// drawing (Transcript) and the one on which begin() runs the request
// (ParseCast). One moves and scrolls the screen buffer while the
// other reads it line by line. This is not "occasionally a wrong
// picture", it is an index past the end of a slice in a goroutine
// nobody recovers -- that is, the death of the process.
//
// Deleting characters is exactly the traffic that triggers this: the
// far side redraws the whole line, and the record arrives in the
// middle of a read.
//
// Gate 5 runs the whole set under -race and stayed silent: no test
// brought these two goroutines together. A real request arriving in
// the middle of a real frame is needed.

import (
	"context"
	"sync"
	"testing"
)

// TestCanary_WatchingIsRaceFree.
//
// Canary: drop the locking in watchState -- the race detector will
// show the write from the request goroutine against the read from the
// drawing goroutine.
func TestCanary_WatchingIsRaceFree(t *testing.T) {
	f := newBareFrame(t)

	line := []byte(`[0.1,"o","typing and deleting\r\n"]` + "\n")
	header := []byte(`{"version":2,"width":80,"height":24}` + "\n")
	first := true
	f.cfg.Actions.AdminSessionTail = func(ctx context.Context, id string, offset int64) ([]byte, int64, int64, bool, string, error) {
		chunk := line
		if first {
			first = false
			chunk = append(append([]byte{}, header...), line...)
		}
		return chunk, offset + int64(len(chunk)), offset + int64(len(chunk)) + 1, true, "cast", nil
	}

	f.watchSession("session:1", "admin", "win-test-vm")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			f.tailWatched()
		}
	}()
	go func() {
		defer wg.Done()
		gtx := newTestLayoutContext(900, 700)
		for i := 0; i < 200; i++ {
			_ = f.layoutLiveSection(gtx)
		}
	}()
	wg.Wait()

	// Nothing to assert beyond "it did not die and -race stayed quiet":
	// the failure this guards is a crash, and the detector is the
	// verdict. A sanity check that the work actually happened, so a
	// future edit cannot make this pass by doing nothing.
	f.watch.mu.Lock()
	total := f.watch.total
	f.watch.mu.Unlock()
	if total == 0 {
		t.Fatal("two hundred passes read nothing -- the canary checked nothing")
	}
}
