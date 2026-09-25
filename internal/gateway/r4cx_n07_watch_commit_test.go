package gateway

// r4cx_n07_watch_commit_test.go — R4 review N-07.
//
// The watcher was marked as journalled BEFORE its session.watch was
// written, and the write's result was not looked at: if that one write
// failed, the live bytes went out anyway (machine path) and every later
// poll saw "already watched" and never wrote the lost event. Now the mark
// is committed only after the event is on disk, and a failed write
// refuses the read.

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// r4cxFailWatchWrites makes every session.watch append fail until the
// returned restore is called; everything else is written as before.
func r4cxFailWatchWrites(t *testing.T, f *fixture) (restore func()) {
	t.Helper()
	saved := f.gw.journalAppendFn.Load()
	fail := func(e events.Event) error {
		if e.Type == events.EventSessionWatch {
			return errors.New("write events.jsonl: disk full")
		}
		if saved != nil {
			return (*saved)(e)
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&fail)
	restore = func() { f.gw.journalAppendFn.Store(saved) }
	t.Cleanup(restore)
	return restore
}

func r4cxWatchCount(t *testing.T, f *fixture) int {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionWatch}})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	return len(evs)
}

func TestR4CXN07_AnAdminWatchWhoseEventFailedIsRecordedOnTheNextPoll(t *testing.T) {
	f := newFixture(t, nil)
	cast := filepath.Join(t.TempDir(), "n07.cast")
	if err := os.WriteFile(cast, []byte("live\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const id = "r4cx-n07"
	f.gw.live.add(id, cast, f.machineID)
	body := []byte(`{"proto":1,"id":"` + id + `","offset":0,"limit":1024}`)

	restore := r4cxFailWatchWrites(t, f)
	if _, cerr := cmdSessionsTail(f.gw, "admin", f.clock.Now(), body); cerr == nil {
		t.Fatalf("R4 review N-07: the live session was served although its session.watch could not be written")
	}
	restore()
	if _, cerr := cmdSessionsTail(f.gw, "admin", f.clock.Now(), body); cerr != nil {
		t.Fatalf("second poll: %v", cerr)
	}
	if n := r4cxWatchCount(t, f); n != 1 {
		t.Fatalf("R4 review N-07: after the journal recovered the watch is in the journal %d times, want 1 — the failed write left the watcher marked and the event was never written", n)
	}
}

func TestR4CXN07_TheMachineIsNotServedWhenItsWatchCannotBeRecorded(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	sess, err := f.gw.aclE.OpenSession(f.person, f.machineID, f.clock.Now(), func(acl.DenyReason) {})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	mc := &machineConn{id: f.machineID, g: f.gw}
	in := mineLine(t)
	in.Op = "sessions.tail"
	in.Tail = &inboundTail{Proto: 1, ID: sess.ID.String(), Offset: 0, Limit: 4096}

	restore := r4cxFailWatchWrites(t, f)
	if resp := mc.tailForMachine(in); resp.OK {
		t.Fatalf("R4 review N-07: the machine was answered although its session.watch could not be written: %+v", resp)
	}
	restore()
	// The failed write put the gateway into IAMT-451's refusing state; the
	// first write that lands lifts it, as any login would in life.
	f.gw.appendEvent(events.Event{Type: events.EventAdminOp, Actor: "root", Object: "journal", Result: "probe:ok"})
	mc.tailForMachine(in)
	if n := r4cxWatchCount(t, f); n != 1 {
		t.Fatalf("after the journal recovered the machine's watch is in the journal %d times, want 1", n)
	}
}

// R4 review N-09: check, write and mark were three steps under three
// separate locks - first requests that arrived together all saw "not
// recorded" and all wrote session.watch. One watch start is one line.
func TestR4CXN09_FirstRequestsArrivingTogetherWriteOneWatch(t *testing.T) {
	f := newFixture(t, nil)
	cast := filepath.Join(t.TempDir(), "n09.cast")
	if err := os.WriteFile(cast, []byte("live\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const id = "r4cx-n09"
	f.gw.live.add(id, cast, f.machineID)
	saved := f.gw.journalAppendFn.Load()
	slow := func(e events.Event) error {
		if e.Type == events.EventSessionWatch {
			time.Sleep(50 * time.Millisecond)
		}
		if saved != nil {
			return (*saved)(e)
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&slow)
	t.Cleanup(func() { f.gw.journalAppendFn.Store(saved) })

	body := []byte(`{"proto":1,"id":"` + id + `","offset":0,"limit":1024}`)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cmdSessionsTail(f.gw, "admin", f.clock.Now(), body)
		}()
	}
	wg.Wait()
	if n := r4cxWatchCount(t, f); n != 1 {
		t.Fatalf("R4 review N-09: six first requests arriving together wrote %d session.watch lines, want 1", n)
	}
}
