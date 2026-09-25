package gateway

// IAMT-471: a line reached the gateway's journal after Gateway.Close had
// returned. The writer was the machine connection's control reader
// (machineConn.readLoop): a machine that drops as the gateway stops makes
// the reader tear the connection down itself - "control-read-error" - and
// its machine.disconnected went into the journal after Close had come
// back, because nothing Close waits for counted that goroutine. Whoever
// owns the journal closes it once Close returns; the line then met a
// closed file, and before 50e23b1 it turned audit-health.json to "the
// journal is broken" on a gateway that had simply stopped.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestIAMT471_NothingIsJournaledAfterCloseReturns(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// The reader's machine.disconnected is held at the journal's door
	// until Close has returned, or for a second at most - long enough for
	// a Close that does not wait for it to come back first.
	var closed atomic.Bool
	closeReturned := make(chan struct{})
	held := make(chan struct{})
	var holdOnce sync.Once
	var mu sync.Mutex
	var late []string
	hook := func(e events.Event) error {
		if e.Type == events.EventMachineDisconnected && e.Result == "control-read-error" {
			holdOnce.Do(func() {
				close(held)
				select {
				case <-closeReturned:
				case <-time.After(time.Second):
				}
			})
		}
		if closed.Load() {
			mu.Lock()
			late = append(late, string(e.Type)+" "+e.Result)
			mu.Unlock()
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&hook)

	fm.close() // the machine drops: the gateway's reader sees the read fail
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("the machine dropped and the gateway never wrote its machine.disconnected")
	}
	if err := f.gw.Close(); err != nil {
		t.Fatal(err)
	}
	closed.Store(true)
	close(closeReturned)
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(late) > 0 {
		t.Fatalf("written to the journal after Gateway.Close returned: %v", late)
	}
}
