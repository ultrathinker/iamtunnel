package gateway

// r4_f12_drain_stuck_reader_test.go — R4 F-12.
//
// Drain wrote the "restarting" line to every live session synchronously,
// before Close. A write into an SSH channel whose peer has stopped granting
// window (Ctrl-S in the person's terminal while output is flowing) blocks
// until the window opens — so one such person held the whole stop past
// gatewayDrainTimeout, until the service manager killed the process and
// every other session's record went unfinalised. The revoke path closed
// this in IAMT-448; the drain path had no such guard.

import (
	"io"
	"testing"
	"time"
)

// r4f12StuckChan is a person's channel whose peer never opens its window:
// every write blocks until the test releases it.
type r4f12StuckChan struct {
	release chan struct{}
}

func (c *r4f12StuckChan) Read([]byte) (int, error)                       { <-c.release; return 0, io.EOF }
func (c *r4f12StuckChan) Write(p []byte) (int, error)                    { <-c.release; return 0, io.ErrClosedPipe }
func (c *r4f12StuckChan) Close() error                                   { return nil }
func (c *r4f12StuckChan) CloseWrite() error                              { return nil }
func (c *r4f12StuckChan) SendRequest(string, bool, []byte) (bool, error) { return true, nil }
func (c *r4f12StuckChan) Stderr() io.ReadWriter                          { return r4f12StuckStderr{c} }

type r4f12StuckStderr struct{ c *r4f12StuckChan }

func (s r4f12StuckStderr) Read([]byte) (int, error)    { <-s.c.release; return 0, io.EOF }
func (s r4f12StuckStderr) Write(p []byte) (int, error) { <-s.c.release; return 0, io.ErrClosedPipe }

func TestR4F12_DrainIsNotHeldByAPersonWhoStoppedReading(t *testing.T) {
	f := newFixture(t, nil)
	stuck := &r4f12StuckChan{release: make(chan struct{})}
	t.Cleanup(func() { close(stuck.release) })
	unwatch := f.gw.watchDrain("r4-f12-stuck", stuck)
	defer unwatch()

	const timeout = 200 * time.Millisecond
	done := make(chan struct{})
	go func() {
		f.gw.Drain(timeout)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("R4 F-12: Drain(%s) is still running after 5s — the restart notice to a person who stopped reading blocks the whole stop, and Close never runs", timeout)
	}
}
